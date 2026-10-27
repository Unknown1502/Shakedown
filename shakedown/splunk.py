"""A read-only Splunk preflight: run a bounded historical search for a Sigma rule and report what it found.

IMPLEMENTED BUT NOT LIVE-VERIFIED until `tools/splunk_smoke.py` has succeeded against an authorised instance (see
`live_verification`). The unit tests use a mock server.

What it will and will not do:
- It uses only the search-job REST endpoints (create, poll, read results, cancel, delete) and the current-context call.
  Any other endpoint is refused in `_request`, before the network. It never touches saved searches, alerts, indexes,
  roles or configuration.
- Every SPL string is checked against a command allowlist before it is sent. Write-capable commands, subsearches and
  macros are refused.
- A search names explicit indexes from an operator-set allowlist and an explicit, bounded time window. There is no default
  scope and no wildcard index.
- It needs no model and never calls one. Events it reads are shown to the analyst only.
- Credentials come from the environment, are never part of a record or an exception message, and TLS is verified by default.
"""
import base64
import json
import re
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

from shakedown.validate import STAGED_NAME, _sigma_exe

ROOT = Path(__file__).resolve().parents[1]
VERIFICATION_FILE = ROOT / "evidence/splunk_live_verification.json"

READ_ONLY_COMMANDS = {"search", "where", "regex", "rex", "eval", "fields", "table", "head", "dedup", "stats", "fieldsummary",
                      "rename", "sort"}
ENDPOINTS = re.compile(r"^/services/(authentication/current-context|search/jobs(/[A-Za-z0-9_.\-]+(/(results|control))?)?)$")
PRIVILEGED_CAPABILITIES = {"admin_all_objects", "edit_user", "edit_roles", "edit_roles_grantable", "delete_by_keyword",
                           "edit_tcp", "edit_monitor", "edit_scripted", "edit_forwarders", "edit_httpauths"}
FIELD_SAMPLE_EVENTS = 1000
VALUE_LIMIT = 300
EXTRA_DISPLAY_FIELDS = ["_time", "host", "source", "EventCode", "User", "ParentImage"]

SYSMON = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
_SCOPES = {
    "process_creation": (SYSMON, 1, "Sysmon process creation. Windows Security 4688 uses different field names (NewProcessName, "
                                     "CommandLine) and is not supported: a rule written with Sigma's Sysmon-style fields would not match it."),
    "ps_script": ("XmlWinEventLog:Microsoft-Windows-PowerShell/Operational", 4104, "PowerShell script block logging."),
    "registry_set": (SYSMON, 13, "Sysmon registry value set."),
    "file_event": (SYSMON, 11, "Sysmon file create."),
    "network_connection": (SYSMON, 3, "Sysmon network connection."),
    "image_load": (SYSMON, 7, "Sysmon image load."),
}
NOTES = [
    "A historical search shows what the rule would have matched in this window. It does not show that the rule can detect an attack "
    "that did not occur in the window.",
    "Field names depend on the add-ons that parse your events; the log-source scope above is an assumption you should check.",
]


class SplunkError(RuntimeError):
    """`kind` is one of: config, auth, permission, query, timeout, cancelled, unavailable, scope, unsafe_query,
    forbidden_endpoint, privileged_account, unsupported_logsource, conversion."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


def _bool(value: str | None, default: bool) -> bool:
    return default if value is None else value.strip().lower() not in ("0", "false", "no", "off")


@dataclass(frozen=True)
class SplunkConfig:
    base_url: str
    token: str | None = field(default=None, repr=False)
    username: str | None = field(default=None, repr=False)
    password: str | None = field(default=None, repr=False)
    allowed_indexes: tuple[str, ...] = ()
    verify_tls: bool = True
    ca_bundle: str | None = None
    max_results: int = 5
    max_time_range_hours: int = 168
    search_timeout_s: float = 120.0
    allow_privileged: bool = False

    def __post_init__(self):
        parts = urllib.parse.urlsplit(self.base_url)
        loopback = parts.hostname in ("127.0.0.1", "localhost", "::1")
        if parts.scheme != "https" and not (parts.scheme == "http" and loopback):
            raise SplunkError("config", "SPLUNK_BASE_URL must be an https URL (plain http is accepted only for loopback)")
        if not (self.token or (self.username and self.password)):
            raise SplunkError("config", "credentials missing: set SPLUNK_TOKEN, or SPLUNK_USERNAME and SPLUNK_PASSWORD")

    @classmethod
    def from_env(cls, env) -> "SplunkConfig":
        missing = []
        if not env.get("SPLUNK_BASE_URL"):
            missing.append("SPLUNK_BASE_URL")
        if not env.get("SPLUNK_ALLOWED_INDEXES"):
            missing.append("SPLUNK_ALLOWED_INDEXES")
        if not (env.get("SPLUNK_TOKEN") or (env.get("SPLUNK_USERNAME") and env.get("SPLUNK_PASSWORD"))):
            missing.append("SPLUNK_TOKEN (or SPLUNK_USERNAME and SPLUNK_PASSWORD)")
        if missing:
            raise SplunkError("config", "Splunk is not configured. Missing: " + ", ".join(missing))
        indexes = tuple(i.strip() for i in env["SPLUNK_ALLOWED_INDEXES"].split(",") if i.strip())
        return cls(base_url=env["SPLUNK_BASE_URL"], token=env.get("SPLUNK_TOKEN") or None, username=env.get("SPLUNK_USERNAME") or None,
                   password=env.get("SPLUNK_PASSWORD") or None, allowed_indexes=indexes,
                   verify_tls=_bool(env.get("SPLUNK_VERIFY_TLS"), True), ca_bundle=env.get("SPLUNK_CA_BUNDLE") or None,
                   max_results=int(env.get("SPLUNK_MAX_RESULTS", 5)), max_time_range_hours=int(env.get("SPLUNK_MAX_TIME_RANGE_HOURS", 168)),
                   search_timeout_s=float(env.get("SPLUNK_SEARCH_TIMEOUT_S", 120)), allow_privileged=_bool(env.get("SPLUNK_ALLOW_PRIVILEGED"), False))


def live_verification(path: Path | None = None) -> dict:
    """Has `tools/splunk_smoke.py` ever succeeded against a real instance? A mock never counts."""
    path = Path(path) if path else VERIFICATION_FILE
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"live_verified": False, "label": "implemented but not live-verified"}
    return {"live_verified": True, "label": "live-verified", "verified_at": doc.get("verified_at"), "server_version": doc.get("server_version")}


# --- query safety ---------------------------------------------------------------------------------------------------
def _segments(spl: str) -> list[str]:
    """Split on pipes outside double quotes. Refuses unquoted subsearch brackets and macros."""
    out, current, quoted, i = [], [], False, 0
    while i < len(spl):
        ch = spl[i]
        if quoted:
            current.append(ch)
            if ch == "\\" and i + 1 < len(spl):
                current.append(spl[i + 1])
                i += 1
            elif ch == '"':
                quoted = False
        elif ch == '"':
            quoted = True
            current.append(ch)
        elif ch in "[]`":
            raise SplunkError("unsafe_query", "subsearches and macros are not allowed in a read-only preflight")
        elif ch == "|":
            out.append("".join(current))
            current = []
        else:
            current.append(ch)
        i += 1
    out.append("".join(current))
    return out


def check_read_only(spl: str) -> None:
    for segment in _segments(spl):
        command = re.match(r"\s*([A-Za-z_]+)", segment)
        name = command.group(1).lower() if command else ""
        if name not in READ_ONLY_COMMANDS:
            raise SplunkError("unsafe_query", f"the command {name or segment.strip()[:20]!r} is not allowed in a read-only preflight")


def convert_to_spl(rule_text: str) -> str:
    """Convert with the Sigma CLI and the Splunk Windows pipeline. The result has NO log-source scope; `preflight` adds it."""
    with tempfile.TemporaryDirectory(prefix="shakedown-splunk-") as tmp:
        path = Path(tmp) / STAGED_NAME
        path.write_text(rule_text, encoding="utf-8")
        proc = subprocess.run([_sigma_exe(), "convert", "-t", "splunk", "-p", "splunk_windows", str(path)],
                              capture_output=True, text=True, encoding="utf-8", timeout=60)
    lines = [l for l in proc.stdout.splitlines() if l.strip() and not l.startswith("Parsing Sigma rules")]
    if proc.returncode != 0 or not lines:
        reason = (proc.stderr.strip().splitlines() or ["no query produced"])[-1]
        raise SplunkError("conversion", f"the Sigma CLI could not convert this rule to SPL: {reason[:200]}")
    if len(lines) > 1:
        raise SplunkError("conversion", "the rule converts to more than one query, which this preflight does not support")
    return lines[0].strip()


def logsource_scope(category: str) -> dict:
    if category not in _SCOPES:
        raise SplunkError("unsupported_logsource", f"log source category {category!r} has no Splunk scope in this preflight")
    source, code, note = _SCOPES[category]
    return {"source": source, "EventCode": code, "clause": f'source="{source}" EventCode={code}', "note": note}


def rule_fields(rule_text: str) -> list[str]:
    detection = (yaml.safe_load(rule_text) or {}).get("detection") or {}
    found: set[str] = set()

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key != "condition":
                    found.add(str(key).split("|")[0])
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk({k: v for k, v in detection.items() if k != "condition"})
    return sorted(f for f in found if f and not re.fullmatch(r"(selection|filter)\w*|keywords?\w*", f))


def _wrap(detect: str) -> str:
    head, *rest = _segments(detect)
    return "(" + head.strip() + ")" + "".join(" |" + r for r in rest)


def _trim(value) -> str:
    text = str(value)
    return text if len(text) <= VALUE_LIMIT else text[:VALUE_LIMIT] + "..."


# --- the connector -------------------------------------------------------------------------------------------------
class SplunkConnector:
    def __init__(self, config: SplunkConfig, poll_interval_s: float = 1.0):
        self.config, self.poll_interval_s = config, poll_interval_s
        self._cancel = threading.Event()
        if urllib.parse.urlsplit(config.base_url).scheme == "https":
            self._ssl = ssl.create_default_context(cafile=config.ca_bundle) if config.verify_tls else ssl._create_unverified_context()
        else:
            self._ssl = None

    def cancel(self) -> None:
        self._cancel.set()

    def _headers(self) -> dict:
        if self.config.token:
            return {"Authorization": f"Bearer {self.config.token}"}
        raw = f"{self.config.username}:{self.config.password}".encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode()}

    def _request(self, method: str, path: str, form: dict | None = None, params: dict | None = None) -> dict:
        if not ENDPOINTS.match(path):
            raise SplunkError("forbidden_endpoint", f"{method} {path} is not a read-only preflight endpoint")
        url = self.config.base_url.rstrip("/") + path + "?" + urllib.parse.urlencode({"output_mode": "json", **(params or {})})
        data = urllib.parse.urlencode({"output_mode": "json", **form}).encode() if form is not None else None
        request = urllib.request.Request(url, data=data, method=method, headers=self._headers())
        try:
            with urllib.request.urlopen(request, timeout=30, context=self._ssl) as resp:
                body = resp.read()
        except urllib.error.HTTPError as exc:
            detail = self._messages(exc.read())
            if exc.code == 401:
                raise SplunkError("auth", "Splunk rejected the credentials (HTTP 401)") from None
            if exc.code == 403:
                raise SplunkError("permission", "the account lacks permission for this call (HTTP 403)") from None
            if exc.code == 400:
                raise SplunkError("query", detail or "Splunk rejected the search (HTTP 400)") from None
            raise SplunkError("unavailable", f"Splunk answered HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise SplunkError("unavailable", f"cannot reach Splunk: {type(exc).__name__}") from None
        try:
            return json.loads(body) if body else {}
        except ValueError:
            raise SplunkError("unavailable", "Splunk returned a response that is not JSON") from None

    @staticmethod
    def _messages(body: bytes) -> str:
        try:
            messages = json.loads(body).get("messages") or []
        except (ValueError, AttributeError):
            return ""
        return "; ".join(str(m.get("text", "")) for m in messages)[:500]

    def _identity(self) -> dict:
        content = ((self._request("GET", "/services/authentication/current-context").get("entry") or [{}])[0]).get("content", {})
        caps = sorted(str(c) for c in content.get("capabilities") or [])
        risky = sorted(set(caps) & PRIVILEGED_CAPABILITIES)
        identity = {"username": content.get("username"), "roles": content.get("roles") or [], "capabilities": caps,
                    "warnings": [], "capabilities_known": bool(caps)}
        if risky and not self.config.allow_privileged:
            raise SplunkError("privileged_account", f"the account has admin-class capabilities ({', '.join(risky)}); use a dedicated "
                                                    "search-only role, or set SPLUNK_ALLOW_PRIVILEGED=true to accept the risk")
        if risky:
            identity["warnings"].append(f"admin-class capabilities present: {', '.join(risky)}")
        if not caps:
            identity["warnings"].append("the server did not report capabilities, so the account's privileges are unknown")
        return identity

    def _search(self, spl: str, earliest: datetime, latest: datetime, count: int) -> dict:
        check_read_only(spl)
        started = time.monotonic()
        sid = self._request("POST", "/services/search/jobs", form={
            "search": spl, "earliest_time": str(int(earliest.timestamp())), "latest_time": str(int(latest.timestamp())),
            "exec_mode": "normal", "adhoc_search_level": "fast"}).get("sid")
        if not sid:
            raise SplunkError("unavailable", "Splunk did not return a search id")
        try:
            deadline = time.monotonic() + self.config.search_timeout_s
            while True:
                if self._cancel.is_set():
                    self._stop(sid)
                    raise SplunkError("cancelled", "the preflight was cancelled and the search job was stopped")
                content = ((self._request("GET", f"/services/search/jobs/{sid}").get("entry") or [{}])[0]).get("content", {})
                if content.get("isFailed") or content.get("dispatchState") == "FAILED":
                    text = "; ".join(str(m.get("text", "")) for m in content.get("messages") or []) or "the search failed"
                    raise SplunkError("query", text[:500])
                if content.get("isDone"):
                    break
                if time.monotonic() > deadline:
                    self._stop(sid)
                    raise SplunkError("timeout", f"the search did not finish within {self.config.search_timeout_s:g} s and was cancelled")
                time.sleep(self.poll_interval_s)
            rows = self._request("GET", f"/services/search/jobs/{sid}/results", params={"count": str(count)}).get("results") or []
            return {"rows": rows, "seconds": round(time.monotonic() - started, 2)}
        finally:
            self._delete(sid)

    def _stop(self, sid: str) -> None:
        try:
            self._request("POST", f"/services/search/jobs/{sid}/control", form={"action": "cancel"})
        except SplunkError:
            pass

    def _delete(self, sid: str) -> None:
        try:
            self._request("DELETE", f"/services/search/jobs/{sid}")
        except SplunkError:
            pass

    def _check_scope(self, indexes: list[str], earliest: datetime, latest: datetime) -> tuple[datetime, datetime]:
        if not indexes or any(not i or i == "*" or "*" in i for i in indexes):
            raise SplunkError("scope", "name one or more specific indexes; empty and wildcard indexes are refused")
        outside = [i for i in indexes if i not in self.config.allowed_indexes]
        if outside:
            raise SplunkError("scope", f"index(es) {outside} are not in the operator's allowed list {list(self.config.allowed_indexes)}")
        earliest, latest = (t if t.tzinfo else t.replace(tzinfo=timezone.utc) for t in (earliest, latest))
        if earliest >= latest:
            raise SplunkError("scope", "the time range must start before it ends")
        if (latest - earliest).total_seconds() > self.config.max_time_range_hours * 3600:
            raise SplunkError("scope", f"the time range exceeds the limit of {self.config.max_time_range_hours} hours")
        if latest.timestamp() > time.time() + 300:
            raise SplunkError("scope", "the time range ends in the future")
        return earliest, latest

    def preflight(self, rule_text: str, *, indexes: list[str], earliest: datetime, latest: datetime) -> dict:
        self._cancel.clear()
        started = time.monotonic()
        earliest, latest = self._check_scope(indexes, earliest, latest)
        category = ((yaml.safe_load(rule_text) or {}).get("logsource") or {}).get("category", "")
        scope = logsource_scope(category)
        identity = self._identity()
        detect = convert_to_spl(rule_text)
        fields = rule_fields(rule_text)

        index_clause = "(" + " OR ".join(f'index="{i}"' for i in indexes) + ")"
        base = f"search {index_clause} {scope['clause']}"
        queries = {"coverage": f"{base} | stats count min(_time) as first max(_time) as last",
                   "fields": f"{base} | head {FIELD_SAMPLE_EVENTS} | fieldsummary maxvals=1 | fields field",
                   "detection": f"{base} {_wrap(detect)} | stats count",
                   "sample": f"{base} {_wrap(detect)} | head {self.config.max_results} | table "
                             + ", ".join(dict.fromkeys(EXTRA_DISPLAY_FIELDS + fields))}
        for query in queries.values():  # refuse anything unsafe before the first request, not when its turn comes
            check_read_only(query)
        result = {
            "connector": {"name": "splunk-rest-read-only", "live_verified": False,  # a connector run is never live-verified by itself
                          "verification": live_verification(), "credential_type": "token" if self.config.token else "basic",
                          "tls_verified": self.config.verify_tls if self.config.base_url.startswith("https") else None},
            "identity": identity,
            "scope": {"indexes": list(indexes), "earliest": earliest.isoformat(), "latest": latest.isoformat(),
                      "logsource_category": category, "logsource_scope": scope["clause"], "logsource_note": scope["note"]},
            "converted_detection": detect, "queries": queries, "notes": list(NOTES),
            "searched_at": datetime.now(timezone.utc).isoformat()}

        cov = self._search(queries["coverage"], earliest, latest, 1)["rows"]
        events = int((cov[0].get("count") if cov else 0) or 0)
        result["coverage"] = {"events_in_scope": events, "first_event": cov[0].get("first") if cov else None,
                              "last_event": cov[0].get("last") if cov else None}
        if events == 0:
            return self._finish(result, started, "telemetry_missing_or_unsupported", "no_events_in_scope",
                                "No events of the required log source exist in the selected indexes and window, so a search for the rule "
                                "cannot match anything. This is missing telemetry, not a clean result.")

        observed = sorted(str(r.get("field")) for r in self._search(queries["fields"], earliest, latest, FIELD_SAMPLE_EVENTS)["rows"])
        missing = [f for f in fields if f not in observed]
        result["fields"] = {"rule_fields": fields, "observed": observed, "missing": missing, "sampled_events": min(events, FIELD_SAMPLE_EVENTS)}
        if missing:
            return self._finish(result, started, "telemetry_missing_or_unsupported", "fields_not_observed",
                                f"The rule uses field(s) {missing} that do not appear in a sample of {min(events, FIELD_SAMPLE_EVENTS)} events from the "
                                "required log source. They may not be extracted by your add-ons, so a search would match nothing even for a real attack. "
                                "Fix the field extraction or map the field names before relying on this rule.")

        rows = self._search(queries["detection"], earliest, latest, 1)["rows"]
        total = int((rows[0].get("count") if rows else 0) or 0)
        examples = []
        if total:
            sample = self._search(queries["sample"], earliest, latest, self.config.max_results)["rows"]
            examples = [{k: _trim(v) for k, v in row.items() if not k.startswith("_") or k == "_time"} for row in sample[:self.config.max_results]]
        result["matches"] = {"count": total, "examples": examples, "examples_shown": len(examples), "examples_limit": self.config.max_results}
        status = "potential_matches_found" if total else "no_matches_in_window"
        detail = ("These are potential matches: review each event to decide whether it is the behaviour the rule is meant to find."
                  if total else "Telemetry exists and the rule's fields were observed, and nothing in the window matched.")
        return self._finish(result, started, status, "", detail)

    @staticmethod
    def _finish(result: dict, started: float, status: str, detail_code: str, detail: str) -> dict:
        result.update(status=status, status_detail=detail_code, explanation=detail, elapsed_s=round(time.monotonic() - started, 2))
        result.setdefault("matches", {"count": None, "examples": [], "examples_shown": 0})
        return result
