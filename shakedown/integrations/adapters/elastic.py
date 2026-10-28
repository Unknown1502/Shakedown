"""Elasticsearch / Elastic Security adapter: a bounded, read-only preflight over the official search API.

What it does: authenticates with an API key (or basic auth), reads who it is signed in as and what that account may do, lists the indices it can
see, converts a Sigma rule to a Lucene query with pySigma's official Elasticsearch backend and an ECS Windows field-mapping pipeline, and runs four
`_search` requests (coverage, field presence, match count, a few examples) over explicit indices and an explicit time window.

What it will not do: it calls only the endpoints in `ALLOWED` (identity, privilege check, index listing, `_search`). Every search body is checked
against a read-only allowlist before it is sent: no scripts, runtime fields, scroll, point-in-time or anything else that changes or widens the search.
It never creates a detection rule, alert, index or API key.

Sigma field names are not assumed to exist in your indices: the rule is mapped through an ECS pipeline, the mapped fields are printed, and the
preflight checks that each one is present in events of the required log source before it calls a count meaningful.
"""
import base64
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml
from sigma.backends.elasticsearch import LuceneBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
import sigma.pipelines.elasticsearch.windows as ecs

from shakedown.splunk import _SCOPES
from shakedown.integrations import policy
from shakedown.integrations.adapters.splunk import _int
from shakedown.integrations.base import (LIVE_VERIFIED_TEST, NOT_LIVE_VERIFIED, Check, ConnectionReport, FieldSpec, IntegrationError, ProviderAdapter,
                                         ProviderSpec, apply_defaults, redact)

ROOT = Path(__file__).resolve().parents[3]
VERIFICATION_FILE = ROOT / "evidence/elastic_live_verification.json"
INDEX_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,99}$")
ALLOWED = (("GET", re.compile(r"^/$")), ("GET", re.compile(r"^/_security/_authenticate$")), ("POST", re.compile(r"^/_security/user/_has_privileges$")),
           ("GET", re.compile(r"^/_resolve/index/\*$")), ("POST", re.compile(r"^/[A-Za-z0-9][A-Za-z0-9_.,\-]{0,990}/_search$")))
FORBIDDEN_KEYS = {"script", "script_fields", "runtime_mappings", "scroll", "pit", "knn", "rescore", "suggest", "stored_fields", "docvalue_fields", "collapse",
                  "inner_hits", "highlight", "indices_boost", "search_after", "stats", "profile", "explain", "update", "delete", "index", "reindex"}
TOP_LEVEL = {"size", "track_total_hits", "timeout", "_source", "sort", "query", "aggs"}
PIPELINES = {"ecs_windows": ecs.ecs_windows, "ecs_windows_old": ecs.ecs_windows_old}
FIELD_SAMPLE = 1000
VALUE_LIMIT = 300
TS_DEFAULT = "@timestamp"
BASE_DISPLAY = ["host.name", "event.code", "user.name", "process.parent.executable"]
PRIVILEGED_CLUSTER = ("all", "manage", "manage_security", "manage_api_key", "manage_index_templates")
PRIVILEGED_INDEX = ("write", "delete", "manage")
NOTES = [
    "A historical search shows what the rule would have matched in this window. It does not show that the rule can detect an attack that did not occur in the window.",
    "Field names depend on how your events are shipped and mapped. The ECS mapping and the log-source scope above are assumptions you should check.",
]


def live_verification(path=None) -> dict:
    try:
        doc = json.loads(Path(path or VERIFICATION_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"live_verified": False, "label": "implemented but not live-verified"}
    loop = bool(doc.get("target_is_loopback"))
    return {"live_verified": True, "label": "live-verified on a loopback test instance" if loop else "live-verified", "target_is_loopback": loop,
            "verified_at": doc.get("verified_at"), "server_version": doc.get("server_version")}


def check_read_only(body: dict) -> None:
    """Refuse a search body that could do anything but run a bounded, ordinary search."""
    if not isinstance(body, dict) or set(body) - TOP_LEVEL:
        raise IntegrationError("unsafe_query", f"the search body uses fields that are not allowed: {sorted(set(body) - TOP_LEVEL) if isinstance(body, dict) else 'not an object'}")
    if len(json.dumps(body)) > 200_000:
        raise IntegrationError("unsafe_query", "the search body is too large")

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if str(key).lower() in FORBIDDEN_KEYS:
                    raise IntegrationError("unsafe_query", f"the search uses {key!r}, which is not allowed in a read-only preflight")
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)
    walk(body)


def _flatten(doc: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in (doc or {}).items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, key + "."))
        else:
            out[key] = ", ".join(map(str, v)) if isinstance(v, list) else v
    return out


def _trim(v) -> str:
    t = str(v)
    return t if len(t) <= VALUE_LIMIT else t[:VALUE_LIMIT] + "..."


def _mapped_fields(rule) -> list:
    found = set()

    def walk(item):
        if hasattr(item, "detection_items"):
            for d in item.detection_items:
                walk(d)
        elif getattr(item, "field", None):
            found.add(str(item.field))
    for det in rule.detection.detections.values():
        walk(det)
    return sorted(found)


def convert_to_lucene(rule_text: str, pipeline: str) -> tuple:
    """(lucene query, the field names the rule uses after mapping). Raises IntegrationError('conversion') with the reason when the rule cannot be mapped."""
    try:
        col = SigmaCollection.from_yaml(rule_text)
        if len(col.rules) != 1:
            raise IntegrationError("conversion", "give exactly one Sigma rule")
        out = LuceneBackend(processing_pipeline=PIPELINES[pipeline]()).convert(col)
        fields = _mapped_fields(col.rules[0])
    except SigmaError as exc:
        raise IntegrationError("conversion", f"pySigma's Elasticsearch backend could not convert this rule: {str(exc)[:240]}") from None
    except (yaml.YAMLError, ValueError, KeyError) as exc:
        raise IntegrationError("conversion", f"the rule could not be read ({type(exc).__name__})") from None
    if len(out) != 1:
        raise IntegrationError("conversion", "the rule converts to more than one query, which this preflight does not support")
    return str(out[0]), fields


def logsource_filters(category: str) -> dict:
    """The explicit log-source scope, in ECS terms. It is an assumption about how events are shipped; it is printed with every plan."""
    try:
        source, code, note = _SCOPES[category]
    except KeyError:
        raise IntegrationError("unsupported_logsource", f"log source category {category!r} has no Elastic scope in this preflight") from None
    channel = source.split(":", 1)[1]
    return {"filters": [{"term": {"winlog.channel": channel}}, {"term": {"event.code": str(code)}}],
            "clause": f'winlog.channel:"{channel}" AND event.code:"{code}"', "note": note.replace("Windows Security 4688 uses different field names (NewProcessName, CommandLine) and is not supported: a rule written with Sigma's Sysmon-style fields would not match it.",
                                                                                                "Windows Security 4688 events use different fields and are not covered by this scope.")}


class _Client:
    def __init__(self, base_url: str, headers: dict, transport: policy.PolicyTransport):
        self.base, self.headers, self.transport = base_url.rstrip("/"), headers, transport

    def call(self, method: str, path: str, body: dict | None = None) -> dict:
        if not any(m == method and rx.match(path.split("?")[0]) for m, rx in ALLOWED):
            raise IntegrationError("forbidden_endpoint", f"{method} {path.split('?')[0][:60]} is not a read-only preflight endpoint")
        data = json.dumps(body).encode("utf-8") if body is not None else None
        status, raw = self.transport.send(method, self.base + path, {**self.headers, **({"Content-Type": "application/json"} if data is not None else {})}, data)
        try:
            doc = json.loads(raw) if raw else {}
        except ValueError:
            doc = {}
        if status >= 400:
            reason = ((doc.get("error") or {}).get("reason") if isinstance(doc.get("error"), dict) else None) or ""
            kind = {401: "auth", 403: "permission", 404: "scope", 400: "query"}.get(status, "unavailable")
            text = {"auth": "the server rejected the credentials (HTTP 401)", "permission": "the account lacks permission for this call (HTTP 403)",
                    "scope": "an index named in the search was not found (HTTP 404)", "query": reason or "Elasticsearch rejected the search (HTTP 400)"}.get(kind, f"Elasticsearch answered HTTP {status}")
            raise IntegrationError(kind, text[:400])
        return doc


class ElasticAdapter(ProviderAdapter):
    def __init__(self, verification_path=None):
        self._verification_path = verification_path

    @property
    def spec(self) -> ProviderSpec:
        v = live_verification(self._verification_path)
        verified = bool(v["live_verified"])
        note = (f"Live-verified on a throwaway local Elasticsearch {v.get('server_version') or ''} test instance with simulated Sysmon events. Not verified against Elastic Cloud, a production cluster, "
                "a real Elastic Agent or Winlogbeat pipeline, or a connection whose certificate verifies.") if verified else \
            "Implemented and tested against a mock server only. Never run against a real Elasticsearch, so its behaviour there is not verified."
        fields = (FieldSpec("endpoint", "Elasticsearch endpoint", "url", True, "The Elasticsearch HTTPS address (not Kibana), for example https://localhost:9200 or your Elastic Cloud Elasticsearch endpoint.", placeholder="https://elasticsearch.example.com:9200"),
                  FieldSpec("verify_tls", "Verify the server certificate", "bool", False, "Leave on. Turning it off is accepted only for a loopback or private test instance.", True),
                  FieldSpec("field_mapping", "Field mapping for Windows events", "select", False, "How your Windows events name their fields. Use the ECS mapping for Elastic Agent or Winlogbeat 7 and later.", "ecs_windows",
                            options=(("ecs_windows", "ECS (Elastic Agent, Winlogbeat 7+)"), ("ecs_windows_old", "Winlogbeat before 7"))),
                  FieldSpec("ca_bundle", "CA bundle file", "text", False, "Path to a PEM file with the CA that signed the server certificate.", advanced=True),
                  FieldSpec("accept_insecure_tls", "I understand certificate checking is off", "bool", False, "Required if verification is off.", False, advanced=True),
                  FieldSpec("allow_privileged", "Accept an account with administrative privileges", "bool", False, "Not recommended. Use a role with only read access to the chosen indices.", False, advanced=True),
                  FieldSpec("timestamp_field", "Timestamp field", "text", False, "The field every search's time window applies to.", TS_DEFAULT, advanced=True),
                  FieldSpec("max_results", "Example events to keep", "number", False, "At most this many matching events are returned for review.", 5, advanced=True),
                  FieldSpec("max_time_range_hours", "Longest allowed window (hours)", "number", False, "A search window can never exceed this.", 168, advanced=True))
        return ProviderSpec(
            id="elastic", name="Elastic Security (Elasticsearch)", status=LIVE_VERIFIED_TEST if verified else NOT_LIVE_VERIFIED, verification_note=note, scope_noun="index", scope_example="winlogbeat-8.15.0",
            query_language="Elasticsearch query (JSON)", auth_methods=(("api_key", "API key (recommended)"), ("basic", "User name and password")), fields=fields,
            secret_fields=(("api_key", FieldSpec("api_key", "API key (the encoded value)", "secret", True, "The `encoded` value returned when the key was created.")),
                           ("basic", FieldSpec("username", "User name", "text", True)), ("basic", FieldSpec("password", "Password", "secret", True))),
            capabilities={"test_connection": True, "discover_scopes": True, "plan": True, "preflight": True, "cancel": False, "oauth": False, "revoke_on_disconnect": False},
            limitations=("A search that is already running cannot be cancelled from Shakedown; it is bounded by a server-side timeout and a client timeout instead.",
                         "Rules are mapped to ECS field names. If your events use other names, the mapped fields will be reported missing instead of producing a misleading result.",
                         "Only Sysmon-style Windows log sources are scoped; Windows Security 4688 is not covered."),
            docs_url="https://www.elastic.co/docs/api/doc/elasticsearch/authentication", summary="Read-only _search requests with an API key, over explicit indices and an explicit time window.")

    # ---- configuration ---------------------------------------------------------------------------------------
    def validate_config(self, config: dict, *, mode: str) -> dict:
        config = apply_defaults(self.spec, config)
        verify = bool(config.get("verify_tls", True))
        if not verify and not config.get("accept_insecure_tls"):
            raise IntegrationError("config", "certificate verification is off: tick the acknowledgement, or turn verification back on")
        ep = policy.validate_endpoint(config.get("endpoint", ""), mode=mode, allow_http_loopback=True, verify_tls=verify)
        mapping = config.get("field_mapping") or "ecs_windows"
        if mapping not in PIPELINES:
            raise IntegrationError("config", "unknown field mapping")
        ts = str(config.get("timestamp_field") or TS_DEFAULT)
        if not re.match(r"^[@A-Za-z_][A-Za-z0-9_.@\-]{0,100}$", ts):
            raise IntegrationError("config", "the timestamp field name is not valid")
        return {"endpoint": ep.base_url, "verify_tls": verify, "accept_insecure_tls": bool(config.get("accept_insecure_tls")), "ca_bundle": config.get("ca_bundle") or None,
                "field_mapping": mapping, "allow_privileged": bool(config.get("allow_privileged")), "timestamp_field": ts,
                "max_results": _int(config, "max_results", 1, 20, 5), "max_time_range_hours": _int(config, "max_time_range_hours", 1, 720, 168)}

    def _client(self, config: dict, secret: dict, mode: str) -> _Client:
        if secret.get("api_key"):
            if not re.fullmatch(r"[A-Za-z0-9+/=_\-]{8,2048}", secret["api_key"]):
                raise IntegrationError("config", "the API key is not in the encoded form (letters, digits and + / = only)")
            header = {"Authorization": "ApiKey " + secret["api_key"]}
        elif secret.get("username") and secret.get("password"):
            header = {"Authorization": "Basic " + base64.b64encode(f"{secret['username']}:{secret['password']}".encode()).decode()}
        else:
            raise IntegrationError("config", "credentials are missing")
        transport = policy.PolicyTransport(mode=mode, verify_tls=config["verify_tls"], ca_bundle=config.get("ca_bundle"), timeout=60, allow_http_loopback=True)
        return _Client(config["endpoint"], header, transport)

    @staticmethod
    def _wrap(exc: IntegrationError, secret: dict) -> IntegrationError:
        return IntegrationError(exc.kind, redact(str(exc), list(secret.values())))

    # ---- connection ---------------------------------------------------------------------------------------------
    def test_connection(self, config: dict, secret: dict, *, mode: str) -> ConnectionReport:
        config = self.validate_config(config, mode=mode)
        ep = policy.validate_endpoint(config["endpoint"], mode=mode, allow_http_loopback=True, verify_tls=config["verify_tls"])
        client = self._client(config, secret, mode)
        info = {"host": ep.display, "loopback": ep.is_loopback, "private": ep.is_private, "tls_verified": config["verify_tls"] if ep.scheme == "https" else None, "scheme": ep.scheme}
        warnings = []
        if ep.scheme == "http":
            warnings.append("This endpoint is plain http on loopback. That is acceptable for a local test instance only.")
        if not config["verify_tls"]:
            warnings.append("Certificate verification is off for this connection. Only a loopback or private test instance is accepted in this mode.")
        checks = []
        root = None
        root_note = ""
        try:
            root = client.call("GET", "/")
        except IntegrationError as exc:
            if exc.kind == "permission":  # authenticated, but the cluster root needs the `monitor` privilege: the version is simply unknown
                root_note = "this account may not read the cluster version (that needs the monitor privilege); a preflight does not need it"
            elif exc.kind == "auth":
                checks += [Check("network_tls", "Network and TLS", "pass", "the server answered over a connection that met the TLS policy"),
                           Check("authentication", "Authentication", "fail", self._wrap(exc, secret).args[0]),
                           Check("permissions", "Permissions", "skipped", "not reached"), Check("endpoint", "Endpoint identity", "skipped", "not reached")]
                return ConnectionReport(checks, {}, info, warnings)
            else:
                checks += [Check("network_tls", "Network and TLS", "fail", self._wrap(exc, secret).args[0]), Check("authentication", "Authentication", "skipped", "not reached"),
                           Check("permissions", "Permissions", "skipped", "not reached"), Check("endpoint", "Endpoint identity", "skipped", "not reached")]
                return ConnectionReport(checks, {}, info, warnings)
        checks.append(Check("network_tls", "Network and TLS", "pass", "connected over " + ("verified TLS" if config["verify_tls"] and ep.scheme == "https" else "a connection that met the policy for this endpoint")))
        who = {}
        try:
            who = client.call("GET", "/_security/_authenticate")
            checks.append(Check("authentication", "Authentication", "pass", f"authenticated as {who.get('username')} ({who.get('authentication_type', 'unknown')})"))
        except IntegrationError as exc:
            checks.append(Check("authentication", "Authentication", "fail", self._wrap(exc, secret).args[0]))
            checks += [Check("permissions", "Permissions", "skipped", "not reached"), Check("endpoint", "Endpoint identity", "skipped", "not reached")]
            return ConnectionReport(checks, {}, info, warnings)
        roles = [str(r) for r in who.get("roles") or []]
        risky = []
        try:
            priv = client.call("POST", "/_security/user/_has_privileges", {"cluster": list(PRIVILEGED_CLUSTER), "index": [{"names": ["*"], "privileges": list(PRIVILEGED_INDEX)}]})
            risky = [k for k, v in (priv.get("cluster") or {}).items() if v] + [f"index:{k}" for k, v in ((priv.get("index") or {}).get("*") or {}).items() if v]
            known = True
        except IntegrationError:
            known = False
        if "superuser" in roles:
            risky.append("role:superuser")
        if risky and not config["allow_privileged"]:
            checks.append(Check("permissions", "Permissions", "fail", f"the account has administrative privileges ({', '.join(sorted(set(risky))[:6])}). Use a role with read access to the chosen indices only, or accept the risk in the advanced options."))
        elif risky:
            checks.append(Check("permissions", "Permissions", "warn", f"administrative privileges accepted by you: {', '.join(sorted(set(risky))[:6])}"))
            warnings.append("This connection uses an account with administrative privileges. Shakedown only searches, but the account could do more.")
        elif not known:
            checks.append(Check("permissions", "Permissions", "warn", "the server would not report this account's privileges, so they are unknown. Read access to the chosen indices is checked before each search."))
        else:
            checks.append(Check("permissions", "Permissions", "pass", "no administrative or write privileges found. Read access to the chosen indices is checked before each search."))
        ver = (root.get("version") or {}) if isinstance(root, dict) else {}
        label = " ".join(x for x in (ver.get("build_flavor"), ver.get("number"), f"cluster {root.get('cluster_name')}" if root and root.get("cluster_name") else "") if x)
        checks.append(Check("endpoint", "Endpoint identity", "pass" if ver.get("number") else "warn", label or root_note or "the server did not report a version"))
        info.update({"product": "Elasticsearch", "version": ver.get("number"), "cluster": (root or {}).get("cluster_name")})
        return ConnectionReport(checks, {"username": who.get("username"), "roles": roles, "capabilities": [], "capabilities_known": known, "authentication_type": who.get("authentication_type")}, info, warnings)

    def discover_scopes(self, config: dict, secret: dict, *, mode: str) -> dict:
        config = self.validate_config(config, mode=mode)
        try:
            doc = self._client(config, secret, mode).call("GET", "/_resolve/index/*")
        except IntegrationError as exc:
            if exc.kind in ("permission", "forbidden_endpoint"):
                return {"discovery": "denied", "items": [], "note": "This account may not list indices. Enter the names of the indices you are allowed to search."}
            raise self._wrap(exc, secret) from None
        names = []
        for key, kind in (("indices", "index"), ("aliases", "alias"), ("data_streams", "data stream")):
            for entry in doc.get(key) or []:
                n = str(entry.get("name", ""))
                if INDEX_NAME.match(n) and not n.startswith("."):
                    names.append({"name": n, "events": None, "datatype": kind})
        return {"discovery": "available", "items": sorted({i["name"]: i for i in names}.values(), key=lambda i: i["name"]), "note": "Indices, aliases and data streams this account can see. System indices (starting with a dot) are not listed."}

    # ---- query and run ------------------------------------------------------------------------------------------
    @staticmethod
    def _bodies(config: dict, indexes: list, scope: dict, lucene: str, fields: list, earliest, latest) -> dict:
        ts = config["timestamp_field"]
        rng = {"range": {ts: {"gte": earliest.isoformat(), "lt": latest.isoformat(), "format": "strict_date_optional_time"}}}
        base = [rng, *scope["filters"]]
        detect = {"query_string": {"query": lucene, "analyze_wildcard": True, "default_operator": "AND"}}
        display = list(dict.fromkeys([ts, *BASE_DISPLAY, *(f.removesuffix(".caseless") for f in fields)]))  # a .caseless sub-field is a mapping detail, not part of _source
        bodies = {
            "coverage": {"size": 0, "track_total_hits": True, "timeout": "30s", "query": {"bool": {"filter": base}},
                         "aggs": {"first": {"min": {"field": ts}}, "last": {"max": {"field": ts}}}},
            "fields": {"size": 0, "timeout": "30s", "query": {"bool": {"filter": base}}, "aggs": {f"f{i}": {"filter": {"exists": {"field": f}}} for i, f in enumerate(fields)}},
            "detection": {"size": 0, "track_total_hits": True, "timeout": "30s", "query": {"bool": {"filter": [*base, detect]}}},
            "sample": {"size": config["max_results"], "timeout": "30s", "_source": display, "sort": [{ts: {"order": "desc"}}], "query": {"bool": {"filter": [*base, detect]}}}}
        for b in bodies.values():
            check_read_only(b)
        return bodies

    def _prepare(self, rule_text: str, config: dict, scope: dict):
        indexes = list(scope.get("indexes") or [])
        if not indexes or any(not INDEX_NAME.match(i) or "*" in i for i in indexes):
            raise IntegrationError("scope", "name one or more specific indices; empty and wildcard names are refused")
        category = ((yaml.safe_load(rule_text) or {}).get("logsource") or {}).get("category", "")
        sc = logsource_filters(category)
        lucene, fields = convert_to_lucene(rule_text, config["field_mapping"])
        return indexes, category, sc, lucene, fields

    def plan(self, rule_text: str, config: dict, scope: dict, window: tuple | None = None) -> dict:
        if window is None:
            raise IntegrationError("scope", "a plan needs an explicit time window")
        earliest, latest = (t if t.tzinfo else t.replace(tzinfo=timezone.utc) for t in window)
        indexes, category, sc, lucene, fields = self._prepare(rule_text, config, scope)
        bodies = self._bodies(config, indexes, sc, lucene, fields, earliest, latest)  # the exact bodies `run` will send for this window
        return {"language": "Elasticsearch query (JSON)", "queries": {k: json.dumps(v, indent=1) for k, v in bodies.items()}, "detection": json.dumps(bodies["detection"], indent=1),
                "converted": lucene, "fields": fields,
                "scope": {"indexes": indexes, "logsource_category": category, "logsource_scope": sc["clause"], "logsource_note": sc["note"], "field_mapping": config["field_mapping"]},
                "notes": list(NOTES) + [f"The rule was converted to this Lucene query with pySigma's Elasticsearch backend and the {config['field_mapping']} pipeline: {lucene}"]}

    def run(self, rule_text: str, config: dict, secret: dict, scope: dict, window: tuple, *, mode: str, cancel=None, handle=None) -> dict:
        started = time.monotonic()
        earliest, latest = (t if t.tzinfo else t.replace(tzinfo=timezone.utc) for t in window)
        indexes, category, sc, lucene, fields = self._prepare(rule_text, config, scope)
        bodies = self._bodies(config, indexes, sc, lucene, fields, earliest, latest)
        client = self._client(config, secret, mode)
        path = "/" + ",".join(indexes) + "/_search"

        def search(name: str) -> dict:
            try:
                doc = client.call("POST", path + "?ignore_unavailable=false&allow_no_indices=false&expand_wildcards=none", bodies[name])
            except IntegrationError as exc:
                raise self._wrap(exc, secret) from None
            if doc.get("timed_out"):
                raise IntegrationError("timeout", "the search timed out on the server, so its result would be partial and is not used")
            failed = ((doc.get("_shards") or {}).get("failed") or 0)
            if failed:
                reason = (((doc.get("_shards") or {}).get("failures") or [{}])[0].get("reason") or {}).get("reason", "a shard failed")
                raise IntegrationError("query", f"{failed} shard(s) failed, so the result would be partial: {str(reason)[:200]}")
            return doc

        try:  # read access to exactly the chosen indices, before any search
            priv = client.call("POST", "/_security/user/_has_privileges", {"index": [{"names": indexes, "privileges": ["read", "view_index_metadata"]}]})
        except IntegrationError as exc:
            raise self._wrap(exc, secret) from None
        if not priv.get("has_all_requested", False):
            missing = sorted(f"{n}:{p}" for n, ps in (priv.get("index") or {}).items() for p, ok in ps.items() if not ok)
            raise IntegrationError("permission", f"the account lacks read access to the chosen indices ({', '.join(missing[:6]) or 'unknown'}). Use a role that can read them.")
        result = {"provider": "elastic", "language": "Elasticsearch query (JSON)",
                  "connector": {"name": "elasticsearch-rest-read-only", "live_verified": False, "verification": live_verification(self._verification_path),
                                "credential_type": "api_key" if secret.get("api_key") else "basic", "tls_verified": config["verify_tls"] if config["endpoint"].startswith("https") else None},
                  "identity": {}, "scope": {"indexes": indexes, "earliest": earliest.isoformat(), "latest": latest.isoformat(), "logsource_category": category,
                                            "logsource_scope": sc["clause"], "logsource_note": sc["note"], "field_mapping": config["field_mapping"]},
                  "converted_detection": lucene, "queries": {k: json.dumps(v, indent=1) for k, v in bodies.items()}, "notes": list(NOTES), "searched_at": datetime.now(timezone.utc).isoformat()}
        cov = search("coverage")
        events = int(((cov.get("hits") or {}).get("total") or {}).get("value") or 0)
        agg = cov.get("aggregations") or {}
        result["coverage"] = {"events_in_scope": events, "first_event": ((agg.get("first") or {}).get("value") or 0) / 1000 or None, "last_event": ((agg.get("last") or {}).get("value") or 0) / 1000 or None}
        if events == 0:
            return self._finish(result, started, "telemetry_missing_or_unsupported", "no_events_in_scope",
                                "No events of the required log source exist in the selected indices and window, so a search for the rule cannot match anything. This is missing telemetry, not a clean result.")
        present = []
        fa = (search("fields").get("aggregations") or {})
        for i, f in enumerate(fields):
            if int((fa.get(f"f{i}") or {}).get("doc_count") or 0) > 0:
                present.append(f)
        missing = [f for f in fields if f not in present]
        result["fields"] = {"rule_fields": fields, "observed": present, "missing": missing, "sampled_events": events}
        if missing:
            return self._finish(result, started, "telemetry_missing_or_unsupported", "fields_not_observed",
                                f"The rule maps to field(s) {missing} that no event of the required log source has in this window. They may not exist under these names in your indices (the rule was mapped with the "
                                f"{config['field_mapping']} pipeline), so a search would match nothing even for a real attack. Fix the field mapping or the shipping pipeline before relying on this rule.")
        det = search("detection")
        total = int(((det.get("hits") or {}).get("total") or {}).get("value") or 0)
        examples = []
        if total:
            for hit in (search("sample").get("hits") or {}).get("hits") or []:
                examples.append({k: _trim(v) for k, v in _flatten(hit.get("_source") or {}).items()})
        result["matches"] = {"count": total, "examples": examples, "examples_shown": len(examples), "examples_limit": config["max_results"]}
        return self._finish(result, started, "potential_matches_found" if total else "no_matches_in_window", "",
                            "These are potential matches: review each event to decide whether it is the behaviour the rule is meant to find." if total else
                            "Telemetry exists, the rule's fields were observed, and nothing in the window matched.")

    @staticmethod
    def _finish(result: dict, started: float, status: str, code: str, detail: str) -> dict:
        result.update(status=status, status_detail=code, explanation=detail, elapsed_s=round(time.monotonic() - started, 2))
        result.setdefault("matches", {"count": None, "examples": [], "examples_shown": 0})
        return result
