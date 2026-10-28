"""Microsoft Sentinel / Azure Monitor Logs adapter: a bounded, read-only preflight over the Log Analytics Query API.

MOCK-TESTED, NOT LIVE-VERIFIED. It has only ever run against a mock; no real Azure tenant or Log Analytics workspace was available.

Sign-in is Microsoft Entra ID, never a key pasted into a page:
* `interactive`         OAuth 2.0 authorization code flow with PKCE as a public client (no secret exists). The browser goes to Microsoft; the code returns to this
                        machine by `form_post` (so it is never in a URL, a log or the history). Only a refresh token is kept, in the secret store.
* `client_credentials`  an app registration's client secret, held in the secret store, for unattended use.

The only hosts it talks to are fixed (login.microsoftonline.com, api.loganalytics.azure.com and, if you allow workspace listing, management.azure.com): the user
cannot point it anywhere else. Sigma is converted with pySigma's Kusto backend and its Azure Monitor pipeline; a rule that uses a field the SecurityEvent table does
not have is refused with the pipeline's own reason instead of producing a guessed query. Only Windows Security process creation (EventID 4688) is scoped.
"""
import base64
import json
import re
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

import yaml
from sigma.backends.kusto import KustoBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.pipelines.azuremonitor import azure_monitor_pipeline

from shakedown.integrations import policy
from shakedown.integrations.adapters.splunk import _int
from shakedown.integrations.base import (NOT_LIVE_VERIFIED, Check, ConnectionReport, FieldSpec, IntegrationError, ProviderAdapter, ProviderSpec, apply_defaults,
                                         redact)

AUTHORITY, API, ARM = "https://login.microsoftonline.com", "https://api.loganalytics.azure.com", "https://management.azure.com"
LA_RESOURCE = "https://api.loganalytics.io"
GUID = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
TENANT = re.compile(r"^(?:[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}|[A-Za-z0-9][A-Za-z0-9.\-]{0,200}\.[A-Za-z]{2,})$")
WORKSPACE_EXAMPLE = "00000000-0000-0000-0000-000000000000"
TABLE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
ALLOWED_OPS = {"where", "project", "summarize", "take", "limit", "order", "sort", "count", "extend", "distinct", "top"}
FORBIDDEN = re.compile(r"\b(externaldata|evaluate|http_request|http_request_post|sql_request|cosmosdb_sql_request|invoke|workspace|cluster|database|app|resource|"
                       r"union|join|lookup|materialize|ingestion_time|set|append|replace|purge|rename|drop|alter|create|delete|let|print_schema|plugin|storage|"
                       r"request_properties|query_parameters|declare|restrict|pattern)\s*\(|^\s*\.|;|\blet\b|\bunion\b|\bjoin\b", re.I)
VALUE_LIMIT = 300
SCOPES = {"process_creation": ("SecurityEvent", 4688, "Windows Security process creation (EventID 4688). It needs the 'Audit Process Creation' policy, and 'Include command line' for CommandLine. "
                                                      "Sysmon in the Event table is not covered.")}
NOTES = [
    "A historical query shows what the rule would have matched in this window. It does not show that the rule can detect an attack that did not occur in the window.",
    "Field names depend on the table schema. The mapping below is pySigma's Azure Monitor SecurityEvent mapping; fields the table does not have are refused, not guessed.",
]


PROBE = re.compile(r"^print\s+[A-Za-z_]\w*\s*=\s*\d{1,6}$")


def _strip_strings(q: str) -> str:
    return re.sub(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'', '""', q)


def _vals(secret: dict, *extra) -> list:
    return [v for v in [*secret.values(), *extra] if isinstance(v, str)]


def check_read_only_kql(query: str) -> None:
    """The Logs Query API is read-only by design; this is a second, local check that the query uses only ordinary read operators and stays in one workspace."""
    bare = _strip_strings(query)
    if FORBIDDEN.search(bare):
        raise IntegrationError("unsafe_query", "the query uses an operator or function that is not allowed in a read-only preflight (a control command, a cross-workspace reference, or a function that reaches outside the table)")
    parts = [p.strip() for p in bare.split("|")]
    if len(parts) == 1 and PROBE.match(parts[0]):
        return
    if not TABLE.match(parts[0].strip()):
        raise IntegrationError("unsafe_query", "the query must start with a single table name")
    for part in parts[1:]:
        op = re.match(r"([A-Za-z\-]+)", part)
        if not op or op.group(1).lower() not in ALLOWED_OPS:
            raise IntegrationError("unsafe_query", f"the operator {op.group(1) if op else part[:20]!r} is not allowed in a read-only preflight")
    if len(query) > 20_000:
        raise IntegrationError("unsafe_query", "the query is too long")


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


def convert_to_kql(rule_text: str) -> tuple:
    """(table, the converted `| where ...` lines, mapped field names). Raises IntegrationError('conversion') with the pipeline's reason."""
    try:
        col = SigmaCollection.from_yaml(rule_text)
        if len(col.rules) != 1:
            raise IntegrationError("conversion", "give exactly one Sigma rule")
        out = KustoBackend(processing_pipeline=azure_monitor_pipeline()).convert(col)
        fields = _mapped_fields(col.rules[0])
    except SigmaError as exc:
        text = re.sub(r"\s+", " ", str(exc))
        raise IntegrationError("conversion", f"pySigma's Kusto backend could not convert this rule: {text[:260]}") from None
    except (yaml.YAMLError, ValueError, KeyError) as exc:
        raise IntegrationError("conversion", f"the rule could not be read ({type(exc).__name__})") from None
    if len(out) != 1:
        raise IntegrationError("conversion", "the rule converts to more than one query, which this preflight does not support")
    head, _, rest = str(out[0]).partition("\n")
    return head.strip(), rest.strip(), fields


def _trim(v) -> str:
    t = str(v)
    return t if len(t) <= VALUE_LIMIT else t[:VALUE_LIMIT] + "..."


class SentinelAdapter(ProviderAdapter):
    def __init__(self, *, authority: str = AUTHORITY, api: str = API, arm: str = ARM, allow_http_loopback: bool = False):
        """The three base URLs are fixed in production. Tests pass loopback addresses (and allow plain http) to point them at a mock."""
        self.authority, self.api, self.arm, self._http = authority.rstrip("/"), api.rstrip("/"), arm.rstrip("/"), allow_http_loopback

    @property
    def spec(self) -> ProviderSpec:
        fields = (FieldSpec("tenant_id", "Directory (tenant) ID", "text", True, "The Microsoft Entra tenant ID (a GUID) or a verified domain name.", placeholder="00000000-0000-0000-0000-000000000000"),
                  FieldSpec("client_id", "Application (client) ID", "text", True, "Your Entra app registration. For interactive sign-in register it as a public client (Mobile and desktop) with the redirect URI shown below "
                                                                              "and the delegated permission Log Analytics API, Data.Read.", placeholder="00000000-0000-0000-0000-000000000000"),
                  FieldSpec("workspace_id", "Log Analytics workspace ID", "text", False, "Optional here: you can choose the workspace in the next step. The account needs the Log Analytics Reader role (or Reader) on it.",
                            placeholder="00000000-0000-0000-0000-000000000000"),
                  FieldSpec("list_workspaces", "Let Shakedown list the workspaces I can see", "bool", False,
                            "Needs the Azure Service Management delegated permission (user_impersonation), or Reader on the subscription for a service principal. Leave off to enter the workspace ID yourself.", False),
                  FieldSpec("max_results", "Example events to keep", "number", False, "At most this many matching events are returned for review.", 5, advanced=True),
                  FieldSpec("max_time_range_hours", "Longest allowed window (hours)", "number", False, "A query window can never exceed this.", 168, advanced=True))
        return ProviderSpec(
            id="sentinel", name="Microsoft Sentinel (Azure Monitor Logs)", status=NOT_LIVE_VERIFIED, status_label="Mock-tested, not live-verified", scope_noun="workspace", scope_example=WORKSPACE_EXAMPLE, query_language="KQL",
            verification_note="Mock-tested only, not live-verified: it has been run against a mock Microsoft sign-in and Logs API, never against a real Azure tenant or workspace, so sign-in, consent, permissions and query behaviour there are not verified.",
            auth_methods=(("interactive", "Sign in with Microsoft (recommended)"), ("client_credentials", "App registration with a client secret")), fields=fields,
            secret_fields=(("client_credentials", FieldSpec("client_secret", "Client secret", "secret", True, "The app registration's client secret value.")),),
            capabilities={"test_connection": True, "discover_scopes": True, "verify_scope": True, "plan": True, "preflight": True, "cancel": False, "oauth": True, "revoke_on_disconnect": False},
            limitations=("Only Windows Security process creation (EventID 4688) is scoped; Sysmon in the Event table and Defender tables are not.",
                         "pySigma's Azure Monitor pipeline maps only SecurityEvent fields: a rule that uses a field such as OriginalFileName is refused, not guessed.",
                         "A running query cannot be cancelled from Shakedown; it is bounded by a server-side timeout and a result cap.",
                         "Public Azure cloud only: sovereign clouds (US Government, China) use other endpoints and are not supported."),
            docs_url="https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/overview", summary="Read-only Log Analytics queries with Microsoft Entra ID sign-in, over one workspace and an explicit time span.")

    # ---- configuration ---------------------------------------------------------------------------------------
    def validate_config(self, config: dict, *, mode: str) -> dict:
        config = apply_defaults(self.spec, config)
        tenant, client = str(config.get("tenant_id", "")).strip(), str(config.get("client_id", "")).strip()
        if not TENANT.match(tenant):
            raise IntegrationError("config", "the tenant must be a directory ID (a GUID) or a domain name such as contoso.onmicrosoft.com")
        if not GUID.match(client):
            raise IntegrationError("config", "the application (client) ID must be a GUID")
        ws = str(config.get("workspace_id") or "").strip()
        if ws and not GUID.match(ws):
            raise IntegrationError("config", "the Log Analytics workspace ID must be a GUID")
        for base in (self.authority, self.api, self.arm):
            policy.validate_endpoint(base, mode=mode, allow_http_loopback=self._http)
        return {"endpoint": self.api, "tenant_id": tenant, "client_id": client, "workspace_id": ws or None, "list_workspaces": bool(config.get("list_workspaces")),
                "max_results": _int(config, "max_results", 1, 20, 5), "max_time_range_hours": _int(config, "max_time_range_hours", 1, 720, 168),
                "verify_tls": True, "allow_privileged": False}

    def _transport(self, mode: str) -> policy.PolicyTransport:
        return policy.PolicyTransport(mode=mode, verify_tls=True, timeout=60, allow_http_loopback=self._http)

    # ---- Microsoft Entra ID ---------------------------------------------------------------------------------------
    def _token_call(self, config: dict, form: dict, mode: str, secret: dict) -> dict:
        url = f"{self.authority}/{urllib.parse.quote(config['tenant_id'], safe='')}/oauth2/v2.0/token"
        status, raw = self._transport(mode).send("POST", url, {"Content-Type": "application/x-www-form-urlencoded"}, urllib.parse.urlencode(form).encode())
        try:
            doc = json.loads(raw) if raw else {}
        except ValueError:
            doc = {}
        if status >= 400 or "access_token" not in doc:
            code = str(doc.get("error", "")) or f"http_{status}"
            desc = re.split(r"\s*(?:Trace ID|Correlation ID|Timestamp):", str(doc.get("error_description", "")))[0].strip()
            kind = "permission" if code in ("consent_required", "interaction_required", "invalid_scope", "access_denied") else "auth"
            hint = {"invalid_client": "the client secret is wrong or expired", "invalid_grant": "the sign-in expired or was revoked; sign in again",
                    "unauthorized_client": "the app is not allowed to use this flow; check the app registration",
                    "consent_required": "an administrator or you must consent to the permission", "interaction_required": "Microsoft needs you to sign in again"}.get(code, "")
            raise IntegrationError(kind, redact(f"Microsoft Entra ID refused the request ({code}). {hint or desc}"[:400], _vals(secret)))
        return doc

    def _access_token(self, config: dict, secret: dict, scope: str, mode: str) -> str:
        if secret.get("client_secret"):
            doc = self._token_call(config, {"grant_type": "client_credentials", "client_id": config["client_id"], "client_secret": secret["client_secret"], "scope": scope}, mode, secret)
        elif secret.get("refresh_token"):
            doc = self._token_call(config, {"grant_type": "refresh_token", "client_id": config["client_id"], "refresh_token": secret["refresh_token"], "scope": scope}, mode, secret)
            if doc.get("refresh_token"):
                secret["refresh_token"] = doc["refresh_token"]  # Entra may rotate it; the service saves the new value
        else:
            raise IntegrationError("auth", "no credential is available for this connection; sign in again")
        return doc["access_token"]

    def oauth_begin(self, config: dict, redirect_uri: str, state: str, challenge: str) -> str:
        scopes = [f"{LA_RESOURCE}/Data.Read", "offline_access", "openid", "profile"] + ([f"{ARM}/user_impersonation"] if config.get("list_workspaces") else [])
        q = {"client_id": config["client_id"], "response_type": "code", "redirect_uri": redirect_uri, "response_mode": "form_post", "scope": " ".join(scopes), "state": state,
             "code_challenge": challenge, "code_challenge_method": "S256", "prompt": "select_account"}
        return f"{self.authority}/{urllib.parse.quote(config['tenant_id'], safe='')}/oauth2/v2.0/authorize?{urllib.parse.urlencode(q)}"

    def oauth_exchange(self, config: dict, code: str, verifier: str, redirect_uri: str, mode: str) -> dict:
        doc = self._token_call(config, {"grant_type": "authorization_code", "client_id": config["client_id"], "code": code, "redirect_uri": redirect_uri, "code_verifier": verifier,
                                        "scope": f"{LA_RESOURCE}/Data.Read offline_access openid profile"}, mode, {"code": code, "code_verifier": verifier})
        if not doc.get("refresh_token"):
            raise IntegrationError("permission", "Microsoft did not return a refresh token (the offline_access permission was not granted), so the sign-in could not be kept")
        claims = {}
        try:
            seg = str(doc.get("id_token", "")).split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))  # read for display only: it came straight from the token endpoint over TLS
        except (IndexError, ValueError):
            pass
        return {"refresh_token": doc["refresh_token"], "_claims": {k: claims.get(k) for k in ("preferred_username", "name", "tid", "oid") if claims.get(k)}}

    # ---- the Logs API ---------------------------------------------------------------------------------------------
    def _query(self, config: dict, token: str, workspace: str, kql: str, timespan: str, mode: str, secret: dict) -> list:
        check_read_only_kql(kql)
        body = json.dumps({"query": kql, "timespan": timespan}).encode()
        try:
            status, raw = self._transport(mode).send("POST", f"{self.api}/v1/workspaces/{urllib.parse.quote(workspace, safe='')}/query",
                                                      {"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Prefer": "wait=60"}, body)
        except IntegrationError as exc:
            raise IntegrationError(exc.kind, redact(str(exc), _vals(secret, token))) from None
        try:
            doc = json.loads(raw) if raw else {}
        except ValueError:
            doc = {}
        if status >= 400:
            err = doc.get("error") or {}
            msg = str(err.get("message") or "")[:300]
            kind = {401: "auth", 403: "permission", 404: "scope", 400: "query", 429: "rate_limited", 504: "timeout"}.get(status, "unavailable")
            text = {"auth": "the access token was rejected (HTTP 401)", "permission": "the account has no access to this workspace (HTTP 403): it needs Log Analytics Reader on it",
                    "scope": "the workspace was not found (HTTP 404)", "rate_limited": "Azure Monitor is throttling queries (HTTP 429); wait and try again"}.get(kind, msg or f"the Logs API answered HTTP {status}")
            raise IntegrationError(kind, redact(text, [token]))
        tables = doc.get("tables") or []
        if not tables:
            return []
        cols = [c["name"] for c in tables[0].get("columns", [])]
        return [dict(zip(cols, row)) for row in tables[0].get("rows", [])]

    @staticmethod
    def _timespan(window: tuple) -> str:
        return "/".join(t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") for t in window)

    # ---- connection ----------------------------------------------------------------------------------------------
    def test_connection(self, config: dict, secret: dict, *, mode: str) -> ConnectionReport:
        config = self.validate_config(config, mode=mode)
        claims = secret.get("_claims") if isinstance(secret.get("_claims"), dict) else {}  # who signed in (display only), kept next to the refresh token
        info = {"host": policy.mask_endpoint(self.api), "tls_verified": True, "scheme": "https", "product": "Azure Monitor Logs (Log Analytics API)", "tenant": config["tenant_id"]}
        checks = []
        try:
            token = self._access_token(config, secret, f"{LA_RESOURCE}/.default" if secret.get("client_secret") else f"{LA_RESOURCE}/Data.Read", mode)
        except IntegrationError as exc:
            if exc.kind in ("unreachable", "tls", "destination", "redirect", "too_large", "unavailable"):
                checks += [Check("network_tls", "Network and TLS", "fail", str(exc)), Check("authentication", "Authentication", "skipped", "not reached")]
            else:
                checks += [Check("network_tls", "Network and TLS", "pass", "Microsoft Entra ID answered over verified TLS"), Check("authentication", "Authentication", "fail", str(exc))]
            checks += [Check("permissions", "Permissions", "skipped", "not reached"), Check("endpoint", "Endpoint identity", "skipped", "not reached")]
            return ConnectionReport(checks, {}, info, [])
        checks.append(Check("network_tls", "Network and TLS", "pass", "Microsoft Entra ID answered over verified TLS"))
        who = (claims or {}).get("preferred_username") or (claims or {}).get("name") or ("app registration " + config["client_id"] if secret.get("client_secret") else "the signed-in account")
        checks.append(Check("authentication", "Authentication", "pass", f"signed in as {who}"))
        ws = config.get("workspace_id")
        if ws:
            try:
                rows = self._query(config, token, ws, "print ok=1", "PT5M", mode, secret)
                checks.append(Check("permissions", "Permissions", "pass" if rows else "warn", f"the account can run a read-only query in workspace {ws}" if rows else "the query ran but returned nothing"))
            except IntegrationError as exc:
                checks.append(Check("permissions", "Permissions", "fail", str(exc)))
        else:
            checks.append(Check("permissions", "Permissions", "skipped", "no workspace was given yet; access to the workspace you choose is checked before each query"))
        checks.append(Check("endpoint", "Endpoint identity", "pass", f"Log Analytics API for tenant {config['tenant_id']}"))
        return ConnectionReport(checks, {"username": who, "roles": [], "capabilities": [], "capabilities_known": False, "authentication_type": "client_credentials" if secret.get("client_secret") else "delegated", **{k: v for k, v in (claims or {}).items() if k in ("tid", "oid")}}, info, [])

    def discover_scopes(self, config: dict, secret: dict, *, mode: str) -> dict:
        config = self.validate_config(config, mode=mode)
        manual = {"discovery": "manual", "items": [], "note": "Enter the Log Analytics workspace ID (a GUID) you want to assess. Find it on the workspace's Overview page in the Azure portal."}
        if not config["list_workspaces"]:
            return manual
        try:
            token = self._access_token(config, secret, f"{ARM}/.default" if secret.get("client_secret") else f"{ARM}/user_impersonation", mode)
            transport = self._transport(mode)

            def get(path):
                status, raw = transport.send("GET", f"{self.arm}{path}", {"Authorization": f"Bearer {token}"}, None)
                if status >= 400:
                    raise IntegrationError("permission" if status == 403 else "unavailable", f"Azure Resource Manager answered HTTP {status}")
                return json.loads(raw)
            items = []
            for sub in (get("/subscriptions?api-version=2022-12-01").get("value") or [])[:20]:
                for w in (get(f"/subscriptions/{sub['subscriptionId']}/providers/Microsoft.OperationalInsights/workspaces?api-version=2022-10-01").get("value") or [])[:200]:
                    cid = (w.get("properties") or {}).get("customerId")
                    if cid and GUID.match(cid):
                        rg = (str(w.get("id", "")).split("/resourceGroups/") + [""])[1].split("/")[0]
                        items.append({"name": cid, "label": f"{w.get('name')} ({rg or 'unknown group'}, {w.get('location', '')})", "events": None, "datatype": "workspace"})
            return {"discovery": "available", "items": sorted(items, key=lambda i: i["label"]), "note": "Workspaces this account can list. Choose the ones to assess; the account still needs Log Analytics Reader on each."}
        except IntegrationError as exc:
            return {**manual, "note": f"Workspaces could not be listed ({exc}). " + manual["note"]}

    def verify_scope(self, config: dict, secret: dict, scope: dict, *, mode: str) -> None:
        """Before a workspace is saved, prove this account can run a read-only query in it. Raises IntegrationError('permission' | 'scope' | ...) otherwise."""
        config = self.validate_config(config, mode=mode)
        token = self._access_token(config, secret, f"{LA_RESOURCE}/.default" if secret.get("client_secret") else f"{LA_RESOURCE}/Data.Read", mode)
        for ws in scope.get("indexes") or []:
            if not GUID.match(ws):
                raise IntegrationError("scope", f"{ws[:40]!r} is not a workspace ID (a GUID)")
            self._query(config, token, ws, "print ok=1", "PT5M", mode, secret)

    # ---- query and run ---------------------------------------------------------------------------------------------
    def _scope(self, rule_text: str) -> tuple:
        category = ((yaml.safe_load(rule_text) or {}).get("logsource") or {}).get("category", "")
        if category not in SCOPES:
            raise IntegrationError("unsupported_logsource", f"log source category {category!r} has no Azure Monitor scope in this preflight (only process_creation on SecurityEvent 4688)")
        return category, *SCOPES[category]

    def plan(self, rule_text: str, config: dict, scope: dict, window: tuple | None = None) -> dict:
        if window is None:
            raise IntegrationError("scope", "a plan needs an explicit time window")
        ws = list(scope.get("indexes") or [])
        if len(ws) != 1 or not GUID.match(ws[0]):
            raise IntegrationError("scope", "choose exactly one Log Analytics workspace (its ID, a GUID) for a preflight")
        category, table, eid, note = self._scope(rule_text)
        t, rest, fields = convert_to_kql(rule_text)
        if t != table:
            raise IntegrationError("conversion", f"the rule converted for table {t}, but the scope for this log source is {table}; refusing to guess")
        cols = ", ".join(f"['{f}']=countif(isnotempty({f}))" for f in fields)
        base = f"{table}\n| where EventID == {eid}"
        queries = {"coverage": f"{base}\n| summarize events=count(), first=min(TimeGenerated), last=max(TimeGenerated)",
                   "fields": f"{base}\n| summarize {cols}", "detection": f"{base}\n{rest}\n| summarize matches=count()",
                   "sample": f"{base}\n{rest}\n| project TimeGenerated, Computer, Account, NewProcessName, ParentProcessName, CommandLine\n| order by TimeGenerated desc\n| take {config['max_results']}"}
        for q in queries.values():
            check_read_only_kql(q)
        span = self._timespan(window)
        return {"language": "KQL", "queries": queries, "detection": queries["detection"], "fields": fields, "converted": f"{table}\n{rest}",
                "scope": {"indexes": ws, "logsource_category": category, "logsource_scope": f"{table} | where EventID == {eid}", "logsource_note": note, "timespan": span},
                "notes": list(NOTES) + [f"Every query is sent with the time span {span}; the span is part of the request, not the query text."]}

    def run(self, rule_text: str, config: dict, secret: dict, scope: dict, window: tuple, *, mode: str, cancel=None, handle=None) -> dict:
        started = time.monotonic()
        earliest, latest = (t if t.tzinfo else t.replace(tzinfo=timezone.utc) for t in window)
        built = self.plan(rule_text, config, scope, (earliest, latest))
        ws, span = built["scope"]["indexes"][0], built["scope"]["timespan"]
        token = self._access_token(config, secret, f"{LA_RESOURCE}/.default" if secret.get("client_secret") else f"{LA_RESOURCE}/Data.Read", mode)
        run = lambda name: self._query(config, token, ws, built["queries"][name], span, mode, secret)
        result = {"provider": "sentinel", "language": "KQL", "provider_label": "Microsoft Sentinel",
                  "connector": {"name": "azure-monitor-logs-query", "live_verified": False, "verification": {"live_verified": False, "label": "mock-tested, not live-verified"},
                                "credential_type": "client_credentials" if secret.get("client_secret") else "delegated", "tls_verified": True},
                  "identity": {}, "scope": {"indexes": [ws], "earliest": earliest.isoformat(), "latest": latest.isoformat(), "logsource_category": built["scope"]["logsource_category"],
                                            "logsource_scope": built["scope"]["logsource_scope"], "logsource_note": built["scope"]["logsource_note"]},
                  "converted_detection": built["converted"], "queries": built["queries"], "notes": built["notes"], "searched_at": datetime.now(timezone.utc).isoformat()}
        cov = run("coverage")
        events = int((cov[0].get("events") if cov else 0) or 0)
        result["coverage"] = {"events_in_scope": events, "first_event": (cov[0].get("first") if cov else None), "last_event": (cov[0].get("last") if cov else None)}
        if events == 0:
            return self._finish(result, started, "telemetry_missing_or_unsupported", "no_events_in_scope",
                                "No events of the required log source exist in this workspace and window (or the account cannot see them), so a query for the rule cannot match anything. "
                                "This is missing telemetry or access, not a clean result.")
        fr = (run("fields") or [{}])[0]
        present = [f for f in built["fields"] if int(fr.get(f) or 0) > 0]
        missing = [f for f in built["fields"] if f not in present]
        result["fields"] = {"rule_fields": built["fields"], "observed": present, "missing": missing, "sampled_events": events}
        if missing:
            return self._finish(result, started, "telemetry_missing_or_unsupported", "fields_not_observed",
                                f"The rule uses column(s) {missing} that are empty in every matching-log-source event in this window (for example command-line auditing may be off), so a query would match nothing "
                                "even for a real attack. Enable the audit setting or map the field before relying on this rule.")
        rows = run("detection")
        total = int((rows[0].get("matches") if rows else 0) or 0)
        examples = [{k: _trim(v) for k, v in r.items()} for r in (run("sample") if total else [])]
        result["matches"] = {"count": total, "examples": examples, "examples_shown": len(examples), "examples_limit": config["max_results"]}
        return self._finish(result, started, "potential_matches_found" if total else "no_matches_in_window", "",
                            "These are potential matches: review each event to decide whether it is the behaviour the rule is meant to find." if total else
                            "Telemetry exists, the rule's columns are populated, and nothing in the window matched.")

    @staticmethod
    def _finish(result: dict, started: float, status: str, code: str, detail: str) -> dict:
        result.update(status=status, status_detail=code, explanation=detail, elapsed_s=round(time.monotonic() - started, 2))
        result.setdefault("matches", {"count": None, "examples": [], "examples_shown": 0})
        return result
