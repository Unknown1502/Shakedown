"""Splunk Enterprise and Splunk Cloud Platform adapters. Both wrap the existing read-only REST connector (shakedown/splunk.py); they add
connection reporting, scope discovery, and a policy-enforcing transport. They do not widen what the connector may call."""
import re
import threading
from dataclasses import replace
from datetime import datetime

from shakedown import splunk
from shakedown.integrations import policy
from shakedown.integrations.base import (LIVE_VERIFIED_TEST, NOT_LIVE_VERIFIED, Check, ConnectionReport, FieldSpec, IntegrationError, ProviderAdapter,
                                         ProviderSpec, apply_defaults, redact)

CLOUD_HOST = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}\.splunkcloud(gc)?\.com$")
NETWORK_KINDS = ("tls", "unreachable", "destination", "redirect", "too_large", "unavailable", "config")


def _int(config: dict, name: str, lo: int, hi: int, default: int) -> int:
    try:
        value = int(config.get(name, default))
    except (TypeError, ValueError):
        raise IntegrationError("config", f"{name} must be a whole number") from None
    if not lo <= value <= hi:
        raise IntegrationError("config", f"{name} must be between {lo} and {hi}")
    return value


class _StickyCancel(threading.Event):
    """The connector clears its cancel flag when a preflight starts. A cancel that arrives before then must not be lost, so clearing is a no-op."""

    def clear(self):
        pass


class SplunkEnterpriseAdapter(ProviderAdapter):
    cloud = False

    def __init__(self, verification_path=None):
        self._verification_path = verification_path

    # --- description -------------------------------------------------------------------------------------------
    @property
    def spec(self) -> ProviderSpec:
        v = splunk.live_verification(self._verification_path)
        verified = bool(v["live_verified"])
        note = ("Live-verified on a throwaway local Splunk Enterprise " + str(v.get("server_version") or "") + " test instance with simulated Sysmon events. "
                "Not verified against a production, clustered or Splunk Cloud deployment, a real Splunk Add-on for Windows or Sysmon, or a connection whose certificate verifies.") \
            if verified else "Implemented and tested against a mock server only. Not live-verified."
        fields = (
            FieldSpec("endpoint", "Management endpoint", "url", True, "The Splunk management (REST) address, normally https://host:8089, not the web UI port.", placeholder="https://splunk.example.com:8089"),
            FieldSpec("verify_tls", "Verify the server certificate", "bool", False, "Leave on. Turning it off is accepted only for a loopback or private test instance.", True),
            FieldSpec("ca_bundle", "CA bundle file", "text", False, "Path to a PEM file with the CA that signed Splunk's certificate (for a private CA).", advanced=True),
            FieldSpec("accept_insecure_tls", "I understand certificate checking is off", "bool", False, "Required if verification is off.", False, advanced=True),
            FieldSpec("allow_privileged", "Accept an account with admin-class capabilities", "bool", False, "Not recommended. Use a dedicated search-only role.", False, advanced=True),
            FieldSpec("max_results", "Example events to keep", "number", False, "At most this many matching events are returned for review.", 5, advanced=True),
            FieldSpec("max_time_range_hours", "Longest allowed window (hours)", "number", False, "A search window can never exceed this.", 168, advanced=True))
        return ProviderSpec(
            id="splunk_enterprise", name="Splunk Enterprise", status=LIVE_VERIFIED_TEST if verified else NOT_LIVE_VERIFIED, verification_note=note,
            scope_noun="index", query_language="SPL", auth_methods=(("token", "Authentication token (recommended)"), ("basic", "User name and password")), fields=fields,
            secret_fields=(("token", FieldSpec("token", "Authentication token", "secret", True, "A Splunk authentication token for a search-only role.")),
                           ("basic", FieldSpec("username", "User name", "text", True)), ("basic", FieldSpec("password", "Password", "secret", True))),
            capabilities={"test_connection": True, "discover_scopes": True, "plan": True, "preflight": True, "cancel": True, "oauth": False, "revoke_on_disconnect": False},
            limitations=("Needs the Sysmon-style field names; Windows Security 4688 is reported unsupported rather than mis-queried.",
                         "The log-source scope in the query is an assumption about how events are indexed; check it.",
                         "A historical search shows what the rule would have matched in the window, not whether it would catch an attack that did not occur in it."),
            docs_url="https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.0/search-endpoints/search-endpoint-descriptions",
            summary="Read-only search-job REST calls against the management port.")

    # --- helpers -----------------------------------------------------------------------------------------------
    def validate_config(self, config: dict, *, mode: str) -> dict:
        config = apply_defaults(self.spec, config)
        verify = bool(config.get("verify_tls", True))
        if not verify and not config.get("accept_insecure_tls"):
            raise IntegrationError("config", "certificate verification is off: tick the acknowledgement, or turn verification back on")
        ep = policy.validate_endpoint(config.get("endpoint", ""), mode=mode, allow_http_loopback=True, verify_tls=verify)
        out = {"endpoint": ep.base_url, "verify_tls": verify, "accept_insecure_tls": bool(config.get("accept_insecure_tls")),
               "ca_bundle": (config.get("ca_bundle") or None), "allow_privileged": bool(config.get("allow_privileged")),
               "max_results": _int(config, "max_results", 1, 20, 5), "max_time_range_hours": _int(config, "max_time_range_hours", 1, 720, 168)}
        if self.cloud:
            if not CLOUD_HOST.match(ep.host) or ep.scheme != "https" or not verify:
                raise IntegrationError("config", "a Splunk Cloud endpoint must be https://<stack>.splunkcloud.com:8089 with certificate verification on")
        return out

    def _transport(self, config: dict, mode: str) -> policy.PolicyTransport:
        return policy.PolicyTransport(mode=mode, verify_tls=config["verify_tls"], ca_bundle=config.get("ca_bundle"), timeout=30, allow_http_loopback=True)

    def _config(self, config: dict, secret: dict, allowed: tuple = (), **over) -> splunk.SplunkConfig:
        args = dict(base_url=config["endpoint"], token=secret.get("token"), username=secret.get("username"), password=secret.get("password"),
                    allowed_indexes=tuple(allowed), verify_tls=config["verify_tls"], ca_bundle=config.get("ca_bundle"),
                    max_results=config["max_results"], max_time_range_hours=config["max_time_range_hours"], allow_privileged=config["allow_privileged"])
        args.update(over)
        try:
            return splunk.SplunkConfig(**args)
        except splunk.SplunkError as exc:
            raise IntegrationError(exc.kind, redact(str(exc), list(secret.values()))) from None

    @staticmethod
    def _wrap(exc: splunk.SplunkError, secret: dict) -> IntegrationError:
        return IntegrationError(exc.kind, redact(str(exc), list(secret.values())))

    # --- connection --------------------------------------------------------------------------------------------
    def test_connection(self, config: dict, secret: dict, *, mode: str) -> ConnectionReport:
        config = self.validate_config(config, mode=mode)
        ep = policy.validate_endpoint(config["endpoint"], mode=mode, allow_http_loopback=True, verify_tls=config["verify_tls"])
        cfg = self._config(config, secret, allow_privileged=True)  # read the identity first; the privilege decision is made below, visibly
        conn = splunk.SplunkConnector(cfg, transport=self._transport(config, mode))
        checks, warnings = [], []
        endpoint_info = {"host": ep.display, "loopback": ep.is_loopback, "private": ep.is_private, "tls_verified": config["verify_tls"] if ep.scheme == "https" else None,
                         "scheme": ep.scheme}
        if ep.scheme == "http":
            warnings.append("This endpoint is plain http on loopback. That is acceptable for a local test instance only.")
        if not config["verify_tls"]:
            warnings.append("Certificate verification is off for this connection. Only a loopback or private test instance is accepted in this mode.")
        identity = None
        try:
            identity = conn._identity()
        except splunk.SplunkError as exc:
            err = self._wrap(exc, secret)
            if exc.kind in NETWORK_KINDS:
                checks += [Check("network_tls", "Network and TLS", "fail", str(err)), Check("authentication", "Authentication", "skipped", "not reached"),
                           Check("permissions", "Permissions", "skipped", "not reached"), Check("endpoint", "Endpoint identity", "skipped", "not reached")]
            elif exc.kind == "auth":
                checks += [Check("network_tls", "Network and TLS", "pass", "the server answered over a connection that met the TLS policy"),
                           Check("authentication", "Authentication", "fail", str(err)), Check("permissions", "Permissions", "skipped", "not reached"),
                           Check("endpoint", "Endpoint identity", "skipped", "not reached")]
            else:  # permission and anything else the identity call reports
                checks += [Check("network_tls", "Network and TLS", "pass", "the server answered over a connection that met the TLS policy"),
                           Check("authentication", "Authentication", "pass" if exc.kind == "permission" else "fail", "the credentials were accepted" if exc.kind == "permission" else str(err)),
                           Check("permissions", "Permissions", "fail", str(err)), Check("endpoint", "Endpoint identity", "skipped", "not reached")]
            return ConnectionReport(checks, {}, endpoint_info, warnings)
        checks.append(Check("network_tls", "Network and TLS", "pass", "connected over " + ("verified TLS" if config["verify_tls"] and ep.scheme == "https" else "a connection that met the policy for this endpoint")))
        checks.append(Check("authentication", "Authentication", "pass", f"authenticated as {identity['username']}"))
        caps = set(identity["capabilities"])
        risky = sorted(caps & splunk.PRIVILEGED_CAPABILITIES)
        if identity["capabilities_known"] and "search" not in caps:
            checks.append(Check("permissions", "Permissions", "fail", "the account does not hold the `search` capability, so it cannot run a preflight"))
        elif risky and not config["allow_privileged"]:
            checks.append(Check("permissions", "Permissions", "fail", f"the account has admin-class capabilities ({', '.join(risky)}). Use a dedicated search-only role, "
                                                                      "or accept the risk in the advanced options."))
        elif risky or identity["warnings"] or not identity["capabilities_known"]:
            checks.append(Check("permissions", "Permissions", "warn", " ".join(identity["warnings"]) or "the server did not report capabilities"))
        else:
            checks.append(Check("permissions", "Permissions", "pass", "the account holds `search` and nothing broader; Shakedown only creates and deletes its own search jobs"))
        warnings += [w for w in identity["warnings"] if w not in warnings]
        try:
            info = conn.server_info()
            endpoint_info.update({k: v for k, v in info.items() if v})
            label = " ".join(x for x in (info.get("product"), info.get("version")) if x) or "reported no version"
            checks.append(Check("endpoint", "Endpoint identity", "pass", label))
        except splunk.SplunkError as exc:
            checks.append(Check("endpoint", "Endpoint identity", "warn", "could not read the server version (" + exc.kind + "); this does not stop a preflight"))
        return ConnectionReport(checks, {"username": identity["username"], "roles": identity["roles"], "capabilities": sorted(caps),
                                         "capabilities_known": identity["capabilities_known"]}, endpoint_info, warnings)

    def discover_scopes(self, config: dict, secret: dict, *, mode: str) -> dict:
        config = self.validate_config(config, mode=mode)
        conn = splunk.SplunkConnector(self._config(config, secret), transport=self._transport(config, mode))
        try:
            items = conn.list_indexes()
        except splunk.SplunkError as exc:
            if exc.kind in ("permission", "forbidden_endpoint"):
                return {"discovery": "denied", "items": [], "note": "This account may not list indexes. Enter the index names you are allowed to search."}
            raise self._wrap(exc, secret) from None
        return {"discovery": "available", "items": items, "note": "Indexes this account can see. Internal and disabled indexes are not listed."}

    # --- query and run -----------------------------------------------------------------------------------------
    def plan(self, rule_text: str, config: dict, scope: dict, window: tuple | None = None) -> dict:
        indexes = list(scope.get("indexes") or [])
        cfg = self._config(config, {"token": "x" * 8}, allowed=tuple(indexes))  # nothing is sent: a placeholder satisfies the config check
        try:
            p = splunk.SplunkConnector(cfg).plan(rule_text, indexes=indexes)
        except splunk.SplunkError as exc:
            raise IntegrationError(exc.kind, str(exc)) from None
        return {"language": "SPL", "queries": p["queries"], "detection": p["converted_detection"], "fields": p["fields"],
                "scope": {"indexes": indexes, "logsource_category": p["category"], "logsource_scope": p["scope"]["clause"], "logsource_note": p["scope"]["note"]},
                "notes": list(splunk.NOTES)}

    def run(self, rule_text: str, config: dict, secret: dict, scope: dict, window: tuple, *, mode: str, cancel=None, handle=None) -> dict:
        indexes = list(scope.get("indexes") or [])
        conn = splunk.SplunkConnector(self._config(config, secret, allowed=tuple(indexes)), transport=self._transport(config, mode))
        conn._cancel = _StickyCancel()
        if handle is not None:
            handle["connector"] = conn
            if handle.get("cancel_requested"):
                conn.cancel()
        try:
            return conn.preflight(rule_text, indexes=indexes, earliest=window[0], latest=window[1])
        except splunk.SplunkError as exc:
            raise self._wrap(exc, secret) from None

    def cancel(self, handle: dict) -> None:
        conn = handle.get("connector")
        if conn is not None:
            conn.cancel()


class SplunkCloudAdapter(SplunkEnterpriseAdapter):
    cloud = True

    @property
    def spec(self) -> ProviderSpec:
        base = super().spec
        fields = tuple(f if f.name != "endpoint" else replace(f, help="Your stack's management endpoint: https://<stack>.splunkcloud.com:8089. The stack's administrator must allow REST access to port 8089 from where Shakedown runs.",
                                                                  placeholder="https://yourstack.splunkcloud.com:8089")
                       for f in base.fields if f.name not in ("verify_tls", "accept_insecure_tls", "ca_bundle"))
        return replace(base, id="splunk_cloud", name="Splunk Cloud Platform", status=NOT_LIVE_VERIFIED, status_label="Implemented, not live-verified", fields=fields,
                       auth_methods=(("token", "Authentication token"),), secret_fields=tuple(x for x in base.secret_fields if x[0] == "token"),
                       verification_note="Implemented on the documented management endpoint pattern and tested against a mock server only. Never run against a real Splunk Cloud "
                                         "stack, so its access, permissions and search behaviour there are not verified.",
                       limitations=base.limitations + ("Certificate verification is always on for Splunk Cloud.",),
                       docs_url="https://help.splunk.com/en/splunk-cloud-platform/rest-api-reference",
                       summary="The same read-only search-job calls, against a Splunk Cloud stack's management endpoint.")

    def validate_config(self, config: dict, *, mode: str) -> dict:
        config = {**config, "verify_tls": True, "ca_bundle": None, "accept_insecure_tls": False}
        return super().validate_config(config, mode=mode)
