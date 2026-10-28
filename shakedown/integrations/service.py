"""The integration service: saved connections, connection tests, scope discovery, query preview, bounded read-only preflights, history, export.

Rules this module enforces for every provider:

* A connection can be saved only from a connection test that passed, and only the credential that passed the test is saved.
* Credentials live in the secret store or in the server's environment, never in a profile, a result, a log line or an error message.
* The query that runs is the query that was previewed: `start_preflight` executes a stored plan, not a fresh request.
* Rule validity, attack validation and environment preflight stay three separate statuses (shakedown.assess builds them).
* Nothing is deployed, scheduled or changed in a SIEM. An assessment is a recommendation for an analyst.
* Every call is scoped to `owner`; another owner's records are reported as not found.
"""
import hashlib
import hmac
import json
import logging
import re
import secrets as token_source
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from shakedown import assess
from shakedown.integrations import policy, vault
from shakedown.integrations.base import Check, ConnectionReport, IntegrationError, ProviderAdapter, pkce_pair, redact
from shakedown.integrations.registry import Registry
from shakedown.integrations.store import AssessmentStore, ProfileStore
from shakedown.validate import validate_rule

log = logging.getLogger("shakedown.integrations")
PENDING_TTL_S, PLAN_TTL_S, CHECK_FRESH_S = 600, 1800, 3600
MAX_PENDING, MAX_JOBS, RATE_LIMIT_PER_MIN = 20, 3, 40
SCOPE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,99}$")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def parse_window(window: dict, max_hours: int, now: datetime | None = None) -> tuple:
    """An explicit, bounded window: `{'last_hours': N}` or `{'earliest': iso, 'latest': iso}`. Never open-ended."""
    now = now or _now()
    try:
        if window.get("last_hours") is not None:
            hours = int(window["last_hours"])
            if not 1 <= hours <= max_hours:
                raise IntegrationError("scope", f"the window must be between 1 and {max_hours} hours")
            return now - timedelta(hours=hours), now
        parse = lambda s: datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        earliest, latest = parse(window["earliest"]), parse(window["latest"])
    except (KeyError, ValueError, TypeError):
        raise IntegrationError("scope", "give an explicit time window: the last N hours, or an earliest and a latest time") from None
    earliest, latest = (t if t.tzinfo else t.replace(tzinfo=timezone.utc) for t in (earliest, latest))
    if earliest >= latest:
        raise IntegrationError("scope", "the window must start before it ends")
    if (latest - earliest).total_seconds() > max_hours * 3600:
        raise IntegrationError("scope", f"the window exceeds the limit of {max_hours} hours")
    if latest > now + timedelta(minutes=5):
        raise IntegrationError("scope", "the window ends in the future")
    return earliest, latest


class IntegrationService:
    def __init__(self, *, data_dir: Path, registry: Registry, secret_store: vault.SecretStore, rules, mode: str = "local", owner: str = "local",
                 validator=validate_rule, environ=None, enabled: bool = True, disabled_reason: str = "", clock=time.monotonic):
        self.registry, self.secrets, self.rules, self.mode, self.owner = registry, secret_store, rules, mode, owner
        self.validator, self.environ, self.enabled, self.disabled_reason, self._clock = validator, environ, enabled, disabled_reason, clock
        base = Path(data_dir)
        self.profiles, self.assessments = ProfileStore(base / "connections.json"), AssessmentStore(base / "assessments")
        self._pending: dict = {}
        self._flows: dict = {}
        self._plans: dict = {}
        self._jobs: dict = {}
        self._calls: deque = deque()
        self._lock = threading.RLock()

    # ---- guards ---------------------------------------------------------------------------------------------
    def _guard(self, rate: bool = False) -> None:
        if not self.enabled:
            raise IntegrationError("disabled", self.disabled_reason or "integrations are disabled on this server")
        if rate:
            now = self._clock()
            with self._lock:
                while self._calls and now - self._calls[0] > 60:
                    self._calls.popleft()
                if len(self._calls) >= RATE_LIMIT_PER_MIN:
                    raise IntegrationError("rate_limited", "too many connection attempts in the last minute; wait and try again")
                self._calls.append(now)

    def status(self) -> dict:
        return {"enabled": self.enabled, "mode": self.mode, "disabled_reason": None if self.enabled else self.disabled_reason,
                "owner_model": "one local operator; there are no user accounts", "secret_store": self.secrets.describe(),
                "supports_env_credentials": True, "providers": self.registry.specs(),
                "limits": {"max_concurrent_preflights": MAX_JOBS, "pending_test_minutes": PENDING_TTL_S // 60}}

    # ---- secrets -------------------------------------------------------------------------------------------
    def _secret_from_input(self, spec, auth: str, secret_input: dict) -> tuple:
        names = [f.name for a, f in spec.secret_fields if a == auth]
        if not names:
            raise IntegrationError("config", "that sign-in method has no credential fields")
        mode = (secret_input or {}).get("mode", "paste")
        if mode == "env":
            env = {n: str(((secret_input or {}).get("env") or {}).get(n, "")).strip() for n in names}
            return vault.resolve_env_refs(env, self.environ), {"mode": "env", "env": env, "fingerprint": None}
        values = {}
        for n in names:
            v = str(((secret_input or {}).get("values") or {}).get(n, "")).strip()
            if not v or len(v) > 4096 or CONTROL.search(v):
                raise IntegrationError("config", f"the {n.replace('_', ' ')} is missing, too long, or contains control characters")
            values[n] = v
        return values, {"mode": "store", "env": None, "fingerprint": vault.fingerprint(values)}

    def _secret_for(self, profile: dict) -> dict:
        ref = profile["secret_ref"]
        if ref["mode"] == "env":
            return vault.resolve_env_refs(ref["env"], self.environ)
        secret = self.secrets.get(self.owner, profile["id"])
        if secret is None:
            raise IntegrationError("auth", "the saved credentials are not available (the server restarted, or they were deleted). Re-enter them to reconnect.")
        return secret

    @staticmethod
    def _secret_values(secret: dict) -> list:
        return [v for v in secret.values() if isinstance(v, str)]

    # ---- connection tests -------------------------------------------------------------------------------------
    def _run_test(self, adapter, config: dict, secret: dict) -> ConnectionReport:
        try:
            return adapter.test_connection(config, secret, mode=self.mode)
        except IntegrationError as exc:
            return ConnectionReport([Check("connection", "Connection", "fail", redact(str(exc), self._secret_values(secret)))], {}, {}, [])
        except Exception as exc:  # aqg: top-level boundary - an adapter bug becomes a failed check with no detail, never a leaked traceback
            log.warning("connection test crashed provider=%s type=%s", adapter.spec.id, type(exc).__name__)
            return ConnectionReport([Check("connection", "Connection", "fail", f"the connection test failed unexpectedly ({type(exc).__name__})")], {}, {}, [])

    @staticmethod
    def _check_record(report: ConnectionReport) -> dict:
        return {"at": _now().isoformat(timespec="seconds"), "ok": report.ok, "checks": [c.public() for c in report.checks], "identity": report.identity,
                "endpoint": report.endpoint, "warnings": report.warnings}

    def test_new(self, provider_id: str, auth: str, config: dict, secret_input: dict) -> dict:
        self._guard(rate=True)
        adapter = self.registry.adapter(provider_id)
        spec = adapter.spec
        if auth not in {a for a, _ in spec.auth_methods}:
            raise IntegrationError("config", "choose one of the sign-in methods this provider supports")
        normalized = adapter.validate_config(config or {}, mode=self.mode)
        if not [1 for a, _ in spec.secret_fields if a == auth]:
            raise IntegrationError("config", "this sign-in method has no credential to paste: start it with the provider's sign-in window")
        secret, ref = self._secret_from_input(spec, auth, secret_input)
        return self._complete_test(adapter, provider_id, auth, normalized, secret, ref)

    def _complete_test(self, adapter, provider_id: str, auth: str, normalized: dict, secret: dict, ref: dict) -> dict:
        spec = adapter.spec
        report = self._run_test(adapter, normalized, secret)
        scopes, test_id = None, None
        if report.ok:
            if spec.capabilities.get("discover_scopes"):
                try:
                    scopes = adapter.discover_scopes(normalized, secret, mode=self.mode)
                except IntegrationError as exc:
                    scopes = {"discovery": "manual", "items": [], "note": redact(str(exc), self._secret_values(secret))}
            test_id = token_source.token_urlsafe(18)
            with self._lock:
                self._prune()
                if len(self._pending) >= MAX_PENDING:
                    raise IntegrationError("rate_limited", "too many unsaved connection tests; save or wait for them to expire")
                self._pending[test_id] = {"owner": self.owner, "provider": provider_id, "auth": auth, "config": normalized, "secret": secret, "ref": ref,
                                          "check": self._check_record(report), "created": self._clock()}
        return {"test_id": test_id, "report": report.public(), "scopes": scopes, "config": normalized, "credential": {"mode": ref["mode"], "fingerprint": ref["fingerprint"], "env": ref["env"]}}

    # ---- browser sign-in (OAuth authorization code + PKCE) --------------------------------------------------------
    def oauth_start(self, provider_id: str, auth: str, config: dict, redirect_uri: str, conn_id: str | None = None) -> dict:
        """Begin a sign-in at the provider. No secret exists on our side except a one-time PKCE verifier, kept in memory with the flow."""
        self._guard(rate=True)
        adapter = self.registry.adapter(provider_id)
        if not adapter.spec.capabilities.get("oauth") or auth != "interactive":
            raise IntegrationError("config", "this provider has no browser sign-in")
        if conn_id:
            profile = self._profile(conn_id)
            if profile["provider"] != provider_id:
                raise IntegrationError("config", "that connection belongs to another provider")
            config = {**profile["config"], **{k: v for k, v in (config or {}).items() if v not in (None, "")}}
        normalized = adapter.validate_config(config or {}, mode=self.mode)
        verifier, challenge = pkce_pair()
        state, flow_id = token_source.token_urlsafe(32), token_source.token_urlsafe(12)
        url = adapter.oauth_begin(normalized, redirect_uri, state, challenge)
        with self._lock:
            self._prune()
            if len(self._flows) >= MAX_PENDING:
                raise IntegrationError("rate_limited", "too many sign-ins are in progress; finish or wait for them to expire")
            self._flows[flow_id] = {"owner": self.owner, "state": state, "provider": provider_id, "auth": auth, "config": normalized, "verifier": verifier,
                                    "redirect_uri": redirect_uri, "conn_id": conn_id, "status": "waiting", "result": None, "error": None, "created": self._clock()}
        return {"flow_id": flow_id, "authorize_url": url, "redirect_uri": redirect_uri, "expires_minutes": PENDING_TTL_S // 60}

    def oauth_callback(self, state: str, code: str, error: str, description: str, callback_uri: str) -> bool:
        """The provider's browser redirect. It is trusted only through `state`: unguessable, single use, short-lived and bound to one waiting flow, whose PKCE
        verifier is held here and never leaves this process, so a code issued to anyone else's authorization request cannot be exchanged. The redirect must also arrive
        at exactly the address the sign-in started from. Returns whether sign-in completed."""
        given = (state or "").encode("utf-8")
        with self._lock:
            self._prune()
            flow = next((f for f in self._flows.values() if f["status"] == "waiting" and hmac.compare_digest(f["state"].encode("utf-8"), given)), None)
            if flow is not None:
                flow["status"] = "exchanging"  # single use: a replayed callback finds nothing waiting
                flow["state"] = ""
        if flow is None:
            return False
        adapter = self.registry.adapter(flow["provider"])
        try:
            if callback_uri != flow["redirect_uri"]:
                raise IntegrationError("destination", "the sign-in returned to a different address than the one it started from, so it was refused. Start it again from the address you registered")
            if error or not code:
                kind = "permission" if error in ("access_denied", "consent_required", "interaction_required") else "auth"
                text = re.split(r"\s*(?:Trace ID|Correlation ID|Timestamp):", description or "")[0].strip()[:240]
                raise IntegrationError(kind, redact(f"Microsoft sign-in did not complete ({str(error or 'no code')[:60]}). {text}", [code or ""]))
            secret = adapter.oauth_exchange(flow["config"], code, flow["verifier"], flow["redirect_uri"], self.mode)
            ref = {"mode": "store", "env": None, "fingerprint": vault.fingerprint({"refresh_token": secret["refresh_token"]})}
            if flow["conn_id"]:
                result = self._apply_reauth(adapter, flow, secret, ref)
            else:
                result = self._complete_test(adapter, flow["provider"], flow["auth"], flow["config"], secret, ref)
            flow.update(status="done", result=result)
            ok = True
        except IntegrationError as exc:
            flow.update(status="failed", error={"kind": exc.kind, "message": redact(str(exc), [code or "", flow["verifier"]])})
            ok = False
        except Exception as exc:  # aqg: top-level boundary - a crashed sign-in becomes a failed flow with no detail, never a stuck one or a traceback
            log.warning("sign-in crashed provider=%s type=%s", flow["provider"], type(exc).__name__)
            flow.update(status="failed", error={"kind": "unavailable", "message": f"the sign-in failed unexpectedly ({type(exc).__name__})"})
            ok = False
        flow["verifier"] = None
        return ok

    def _apply_reauth(self, adapter, flow: dict, secret: dict, ref: dict) -> dict:
        profile = self._profile(flow["conn_id"])
        report = self._run_test(adapter, flow["config"], secret)
        if report.ok:
            self.secrets.put(self.owner, profile["id"], secret)
            self.profiles.update(self.owner, profile["id"], {"config": flow["config"], "auth": flow["auth"], "secret_ref": ref, "last_check": self._check_record(report)})
        return {"report": report.public(), "applied": report.ok, "connection": self._public(self._profile(profile["id"]))}

    def oauth_status(self, flow_id: str) -> dict:
        self._guard()
        with self._lock:
            self._prune()
            flow = self._flows.get(flow_id)
            if flow is None or flow["owner"] != self.owner:
                raise IntegrationError("not_found", "that sign-in has expired or does not exist; start it again")
            if flow["status"] in ("done", "failed"):
                self._flows.pop(flow_id, None)
        return {"status": flow["status"], "result": flow["result"], "error": flow["error"]}

    def _persist_rotation(self, profile: dict, secret: dict, before: dict) -> None:
        """An OAuth refresh may issue a new refresh token; keep it, or the saved sign-in would stop working."""
        if profile["secret_ref"]["mode"] == "store" and secret != before:
            try:
                self.secrets.put(self.owner, profile["id"], secret)
            except IntegrationError:
                log.warning("could not persist a rotated credential provider=%s", profile["provider"])

    def _prune(self) -> None:
        now = self._clock()
        for k in [k for k, v in self._pending.items() if now - v["created"] > PENDING_TTL_S]:
            self._pending.pop(k, None)
        for k in [k for k, v in self._plans.items() if now - v["created"] > PLAN_TTL_S]:
            self._plans.pop(k, None)
        for k in [k for k, v in self._flows.items() if now - v["created"] > PENDING_TTL_S]:
            self._flows.pop(k, None)

    # ---- saved connections -----------------------------------------------------------------------------------
    @staticmethod
    def _clean_scope(spec, scope: dict) -> dict:
        items = (scope or {}).get("indexes") or []
        if not isinstance(items, list) or not items or len(items) > 20:
            raise IntegrationError("scope", f"choose between 1 and 20 {spec.scope_noun}s")
        names = []
        for i in items:
            if not isinstance(i, str) or not SCOPE_NAME.match(i) or "*" in i:
                raise IntegrationError("scope", f"{str(i)[:40]!r} is not a valid {spec.scope_noun} name; names must be specific, with no wildcard")
            names.append(i)
        out = {"indexes": list(dict.fromkeys(names))}
        hours = (scope or {}).get("default_window_hours")
        if hours is not None:
            if isinstance(hours, bool) or not isinstance(hours, int) or not 1 <= hours <= 720:
                raise IntegrationError("scope", "the default search window must be a whole number of hours between 1 and 720")
            out["default_window_hours"] = hours
        return out

    def save(self, test_id: str, label: str, scope: dict) -> dict:
        self._guard()
        with self._lock:
            self._prune()
            pending = self._pending.get(test_id)
            if not pending or pending["owner"] != self.owner:
                raise IntegrationError("not_found", "that connection test has expired or does not exist; test the connection again")
            if not pending["check"]["ok"]:
                raise IntegrationError("conflict", "only a connection that passed its test can be saved")
            spec = self.registry.spec(pending["provider"])
            label = (label or "").strip()
            if not 1 <= len(label) <= 80 or CONTROL.search(label):
                raise IntegrationError("config", "give the connection a name of 1 to 80 characters")
            clean = self._clean_scope(spec, scope)
            adapter = self.registry.adapter(pending["provider"])
            try:
                adapter.verify_scope(pending["config"], pending["secret"], clean, mode=self.mode)
            except IntegrationError as exc:
                raise IntegrationError(exc.kind, redact(str(exc), self._secret_values(pending["secret"]))) from None
            profile = self.profiles.create(self.owner, {"provider": pending["provider"], "label": label, "auth": pending["auth"], "config": pending["config"],
                                                        "scope": clean, "secret_ref": pending["ref"], "last_check": pending["check"], "last_preflight": None})
            if pending["ref"]["mode"] == "store":
                try:
                    self.secrets.put(self.owner, profile["id"], pending["secret"])
                except IntegrationError:
                    self.profiles.delete(self.owner, profile["id"])
                    raise
            self._pending.pop(test_id, None)
        return self._public(profile)

    def _state(self, profile: dict) -> str:
        ref = profile["secret_ref"]
        if ref["mode"] == "store" and self.secrets.get(self.owner, profile["id"]) is None:
            return "needs_credentials"
        if ref["mode"] == "env":
            try:
                vault.resolve_env_refs(ref["env"], self.environ)
            except IntegrationError:
                return "needs_credentials"
        check = profile.get("last_check")
        if not check:
            return "unverified"
        if not check["ok"]:
            return "check_failed"
        age = (_now() - datetime.fromisoformat(check["at"])).total_seconds()
        return "connected" if age <= CHECK_FRESH_S else "stale"

    def _public(self, profile: dict) -> dict:
        spec = self.registry.spec(profile["provider"])
        endpoint = policy.mask_endpoint(profile["config"]["endpoint"])
        ref = profile["secret_ref"]
        return {"id": profile["id"], "provider": profile["provider"], "provider_name": spec.name, "provider_status": spec.status, "provider_status_label": spec.status_label, "label": profile["label"],
                "endpoint": endpoint, "auth": profile.get("auth"), "state": self._state(profile), "scope_noun": spec.scope_noun, "scope": profile["scope"],
                "credential": {"mode": ref["mode"], "fingerprint": ref.get("fingerprint"), "env": ref.get("env"), "store": self.secrets.kind if ref["mode"] == "store" else "environment"},
                "last_check": profile.get("last_check"), "last_preflight": profile.get("last_preflight"), "capabilities": spec.capabilities,
                "created_at": profile["created_at"], "updated_at": profile["updated_at"], "check_fresh_seconds": CHECK_FRESH_S,
                "config": {k: v for k, v in profile["config"].items() if k != "endpoint"}}

    def list_connections(self) -> list:
        self._guard()
        return [self._public(p) for p in self.profiles.list(self.owner)]

    def _profile(self, conn_id: str) -> dict:
        profile = self.profiles.get(self.owner, conn_id)
        if profile is None:
            raise IntegrationError("not_found", "no such connection")
        return profile

    def get_connection(self, conn_id: str) -> dict:
        self._guard()
        return self._public(self._profile(conn_id))

    def update(self, conn_id: str, label: str | None = None, scope: dict | None = None) -> dict:
        self._guard()
        profile = self._profile(conn_id)
        patch = {}
        if label is not None:
            if not 1 <= len(label.strip()) <= 80 or CONTROL.search(label):
                raise IntegrationError("config", "give the connection a name of 1 to 80 characters")
            patch["label"] = label.strip()
        if scope is not None:
            patch["scope"] = self._clean_scope(self.registry.spec(profile["provider"]), scope)
            adapter = self.registry.adapter(profile["provider"])
            if type(adapter).verify_scope is not ProviderAdapter.verify_scope:  # only providers that can prove access need the credential here
                secret = self._secret_for(profile)
                before = dict(secret)
                try:
                    adapter.verify_scope(profile["config"], secret, patch["scope"], mode=self.mode)
                except IntegrationError as exc:
                    raise IntegrationError(exc.kind, redact(str(exc), self._secret_values(secret))) from None
                finally:
                    self._persist_rotation(profile, secret, before)
        return self._public(self.profiles.update(self.owner, conn_id, patch)) if patch else self._public(profile)

    def retest(self, conn_id: str) -> dict:
        self._guard(rate=True)
        profile = self._profile(conn_id)
        adapter = self.registry.adapter(profile["provider"])
        try:
            secret = self._secret_for(profile)
        except IntegrationError as exc:
            report = ConnectionReport([Check("credentials", "Credentials", "fail", str(exc))], {}, {}, [])
        else:
            before = dict(secret)
            report = self._run_test(adapter, profile["config"], secret)
            self._persist_rotation(profile, secret, before)
        self.profiles.update(self.owner, conn_id, {"last_check": self._check_record(report)})
        return {"report": report.public(), "connection": self._public(self._profile(conn_id))}

    def reconfigure(self, conn_id: str, auth: str, config: dict, secret_input: dict) -> dict:
        """Change the endpoint, sign-in settings or credential. Nothing changes unless the new settings pass a test."""
        self._guard(rate=True)
        profile = self._profile(conn_id)
        adapter = self.registry.adapter(profile["provider"])
        if auth not in {a for a, _ in adapter.spec.auth_methods}:
            raise IntegrationError("config", "choose one of the sign-in methods this provider supports")
        merged = {**profile["config"], **{k: v for k, v in (config or {}).items() if v not in (None, "")}}  # a blank field keeps the saved value
        normalized = adapter.validate_config(merged, mode=self.mode)
        secret, ref = self._secret_from_input(adapter.spec, auth, secret_input)
        report = self._run_test(adapter, normalized, secret)
        if report.ok:
            if ref["mode"] == "store":
                self.secrets.put(self.owner, conn_id, secret)
            elif profile["secret_ref"]["mode"] == "store":
                self.secrets.delete(self.owner, conn_id)
            self.profiles.update(self.owner, conn_id, {"config": normalized, "auth": auth, "secret_ref": ref, "last_check": self._check_record(report)})
        return {"report": report.public(), "applied": report.ok, "connection": self._public(self._profile(conn_id))}

    def discover(self, conn_id: str) -> dict:
        self._guard(rate=True)
        profile = self._profile(conn_id)
        adapter = self.registry.adapter(profile["provider"])
        secret = self._secret_for(profile)
        before = dict(secret)
        try:
            return adapter.discover_scopes(profile["config"], secret, mode=self.mode)
        except IntegrationError as exc:
            raise IntegrationError(exc.kind, redact(str(exc), self._secret_values(secret))) from None
        finally:
            self._persist_rotation(profile, secret, before)

    def disconnect(self, conn_id: str, delete_assessments: bool = False) -> dict:
        self._guard()
        profile = self._profile(conn_id)
        with self._lock:
            for job_id, job in list(self._jobs.items()):
                if job["connection_id"] == conn_id and job["thread"].is_alive():
                    self._cancel_job(job_id)
        self.secrets.delete(self.owner, conn_id)
        self.profiles.delete(self.owner, conn_id)
        removed = self.assessments.delete_for_connection(self.owner, conn_id) if delete_assessments else 0
        spec = self.registry.spec(profile["provider"])
        revoked = bool(spec.capabilities.get("revoke_on_disconnect"))
        return {"disconnected": True, "secret_deleted": True, "assessments_deleted": removed, "token_revoked": revoked,
                "note": "Shakedown deleted its saved credential." + ("" if revoked else " It cannot revoke the credential at the provider: revoke the token there if you no longer need it.")}

    # ---- rules, plans, runs ---------------------------------------------------------------------------------
    def rule_candidates(self) -> list:
        self._guard()
        return self.rules.list()

    def plan(self, conn_id: str, rule: dict, indexes: list, window: dict) -> dict:
        self._guard()
        profile = self._profile(conn_id)
        adapter = self.registry.adapter(profile["provider"])
        if rule.get("ref"):
            found = self.rules.get(rule["ref"])
            if found is None:
                raise IntegrationError("not_found", "no such rule or assessment")
            rule_text, source = found["text"], {"ref": rule["ref"], "label": found["label"], "record": found.get("record")}
        else:
            rule_text = str(rule.get("text") or "")
            if not 20 <= len(rule_text) <= 100_000:
                raise IntegrationError("config", "paste a Sigma rule, or choose one from an earlier assessment")
            source = {"ref": None, "label": "pasted rule", "record": None}
        try:
            doc = yaml.safe_load(rule_text) or {}
            if not isinstance(doc, dict):
                raise ValueError
        except (yaml.YAMLError, ValueError):
            raise IntegrationError("config", "the rule is not valid YAML") from None
        saved = profile["scope"]["indexes"]
        chosen = list(dict.fromkeys(indexes or saved))
        outside = [i for i in chosen if i not in saved]
        if outside:
            raise IntegrationError("scope", f"{outside} are not part of this connection's saved {self.registry.spec(profile['provider']).scope_noun}s; edit the connection to add them")
        window = window or ({"last_hours": profile["scope"]["default_window_hours"]} if profile["scope"].get("default_window_hours") else {})
        earliest, latest = parse_window(window, int(profile["config"].get("max_time_range_hours", 168)))
        validation = self.validator(rule_text)
        rule_info = {"title": str(doc.get("title", "")), "id": str(doc.get("id", "")), "sha256": hashlib.sha256(rule_text.encode("utf-8")).hexdigest(), "source": source["label"]}
        base = {"rule": rule_info, "rule_validity": {"ok": validation.ok, "errors": validation.errors, "output": validation.sigma_output[-1500:]},
                "window": {"earliest": earliest.isoformat(), "latest": latest.isoformat(), "hours": round((latest - earliest).total_seconds() / 3600, 2)},
                "scope": {"indexes": chosen}, "connection_id": conn_id, "runnable": False}
        if not validation.ok:
            return {**base, "reason": "The Sigma validator rejected this rule, so no query is generated and nothing can be run."}
        try:
            built = adapter.plan(rule_text, profile["config"], {"indexes": chosen}, (earliest, latest))
        except IntegrationError as exc:
            return {**base, "reason": str(exc), "reason_kind": exc.kind}
        plan_id = hashlib.sha256(json.dumps([conn_id, rule_info["sha256"], built["queries"], chosen, base["window"]], sort_keys=True).encode()).hexdigest()[:20]
        with self._lock:
            self._prune()
            self._plans[plan_id] = {"owner": self.owner, "connection_id": conn_id, "rule_text": rule_text, "source": source, "validation": validation,
                                    "built": built, "scope": {"indexes": chosen}, "window": (earliest, latest), "created": self._clock()}
        return {**base, "runnable": True, "plan_id": plan_id, "language": built["language"], "queries": built["queries"], "detection": built["detection"],
                "fields": built.get("fields", []), "query_scope": built["scope"], "notes": built.get("notes", []), "expires_minutes": PLAN_TTL_S // 60}

    def start_preflight(self, conn_id: str, plan_id: str, confirm: bool) -> dict:
        self._guard(rate=True)
        if confirm is not True:
            raise IntegrationError("config", "a preflight runs only after you confirm it")
        profile = self._profile(conn_id)
        with self._lock:
            self._prune()
            plan = self._plans.get(plan_id)
            if not plan or plan["owner"] != self.owner or plan["connection_id"] != conn_id:
                raise IntegrationError("not_found", "that query preview has expired; preview the query again")
            if any(j["thread"].is_alive() and j["connection_id"] == conn_id for j in self._jobs.values()):
                raise IntegrationError("conflict", "a preflight is already running on this connection")
            if sum(1 for j in self._jobs.values() if j["thread"].is_alive()) >= MAX_JOBS:
                raise IntegrationError("rate_limited", "too many preflights are running; wait for one to finish")
            adapter = self.registry.adapter(profile["provider"])
            secret = self._secret_for(profile)
            spec = adapter.spec
            record = self.assessments.save(self.owner, {
                "connection_id": conn_id, "provider": profile["provider"], "provider_name": spec.name, "connection_label": profile["label"],
                "endpoint": self._public(profile)["endpoint"], "status": "running", "origin": "new_execution", "plan_id": plan_id, "capabilities": dict(spec.capabilities),
                "started_at": _now().isoformat(timespec="seconds"), "rule": {k: str(v) for k, v in (yaml.safe_load(plan["rule_text"]) or {}).items() if k in ("title", "id")},
                "rule_source": plan["source"]["label"],
                "scope": plan["scope"], "window": {"earliest": plan["window"][0].isoformat(), "latest": plan["window"][1].isoformat()},
                "language": plan["built"]["language"], "queries": plan["built"]["queries"], "query_sha256": hashlib.sha256(json.dumps(plan["built"]["queries"], sort_keys=True).encode()).hexdigest(),
                "credential_fingerprint": profile["secret_ref"].get("fingerprint"), "rule_text": plan["rule_text"], "assessment": None})
            handle: dict = {}
            thread = threading.Thread(target=self._execute, args=(record["id"], profile, adapter, secret, plan, handle), daemon=True)
            self._jobs[record["id"]] = {"thread": thread, "handle": handle, "connection_id": conn_id, "adapter": adapter}
            thread.start()
        return {"assessment_id": record["id"], "status": "running"}

    def _execute(self, assessment_id: str, profile: dict, adapter, secret: dict, plan: dict, handle: dict) -> None:
        started = time.monotonic()
        values = self._secret_values(secret)
        before = dict(secret)
        try:
            env = adapter.run(plan["rule_text"], profile["config"], secret, plan["scope"], plan["window"], mode=self.mode, handle=handle)
            env = {**env, "provider": env.get("provider", adapter.spec.id.split("_")[0]), "language": env.get("language", plan["built"]["language"])}
        except IntegrationError as exc:
            env = {"status": "query_failed", "error": {"kind": exc.kind, "message": redact(str(exc), values)}, "provider": adapter.spec.id.split("_")[0],
                   "language": plan["built"]["language"], "queries": plan["built"]["queries"], "scope": plan["scope"]}
        except Exception as exc:  # aqg: top-level boundary - a crashed run is recorded as a failure, with no traceback or payload
            log.warning("preflight crashed provider=%s type=%s", adapter.spec.id, type(exc).__name__)
            env = {"status": "query_failed", "error": {"kind": "unavailable", "message": f"the preflight failed unexpectedly ({type(exc).__name__})"},
                   "provider": adapter.spec.id.split("_")[0], "language": plan["built"]["language"]}
        self._persist_rotation(profile, secret, before)
        record_src = plan["source"].get("record")
        attack = lab = None
        if record_src:
            try:
                attack = assess.lab_attack_from_record(record_src)
            except (KeyError, IndexError, TypeError):
                attack = None
        report = assess.report_from_record(record_src) if record_src else None
        assessment = assess.build_assessment(plan["rule_text"], validation=plan["validation"], attack=attack, environment=env, report=report, lab=lab)
        env_state = assessment["statuses"]["environment_preflight"]["state"]
        current = self.assessments.get(self.owner, assessment_id) or {}
        final = {**current, "status": env_state, "finished_at": _now().isoformat(timespec="seconds"), "elapsed_s": round(time.monotonic() - started, 2), "assessment": assessment}
        self.assessments.save(self.owner, final)
        try:
            self.profiles.update(self.owner, profile["id"], {"last_preflight": {"assessment_id": assessment_id, "at": final["finished_at"], "status": env_state}})
        except IntegrationError:
            pass  # the connection was disconnected while the run was finishing

    def _cancel_job(self, assessment_id: str) -> None:
        job = self._jobs.get(assessment_id)
        if job and job["thread"].is_alive():
            job["handle"]["cancel_requested"] = True  # also covers a cancel that arrives before the adapter has built its connector
            try:
                job["adapter"].cancel(job["handle"])
            except (NotImplementedError, IntegrationError):
                pass

    def cancel(self, assessment_id: str) -> dict:
        self._guard()
        record = self.assessments.get(self.owner, assessment_id)
        if record is None:
            raise IntegrationError("not_found", "no such assessment")
        if record.get("capabilities") is not None and not record["capabilities"].get("cancel"):
            raise IntegrationError("conflict", f"{record.get('provider_name')} searches cannot be cancelled from Shakedown; this one is bounded by a server-side timeout")
        with self._lock:
            self._cancel_job(assessment_id)
        return {"assessment_id": assessment_id, "cancel_requested": True}

    def join(self, assessment_id: str, timeout: float = 30.0) -> None:
        job = self._jobs.get(assessment_id)
        if job:
            job["thread"].join(timeout)

    # ---- history and export ---------------------------------------------------------------------------------
    @staticmethod
    def _summary(rec: dict) -> dict:
        a = rec.get("assessment") or {}
        st = a.get("statuses") or {}
        return {"id": rec["id"], "connection_id": rec["connection_id"], "connection_label": rec.get("connection_label"), "provider": rec.get("provider"),
                "provider_name": rec.get("provider_name"), "status": rec.get("status"), "origin": rec.get("origin"), "started_at": rec.get("started_at"),
                "finished_at": rec.get("finished_at"), "elapsed_s": rec.get("elapsed_s"), "scope": rec.get("scope"), "window": rec.get("window"),
                "rule": rec.get("rule"), "rule_source": rec.get("rule_source"), "query_sha256": rec.get("query_sha256"), "language": rec.get("language"),
                "verdicts": {k: {"state": v.get("state"), "label": v.get("label")} for k, v in st.items()},
                "matches": ((st.get("environment_preflight") or {}).get("matches") or {}).get("count")}

    def list_assessments(self, conn_id: str | None = None) -> list:
        self._guard()
        return [self._summary(r) for r in self.assessments.list(self.owner, conn_id)]

    def get_assessment(self, assessment_id: str) -> dict:
        self._guard()
        rec = self.assessments.get(self.owner, assessment_id)
        if rec is None:
            raise IntegrationError("not_found", "no such assessment")
        with self._lock:
            job = self._jobs.get(assessment_id)
        if rec["status"] == "running" and (job is None or not job["thread"].is_alive()):
            rec = {**rec, "status": "interrupted"}  # the server restarted while it ran; nothing is still running
        return rec

    def export(self, assessment_id: str) -> dict:
        rec = self.get_assessment(assessment_id)
        a = rec.get("assessment")
        if not a:
            raise IntegrationError("conflict", "this assessment has not finished, so there is nothing to export")
        _, _, _, ext = assess.provider_of({"provider": (a.get("environment_provider") or {}).get("id", "splunk")})
        integration = {"connection": rec.get("connection_label"), "provider": rec.get("provider_name"), "endpoint": rec.get("endpoint"), "scope": rec.get("scope"),
                       "window": rec.get("window"), "credential_fingerprint": rec.get("credential_fingerprint"), "origin": rec.get("origin"),
                       "query_sha256": rec.get("query_sha256"), "started_at": rec.get("started_at"), "finished_at": rec.get("finished_at"),
                       "note": "Credentials are never part of this packet. Event excerpts, if any, come from your SIEM."}
        q = a.get("target_query")
        return {"assessment_id": assessment_id, "contains_event_excerpts": bool(((a["statuses"]["environment_preflight"].get("matches") or {}).get("examples"))),
                "files": {"review_packet.md": assess.render_packet(rec["rule_text"], a), "assessment.json": json.dumps(a, indent=1, default=str), "rule.yml": rec["rule_text"],
                          f"query.{ext}": ((q["detection"] if q else "") + "\n"), "integration.json": json.dumps(integration, indent=1)}}
