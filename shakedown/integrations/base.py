"""Provider-independent contracts for SIEM integrations.

A provider declares what it can do (`ProviderSpec.capabilities`); the UI and the API derive their actions from that
declaration, never from the provider's name. Providers differ in authentication, query language, field schema and
cancellation, and nothing here pretends otherwise.

Errors carry a `kind` (a stable machine-readable class) and a message that has already been redacted: a credential
never appears in an exception, a result, a log line or a packet.
"""
import base64
import hashlib
import re
import secrets as token_source
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

# How far a provider has been exercised. A mock never counts as live verification.
LIVE_VERIFIED_TEST = "live_verified_test_instance"
NOT_LIVE_VERIFIED = "not_live_verified"
PLANNED = "planned"

ERROR_KINDS = ("config", "destination", "unreachable", "tls", "redirect", "too_large", "auth", "permission", "scope", "query", "unsafe_query",
               "timeout", "cancelled", "unavailable", "conversion", "unsupported_logsource", "privileged_account", "forbidden_endpoint",
               "forbidden", "not_found", "conflict", "disabled", "rate_limited", "secret_store")


class IntegrationError(RuntimeError):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


_PATTERNS = [re.compile(p, re.I) for p in (
    r"(authorization)\s*[=:]\s*(?:bearer|basic|splunk|apikey|token)?\s*\S+",
    r"\b(bearer)\s+[A-Za-z0-9._~+/=-]{12,}",
    r"\b(basic)\s+[A-Za-z0-9+/=]{16,}",
    r"\b(apikey|api-key)\s+[A-Za-z0-9._~+/=-]{8,}",
    r"\b(splunk)\s+[A-Za-z0-9]{20,}",
    r"(x-api-key|api[_-]?key|token|password|secret|client_secret|refresh_token|access_token|code_verifier)\s*[=:]\s*\S+",
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}",
)]


def redact(text: Any, secrets: Iterable[str] = ()) -> str:
    """Remove known secret values and credential-shaped strings from text that may be shown or logged."""
    out = str(text)
    for s in secrets:
        if s and len(s) >= 4:
            out = out.replace(s, "[redacted]")
    for pat in _PATTERNS:
        out = pat.sub(lambda m: (m.group(1) + " [redacted]") if m.lastindex else "[redacted]", out)
    return out


def pkce_pair() -> tuple:
    """(code_verifier, S256 code_challenge) for an OAuth public client (RFC 7636)."""
    verifier = token_source.token_urlsafe(48)
    return verifier, base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class FieldSpec:
    name: str
    label: str
    kind: str = "text"            # text | url | secret | select | bool | number | list
    required: bool = True
    help: str = ""
    default: Any = None
    options: tuple = ()           # for select: ((value, label), ...)
    placeholder: str = ""
    advanced: bool = False

    def public(self) -> dict:
        return {"name": self.name, "label": self.label, "kind": self.kind, "required": self.required, "help": self.help, "default": self.default,
                "options": [list(o) for o in self.options], "placeholder": self.placeholder, "advanced": self.advanced}


@dataclass(frozen=True)
class ProviderSpec:
    id: str
    name: str
    status: str                   # LIVE_VERIFIED_TEST | NOT_LIVE_VERIFIED | PLANNED
    verification_note: str
    implemented: bool = True
    scope_noun: str = "index"     # what the data scope is called for this provider
    scope_example: str = "win_sysmon, security"
    status_label: str = ""        # the precise wording for `status`, shown in the UI; blank means the generic label for the status
    query_language: str = ""
    auth_methods: tuple = ()      # ((id, label), ...)
    fields: tuple = ()            # FieldSpec for the non-secret configuration
    secret_fields: tuple = ()     # FieldSpec for credentials, keyed by auth method via `for_auth`
    capabilities: dict = field(default_factory=dict)
    limitations: tuple = ()
    docs_url: str = ""
    summary: str = ""

    def public(self) -> dict:
        return {"id": self.id, "name": self.name, "status": self.status, "verification_note": self.verification_note, "implemented": self.implemented,
                "scope_noun": self.scope_noun, "scope_example": self.scope_example, "status_label": self.status_label, "query_language": self.query_language, "auth_methods": [list(a) for a in self.auth_methods],
                "fields": [f.public() for f in self.fields], "secret_fields": [f.public() | {"auth": a} for a, f in self.secret_fields],
                "capabilities": dict(self.capabilities), "limitations": list(self.limitations), "docs_url": self.docs_url, "summary": self.summary}


@dataclass
class Check:
    id: str
    label: str
    status: str                   # pass | fail | warn | skipped
    detail: str = ""

    def public(self) -> dict:
        return {"id": self.id, "label": self.label, "status": self.status, "detail": self.detail}


@dataclass
class ConnectionReport:
    checks: list
    identity: dict = field(default_factory=dict)
    endpoint: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.status in ("pass", "warn", "skipped") for c in self.checks) and any(c.status == "pass" for c in self.checks)

    def public(self) -> dict:
        return {"ok": self.ok, "checks": [c.public() for c in self.checks], "identity": self.identity, "endpoint": self.endpoint, "warnings": list(self.warnings)}


class ProviderAdapter(ABC):
    """One implementation per SIEM. `config` holds non-secret settings; `secret` holds the credential material
    (a dict of named values) and exists only in memory for the duration of a call."""

    spec: ProviderSpec

    @abstractmethod
    def validate_config(self, config: dict, *, mode: str) -> dict:
        """Return the normalised, non-secret configuration, or raise IntegrationError('config' | 'destination')."""

    @abstractmethod
    def test_connection(self, config: dict, secret: dict, *, mode: str) -> ConnectionReport: ...

    def discover_scopes(self, config: dict, secret: dict, *, mode: str) -> dict:
        """{'discovery': 'available' | 'manual' | 'denied', 'items': [{'name': ..., ...}], 'note': ''}"""
        return {"discovery": "manual", "items": [], "note": f"This provider does not list {self.spec.scope_noun}s; enter them by name."}

    def verify_scope(self, config: dict, secret: dict, scope: dict, *, mode: str) -> None:
        """Optional: prove, before a scope is saved, that this credential can read it. Raise IntegrationError when it cannot."""

    def oauth_begin(self, config: dict, redirect_uri: str, state: str, challenge: str) -> str:
        raise NotImplementedError

    def oauth_exchange(self, config: dict, code: str, verifier: str, redirect_uri: str, mode: str) -> dict:
        raise NotImplementedError

    @abstractmethod
    def plan(self, rule_text: str, config: dict, scope: dict, window: tuple | None = None) -> dict:
        """Convert the rule and return the native queries (for this window) WITHOUT contacting the SIEM. What is returned is what `run` sends:
        {'language', 'queries': {name: text}, 'detection': text, 'scope': {...}, 'notes': [...]}.
        Raise IntegrationError('conversion' | 'unsupported_logsource' | 'unsafe_query' | 'scope') when it cannot."""

    @abstractmethod
    def run(self, rule_text: str, config: dict, secret: dict, scope: dict, window: tuple, *, mode: str,
            cancel: "Callable[[], None] | None" = None, handle: "dict | None" = None) -> dict:
        """Execute the bounded, read-only preflight and return the shared environment result
        ({'status': 'potential_matches_found' | 'no_matches_in_window' | 'telemetry_missing_or_unsupported', ...})."""

    def cancel(self, handle: dict) -> None:
        """Stop an in-progress run. `handle` is the dict passed to `run`; adapters keep what they need in it."""
        raise NotImplementedError


def apply_defaults(spec: ProviderSpec, config: dict) -> dict:
    out = dict(config)
    for f in spec.fields:
        if f.name not in out or out[f.name] in (None, ""):
            if f.default is not None:
                out[f.name] = f.default
    return out
