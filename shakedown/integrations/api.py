"""HTTP API for the Integrations workspace, with the protections a LOCAL API that holds SIEM access needs.

This API can run searches in a person's SIEM with credentials the person saved. A web page open in the same browser must not be able to
drive it, so every route except `status` and `session` requires:

* a `Host` header that names this server (defeats DNS rebinding: a hostile domain pointed at 127.0.0.1 sends its own Host),
* `Sec-Fetch-Site` of `same-origin` or `none` when the browser sends it (defeats cross-site requests),
* for anything that changes state, an `Origin` header that is this server,
* a secret request header obtained from `GET /session`, which a cross-origin page cannot read.

Responses are `no-store`. Request bodies are never logged. No route returns a credential.
"""
import hmac
import json
import re
import secrets as token_source
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

from shakedown.integrations import vault
from shakedown.integrations.base import IntegrationError
from shakedown.integrations.registry import Registry, default_registry
from shakedown.integrations.service import IntegrationService

HTTP_STATUS = {"config": 422, "scope": 422, "destination": 422, "unsafe_query": 422, "unsupported_logsource": 422, "conversion": 422, "query": 422,
               "not_found": 404, "conflict": 409, "disabled": 403, "forbidden": 403, "privileged_account": 403, "permission": 403, "auth": 401,
               "rate_limited": 429, "unreachable": 502, "tls": 502, "redirect": 502, "too_large": 502, "unavailable": 502, "timeout": 504,
               "cancelled": 409, "secret_store": 500, "forbidden_endpoint": 403}
HOSTED_REASON = ("Connecting a SIEM is turned off on this server. It needs a self-hosted Shakedown running on your own machine: this server has no user accounts, "
                 "no tenant isolation and no secret vault, so it must not accept SIEM credentials.")
CSRF_HEADER = "x-shakedown-csrf"


@dataclass
class IntegrationsConfig:
    enabled: bool = False
    reason: str = HOSTED_REASON
    data_dir: Path | None = None
    secret_store: str = "auto"          # auto | memory | keyring
    mode: str = "local"
    allowed_hosts: set = field(default_factory=set)
    registry: Registry | None = None
    environ: dict | None = None
    validator: object | None = None

    @classmethod
    def disabled(cls, reason: str = HOSTED_REASON) -> "IntegrationsConfig":
        return cls(enabled=False, reason=reason)


class ServerRules:
    """Rules available to preflight: the best rule of each recorded run and of each finished live run on this server."""

    def __init__(self, recorded_files, runs: dict):
        self._recorded, self._runs = recorded_files, runs

    @staticmethod
    def _best(rec: dict) -> dict | None:
        try:
            return rec["iterations"][rec["best_index"]]
        except (KeyError, IndexError, TypeError):
            return None

    @staticmethod
    def _title(text: str) -> str:
        try:
            return str((yaml.safe_load(text) or {}).get("title", ""))
        except yaml.YAMLError:
            return ""

    def _records(self):
        for slug, path in self._recorded().items():
            try:
                yield f"recorded:{slug}", "recorded run", json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
        for run_id, state in list(self._runs.items()):
            if state.get("status") == "done" and state.get("record"):
                yield f"live:{run_id}", "live run (this server)", state["record"]

    def list(self) -> list:
        out = []
        for ref, kind, rec in self._records():
            best = self._best(rec)
            if best:
                out.append({"ref": ref, "scenario": rec["scenario"]["title"], "source": kind, "success": bool(rec.get("success")), "attempts": len(rec["iterations"]),
                            "rule_title": self._title(best["rule_text"]), "rule_valid": bool(best["validation"]["ok"]), "recorded_at": rec.get("created_at")})
        return out

    def get(self, ref: str) -> dict | None:
        for r, kind, rec in self._records():
            if r == ref:
                best = self._best(rec)
                if best:
                    return {"text": best["rule_text"], "label": f"{kind}: {rec['scenario']['title']}", "record": rec}
        return None


def _bounded(v):
    if len(json.dumps(v, default=str)) > 20000:
        raise ValueError("too large")
    return v


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ConnectionTestIn(Model):
    provider: str = Field(max_length=40)
    auth: str = Field(max_length=20)
    config: dict = Field(default_factory=dict)
    secret: dict = Field(default_factory=dict)
    _b = field_validator("config", "secret")(_bounded)


class OAuthStartIn(Model):
    provider: str = Field(max_length=40)
    auth: str = Field(default="interactive", max_length=20)
    config: dict = Field(default_factory=dict)
    connection_id: str | None = Field(default=None, max_length=64)
    _b = field_validator("config")(_bounded)


class SaveIn(Model):
    test_id: str = Field(max_length=64)
    label: str = Field(max_length=200)
    scope: dict = Field(default_factory=dict)
    _b = field_validator("scope")(_bounded)


class UpdateIn(Model):
    label: str | None = Field(default=None, max_length=200)
    scope: dict | None = None
    _b = field_validator("scope")(lambda v: _bounded(v) if v is not None else v)


class ReconfIn(Model):
    auth: str = Field(max_length=20)
    config: dict = Field(default_factory=dict)
    secret: dict = Field(default_factory=dict)
    _b = field_validator("config", "secret")(_bounded)


class PlanIn(Model):
    rule: dict
    indexes: list[str] = Field(default_factory=list, max_length=20)
    window: dict = Field(default_factory=dict)
    _b = field_validator("rule", "window")(_bounded)


class RunIn(Model):
    plan_id: str = Field(max_length=64)
    confirm: StrictBool = False


def mount_integrations(app: FastAPI, cfg: IntegrationsConfig, rules: ServerRules) -> IntegrationService:
    token = token_source.token_urlsafe(32)
    hosts = {h.lower() for h in cfg.allowed_hosts}
    origins = {f"{scheme}://{h}" for h in hosts for scheme in ("http", "https")}
    service = IntegrationService(data_dir=cfg.data_dir or Path("data/integrations"), registry=cfg.registry or default_registry(),
                                 secret_store=vault.choose_store(cfg.secret_store) if cfg.enabled else vault.MemorySecretStore(), rules=rules, mode=cfg.mode,
                                 enabled=cfg.enabled, disabled_reason=cfg.reason, environ=cfg.environ,
                                 **({"validator": cfg.validator} if cfg.validator else {}))
    router_prefix = "/api/integrations"

    def common(request: Request) -> None:
        host = (request.headers.get("host") or "").lower()
        if host not in hosts:
            raise HTTPException(403, "This request names a host this server does not serve. If you opened the page by another address, use http://127.0.0.1 or http://localhost.")
        site = request.headers.get("sec-fetch-site")
        if site is not None and site not in ("same-origin", "none"):
            raise HTTPException(403, "Cross-site requests to the integrations API are refused.")

    def read_guard(request: Request) -> None:
        common(request)
        if not hmac.compare_digest(request.headers.get(CSRF_HEADER, "").encode("utf-8", "replace"), token.encode("utf-8")):
            raise HTTPException(403, "Missing or invalid session token. Reload the page.")

    def write_guard(request: Request) -> None:
        read_guard(request)
        if (request.headers.get("origin") or "").lower() not in origins:
            raise HTTPException(403, "State-changing requests must come from this server's own pages.")

    @app.exception_handler(IntegrationError)
    async def _handle(request: Request, exc: IntegrationError):
        return JSONResponse({"detail": str(exc), "kind": exc.kind}, status_code=HTTP_STATUS.get(exc.kind, 400), headers={"Cache-Control": "no-store"})

    r = APIRouter(prefix=router_prefix)

    @r.get("/status")
    def status():
        return JSONResponse(service.status(), headers={"Cache-Control": "no-store"})

    @r.get("/session", dependencies=[Depends(common)])
    def session():
        return JSONResponse({"csrf": token, "header": CSRF_HEADER}, headers={"Cache-Control": "no-store"})

    def ok(payload, status_code: int = 200):
        return JSONResponse(payload, status_code=status_code, headers={"Cache-Control": "no-store"})

    @r.get("/connections", dependencies=[Depends(read_guard)])
    def list_connections():
        return ok({"connections": service.list_connections()})

    @r.post("/connections/test", dependencies=[Depends(write_guard)])
    def test_new(body: ConnectionTestIn):
        return ok(service.test_new(body.provider, body.auth, body.config, {"mode": body.secret.get("mode", "paste"), "values": body.secret.get("values") or {},
                                                                            "env": body.secret.get("env") or {}}))

    def callback_uri(request: Request) -> str:
        return f"{request.url.scheme}://{request.headers['host']}{router_prefix}/oauth/callback"

    @r.post("/oauth/start", dependencies=[Depends(write_guard)])
    def oauth_start(request: Request, body: OAuthStartIn):
        return ok(service.oauth_start(body.provider, body.auth, body.config, callback_uri(request), body.connection_id))

    @r.get("/oauth/flows/{flow_id}", dependencies=[Depends(read_guard)])
    def oauth_flow(flow_id: str):
        return ok(service.oauth_status(flow_id))

    @r.post("/oauth/callback")
    async def oauth_callback(request: Request):
        """The identity provider's browser redirect (response_mode=form_post), so it is a cross-site POST by design: only the Host is checked here.
        It is trusted through `state` alone, which is unguessable, single-use and bound to one waiting flow. The page it returns echoes nothing."""
        if (request.headers.get("host") or "").lower() not in hosts:
            raise HTTPException(403, "This request names a host this server does not serve.")
        raw = b"" if int(request.headers.get("content-length") or 0) > 16_384 else await request.body()
        done, form = False, {}
        if 0 < len(raw) <= 16_384:
            form = {k: v[0] for k, v in urllib.parse.parse_qs(raw.decode("utf-8", "replace"), max_num_fields=20).items()}
            done = service.oauth_callback(form.get("state", ""), form.get("code", ""), form.get("error", ""), form.get("error_description", ""), callback_uri(request))
        text = ("Sign-in finished. Return to the Shakedown tab to continue." if done else
                "This sign-in could not be completed. Return to the Shakedown tab to see why, or start it again.")
        return HTMLResponse(f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Shakedown sign-in</title>"
                            f"<body style='font:16px system-ui;margin:3rem auto;max-width:32rem;padding:0 1rem'><p>{text}</p>",
                            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})

    @r.post("/connections", dependencies=[Depends(write_guard)])
    def save(body: SaveIn):
        return ok(service.save(body.test_id, body.label, body.scope), 201)

    @r.get("/connections/{conn_id}", dependencies=[Depends(read_guard)])
    def get_connection(conn_id: str):
        return ok(service.get_connection(conn_id))

    @r.patch("/connections/{conn_id}", dependencies=[Depends(write_guard)])
    def update(conn_id: str, body: UpdateIn):
        return ok(service.update(conn_id, body.label, body.scope))

    @r.delete("/connections/{conn_id}", dependencies=[Depends(write_guard)])
    def disconnect(conn_id: str, delete_assessments: bool = False):
        return ok(service.disconnect(conn_id, delete_assessments))

    @r.post("/connections/{conn_id}/test", dependencies=[Depends(write_guard)])
    def retest(conn_id: str):
        return ok(service.retest(conn_id))

    @r.post("/connections/{conn_id}/reconfigure", dependencies=[Depends(write_guard)])
    def reconfigure(conn_id: str, body: ReconfIn):
        return ok(service.reconfigure(conn_id, body.auth, body.config, {"mode": body.secret.get("mode", "paste"), "values": body.secret.get("values") or {},
                                                                         "env": body.secret.get("env") or {}}))

    @r.get("/connections/{conn_id}/scopes", dependencies=[Depends(read_guard)])
    def scopes(conn_id: str):
        return ok(service.discover(conn_id))

    @r.get("/rules", dependencies=[Depends(read_guard)])
    def rule_list():
        return ok({"rules": service.rule_candidates()})

    @r.post("/connections/{conn_id}/plan", dependencies=[Depends(write_guard)])
    def plan(conn_id: str, body: PlanIn):
        return ok(service.plan(conn_id, body.rule, body.indexes, body.window))

    @r.post("/connections/{conn_id}/preflight", dependencies=[Depends(write_guard)])
    def preflight(conn_id: str, body: RunIn):
        return ok(service.start_preflight(conn_id, body.plan_id, body.confirm), 202)

    @r.get("/assessments", dependencies=[Depends(read_guard)])
    def assessments(connection_id: str | None = None):
        return ok({"assessments": service.list_assessments(connection_id)})

    @r.get("/assessments/{assessment_id}", dependencies=[Depends(read_guard)])
    def assessment(assessment_id: str):
        return ok(service.get_assessment(assessment_id))

    @r.post("/assessments/{assessment_id}/cancel", dependencies=[Depends(write_guard)])
    def cancel(assessment_id: str):
        return ok(service.cancel(assessment_id))

    @r.get("/assessments/{assessment_id}/export", dependencies=[Depends(read_guard)])
    def export(assessment_id: str):
        return ok(service.export(assessment_id))

    app.include_router(r)
    return service
