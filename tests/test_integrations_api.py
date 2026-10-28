"""The Integrations HTTP API: the local-only guard, request validation, the whole flow over HTTP, and that no response or log holds a credential.
Mock Splunk (tests/fake_splunk.py): a test of the API, not evidence about a real SIEM."""
import json
import logging
import time

import pytest
from fake_splunk import TOKEN, FakeSplunk
from fastapi.testclient import TestClient

from shakedown import splunk
from shakedown.integrations.api import CSRF_HEADER, IntegrationsConfig
from shakedown.server import create_app
from shakedown.validate import Validation

RULE = """title: API test rule
id: 11111111-2222-4333-8444-555555555555
status: test
description: d
author: a
date: 2026-10-27
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\x.exe'
    condition: selection
falsepositives:
    - none
level: low
"""
RECORD = {"scenario": {"id": "s1", "title": "Recorded scenario", "category": "process_creation"}, "success": True, "model": "m", "research": None, "created_at": "2026-10-27T10:00:00+00:00",
          "iterations": [{"action": "generate", "rule_text": RULE, "validation": {"ok": True, "errors": []}, "evaluation": None}], "best_index": 0,
          "totals": {"tokens": 1, "seconds": 1.0}, "events": [], "heldout": None}
SCENARIOS = [{"id": "s1", "title": "Recorded scenario", "category": "process_creation", "reference_urls": []}]


def handler(spl, e, l):
    if "fieldsummary" in spl:
        return {"count": 1, "results": [{"field": "Image"}]}
    if "min(_time)" in spl:
        return {"count": 1, "results": [{"count": "50", "first": "1", "last": "2"}]}
    if "| table" in spl:
        return {"count": 1, "results": [{"_time": "t", "Image": "C:\\x.exe"}]}
    return {"count": 1, "results": [{"count": "2"}]}


@pytest.fixture(autouse=True)
def conversion(monkeypatch):
    monkeypatch.setattr(splunk, "convert_to_spl", lambda text: 'Image="*\\\\x.exe"')


def make_app(tmp_path, enabled=True, **kw):
    rec = tmp_path / "recorded"
    rec.mkdir(exist_ok=True)
    (rec / "recorded-one.json").write_text(json.dumps(RECORD), encoding="utf-8")
    cfg = IntegrationsConfig(enabled=True, reason="", data_dir=tmp_path / "data", secret_store="memory", allowed_hosts={"testserver"}, environ={},
                             validator=lambda text: Validation(True, [], "ok")) if enabled else IntegrationsConfig(enabled=False, allowed_hosts={"testserver"})
    return create_app(tmp_path, SCENARIOS, recorded_dir=rec, integrations=cfg, **kw)


class Client:
    """A browser-like client: it fetches the session token and sends the headers a same-origin page sends."""

    def __init__(self, app):
        self.c = TestClient(app)
        self.seen = []
        self.token = self.c.get("/api/integrations/session").json()["csrf"]

    def req(self, method, path, body=None, origin="http://testserver", token=True, headers=None):
        h = {"Origin": origin} if origin else {}
        if token:
            h[CSRF_HEADER] = self.token
        h.update(headers or {})
        r = self.c.request(method, "/api/integrations" + path, json=body, headers=h)
        self.seen.append(r.text)
        return r


def connect(cl, fake):
    t = cl.req("POST", "/connections/test", {"provider": "splunk_enterprise", "auth": "token", "config": {"endpoint": fake.url, "verify_tls": True},
                                             "secret": {"mode": "paste", "values": {"token": TOKEN}}})
    assert t.status_code == 200 and t.json()["test_id"], t.text
    s = cl.req("POST", "/connections", {"test_id": t.json()["test_id"], "label": "lab", "scope": {"indexes": ["win"]}})
    assert s.status_code == 201, s.text
    return s.json()


# --- availability ------------------------------------------------------------------------------------------------
def test_without_the_flag_a_server_says_why_integrations_are_off_and_refuses_to_act(tmp_path):
    cl = Client(make_app(tmp_path, enabled=False))
    st = cl.c.get("/api/integrations/status").json()
    assert st["enabled"] is False and "self-hosted" in st["disabled_reason"] and "vault" in st["disabled_reason"]
    r = cl.req("POST", "/connections/test", {"provider": "splunk_enterprise", "auth": "token", "config": {"endpoint": "https://x:8089"}, "secret": {"mode": "paste", "values": {"token": "abcdefgh"}}})
    assert r.status_code == 403 and r.json()["kind"] == "disabled"
    assert cl.req("GET", "/connections").status_code == 403


def test_the_server_default_is_disabled_so_a_hosted_deployment_never_accepts_credentials(tmp_path):
    rec = tmp_path / "recorded"
    rec.mkdir()
    app = create_app(tmp_path, SCENARIOS, recorded_dir=rec)  # no integrations argument: how the hosted image runs
    client = TestClient(app)
    assert client.get("/api/integrations/status").json()["enabled"] is False
    assert client.get("/api/integrations/session").status_code == 403  # no allowed host is configured, so there is no way to obtain a token at all


# --- the local-only guard ------------------------------------------------------------------------------------------
def test_requests_without_the_session_token_are_refused(tmp_path):
    cl = Client(make_app(tmp_path))
    assert cl.req("GET", "/connections", token=False).status_code == 403
    assert cl.req("GET", "/connections", headers={CSRF_HEADER: "guess"}).status_code == 403
    assert cl.req("GET", "/connections").status_code == 200


def test_a_request_that_names_another_host_is_refused_even_with_a_valid_token(tmp_path):
    cl = Client(make_app(tmp_path))  # DNS rebinding: the browser sends the attacker's host name
    for path in ("/connections", "/session", "/rules"):
        r = cl.req("GET", path, headers={"Host": "attacker.example:8000"})
        assert r.status_code == 403, path
    assert cl.c.get("/api/integrations/session", headers={"Host": "attacker.example"}).status_code == 403


def test_cross_site_requests_are_refused(tmp_path):
    cl = Client(make_app(tmp_path))
    assert cl.req("GET", "/connections", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert cl.req("GET", "/connections", headers={"Sec-Fetch-Site": "same-site"}).status_code == 403
    assert cl.req("GET", "/connections", headers={"Sec-Fetch-Site": "same-origin"}).status_code == 200
    assert cl.c.get("/api/integrations/session", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403


@pytest.mark.parametrize("origin", [None, "", "http://attacker.example", "http://testserver.attacker.example", "null", "https://evil.test"])
def test_state_changing_requests_need_this_servers_own_origin(tmp_path, origin):
    cl = Client(make_app(tmp_path))
    body = {"provider": "splunk_enterprise", "auth": "token", "config": {"endpoint": "https://x:8089"}, "secret": {"mode": "paste", "values": {"token": "abcdefgh"}}}
    assert cl.req("POST", "/connections/test", body, origin=origin).status_code == 403
    assert cl.req("DELETE", "/connections/abc", origin=origin).status_code == 403


def test_no_route_offers_cors_and_everything_is_not_cached(tmp_path):
    cl = Client(make_app(tmp_path))
    for method, path in (("GET", "/status"), ("GET", "/session"), ("GET", "/connections"), ("GET", "/rules"), ("GET", "/assessments")):
        r = cl.req(method, path)
        assert "access-control-allow-origin" not in {k.lower() for k in r.headers} and r.headers["cache-control"] == "no-store", path
    pre = cl.c.options("/api/integrations/connections", headers={"Origin": "http://attacker.example", "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in {k.lower() for k in pre.headers}


def test_pages_carry_security_headers_that_restrict_scripts_and_framing(tmp_path):
    cl = Client(make_app(tmp_path))
    r = cl.c.get("/")
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp and "object-src 'none'" in csp and "connect-src 'self'" in csp
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY" and r.headers["referrer-policy"] == "no-referrer"
    assert "content-security-policy" in cl.c.get("/api/integrations/status").headers


# --- request validation ------------------------------------------------------------------------------------------
def test_unknown_fields_wrong_types_and_oversized_bodies_are_refused(tmp_path):
    cl = Client(make_app(tmp_path))
    good = {"provider": "splunk_enterprise", "auth": "token", "config": {}, "secret": {"mode": "paste", "values": {"token": "abcdefgh"}}}
    assert cl.req("POST", "/connections/test", {**good, "extra": 1}).status_code == 422
    assert cl.req("POST", "/connections/test", {**good, "config": {"endpoint": "x" * 30000}}).status_code == 422
    assert cl.req("POST", "/connections/test", {**good, "provider": "x" * 80}).status_code == 422
    assert cl.req("POST", "/connections/test", {**good, "provider": "nope"}).status_code == 404
    assert cl.req("POST", "/connections/test", {**good, "provider": "qradar"}).status_code in (404, 422, 502)
    assert cl.req("POST", "/connections/abc/preflight", {"plan_id": "p", "confirm": "yes"}).status_code == 422  # strict boolean: "yes" is not a confirmation


def test_error_kinds_map_to_http_statuses_and_carry_a_kind(tmp_path):
    cl = Client(make_app(tmp_path))
    r = cl.req("GET", "/connections/doesnotexist")
    assert r.status_code == 404 and r.json()["kind"] == "not_found"
    r = cl.req("POST", "/connections/test", {"provider": "splunk_enterprise", "auth": "token", "config": {"endpoint": "ftp://x"}, "secret": {"mode": "paste", "values": {"token": "abcdefgh"}}})
    assert r.status_code == 422 and r.json()["kind"] == "config"


# --- the whole flow ----------------------------------------------------------------------------------------------
def wait(cl, aid):
    for _ in range(100):
        rec = cl.req("GET", f"/assessments/{aid}").json()
        if rec["status"] != "running":
            return rec
        time.sleep(0.1)
    raise AssertionError("assessment did not finish")


def test_connect_preview_run_export_and_disconnect_over_http_with_no_credential_in_any_response_or_log(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    cl = Client(make_app(tmp_path))
    with FakeSplunk(handler) as fake:
        conn = connect(cl, fake)
        assert conn["state"] == "connected" and "endpoint" in conn and TOKEN not in json.dumps(conn)
        assert [c["id"] for c in cl.req("GET", "/connections").json()["connections"]] == [conn["id"]]
        scopes = cl.req("GET", f"/connections/{conn['id']}/scopes").json()
        assert [i["name"] for i in scopes["items"]] == ["other", "win"]
        rules = cl.req("GET", "/rules").json()["rules"]
        assert rules[0]["ref"] == "recorded:recorded-one" and rules[0]["rule_valid"] is True
        plan = cl.req("POST", f"/connections/{conn['id']}/plan", {"rule": {"ref": rules[0]["ref"]}, "indexes": ["win"], "window": {"last_hours": 6}}).json()
        assert plan["runnable"] and 'index="win"' in plan["queries"]["detection"]
        started = cl.req("POST", f"/connections/{conn['id']}/preflight", {"plan_id": plan["plan_id"], "confirm": True})
        assert started.status_code == 202
        rec = wait(cl, started.json()["assessment_id"])
        assert rec["status"] == "potential_matches_found" and rec["assessment"]["statuses"]["environment_preflight"]["matches"]["count"] == 2
        assert [s["id"] for s in cl.req("GET", "/assessments").json()["assessments"]] == [rec["id"]]
        files = cl.req("GET", f"/assessments/{rec['id']}/export").json()["files"]
        assert "review_packet.md" in files and 'index="win"' in files["query.spl"]
        gone = cl.req("DELETE", f"/connections/{conn['id']}?delete_assessments=true").json()
        assert gone["secret_deleted"] and cl.req("GET", f"/connections/{conn['id']}").status_code == 404
        assert cl.req("GET", f"/assessments/{rec['id']}").status_code == 404
    assert all(TOKEN not in text for text in cl.seen), "a credential appeared in a response"
    assert TOKEN not in caplog.text, "a credential appeared in a log line"
    disk = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "data").rglob("*.json"))
    assert TOKEN not in disk


def test_the_index_page_loads_and_still_serves_the_ui(tmp_path):
    cl = Client(make_app(tmp_path))
    assert cl.c.get("/").status_code == 200 and cl.c.get("/api/health").status_code == 200 and cl.c.get("/api/recorded").status_code == 200
