"""The Microsoft Sentinel / Azure Monitor Logs adapter and its use through the service and API.

ALL MICROSOFT ENDPOINTS HERE ARE MOCKS (tests/fake_microsoft.py). The conversion tests use the real pySigma Kusto backend, but nothing here is evidence about a real
Azure tenant, Entra sign-in or Log Analytics workspace: the connector has never been run against one.
"""
import json
import urllib.parse
from datetime import datetime, timedelta, timezone

import pytest
from fake_microsoft import CLIENT_ID, CLIENT_SECRET, GOOD_CODE, OTHER_WORKSPACE, TENANT, WORKSPACE, FakeMicrosoft
from fastapi.testclient import TestClient

from shakedown.integrations import vault
from shakedown.integrations.adapters import sentinel
from shakedown.integrations.adapters.sentinel import SentinelAdapter
from shakedown.integrations.api import CSRF_HEADER, IntegrationsConfig
from shakedown.integrations.base import NOT_LIVE_VERIFIED, IntegrationError
from shakedown.integrations.registry import Registry, default_registry
from shakedown.integrations.service import IntegrationService
from shakedown.server import create_app
from shakedown.validate import Validation

RULE = """title: Sentinel test rule
id: 11111111-2222-4333-8444-555555555557
status: test
description: d
author: a
date: 2026-10-27
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\AdFind.exe'
        CommandLine|contains: '-f'
    condition: selection
falsepositives:
    - admin
level: low
"""
CFG = {"tenant_id": TENANT, "client_id": CLIENT_ID}
SECRET = {"mode": "paste", "values": {"client_secret": CLIENT_SECRET}}
WINDOW = {"last_hours": 24}


class Rules:
    def list(self):
        return []

    def get(self, ref):
        return {"text": RULE, "label": "test rule", "record": None} if ref == "t" else None


def adapter(fake):
    return SentinelAdapter(authority=fake.url, api=fake.url, arm=fake.url, allow_http_loopback=True)


def service(tmp_path, fake, store=None):
    return IntegrationService(data_dir=tmp_path / "i", registry=Registry([adapter(fake)]), secret_store=store or vault.MemorySecretStore(), rules=Rules(),
                              validator=lambda text: Validation(True, [], "ok"))


def connect(svc, workspace=WORKSPACE, **cfg):
    t = svc.test_new("sentinel", "client_credentials", {**CFG, **cfg}, SECRET)
    assert t["test_id"], t["report"]
    return svc.save(t["test_id"], "law", {"indexes": [workspace]})


def run(svc, conn, hours=24):
    plan = svc.plan(conn["id"], {"ref": "t"}, [WORKSPACE], {"last_hours": hours})
    assert plan["runnable"], plan
    started = svc.start_preflight(conn["id"], plan["plan_id"], True)
    svc.join(started["assessment_id"], 30)
    return plan, svc.get_assessment(started["assessment_id"])


# --- the provider declares what it is -------------------------------------------------------------------------------------
def test_sentinel_is_registered_implemented_and_not_labelled_live_verified():
    spec = default_registry().spec("sentinel")
    assert spec.implemented and spec.status == NOT_LIVE_VERIFIED and spec.status_label == "Mock-tested, not live-verified" and "never against a real azure" in spec.verification_note.lower()
    assert spec.capabilities["oauth"] and not spec.capabilities["cancel"] and not spec.capabilities["revoke_on_disconnect"]
    assert [a for a, _ in spec.auth_methods] == ["interactive", "client_credentials"]
    assert [(a, f.name) for a, f in spec.secret_fields] == [("client_credentials", "client_secret")]  # a browser sign-in has no pasted credential


# --- conversion (the real pySigma Kusto backend) ----------------------------------------------------------------------------
def test_the_real_backend_maps_sigma_fields_to_securityevent_columns():
    table, rest, fields = sentinel.convert_to_kql(RULE)
    assert table == "SecurityEvent" and rest.startswith("| where NewProcessName endswith") and fields == ["CommandLine", "NewProcessName"]


def test_a_field_the_table_does_not_have_is_a_named_conversion_error_not_a_guess():
    with pytest.raises(IntegrationError) as exc:
        sentinel.convert_to_kql(RULE.replace("Image|endswith", "OriginalFileName|endswith"))
    assert exc.value.kind == "conversion" and "OriginalFileName" in str(exc.value) and len(str(exc.value)) < 500
    with pytest.raises(IntegrationError) as exc:
        sentinel.convert_to_kql("title: x\ndetection: [")
    assert exc.value.kind == "conversion"


def test_only_windows_security_process_creation_has_a_scope():
    a = SentinelAdapter()
    now = datetime.now(timezone.utc)
    with pytest.raises(IntegrationError) as exc:
        a.plan(RULE.replace("category: process_creation", "category: registry_set"), {"max_results": 5}, {"indexes": [WORKSPACE]}, (now - timedelta(hours=1), now))
    assert exc.value.kind == "unsupported_logsource"


def test_a_plan_needs_exactly_one_workspace_guid_and_an_explicit_window():
    a, now = SentinelAdapter(), datetime.now(timezone.utc)
    for bad in ([], [WORKSPACE, OTHER_WORKSPACE], ["not-a-guid"]):
        with pytest.raises(IntegrationError) as exc:
            a.plan(RULE, {"max_results": 5}, {"indexes": bad}, (now - timedelta(hours=1), now))
        assert exc.value.kind == "scope"
    with pytest.raises(IntegrationError):
        a.plan(RULE, {"max_results": 5}, {"indexes": [WORKSPACE]}, None)


def test_the_plan_carries_the_time_span_and_every_query_passes_the_read_only_check():
    a, now = SentinelAdapter(), datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)
    p = a.plan(RULE, {"max_results": 5}, {"indexes": [WORKSPACE]}, (now - timedelta(hours=24), now))
    assert p["scope"]["timespan"] == "2026-10-26T12:00:00Z/2026-10-27T12:00:00Z" and set(p["queries"]) == {"coverage", "fields", "detection", "sample"}
    assert p["queries"]["sample"].endswith("| take 5") and "EventID == 4688" in p["queries"]["detection"]
    for q in p["queries"].values():
        sentinel.check_read_only_kql(q)


# --- the read-only guard ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("kql", [
    ".drop table SecurityEvent", ".set-or-append T <| SecurityEvent", "SecurityEvent | join (Other) on Computer", "union SecurityEvent, Event",
    'workspace("other").SecurityEvent', 'SecurityEvent | where x == 1 | evaluate bag_unpack(y)', 'externaldata(a:string) ["https://x"]',
    "SecurityEvent | where x == 1; Event", "let t = SecurityEvent; t", 'SecurityEvent | invoke f()', "SecurityEvent | mv-expand x", "SecurityEvent | parse x with y",
    'cluster("x").database("y").T', "Heartbeat | extend a = http_request('https://x')", "print x=1 | take 1", "",
])
def test_the_kql_guard_refuses_anything_that_is_not_a_plain_read_of_one_table(kql):
    with pytest.raises(IntegrationError) as exc:
        sentinel.check_read_only_kql(kql)
    assert exc.value.kind == "unsafe_query"


def test_the_kql_guard_ignores_forbidden_words_inside_string_literals():
    sentinel.check_read_only_kql('SecurityEvent\n| where EventID == 4688\n| where CommandLine contains "union join .drop; evaluate workspace(x)"\n| summarize matches=count()')
    sentinel.check_read_only_kql("print ok=1")


# --- connection tests (mock Microsoft) --------------------------------------------------------------------------------------
def test_a_client_secret_connection_passes_and_does_not_claim_a_workspace_it_has_not_checked():
    with FakeMicrosoft() as ms:
        r = adapter(ms).test_connection(adapter(ms).validate_config(CFG, mode="local"), {"client_secret": CLIENT_SECRET}, mode="local")
    status = {c.id: c.status for c in r.checks}
    assert r.ok and status == {"network_tls": "pass", "authentication": "pass", "permissions": "skipped", "endpoint": "pass"}
    assert r.identity["authentication_type"] == "client_credentials" and CLIENT_SECRET not in json.dumps(r.public())


def test_a_workspace_in_the_config_is_proved_readable_with_a_real_query():
    with FakeMicrosoft() as ms:
        r = adapter(ms).test_connection({**CFG, "workspace_id": WORKSPACE}, {"client_secret": CLIENT_SECRET}, mode="local")
        assert {c.id: c.status for c in r.checks}["permissions"] == "pass" and ms.queries[-1]["query"] == "print ok=1" and ms.queries[-1]["workspace"] == WORKSPACE
        denied = adapter(ms).test_connection({**CFG, "workspace_id": OTHER_WORKSPACE}, {"client_secret": CLIENT_SECRET}, mode="local")
    perm = next(c for c in denied.checks if c.id == "permissions")
    assert not denied.ok and perm.status == "fail" and "Log Analytics Reader" in perm.detail


def test_a_wrong_client_secret_fails_authentication_after_the_network_check_passed_and_is_never_echoed():
    with FakeMicrosoft() as ms:
        r = adapter(ms).test_connection(CFG, {"client_secret": "a-wrong-secret-value-12345"}, mode="local")
    status = {c.id: c.status for c in r.checks}
    detail = next(c for c in r.checks if c.id == "authentication").detail
    assert not r.ok and status["network_tls"] == "pass" and status["authentication"] == "fail"
    assert "client secret is wrong or expired" in detail and "a-wrong-secret-value-12345" not in json.dumps(r.public()) and "Trace ID" not in detail


def test_an_unreachable_authority_fails_at_the_network_check():
    with FakeMicrosoft() as ms:
        pass  # stopped and closed again: nothing listens on its port any more
    r = adapter(ms).test_connection(CFG, {"client_secret": CLIENT_SECRET}, mode="local")
    assert not r.ok and r.checks[0].id == "network_tls" and r.checks[0].status == "fail"


def test_a_consent_problem_is_reported_as_a_permission_problem():
    with FakeMicrosoft(token_error="consent_required") as ms:
        r = adapter(ms).test_connection(CFG, {"client_secret": CLIENT_SECRET}, mode="local")
    assert not r.ok and "consent" in next(c for c in r.checks if c.id == "authentication").detail


def test_tenant_and_ids_are_validated_before_anything_is_sent():
    a = SentinelAdapter(authority="http://127.0.0.1:1", api="http://127.0.0.1:1", arm="http://127.0.0.1:1", allow_http_loopback=True)  # loopback: no DNS lookup in a unit test
    for bad in ({"tenant_id": "../x", "client_id": CLIENT_ID}, {"tenant_id": TENANT, "client_id": "nope"}, {"tenant_id": TENANT, "client_id": CLIENT_ID, "workspace_id": "x"}):
        with pytest.raises(IntegrationError) as exc:
            a.validate_config(bad, mode="local")
        assert exc.value.kind == "config"
    assert a.validate_config({"tenant_id": "contoso.onmicrosoft.com", "client_id": CLIENT_ID}, mode="local")["tenant_id"] == "contoso.onmicrosoft.com"


def test_the_endpoints_are_fixed_and_a_hosted_server_would_refuse_loopback_ones():
    with pytest.raises(IntegrationError):
        SentinelAdapter(authority="http://127.0.0.1:1", api="http://127.0.0.1:1", arm="http://127.0.0.1:1", allow_http_loopback=True).validate_config(CFG, mode="hosted")
    assert "endpoint" not in SentinelAdapter().spec.public()["fields"] and all(f["name"] != "endpoint" for f in SentinelAdapter().spec.public()["fields"])


# --- workspace discovery -----------------------------------------------------------------------------------------------------
def test_workspaces_are_listed_only_when_asked_and_otherwise_entered_by_hand():
    with FakeMicrosoft() as ms:
        a = adapter(ms)
        manual = a.discover_scopes(a.validate_config(CFG, mode="local"), {"client_secret": CLIENT_SECRET}, mode="local")
        assert manual["discovery"] == "manual" and not ms.arm_requests
        listed = a.discover_scopes(a.validate_config({**CFG, "list_workspaces": True}, mode="local"), {"client_secret": CLIENT_SECRET}, mode="local")
        denied = FakeMicrosoft(subscriptions_status=403)
    assert listed["discovery"] == "available" and listed["items"][0]["name"] == WORKSPACE and "rg-soc" in listed["items"][0]["label"]
    with denied as ms2:
        a2 = adapter(ms2)
        out = a2.discover_scopes(a2.validate_config({**CFG, "list_workspaces": True}, mode="local"), {"client_secret": CLIENT_SECRET}, mode="local")
    assert out["discovery"] == "manual" and "could not be listed" in out["note"]


# --- through the service -----------------------------------------------------------------------------------------------------
def test_a_saved_workspace_must_be_readable_with_the_credential_that_passed_the_test(tmp_path):
    with FakeMicrosoft() as ms:
        svc = service(tmp_path, ms)
        t = svc.test_new("sentinel", "client_credentials", CFG, SECRET)
        with pytest.raises(IntegrationError) as exc:
            svc.save(t["test_id"], "law", {"indexes": [OTHER_WORKSPACE]})
        assert exc.value.kind == "permission" and svc.list_connections() == []
        conn = svc.save(t["test_id"], "law", {"indexes": [WORKSPACE]})
    assert conn["state"] == "connected" and conn["provider"] == "sentinel" and conn["credential"]["mode"] == "store"


def test_preflight_runs_the_previewed_queries_and_reports_the_matches(tmp_path):
    with FakeMicrosoft(events=100, matches=3) as ms:
        svc = service(tmp_path, ms)
        conn = connect(svc)
        ms.queries.clear()
        plan, rec = run(svc, conn)
        st = rec["assessment"]["statuses"]["environment_preflight"]
        sent = {q["query"] for q in ms.queries}
        spans = {q["timespan"] for q in ms.queries}
    assert rec["status"] == "potential_matches_found" and st["coverage"]["events_in_scope"] == 100 and st["matches"]["count"] == 3 and st["fields"]["missing"] == []
    assert sent == set(plan["queries"].values()) and spans == {plan["query_scope"]["timespan"]} and st["queries"] == plan["queries"]
    assert len(st["matches"]["examples"]) == 3 and all(len(e["CommandLine"]) <= 303 for e in st["matches"]["examples"])
    assert rec["assessment"]["statuses"]["attack_validation"]["state"] == "not_run" and st["connector_label"] == "mock-tested, not live-verified"
    blob = json.dumps([rec, svc.export(rec["id"])])
    assert CLIENT_SECRET not in blob and "-mock-access-token" not in blob


def test_no_events_is_missing_telemetry_not_a_clean_result(tmp_path):
    with FakeMicrosoft(events=0) as ms:
        svc = service(tmp_path, ms)
        _, rec = run(svc, connect(svc))
    assert rec["status"] == "telemetry_missing_or_unsupported" and "missing telemetry or access" in rec["assessment"]["statuses"]["environment_preflight"]["detail"]


def test_empty_columns_are_reported_as_missing_fields_before_any_detection_query(tmp_path):
    with FakeMicrosoft(present={"NewProcessName"}) as ms:
        svc = service(tmp_path, ms)
        conn = connect(svc)
        ms.queries.clear()
        _, rec = run(svc, conn)
        detection_sent = any("matches=count()" in q["query"] for q in ms.queries)
    st = rec["assessment"]["statuses"]["environment_preflight"]
    assert rec["status"] == "telemetry_missing_or_unsupported" and st["fields"]["missing"] == ["CommandLine"] and not detection_sent


def test_a_throttled_or_failing_logs_api_is_a_named_failure_with_no_payload(tmp_path):
    with FakeMicrosoft() as ms:
        svc = service(tmp_path, ms)
        conn = connect(svc)
        ms.query_status = 429
        _, rec = run(svc, conn)
    err = rec["assessment"]["statuses"]["environment_preflight"]["error"]
    assert rec["status"] == "query_failed" and err["kind"] == "rate_limited" and "throttling" in err["message"]


def test_a_rule_with_a_field_the_table_lacks_cannot_be_planned(tmp_path):
    with FakeMicrosoft() as ms:
        svc = service(tmp_path, ms)
        conn = connect(svc)
        svc.rules = type("R", (), {"list": lambda s: [], "get": lambda s, r: {"text": RULE.replace("Image|endswith", "OriginalFileName|endswith"), "label": "x", "record": None}})()
        plan = svc.plan(conn["id"], {"ref": "t"}, [WORKSPACE], WINDOW)
    assert plan["runnable"] is False and plan["reason_kind"] == "conversion" and "OriginalFileName" in plan["reason"]


def test_sentinel_cannot_be_cancelled_and_says_why(tmp_path):
    with FakeMicrosoft() as ms:
        svc = service(tmp_path, ms)
        _, rec = run(svc, connect(svc))
        with pytest.raises(IntegrationError) as exc:
            svc.cancel(rec["id"])
    assert exc.value.kind == "conflict" and "cannot be cancelled" in str(exc.value)


def test_pasting_a_credential_into_the_interactive_method_is_refused(tmp_path):
    with FakeMicrosoft() as ms:
        svc = service(tmp_path, ms)
        with pytest.raises(IntegrationError) as exc:
            svc.test_new("sentinel", "interactive", CFG, {"mode": "paste", "values": {"client_secret": "x" * 20}})
    assert exc.value.kind == "config" and "sign-in" in str(exc.value)


# --- browser sign-in: authorization code + PKCE -------------------------------------------------------------------------------
REDIRECT = "http://127.0.0.1:8000/api/integrations/oauth/callback"


def begin(svc, ms, conn_id=None):
    flow = svc.oauth_start("sentinel", "interactive", CFG, REDIRECT, conn_id)
    q = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(flow["authorize_url"]).query).items()}
    ms.challenge = q["code_challenge"]  # what Microsoft would remember from the authorize request
    return flow, q


def test_the_authorize_url_is_a_pkce_public_client_request_with_no_secret_in_it(tmp_path):
    with FakeMicrosoft() as ms:
        flow, q = begin(service(tmp_path, ms), ms)
    parts = urllib.parse.urlsplit(flow["authorize_url"])
    assert parts.path == f"/{TENANT}/oauth2/v2.0/authorize"
    assert q["response_type"] == "code" and q["response_mode"] == "form_post" and q["code_challenge_method"] == "S256" and q["redirect_uri"] == REDIRECT and q["client_id"] == CLIENT_ID
    assert "Data.Read" in q["scope"] and "offline_access" in q["scope"] and "user_impersonation" not in q["scope"] and len(q["state"]) >= 40 and len(q["code_challenge"]) == 43
    assert "client_secret" not in flow["authorize_url"] and "code_verifier" not in flow["authorize_url"]


def test_listing_workspaces_adds_the_management_permission_to_the_request(tmp_path):
    with FakeMicrosoft() as ms:
        svc = service(tmp_path, ms)
        flow = svc.oauth_start("sentinel", "interactive", {**CFG, "list_workspaces": True}, REDIRECT)
    assert "user_impersonation" in flow["authorize_url"]


def test_a_completed_sign_in_becomes_a_tested_connection_that_keeps_only_a_refresh_token(tmp_path):
    with FakeMicrosoft() as ms:
        store = vault.MemorySecretStore()
        svc = service(tmp_path, ms, store)
        flow, q = begin(svc, ms)
        assert svc.oauth_status(flow["flow_id"])["status"] == "waiting"
        assert svc.oauth_callback(q["state"], GOOD_CODE, "", "", REDIRECT) is True
        done = svc.oauth_status(flow["flow_id"])
        exchange = next(r for r in ms.token_requests if r["grant_type"] == "authorization_code")
        verifier = exchange["code_verifier"]
        conn = svc.save(done["result"]["test_id"], "law (signed in)", {"indexes": [WORKSPACE]})
        stored = store.get("local", conn["id"])
    assert done["status"] == "done" and done["result"]["report"]["ok"] and "analyst@contoso.example" in json.dumps(done["result"]["report"])
    assert set(stored) == {"refresh_token", "_claims"} and stored["refresh_token"] in ms.refresh_tokens and "client_secret" not in exchange
    assert verifier not in json.dumps([done, conn]) and "RT-" not in json.dumps([done, conn]) and conn["state"] == "connected"
    with pytest.raises(IntegrationError):
        svc.oauth_status(flow["flow_id"])  # the result is delivered once


def test_a_callback_is_trusted_only_through_its_state_and_only_once(tmp_path):
    with FakeMicrosoft() as ms:
        svc = service(tmp_path, ms)
        flow, q = begin(svc, ms)
        assert svc.oauth_callback("x" * 43, GOOD_CODE, "", "", REDIRECT) is False and svc.oauth_callback("", GOOD_CODE, "", "", REDIRECT) is False
        assert svc.oauth_status(flow["flow_id"])["status"] == "waiting" and not ms.token_requests
        assert svc.oauth_callback(q["state"], GOOD_CODE, "", "", REDIRECT) is True
        assert svc.oauth_callback(q["state"], GOOD_CODE, "", "", REDIRECT) is False  # replayed


def test_a_wrong_code_or_a_failed_pkce_check_is_a_redacted_failure(tmp_path):
    with FakeMicrosoft() as ms:
        svc = service(tmp_path, ms)
        flow, q = begin(svc, ms)
        assert svc.oauth_callback(q["state"], "a-code-microsoft-rejects", "", "", REDIRECT) is False
        out = svc.oauth_status(flow["flow_id"])
    assert out["status"] == "failed" and out["error"]["kind"] == "auth" and "a-code-microsoft-rejects" not in json.dumps(out) and "Trace ID" not in json.dumps(out)


def test_declining_consent_is_reported_without_echoing_microsoft_diagnostics(tmp_path):
    with FakeMicrosoft() as ms:
        svc = service(tmp_path, ms)
        flow, q = begin(svc, ms)
        assert svc.oauth_callback(q["state"], "", "access_denied", "AADSTS65004: The user declined to consent. Trace ID: abc Correlation ID: def", REDIRECT) is False
        out = svc.oauth_status(flow["flow_id"])
    assert out["error"]["kind"] == "permission" and "declined to consent" in out["error"]["message"] and "Trace ID" not in out["error"]["message"] and not ms.token_requests


def test_an_unfinished_sign_in_expires(tmp_path):
    with FakeMicrosoft() as ms:
        now = [0.0]
        svc = IntegrationService(data_dir=tmp_path / "i", registry=Registry([adapter(ms)]), secret_store=vault.MemorySecretStore(), rules=Rules(), clock=lambda: now[0])
        flow, q = begin(svc, ms)
        now[0] = 601
        assert svc.oauth_callback(q["state"], GOOD_CODE, "", "", REDIRECT) is False
        with pytest.raises(IntegrationError) as exc:
            svc.oauth_status(flow["flow_id"])
    assert exc.value.kind == "not_found"


def test_the_refresh_token_that_microsoft_rotates_is_kept_so_the_connection_keeps_working(tmp_path):
    with FakeMicrosoft() as ms:
        store = vault.MemorySecretStore()
        svc = service(tmp_path, ms, store)
        flow, q = begin(svc, ms)
        svc.oauth_callback(q["state"], GOOD_CODE, "", "", REDIRECT)
        conn = svc.save(svc.oauth_status(flow["flow_id"])["result"]["test_id"], "law", {"indexes": [WORKSPACE]})
        first = svc.retest(conn["id"])
        second = svc.retest(conn["id"])  # would fail with invalid_grant if the first rotated token had not been saved
        _, rec = run(svc, conn)
        stored = store.get("local", conn["id"])["refresh_token"]
    assert first["report"]["ok"] and second["report"]["ok"] and rec["status"] == "potential_matches_found" and stored != "RT-1" and stored in ms.refresh_tokens


def test_reauthorizing_replaces_the_credential_only_when_the_new_sign_in_passes(tmp_path):
    with FakeMicrosoft() as ms:
        store = vault.MemorySecretStore()
        svc = service(tmp_path, ms, store)
        conn = connect(svc)
        assert store.get("local", conn["id"]) == {"client_secret": CLIENT_SECRET}
        flow, q = begin(svc, ms, conn["id"])
        svc.oauth_callback(q["state"], GOOD_CODE, "", "", REDIRECT)
        out = svc.oauth_status(flow["flow_id"])["result"]
        assert out["applied"] is True and out["connection"]["auth"] == "interactive" and set(store.get("local", conn["id"])) == {"refresh_token", "_claims"}
        flow2, q2 = begin(svc, ms, conn["id"])
        svc.oauth_callback(q2["state"], "bad-code-from-the-user", "", "", REDIRECT)
        assert svc.oauth_status(flow2["flow_id"])["status"] == "failed" and svc.get_connection(conn["id"])["auth"] == "interactive"


def test_disconnect_deletes_the_saved_sign_in_and_says_it_cannot_revoke_it(tmp_path):
    with FakeMicrosoft() as ms:
        store = vault.MemorySecretStore()
        svc = service(tmp_path, ms, store)
        flow, q = begin(svc, ms)
        svc.oauth_callback(q["state"], GOOD_CODE, "", "", REDIRECT)
        conn = svc.save(svc.oauth_status(flow["flow_id"])["result"]["test_id"], "law", {"indexes": [WORKSPACE]})
        out = svc.disconnect(conn["id"])
    assert store.get("local", conn["id"]) is None and out["secret_deleted"] and out["token_revoked"] is False and "revoke" in out["note"]


# --- over HTTP ---------------------------------------------------------------------------------------------------------------
def make_app(tmp_path, ms):
    cfg = IntegrationsConfig(enabled=True, reason="", data_dir=tmp_path / "data", secret_store="memory", allowed_hosts={"testserver"}, environ={}, registry=Registry([adapter(ms)]),
                             validator=lambda text: Validation(True, [], "ok"))
    return create_app(tmp_path, [], recorded_dir=tmp_path, integrations=cfg)


def test_the_http_sign_in_flow_and_the_cross_site_callback(tmp_path):
    with FakeMicrosoft() as ms:
        c = TestClient(make_app(tmp_path, ms))
        token = c.get("/api/integrations/session").json()["csrf"]
        h = {"Origin": "http://testserver", CSRF_HEADER: token}
        start = c.post("/api/integrations/oauth/start", json={"provider": "sentinel", "config": CFG}, headers=h)
        assert start.status_code == 200, start.text
        flow = start.json()
        assert flow["redirect_uri"] == "http://testserver/api/integrations/oauth/callback"
        q = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(flow["authorize_url"]).query).items()}
        ms.challenge = q["code_challenge"]
        # Microsoft's page posts the code from another site: no token, no same-origin headers. Only the host and the state count.
        cross = {"Host": "testserver", "Origin": "https://login.microsoftonline.com", "Sec-Fetch-Site": "cross-site"}
        cb = c.post("/api/integrations/oauth/callback", data={"state": q["state"], "code": GOOD_CODE}, headers=cross)
        assert cb.status_code == 200 and "Sign-in finished" in cb.text and q["state"] not in cb.text and GOOD_CODE not in cb.text and cb.headers["cache-control"] == "no-store"
        polled = c.get(f"/api/integrations/oauth/flows/{flow['flow_id']}", headers={CSRF_HEADER: token}).json()
        saved = c.post("/api/integrations/connections", json={"test_id": polled["result"]["test_id"], "label": "law", "scope": {"indexes": [WORKSPACE]}}, headers=h)
        assert polled["status"] == "done" and saved.status_code == 201
        body = json.dumps([start.text, polled, saved.text])
    assert GOOD_CODE not in body and "RT-" not in body and q["code_challenge"] in start.text


def test_the_callback_refuses_a_foreign_host_and_a_wrong_state_and_echoes_nothing(tmp_path):
    with FakeMicrosoft() as ms:
        c = TestClient(make_app(tmp_path, ms))
        foreign = c.post("/api/integrations/oauth/callback", data={"state": "s", "code": "c"}, headers={"Host": "evil.example"})
        wrong = c.post("/api/integrations/oauth/callback", data={"state": "<script>alert(1)</script>", "code": "c"}, headers={"Host": "testserver"})
        huge = c.post("/api/integrations/oauth/callback", content=b"state=" + b"a" * 20_000, headers={"Host": "testserver", "Content-Type": "application/x-www-form-urlencoded"})
    assert foreign.status_code == 403
    assert wrong.status_code == 200 and "could not be completed" in wrong.text and "script" not in wrong.text and not ms.token_requests
    assert "could not be completed" in huge.text


def test_starting_a_sign_in_needs_the_session_token_and_a_same_site_origin(tmp_path):
    with FakeMicrosoft() as ms:
        c = TestClient(make_app(tmp_path, ms))
        token = c.get("/api/integrations/session").json()["csrf"]
        body = {"provider": "sentinel", "config": CFG}
        assert c.post("/api/integrations/oauth/start", json=body, headers={"Origin": "http://testserver"}).status_code == 403
        assert c.post("/api/integrations/oauth/start", json=body, headers={CSRF_HEADER: token, "Origin": "https://evil.example"}).status_code == 403
        assert c.get("/api/integrations/oauth/flows/abc", headers={"Sec-Fetch-Site": "cross-site", CSRF_HEADER: token}).status_code == 403
        assert c.post("/api/integrations/oauth/start", json={"provider": "splunk_enterprise", "config": {}}, headers={CSRF_HEADER: token, "Origin": "http://testserver"}).status_code in (422, 404)


def test_a_crashing_exchange_ends_the_sign_in_as_a_failure_not_a_stuck_flow(tmp_path, monkeypatch):
    with FakeMicrosoft() as ms:
        svc = service(tmp_path, ms)
        flow, q = begin(svc, ms)
        monkeypatch.setattr(SentinelAdapter, "oauth_exchange", lambda *a, **k: {}["boom"])
        assert svc.oauth_callback(q["state"], GOOD_CODE, "", "", REDIRECT) is False
        out = svc.oauth_status(flow["flow_id"])
    assert out["status"] == "failed" and out["error"]["kind"] == "unavailable" and "KeyError" in out["error"]["message"] and "boom" not in out["error"]["message"]


# --- OAuth security review regressions -----------------------------------------------------------------------------------------
def test_a_non_ascii_state_or_csrf_header_is_refused_not_a_server_error(tmp_path):
    with FakeMicrosoft() as ms:
        c = TestClient(make_app(tmp_path, ms), raise_server_exceptions=False)
        token = c.get("/api/integrations/session").json()["csrf"]
        bad_state = c.post("/api/integrations/oauth/callback", data={"state": "é" * 43, "code": "c"}, headers={"Host": "testserver"})
        bad_header = c.get("/api/integrations/connections", headers={CSRF_HEADER: "tokén".encode("latin-1"), "Origin": "http://testserver"})
        ok = c.get("/api/integrations/connections", headers={CSRF_HEADER: token, "Origin": "http://testserver"})
    assert bad_state.status_code == 200 and "could not be completed" in bad_state.text
    assert bad_header.status_code == 403 and ok.status_code == 200


def test_a_callback_on_a_different_address_than_the_sign_in_started_from_is_refused_and_ends_the_flow(tmp_path):
    with FakeMicrosoft() as ms:
        svc = service(tmp_path, ms)
        flow, q = begin(svc, ms)
        assert svc.oauth_callback(q["state"], GOOD_CODE, "", "", "http://127.0.0.1:9999/api/integrations/oauth/callback") is False
        out = svc.oauth_status(flow["flow_id"])
        assert out["status"] == "failed" and "different address" in out["error"]["message"] and not ms.token_requests
        assert svc.oauth_callback(q["state"], GOOD_CODE, "", "", REDIRECT) is False  # the state is spent: it cannot be retried on the right address


def test_the_state_value_is_erased_when_it_is_consumed(tmp_path):
    with FakeMicrosoft() as ms:
        svc = service(tmp_path, ms)
        flow, q = begin(svc, ms)
        svc.oauth_callback(q["state"], GOOD_CODE, "", "", REDIRECT)
        assert all(f["state"] == "" and f["verifier"] is None for f in svc._flows.values())


def test_pkce_the_verifier_sent_at_exchange_hashes_to_the_challenge_in_the_authorize_url_and_never_travels_in_it(tmp_path):
    import base64
    import hashlib
    with FakeMicrosoft() as ms:
        svc = service(tmp_path, ms)
        flow, q = begin(svc, ms)
        svc.oauth_callback(q["state"], GOOD_CODE, "", "", REDIRECT)
        exchange = next(r for r in ms.token_requests if r["grant_type"] == "authorization_code")
    digest = base64.urlsafe_b64encode(hashlib.sha256(exchange["code_verifier"].encode()).digest()).rstrip(b"=").decode()
    assert digest == q["code_challenge"] and exchange["code_verifier"] not in flow["authorize_url"] and exchange["redirect_uri"] == REDIRECT and len(exchange["code_verifier"]) >= 43


def test_a_wrong_verifier_is_rejected_by_the_provider_so_a_substituted_code_cannot_be_exchanged(tmp_path):
    with FakeMicrosoft() as ms:
        svc = service(tmp_path, ms)
        flow, q = begin(svc, ms)
        ms.challenge = "a-challenge-from-somebody-elses-authorize-request"  # the code was issued for another flow's challenge
        assert svc.oauth_callback(q["state"], GOOD_CODE, "", "", REDIRECT) is False
        assert svc.oauth_status(flow["flow_id"])["status"] == "failed"


def test_states_verifiers_and_flow_ids_are_unpredictable_and_distinct(tmp_path):
    with FakeMicrosoft() as ms:
        svc = service(tmp_path, ms)
        seen = [svc.oauth_start("sentinel", "interactive", CFG, REDIRECT) for _ in range(15)]
        flows = list(svc._flows.values())
    assert len({f["state"] for f in flows}) == 15 and len({f["verifier"] for f in flows}) == 15 and len({s["flow_id"] for s in seen}) == 15
    assert all(len(f["state"]) >= 43 and len(f["verifier"]) >= 64 for f in flows)


def test_an_expired_state_is_rejected_and_the_expired_flow_is_erased(tmp_path):
    with FakeMicrosoft() as ms:
        now = [0.0]
        svc = IntegrationService(data_dir=tmp_path / "i", registry=Registry([adapter(ms)]), secret_store=vault.MemorySecretStore(), rules=Rules(), clock=lambda: now[0])
        flow, q = begin(svc, ms)
        now[0] = 601
        assert svc.oauth_callback(q["state"], GOOD_CODE, "", "", REDIRECT) is False and svc._flows == {}


def test_every_failure_path_erases_the_verifier(tmp_path):
    with FakeMicrosoft() as ms:
        svc = service(tmp_path, ms)
        for code, err in (("a-code-microsoft-rejects", ""), ("", "access_denied")):
            flow, q = begin(svc, ms)
            assert svc.oauth_callback(q["state"], code, err, "", REDIRECT) is False
        assert all(f["status"] == "failed" and f["verifier"] is None and f["state"] == "" for f in svc._flows.values())


def test_nothing_secret_reaches_the_logs_or_any_response_during_a_full_sign_in(tmp_path, caplog):
    import logging
    caplog.set_level(logging.DEBUG)
    with FakeMicrosoft() as ms:
        c = TestClient(make_app(tmp_path, ms))
        token = c.get("/api/integrations/session").json()["csrf"]
        h = {"Origin": "http://testserver", CSRF_HEADER: token}
        flow = c.post("/api/integrations/oauth/start", json={"provider": "sentinel", "config": CFG}, headers=h).json()
        q = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(flow["authorize_url"]).query).items()}
        ms.challenge = q["code_challenge"]
        cb = c.post("/api/integrations/oauth/callback", data={"state": q["state"], "code": GOOD_CODE}, headers={"Host": "testserver"})
        polled = c.get(f"/api/integrations/oauth/flows/{flow['flow_id']}", headers={CSRF_HEADER: token})
        c.post("/api/integrations/connections", json={"test_id": polled.json()["result"]["test_id"], "label": "law", "scope": {"indexes": [WORKSPACE]}}, headers=h)
        listing = c.get("/api/integrations/connections", headers={CSRF_HEADER: token, "Origin": "http://testserver"})
        exchange = next(r for r in ms.token_requests if r["grant_type"] == "authorization_code")
        secrets = [GOOD_CODE, exchange["code_verifier"], q["state"], *ms.refresh_tokens]
        outputs = caplog.text + cb.text + polled.text + listing.text + json.dumps(dict(cb.headers))
    assert not [s for s in secrets if s in outputs]


def test_provider_status_labels_never_overstate_what_was_verified():
    specs = {s["id"]: s for s in default_registry().specs()}
    assert specs["splunk_enterprise"]["status"] == "live_verified_test_instance" and "throwaway" in specs["splunk_enterprise"]["verification_note"].lower()
    assert specs["elastic"]["status"] == "live_verified_test_instance" and "throwaway" in specs["elastic"]["verification_note"].lower()
    assert specs["splunk_cloud"]["status"] == "not_live_verified" and specs["splunk_cloud"]["status_label"] == "Implemented, not live-verified"
    assert specs["sentinel"]["status"] == "not_live_verified" and specs["sentinel"]["status_label"] == "Mock-tested, not live-verified"
    assert specs["qradar"]["status"] == "planned" and specs["qradar"]["implemented"] is False
    for s in specs.values():
        if s["id"] in ("splunk_cloud", "sentinel", "qradar"):
            assert "production" not in s["verification_note"].lower() or "not" in s["verification_note"].lower()
