"""The integration service end to end against the MOCK Splunk (tests/fake_splunk.py): real HTTP, real policy transport, real stores.
These are mock tests. They are not evidence that a connector works against a real SIEM; the opt-in live tests are in tests/live/."""
import json
import re
import threading
from pathlib import Path

import pytest
from fake_splunk import TOKEN, FakeSplunk

from shakedown import splunk
from shakedown.integrations import vault
from shakedown.integrations.base import IntegrationError
from shakedown.integrations.registry import default_registry
from shakedown.integrations.service import IntegrationService, parse_window
from shakedown.validate import Validation

RULE = """title: Test rule
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
        CommandLine|contains: 'evil'
    condition: selection
falsepositives:
    - admin tools
level: low
"""
DETECT = 'Image="*\\\\x.exe" CommandLine="*evil*"'
INDEXES = {"indexes": ["win"]}
WINDOW = {"last_hours": 24}


@pytest.fixture(autouse=True)
def fixed_conversion(monkeypatch):
    monkeypatch.setattr(splunk, "convert_to_spl", lambda rule_text: DETECT)


class Rules:
    def list(self):
        return [{"ref": "recorded:one", "title": "A recorded rule", "source": "recorded run"}]

    def get(self, ref):
        return {"text": RULE, "label": "recorded run: one", "record": None} if ref == "recorded:one" else None


def handler(coverage=1000, fields=("Image", "CommandLine", "EventCode"), matches=3, fail=None):
    def handle(spl, earliest, latest):
        if fail:
            return {"error": fail, "status": 400}
        if "fieldsummary" in spl:
            return {"count": len(fields), "results": [{"field": f} for f in fields]}
        if "min(_time)" in spl:
            return {"count": 1, "results": [{"count": str(coverage), "first": "1", "last": "2"}]}
        if "| table" in spl:
            ex = [{"_time": "t", "Image": "C:\\x.exe", "CommandLine": "evil run"}] * min(matches, 5)
            return {"count": len(ex), "results": ex}
        if "stats count" in spl:
            return {"count": 1, "results": [{"count": str(matches)}]}
        return {"count": 0, "results": []}
    return handle


def service(tmp_path, owner="alice", store=None, mode="local", environ=None, **kw):
    return IntegrationService(data_dir=tmp_path / "integ", registry=default_registry(), secret_store=store or vault.MemorySecretStore(), rules=Rules(), mode=mode, owner=owner,
                              validator=lambda text: Validation(True, [], "ok"), environ=environ or {}, **kw)


def cfg(fake, **kw):
    return {"endpoint": fake.url, "verify_tls": True, **kw}


def paste(token=TOKEN):
    return {"mode": "paste", "values": {"token": token}}


def connect(svc, fake, label="lab", indexes=("win",), token=TOKEN, **kw):
    t = svc.test_new("splunk_enterprise", "token", cfg(fake, **kw), paste(token))
    assert t["test_id"], t["report"]
    return svc.save(t["test_id"], label, {"indexes": list(indexes)})


# --- availability ------------------------------------------------------------------------------------------------
def test_a_disabled_service_refuses_every_action_but_still_explains_itself(tmp_path):
    svc = service(tmp_path, enabled=False, disabled_reason="hosted mode: no accounts, no vault")
    st = svc.status()
    assert st["enabled"] is False and "hosted" in st["disabled_reason"] and st["providers"]
    for call in (svc.list_connections, svc.rule_candidates, svc.list_assessments):
        with pytest.raises(IntegrationError) as exc:
            call()
        assert exc.value.kind == "disabled"
    with pytest.raises(IntegrationError):
        svc.test_new("splunk_enterprise", "token", {"endpoint": "https://x:8089"}, paste())


def test_providers_declare_their_capabilities_and_planned_ones_have_no_wizard(tmp_path):
    specs = {s["id"]: s for s in service(tmp_path).status()["providers"]}
    assert specs["splunk_enterprise"]["capabilities"]["preflight"] is True and specs["splunk_enterprise"]["implemented"] is True
    assert specs["splunk_cloud"]["status"] == "not_live_verified"
    assert specs["qradar"]["implemented"] is False and specs["qradar"]["status"] == "planned" and specs["qradar"]["fields"] == []
    with pytest.raises(IntegrationError):
        service(tmp_path).test_new("qradar", "token", {"endpoint": "https://x"}, paste())


# --- the connection wizard: test, discover, save ----------------------------------------------------------------------
def test_a_good_connection_reports_each_check_discovers_indexes_and_never_returns_the_secret(tmp_path):
    with FakeSplunk(handler()) as fake:
        out = service(tmp_path).test_new("splunk_enterprise", "token", cfg(fake), paste())
    ids = {c["id"]: c["status"] for c in out["report"]["checks"]}
    assert out["report"]["ok"] and ids == {"network_tls": "pass", "authentication": "pass", "permissions": "pass", "endpoint": "pass"}
    assert out["report"]["endpoint"]["version"] == "9.9.9-mock" and out["report"]["identity"]["username"] == "svc_preflight"
    assert [i["name"] for i in out["scopes"]["items"]] == ["other", "win"] and out["scopes"]["discovery"] == "available"  # internal and disabled left out
    assert TOKEN not in json.dumps(out) and out["credential"]["fingerprint"].startswith("sha256:")


def test_a_wrong_credential_fails_at_authentication_not_at_the_network_and_cannot_be_saved(tmp_path):
    svc = service(tmp_path)
    with FakeSplunk(handler()) as fake:
        out = svc.test_new("splunk_enterprise", "token", cfg(fake), paste("wrong-token-value"))
    ids = {c["id"]: c["status"] for c in out["report"]["checks"]}
    assert not out["report"]["ok"] and out["test_id"] is None and ids["network_tls"] == "pass" and ids["authentication"] == "fail"
    assert "wrong-token-value" not in json.dumps(out)
    with pytest.raises(IntegrationError):
        svc.save("not-a-test", "x", INDEXES)


def test_an_unreachable_endpoint_is_a_network_failure_with_later_checks_not_run(tmp_path):
    out = service(tmp_path).test_new("splunk_enterprise", "token", {"endpoint": "http://127.0.0.1:9", "verify_tls": True}, paste())
    ids = {c["id"]: c["status"] for c in out["report"]["checks"]}
    assert ids["network_tls"] == "fail" and ids["authentication"] == "skipped" and out["test_id"] is None


def test_an_account_without_the_search_capability_fails_the_permission_check(tmp_path):
    with FakeSplunk(handler(), capabilities=("list_inputs",)) as fake:
        out = service(tmp_path).test_new("splunk_enterprise", "token", cfg(fake), paste())
    perm = next(c for c in out["report"]["checks"] if c["id"] == "permissions")
    assert perm["status"] == "fail" and "search" in perm["detail"] and not out["report"]["ok"]


def test_an_admin_class_account_is_refused_unless_the_user_accepts_the_risk_visibly(tmp_path):
    with FakeSplunk(handler(), capabilities=("search", "admin_all_objects")) as fake:
        refused = service(tmp_path).test_new("splunk_enterprise", "token", cfg(fake), paste())
        accepted = service(tmp_path).test_new("splunk_enterprise", "token", cfg(fake, allow_privileged=True), paste())
    assert not refused["report"]["ok"] and next(c for c in refused["report"]["checks"] if c["id"] == "permissions")["status"] == "fail"
    assert accepted["report"]["ok"] and next(c for c in accepted["report"]["checks"] if c["id"] == "permissions")["status"] == "warn"


def test_a_role_that_cannot_list_indexes_falls_back_to_manual_entry_without_failing(tmp_path):
    with FakeSplunk(handler(), indexes_status=403, info_status=403) as fake:
        out = service(tmp_path).test_new("splunk_enterprise", "token", cfg(fake), paste())
    assert out["report"]["ok"] and out["scopes"]["discovery"] == "denied" and out["scopes"]["items"] == []
    assert next(c for c in out["report"]["checks"] if c["id"] == "endpoint")["status"] == "warn"


def test_saving_stores_the_credential_in_the_secret_store_and_nothing_secret_on_disk(tmp_path):
    store = vault.MemorySecretStore()
    svc = service(tmp_path, store=store)
    with FakeSplunk(handler()) as fake:
        conn = connect(svc, fake)
    assert conn["state"] == "connected" and conn["credential"]["store"] == "memory" and store.get("alice", conn["id"]) == {"token": TOKEN}
    disk = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "integ").rglob("*.json"))
    assert TOKEN not in disk and TOKEN not in json.dumps(conn) and TOKEN not in json.dumps(svc.list_connections())
    assert conn["endpoint"].startswith("http://127.0.0.1:")


def test_save_validates_the_name_and_the_scope(tmp_path):
    svc = service(tmp_path)
    with FakeSplunk(handler()) as fake:
        for label, scope in (("", INDEXES), ("x" * 81, INDEXES), ("ok", {"indexes": []}), ("ok", {"indexes": ["*"]}), ("ok", {"indexes": ["a b"]}), ("ok", {"indexes": ["a"] * 0 + [f"i{n}" for n in range(21)]})):
            t = svc.test_new("splunk_enterprise", "token", cfg(fake), paste())
            with pytest.raises(IntegrationError):
                svc.save(t["test_id"], label, scope)


def test_a_test_result_can_be_saved_once_only(tmp_path):
    svc = service(tmp_path)
    with FakeSplunk(handler()) as fake:
        t = svc.test_new("splunk_enterprise", "token", cfg(fake), paste())
        svc.save(t["test_id"], "one", INDEXES)
        with pytest.raises(IntegrationError):
            svc.save(t["test_id"], "two", INDEXES)


def test_certificate_checking_cannot_be_disabled_silently_or_for_a_public_name(tmp_path):
    svc = service(tmp_path)
    with pytest.raises(IntegrationError) as exc:
        svc.test_new("splunk_enterprise", "token", {"endpoint": "https://127.0.0.1:8089", "verify_tls": False}, paste())
    assert exc.value.kind == "config"  # needs the acknowledgement
    with pytest.raises(IntegrationError) as exc:
        svc.test_new("splunk_enterprise", "token", {"endpoint": "https://93.184.216.34:8089", "verify_tls": False, "accept_insecure_tls": True}, paste())
    assert exc.value.kind == "destination"


def test_hosted_mode_refuses_a_loopback_endpoint(tmp_path):
    with FakeSplunk(handler()) as fake:
        with pytest.raises(IntegrationError) as exc:
            service(tmp_path, mode="hosted").test_new("splunk_enterprise", "token", cfg(fake), paste())
    assert exc.value.kind in ("config", "destination")


def test_splunk_cloud_only_accepts_a_splunk_cloud_endpoint_with_verification_on(tmp_path):
    svc = service(tmp_path)
    for endpoint in ("https://evil.example.com:8089", "https://stack.splunkcloud.com.evil.com:8089", "http://127.0.0.1:8089"):
        with pytest.raises(IntegrationError):
            svc.test_new("splunk_cloud", "token", {"endpoint": endpoint}, paste())


# --- credentials from the environment, restarts, reauthorisation ---------------------------------------------------
def test_a_connection_can_read_its_credential_from_an_environment_variable_and_stores_only_the_name(tmp_path):
    svc = service(tmp_path, environ={"SPLUNK_TOKEN": TOKEN})
    with FakeSplunk(handler()) as fake:
        t = svc.test_new("splunk_enterprise", "token", cfg(fake), {"mode": "env", "env": {"token": "SPLUNK_TOKEN"}})
        conn = svc.save(t["test_id"], "env conn", INDEXES)
        assert conn["credential"]["mode"] == "env" and conn["credential"]["env"] == {"token": "SPLUNK_TOKEN"} and conn["state"] == "connected"
        assert TOKEN not in json.dumps(conn) and TOKEN not in (tmp_path / "integ" / "connections.json").read_text(encoding="utf-8")
        assert svc.retest(conn["id"])["report"]["ok"]
    gone = service(tmp_path, environ={})
    assert gone.get_connection(conn["id"])["state"] == "needs_credentials"


def test_after_a_restart_a_memory_credential_is_gone_and_the_connection_says_so_not_healthy(tmp_path):
    with FakeSplunk(handler()) as fake:
        conn = connect(service(tmp_path), fake)
        restarted = service(tmp_path, store=vault.MemorySecretStore())  # a new process: same profile file, empty memory
        shown = restarted.get_connection(conn["id"])
        assert shown["state"] == "needs_credentials"
        again = restarted.retest(conn["id"])
        assert not again["report"]["ok"] and again["connection"]["state"] == "needs_credentials"
        with pytest.raises(IntegrationError):
            restarted.start_preflight(conn["id"], "nope", True)
        fixed = restarted.reconfigure(conn["id"], "token", cfg(fake), paste())
        assert fixed["applied"] and fixed["connection"]["state"] == "connected"


def test_a_failed_reconfiguration_changes_nothing(tmp_path):
    svc = service(tmp_path)
    with FakeSplunk(handler()) as fake:
        conn = connect(svc, fake)
        before = svc.get_connection(conn["id"])
        bad = svc.reconfigure(conn["id"], "token", cfg(fake), paste("a-different-wrong-token"))
        assert bad["applied"] is False
        assert svc.get_connection(conn["id"])["credential"]["fingerprint"] == before["credential"]["fingerprint"]
        assert svc.retest(conn["id"])["report"]["ok"]


def test_an_old_successful_check_is_marked_stale_not_connected(tmp_path):
    svc = service(tmp_path)
    with FakeSplunk(handler()) as fake:
        conn = connect(svc, fake)
    prof = svc.profiles.get("alice", conn["id"])
    prof["last_check"]["at"] = "2020-01-01T00:00:00+00:00"
    svc.profiles.update("alice", conn["id"], {"last_check": prof["last_check"]})
    assert svc.get_connection(conn["id"])["state"] == "stale"


def test_a_failed_retest_is_recorded_and_shown(tmp_path):
    svc = service(tmp_path)
    with FakeSplunk(handler()) as fake:
        conn = connect(svc, fake)
        fake.token = "rotated-by-an-admin"
        out = svc.retest(conn["id"])
    assert not out["report"]["ok"] and out["connection"]["state"] == "check_failed"


# --- previewing the query ----------------------------------------------------------------------------------------
def test_the_plan_shows_the_exact_queries_and_sends_nothing(tmp_path):
    svc = service(tmp_path)
    with FakeSplunk(handler()) as fake:
        conn = connect(svc, fake)
        before = len(fake.requests)
        plan = svc.plan(conn["id"], {"ref": "recorded:one"}, ["win"], WINDOW)
        assert len(fake.requests) == before
    assert plan["runnable"] and plan["language"] == "SPL" and set(plan["queries"]) == {"coverage", "fields", "detection", "sample"}
    assert DETECT.replace("\\\\", "\\\\") in plan["detection"] and 'index="win"' in plan["queries"]["detection"]
    assert plan["rule_validity"]["ok"] and plan["window"]["hours"] == 24 and plan["plan_id"]


def test_an_invalid_rule_produces_no_query_and_cannot_run(tmp_path):
    svc = service(tmp_path)
    svc.validator = lambda text: Validation(False, ["rule could not be built: broken"], "bad")
    with FakeSplunk(handler()) as fake:
        conn = connect(svc, fake)
        plan = svc.plan(conn["id"], {"text": RULE}, ["win"], WINDOW)
        assert plan["runnable"] is False and "queries" not in plan and plan["rule_validity"]["ok"] is False
        with pytest.raises(IntegrationError):
            svc.start_preflight(conn["id"], "anything", True)


@pytest.mark.parametrize("indexes,window", [(["other"], WINDOW), (["*"], WINDOW), (["win"], {"last_hours": 9999}), (["win"], {"last_hours": 0}), (["win"], {}),
                                            (["win"], {"earliest": "2026-01-02T00:00:00Z", "latest": "2026-01-01T00:00:00Z"}),
                                            (["win"], {"earliest": "2026-10-27T00:00:00Z", "latest": "2999-01-01T00:00:00Z"})])
def test_scope_and_window_problems_are_refused_before_any_query(tmp_path, indexes, window):
    svc = service(tmp_path)
    with FakeSplunk(handler()) as fake:
        conn = connect(svc, fake)
        with pytest.raises(IntegrationError) as exc:
            svc.plan(conn["id"], {"ref": "recorded:one"}, indexes, window)
    assert exc.value.kind in ("scope", "config")


def test_unsupported_log_sources_are_named_not_mis_queried(tmp_path):
    svc = service(tmp_path)
    with FakeSplunk(handler()) as fake:
        conn = connect(svc, fake)
        plan = svc.plan(conn["id"], {"text": RULE.replace("process_creation", "dns_query")}, ["win"], WINDOW)
    assert plan["runnable"] is False and plan["reason_kind"] == "unsupported_logsource"


def test_parse_window_rules():
    assert (lambda w: (w[1] - w[0]).total_seconds())(parse_window({"last_hours": 2}, 168)) == 7200
    with pytest.raises(IntegrationError):
        parse_window({"last_hours": 200}, 168)


# --- running ---------------------------------------------------------------------------------------------------
def run(svc, conn, ref="recorded:one", indexes=("win",)):
    plan = svc.plan(conn["id"], {"ref": ref}, list(indexes), WINDOW)
    started = svc.start_preflight(conn["id"], plan["plan_id"], True)
    svc.join(started["assessment_id"])
    return plan, svc.get_assessment(started["assessment_id"])


def test_a_run_needs_explicit_confirmation(tmp_path):
    svc = service(tmp_path)
    with FakeSplunk(handler()) as fake:
        conn = connect(svc, fake)
        plan = svc.plan(conn["id"], {"ref": "recorded:one"}, ["win"], WINDOW)
        for bad in (False, None, "yes", 1):
            with pytest.raises(IntegrationError):
                svc.start_preflight(conn["id"], plan["plan_id"], bad)
        assert fake.searches == []


def test_the_query_that_runs_is_exactly_the_query_that_was_previewed(tmp_path):
    svc = service(tmp_path)
    with FakeSplunk(handler()) as fake:
        conn = connect(svc, fake)
        plan, rec = run(svc, conn)
    sent = [s["search"] for s in fake.searches]
    assert sent == [plan["queries"][k] for k in ("coverage", "fields", "detection", "sample")]
    assert rec["query_sha256"] and rec["origin"] == "new_execution"


def test_a_finished_run_keeps_the_three_verdicts_separate_and_carries_real_results(tmp_path):
    svc = service(tmp_path)
    with FakeSplunk(handler(matches=3)) as fake:
        conn = connect(svc, fake)
        _, rec = run(svc, conn)
    st = rec["assessment"]["statuses"]
    assert (st["rule_validity"]["state"], st["attack_validation"]["state"], st["environment_preflight"]["state"]) == ("valid", "not_run", "potential_matches_found")
    assert st["environment_preflight"]["matches"]["count"] == 3 and st["environment_preflight"]["matches"]["examples"][0]["Image"] == "C:\\x.exe"
    assert rec["status"] == "potential_matches_found" and rec["assessment"]["recommendation"]["automatic_deployment"] is False
    assert svc.get_connection(conn["id"])["last_preflight"]["assessment_id"] == rec["id"]
    assert TOKEN not in json.dumps(rec)


@pytest.mark.parametrize("kw,state", [({"coverage": 0}, "telemetry_missing_or_unsupported"), ({"fields": ("Image",)}, "telemetry_missing_or_unsupported"),
                                       ({"matches": 0}, "no_matches_in_window")])
def test_empty_and_missing_telemetry_results_are_classified_honestly(tmp_path, kw, state):
    svc = service(tmp_path)
    with FakeSplunk(handler(**kw)) as fake:
        conn = connect(svc, fake)
        _, rec = run(svc, conn)
    assert rec["assessment"]["statuses"]["environment_preflight"]["state"] == state
    if state == "telemetry_missing_or_unsupported":
        assert "not a clean result" in rec["assessment"]["statuses"]["environment_preflight"]["detail"] or "map the field" in rec["assessment"]["statuses"]["environment_preflight"]["detail"]


def test_a_query_error_is_a_failed_search_with_the_secret_redacted(tmp_path):
    svc = service(tmp_path)
    with FakeSplunk(handler(fail=f"Error in search; header was Authorization: Bearer {TOKEN}")) as fake:
        conn = connect(svc, fake)
        _, rec = run(svc, conn)
    env = rec["assessment"]["statuses"]["environment_preflight"]
    assert env["state"] == "query_failed" and env["error"]["kind"] == "query" and TOKEN not in json.dumps(rec)


def test_a_credential_revoked_after_saving_fails_the_run_as_authentication(tmp_path):
    svc = service(tmp_path)
    with FakeSplunk(handler()) as fake:
        conn = connect(svc, fake)
        fake.token = "rotated"
        _, rec = run(svc, conn)
    assert rec["assessment"]["statuses"]["environment_preflight"]["error"]["kind"] == "auth"


def test_only_one_run_at_a_time_per_connection_and_a_running_search_can_be_cancelled(tmp_path):
    svc = service(tmp_path)
    slow = {"never": True, "count": 1, "results": [{"count": "1"}]}
    with FakeSplunk(lambda spl, e, l: slow, poll_delay_s=0) as fake:
        conn = connect(svc, fake)
        plan = svc.plan(conn["id"], {"ref": "recorded:one"}, ["win"], WINDOW)
        first = svc.start_preflight(conn["id"], plan["plan_id"], True)
        with pytest.raises(IntegrationError) as exc:
            svc.start_preflight(conn["id"], plan["plan_id"], True)
        assert exc.value.kind == "conflict"
        svc.cancel(first["assessment_id"])
        svc.join(first["assessment_id"], 15)
        rec = svc.get_assessment(first["assessment_id"])
        cancel_paths = [p for m, p in fake.requests if m == "POST" and p.endswith("/control")]
    assert rec["assessment"]["statuses"]["environment_preflight"]["error"]["kind"] == "cancelled" and cancel_paths


def test_a_rule_taken_from_a_recorded_run_brings_lab_evidence_as_a_separate_labelled_verdict(tmp_path):
    record = {"iterations": [{"action": "generate", "evaluation": {"attack_total": 1, "attack_detected": 1, "attack_missed": [], "benign": {}}}], "best_index": 0,
              "heldout": {}, "research": {"primary": {"url": "https://example.org/r", "retrieved_at": "t"}}, "scenario": {"title": "S"}}

    class WithRecord(Rules):
        def get(self, ref):
            return {"text": RULE, "label": "recorded run: one", "record": record}
    svc = service(tmp_path)
    svc.rules = WithRecord()
    with FakeSplunk(handler()) as fake:
        conn = connect(svc, fake)
        _, rec = run(svc, conn)
    st = rec["assessment"]["statuses"]
    assert st["attack_validation"]["state"] == "validated_on_supplied_attack_evidence" and st["attack_validation"]["origin"] == "controlled_lab_fixture"
    assert st["environment_preflight"]["origin"] == "splunk_read_only_search" and st["rule_validity"]["state"] == "valid"


# --- history, export ---------------------------------------------------------------------------------------------
def test_history_lists_new_runs_and_export_contains_the_evidence_but_no_credential(tmp_path):
    svc = service(tmp_path)
    with FakeSplunk(handler()) as fake:
        conn = connect(svc, fake)
        _, rec = run(svc, conn)
    listed = svc.list_assessments()
    assert [r["id"] for r in listed] == [rec["id"]] and listed[0]["origin"] == "new_execution" and listed[0]["matches"] == 3
    out = svc.export(rec["id"])
    assert set(out["files"]) == {"review_packet.md", "assessment.json", "rule.yml", "query.spl", "integration.json"} and out["contains_event_excerpts"] is True
    blob = json.dumps(out)
    assert TOKEN not in blob and "Environment preflight" in out["files"]["review_packet.md"] and 'index="win"' in out["files"]["query.spl"]
    assert json.loads(out["files"]["integration.json"])["credential_fingerprint"].startswith("sha256:")


def test_a_run_that_was_interrupted_by_a_restart_is_shown_as_interrupted_not_running(tmp_path):
    svc = service(tmp_path)
    with FakeSplunk(handler()) as fake:
        conn = connect(svc, fake)
    svc.assessments.save("alice", {"id": "dead1", "connection_id": conn["id"], "status": "running", "assessment": None})
    assert service(tmp_path).get_assessment("dead1")["status"] == "interrupted"
    with pytest.raises(IntegrationError):
        service(tmp_path).export("dead1")


# --- isolation, disconnect ---------------------------------------------------------------------------------------
def test_another_owner_cannot_see_use_change_export_or_remove_a_connection_or_its_results(tmp_path):
    store = vault.MemorySecretStore()
    alice, bob = service(tmp_path, "alice", store), service(tmp_path, "bob", store)
    with FakeSplunk(handler()) as fake:
        conn = connect(alice, fake)
        _, rec = run(alice, conn)
        assert bob.list_connections() == [] and bob.list_assessments() == []
        for call in (lambda: bob.get_connection(conn["id"]), lambda: bob.retest(conn["id"]), lambda: bob.discover(conn["id"]), lambda: bob.update(conn["id"], "x"),
                     lambda: bob.plan(conn["id"], {"ref": "recorded:one"}, ["win"], WINDOW), lambda: bob.disconnect(conn["id"]),
                     lambda: bob.reconfigure(conn["id"], "token", cfg(fake), paste()), lambda: bob.get_assessment(rec["id"]), lambda: bob.export(rec["id"]),
                     lambda: bob.cancel(rec["id"]), lambda: bob.start_preflight(conn["id"], "x", True)):
            with pytest.raises(IntegrationError) as exc:
                call()
            assert exc.value.kind == "not_found", call
        assert alice.get_connection(conn["id"])["state"] == "connected" and store.get("alice", conn["id"]) == {"token": TOKEN}
        t = bob.test_new("splunk_enterprise", "token", cfg(fake), paste())
        with pytest.raises(IntegrationError):  # bob cannot save over a test that is alice's
            alice.save(t["test_id"], "stolen", INDEXES)


def test_disconnect_deletes_the_credential_the_profile_and_optionally_the_results(tmp_path):
    store = vault.MemorySecretStore()
    svc = service(tmp_path, store=store)
    with FakeSplunk(handler()) as fake:
        conn = connect(svc, fake)
        _, rec = run(svc, conn)
        out = svc.disconnect(conn["id"], delete_assessments=True)
    assert out["secret_deleted"] and out["assessments_deleted"] == 1 and out["token_revoked"] is False and "revoke" in out["note"]
    assert store.get("alice", conn["id"]) is None and svc.list_connections() == []
    with pytest.raises(IntegrationError):
        svc.get_connection(conn["id"])
    assert svc.assessments.get("alice", rec["id"]) is None


def test_disconnect_keeps_results_unless_asked_and_stops_a_running_search(tmp_path):
    svc = service(tmp_path)
    with FakeSplunk(lambda spl, e, l: {"never": True, "count": 1, "results": []}) as fake:
        conn = connect(svc, fake)
        plan = svc.plan(conn["id"], {"ref": "recorded:one"}, ["win"], WINDOW)
        started = svc.start_preflight(conn["id"], plan["plan_id"], True)
        out = svc.disconnect(conn["id"])
        svc.join(started["assessment_id"], 15)
    assert out["assessments_deleted"] == 0 and svc.assessments.get("alice", started["assessment_id"]) is not None


# --- rate limiting ------------------------------------------------------------------------------------------------
def test_connection_tests_are_rate_limited(tmp_path):
    now = [0.0]
    svc = service(tmp_path, clock=lambda: now[0])
    with FakeSplunk(handler()) as fake:
        hit = None
        for _ in range(60):
            try:
                svc.test_new("splunk_enterprise", "token", cfg(fake), paste("wrong-token-value"))
            except IntegrationError as exc:
                hit = exc
                break
        assert hit is not None and hit.kind == "rate_limited"
        now[0] += 61
        svc.test_new("splunk_enterprise", "token", cfg(fake), paste("wrong-token-value"))


def test_a_cancel_requested_before_the_search_starts_is_not_lost(tmp_path):
    """Regression: the connector used to clear its cancel flag at the start of a run, so a quick cancel could be dropped."""
    from shakedown.integrations.adapters.splunk import SplunkEnterpriseAdapter
    adapter = SplunkEnterpriseAdapter()
    with FakeSplunk(lambda spl, e, l: {"never": True, "count": 1, "results": []}) as fake:
        config = adapter.validate_config(cfg(fake), mode="local")
        started = __import__("time").monotonic()
        with pytest.raises(IntegrationError) as exc:
            adapter.run(RULE, config, {"token": TOKEN}, {"indexes": ["win"]}, parse_window(WINDOW, 168), mode="local", handle={"cancel_requested": True})
    assert exc.value.kind == "cancelled" and __import__("time").monotonic() - started < 20
