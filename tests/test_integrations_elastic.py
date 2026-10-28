"""The Elasticsearch adapter and its use through the service. ALL SERVERS HERE ARE MOCKS (tests/fake_elastic.py). The conversion tests use the real pySigma
Elasticsearch backend, but nothing here is evidence about a real Elasticsearch cluster."""
import json

import pytest
from fake_elastic import API_KEY, FakeElastic

from shakedown.integrations import vault
from shakedown.integrations.adapters import elastic
from shakedown.integrations.base import IntegrationError
from shakedown.integrations.registry import default_registry
from shakedown.integrations.service import IntegrationService
from shakedown.validate import Validation

RULE = """title: Elastic test rule
id: 11111111-2222-4333-8444-555555555556
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
WINDOW = {"last_hours": 24}


class Rules:
    def list(self):
        return []

    def get(self, ref):
        return {"text": RULE, "label": "test rule", "record": None} if ref == "t" else None


def service(tmp_path, owner="alice", store=None):
    return IntegrationService(data_dir=tmp_path / "i", registry=default_registry(), secret_store=store or vault.MemorySecretStore(), rules=Rules(), owner=owner,
                              validator=lambda text: Validation(True, [], "ok"))


def key(k=API_KEY):
    return {"mode": "paste", "values": {"api_key": k}}


def cfg(fake, **kw):
    return {"endpoint": fake.url, "verify_tls": True, **kw}


def connect(svc, fake, indexes=("winlogbeat-test",)):
    t = svc.test_new("elastic", "api_key", cfg(fake), key())
    assert t["test_id"], t["report"]
    return svc.save(t["test_id"], "es", {"indexes": list(indexes)})


# --- conversion (the real pySigma backend) ---------------------------------------------------------------------------
def test_the_real_backend_maps_sigma_fields_to_ecs_and_the_mapped_fields_are_reported():
    lucene, fields = elastic.convert_to_lucene(RULE, "ecs_windows")
    assert "process.executable" in lucene and "process.command_line" in lucene and "Image" not in lucene
    assert fields == ["process.command_line", "process.executable.caseless"]  # the ECS pipeline matches case-insensitively through a .caseless sub-field


def test_a_rule_the_backend_cannot_map_is_a_named_conversion_error_not_a_guess():
    with pytest.raises(IntegrationError) as exc:
        elastic.convert_to_lucene(RULE.replace("Image|endswith", "NoSuchSigmaField|invalid_modifier"), "ecs_windows")
    assert exc.value.kind == "conversion"
    with pytest.raises(IntegrationError) as exc:
        elastic.convert_to_lucene("title: x\ndetection: [", "ecs_windows")
    assert exc.value.kind == "conversion"


def test_only_known_windows_log_sources_have_a_scope():
    assert elastic.logsource_filters("process_creation")["clause"] == 'winlog.channel:"Microsoft-Windows-Sysmon/Operational" AND event.code:"1"'
    with pytest.raises(IntegrationError) as exc:
        elastic.logsource_filters("dns_query")
    assert exc.value.kind == "unsupported_logsource"


# --- the read-only guard -----------------------------------------------------------------------------------------
@pytest.mark.parametrize("body", [
    {"query": {"match_all": {}}, "script_fields": {"x": {"script": "1"}}}, {"query": {"bool": {"filter": [{"script": {"script": "doc['a'].value > 1"}}]}}},
    {"query": {"match_all": {}}, "runtime_mappings": {"x": {"type": "keyword"}}}, {"query": {"match_all": {}}, "scroll": "1m"}, {"query": {"match_all": {}}, "pit": {"id": "x"}},
    {"query": {"match_all": {}}, "update": {}}, {"aggs": {"a": {"filter": {"script": {"script": "x"}}}}}, {"unknown_top_level": 1}, "not an object"])
def test_search_bodies_that_could_do_more_than_search_are_refused_locally(body):
    with pytest.raises(IntegrationError) as exc:
        elastic.check_read_only(body)
    assert exc.value.kind == "unsafe_query"


def test_only_the_documented_read_endpoints_can_be_called(tmp_path):
    with FakeElastic() as fake:
        client = elastic.ElasticAdapter()._client(elastic.ElasticAdapter().validate_config(cfg(fake), mode="local"), {"api_key": API_KEY}, "local")
        for method, path in (("POST", "/_security/api_key"), ("PUT", "/winlogbeat-test/_doc/1"), ("DELETE", "/winlogbeat-test"), ("POST", "/_bulk"), ("GET", "/_cluster/settings"),
                             ("POST", "/_delete_by_query"), ("POST", "/winlogbeat-test/_delete_by_query"), ("POST", "/_search/scroll"), ("GET", "/_cat/indices")):
            with pytest.raises(IntegrationError) as exc:
                client.call(method, path, {})
            assert exc.value.kind == "forbidden_endpoint", (method, path)
        assert fake.requests == []


def test_wildcard_and_odd_index_names_are_refused_before_any_request(tmp_path):
    svc = service(tmp_path)
    with FakeElastic() as fake:
        conn = connect(svc, fake)
        for bad in (["*"], ["a,b"], ["../x"], ["-leading"], ["a/b"]):
            with pytest.raises(IntegrationError):
                svc.plan(conn["id"], {"text": RULE}, bad, WINDOW)


# --- the connection ------------------------------------------------------------------------------------------------
def test_a_good_connection_reports_each_check_and_lists_visible_indices_without_system_ones(tmp_path):
    with FakeElastic() as fake:
        out = service(tmp_path).test_new("elastic", "api_key", cfg(fake), key())
    checks = {c["id"]: c["status"] for c in out["report"]["checks"]}
    assert out["report"]["ok"] and checks == {"network_tls": "pass", "authentication": "pass", "permissions": "pass", "endpoint": "pass"}
    assert out["report"]["identity"]["username"] == "svc_es" and out["report"]["endpoint"]["version"] == "8.15.0-mock"
    assert [i["name"] for i in out["scopes"]["items"]] == ["logs-other", "winlogbeat-test"]
    assert API_KEY not in json.dumps(out)


def test_a_read_only_key_that_cannot_read_the_cluster_root_still_connects_with_the_version_unknown(tmp_path):
    """Found live: a key with only index read access gets HTTP 403 on GET /, which is not an authentication failure."""
    with FakeElastic(root_status=403) as fake:
        out = service(tmp_path).test_new("elastic", "api_key", cfg(fake), key())
    ids = {c["id"]: c["status"] for c in out["report"]["checks"]}
    assert out["report"]["ok"] and out["test_id"] and ids["authentication"] == "pass" and ids["endpoint"] == "warn" and "monitor" in next(c for c in out["report"]["checks"] if c["id"] == "endpoint")["detail"]


def test_a_wrong_key_fails_authentication_and_cannot_be_saved(tmp_path):
    with FakeElastic() as fake:
        out = service(tmp_path).test_new("elastic", "api_key", cfg(fake), key("d3Jvbmcta2V5LXZhbHVl"))
    ids = {c["id"]: c["status"] for c in out["report"]["checks"]}
    assert not out["report"]["ok"] and ids["authentication"] == "fail" and ids["permissions"] == "skipped" and out["test_id"] is None


def test_a_key_that_is_not_in_the_encoded_form_is_a_config_error_not_a_request(tmp_path):
    with FakeElastic() as fake:
        out = service(tmp_path).test_new("elastic", "api_key", cfg(fake), key("not a valid key!"))
        assert not out["report"]["ok"] and "encoded form" in out["report"]["checks"][0]["detail"] and fake.requests == [] and out["test_id"] is None


def test_an_administrative_account_is_refused_unless_accepted_visibly(tmp_path):
    with FakeElastic(admin=True, roles=("superuser",)) as fake:
        refused = service(tmp_path).test_new("elastic", "api_key", cfg(fake), key())
        accepted = service(tmp_path).test_new("elastic", "api_key", cfg(fake, allow_privileged=True), key())
    assert not refused["report"]["ok"] and next(c for c in refused["report"]["checks"] if c["id"] == "permissions")["status"] == "fail"
    assert accepted["report"]["ok"] and next(c for c in accepted["report"]["checks"] if c["id"] == "permissions")["status"] == "warn"


def test_a_role_that_cannot_list_indices_falls_back_to_manual_entry(tmp_path):
    with FakeElastic(resolve_status=403) as fake:
        out = service(tmp_path).test_new("elastic", "api_key", cfg(fake), key())
    assert out["report"]["ok"] and out["scopes"]["discovery"] == "denied"


def test_an_unreachable_endpoint_fails_at_the_network_check(tmp_path):
    out = service(tmp_path).test_new("elastic", "api_key", {"endpoint": "http://127.0.0.1:9", "verify_tls": True}, key())
    assert next(c for c in out["report"]["checks"] if c["id"] == "network_tls")["status"] == "fail"


def test_basic_authentication_is_supported_with_its_own_credential_fields(tmp_path):
    spec = default_registry().spec("elastic")
    assert [f.name for a, f in spec.secret_fields if a == "basic"] == ["username", "password"] and spec.capabilities["cancel"] is False


# --- plan and run -----------------------------------------------------------------------------------------------------
def test_the_plan_shows_the_exact_bodies_with_the_window_and_sends_nothing(tmp_path):
    svc = service(tmp_path)
    with FakeElastic() as fake:
        conn = connect(svc, fake)
        before = len(fake.requests)
        plan = svc.plan(conn["id"], {"text": RULE}, ["winlogbeat-test"], WINDOW)
        assert len(fake.requests) == before
    assert plan["runnable"] and plan["language"] == "Elasticsearch query (JSON)" and set(plan["queries"]) == {"coverage", "fields", "detection", "sample"}
    det = json.loads(plan["queries"]["detection"])
    assert det["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"] == plan["window"]["earliest"]
    assert "process.executable" in det["query"]["bool"]["filter"][-1]["query_string"]["query"] and plan["fields"] == ["process.command_line", "process.executable.caseless"]
    assert {"term": {"event.code": "1"}} in det["query"]["bool"]["filter"]


def run(svc, conn, indexes=("winlogbeat-test",)):
    plan = svc.plan(conn["id"], {"text": RULE}, list(indexes), WINDOW)
    started = svc.start_preflight(conn["id"], plan["plan_id"], True)
    svc.join(started["assessment_id"])
    return plan, svc.get_assessment(started["assessment_id"])


def test_the_bodies_sent_are_exactly_the_bodies_previewed(tmp_path):
    svc = service(tmp_path)
    with FakeElastic() as fake:
        conn = connect(svc, fake)
        plan, rec = run(svc, conn)
    assert fake.bodies == [json.loads(plan["queries"][k]) for k in ("coverage", "fields", "detection", "sample")]
    assert all(b.get("timeout") == "30s" for b in fake.bodies)


def test_a_finished_run_reports_real_counts_examples_and_three_separate_verdicts(tmp_path):
    svc = service(tmp_path)
    with FakeElastic(events=250, matches=3) as fake:
        conn = connect(svc, fake)
        _, rec = run(svc, conn)
    st = rec["assessment"]["statuses"]
    env = st["environment_preflight"]
    assert env["state"] == "potential_matches_found" and env["coverage"]["events_in_scope"] == 250 and env["matches"]["count"] == 3
    assert env["origin"] == "elastic_read_only_search" and rec["assessment"]["environment_provider"]["id"] == "elastic"
    assert env["matches"]["examples"][0]["host.name"] == "WS-0" and len(env["matches"]["examples"][0]["process.command_line"]) < 320
    assert (st["rule_validity"]["state"], st["attack_validation"]["state"]) == ("valid", "not_run") and API_KEY not in json.dumps(rec)


@pytest.mark.parametrize("kw,state,why", [({"events": 0}, "telemetry_missing_or_unsupported", "no_events_in_scope"),
                                          ({"present": {"process.executable.caseless"}}, "telemetry_missing_or_unsupported", "fields_not_observed"),
                                          ({"matches": 0}, "no_matches_in_window", "")])
def test_empty_and_missing_telemetry_are_classified_honestly(tmp_path, kw, state, why):
    svc = service(tmp_path)
    with FakeElastic(**kw) as fake:
        conn = connect(svc, fake)
        _, rec = run(svc, conn)
    env = rec["assessment"]["statuses"]["environment_preflight"]
    assert env["state"] == state and (rec["assessment"]["statuses"]["environment_preflight"].get("fields") or {}).get("missing", []) == (["process.command_line"] if why == "fields_not_observed" else [])


def test_a_missing_read_privilege_is_a_permission_failure_before_any_search(tmp_path):
    svc = service(tmp_path)
    with FakeElastic(can_read=False) as fake:
        conn = connect(svc, fake)
        _, rec = run(svc, conn)
        assert fake.bodies == []
    env = rec["assessment"]["statuses"]["environment_preflight"]
    assert env["state"] == "query_failed" and env["error"]["kind"] == "permission" and "read access" in env["error"]["message"]


@pytest.mark.parametrize("kw,kind", [({"search_error": "bad query near token"}, "query"), ({"timed_out": True}, "timeout"), ({"shard_failed": 1}, "query")])
def test_search_failures_are_named_and_never_reported_as_clean_results(tmp_path, kw, kind):
    svc = service(tmp_path)
    with FakeElastic(**kw) as fake:
        conn = connect(svc, fake)
        _, rec = run(svc, conn)
    env = rec["assessment"]["statuses"]["environment_preflight"]
    assert env["state"] == "query_failed" and env["error"]["kind"] == kind


def test_a_key_revoked_after_saving_fails_the_run_as_authentication_and_the_message_holds_no_credential(tmp_path):
    svc = service(tmp_path)
    with FakeElastic() as fake:
        conn = connect(svc, fake)
        fake.key = "rotated"
        _, rec = run(svc, conn)
    assert rec["assessment"]["statuses"]["environment_preflight"]["error"]["kind"] == "auth" and API_KEY not in json.dumps(rec)


def test_elastic_searches_cannot_be_cancelled_and_the_service_says_so(tmp_path):
    svc = service(tmp_path)
    with FakeElastic() as fake:
        conn = connect(svc, fake)
        _, rec = run(svc, conn)
    with pytest.raises(IntegrationError) as exc:
        svc.cancel(rec["id"])
    assert exc.value.kind == "conflict" and "cannot be cancelled" in str(exc.value)


def test_another_owner_cannot_use_an_elastic_connection(tmp_path):
    store = vault.MemorySecretStore()
    alice, bob = service(tmp_path, "alice", store), service(tmp_path, "bob", store)
    with FakeElastic() as fake:
        conn = connect(alice, fake)
        for call in (lambda: bob.get_connection(conn["id"]), lambda: bob.plan(conn["id"], {"text": RULE}, ["winlogbeat-test"], WINDOW), lambda: bob.discover(conn["id"])):
            with pytest.raises(IntegrationError) as exc:
                call()
            assert exc.value.kind == "not_found"


def test_the_packet_is_labelled_for_elasticsearch_not_splunk(tmp_path):
    svc = service(tmp_path)
    with FakeElastic() as fake:
        conn = connect(svc, fake)
        _, rec = run(svc, conn)
    out = svc.export(rec["id"])
    md = out["files"]["review_packet.md"]
    assert "## 4. Elasticsearch query (not deployed)" in md and "query.json" in out["files"] and "Splunk" not in md
