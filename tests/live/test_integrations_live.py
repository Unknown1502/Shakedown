"""LIVE tests of the integration service against real SIEMs. Opt-in, never run by default.

    SPLUNK_LIVE_TEST=1   needs the throwaway Splunk container and data/splunk_live/ from tools/splunk_live_setup.py
    ELASTIC_LIVE_TEST=1  needs the throwaway Elasticsearch container and data/elastic_live/ from tools/elastic_live_setup.py
    uv run pytest tests/live/test_integrations_live.py -m live -q

These talk to real servers (loopback test instances with SIMULATED Sysmon events). A pass is evidence about the connector on that instance; it is not
evidence about a production SIEM, a real Sysmon add-on, or Elastic Cloud / Splunk Cloud.
"""
import json
import os
import tempfile
from pathlib import Path

import pytest

from shakedown.integrations import vault
from shakedown.integrations.base import IntegrationError
from shakedown.integrations.registry import default_registry
from shakedown.integrations.service import IntegrationService

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.live
RULE = (ROOT / "data/splunk_live/rule_adfind.yml")


def load(path: Path) -> dict:
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip("\"'")
    return out


class Rules:
    def __init__(self, text):
        self.text = text

    def list(self):
        return []

    def get(self, ref):
        return {"text": self.text, "label": "lab rule", "record": None}


def make_service(env: dict, text: str) -> IntegrationService:
    return IntegrationService(data_dir=Path(tempfile.mkdtemp()), registry=default_registry(), secret_store=vault.MemorySecretStore(), rules=Rules(text), environ=env)


def run(svc, conn, indexes, hours=48):
    plan = svc.plan(conn["id"], {"ref": "x"}, indexes, {"last_hours": hours})
    assert plan["runnable"], plan
    started = svc.start_preflight(conn["id"], plan["plan_id"], True)
    svc.join(started["assessment_id"], 180)
    return plan, svc.get_assessment(started["assessment_id"])


# ======================================== Splunk Enterprise ========================================================
splunk_live = pytest.mark.skipif(os.environ.get("SPLUNK_LIVE_TEST") != "1" or not (ROOT / "data/splunk_live/splunk.env").exists(), reason="set SPLUNK_LIVE_TEST=1 with the throwaway Splunk running")


@pytest.fixture(scope="module")
def sp():
    env = load(ROOT / "data/splunk_live/splunk.env")
    svc = make_service(env, RULE.read_text(encoding="utf-8"))
    cfg = {"endpoint": env["SPLUNK_BASE_URL"], "verify_tls": False, "accept_insecure_tls": True}
    t = svc.test_new("splunk_enterprise", "token", cfg, {"mode": "env", "env": {"token": "SPLUNK_TOKEN"}})
    return svc, env, cfg, t


@splunk_live
def test_splunk_connection_passes_all_four_checks_and_reads_the_real_version(sp):
    svc, env, cfg, t = sp
    assert t["report"]["ok"] and [c["status"] for c in t["report"]["checks"]] == ["pass"] * 4
    assert t["report"]["endpoint"]["version"] == "10.6.1.1" and t["report"]["identity"]["capabilities"] == ["search"]


@splunk_live
def test_splunk_certificate_verification_on_fails_at_tls_with_the_remedy(sp):
    svc, env, cfg, _ = sp
    out = svc.test_new("splunk_enterprise", "token", {**cfg, "verify_tls": True, "accept_insecure_tls": False}, {"mode": "env", "env": {"token": "SPLUNK_TOKEN"}})
    first = out["report"]["checks"][0]
    assert first["status"] == "fail" and "TLS certificate verification failed" in first["detail"] and out["test_id"] is None


@splunk_live
def test_splunk_discovers_only_visible_non_internal_indexes(sp):
    names = [i["name"] for i in sp[3]["scopes"]["items"]]
    assert "shakedown_test" in names and not any(n.startswith("_") for n in names)


@splunk_live
def test_splunk_preflight_through_the_service_matches_the_known_events(sp):
    svc, env, cfg, t = sp
    conn = svc.save(t["test_id"], "live splunk", {"indexes": ["shakedown_test"]})
    plan, rec = run(svc, conn, ["shakedown_test"])
    env_st = rec["assessment"]["statuses"]["environment_preflight"]
    assert rec["status"] == "potential_matches_found" and env_st["coverage"]["events_in_scope"] == 4 and env_st["matches"]["count"] == 2
    assert sorted({e["host"] for e in env_st["matches"]["examples"]}) == ["LAB-W10-01", "LAB-W10-02"]
    assert env_st["queries"] == plan["queries"]  # what the live run reports it executed is exactly what was previewed
    assert env["SPLUNK_TOKEN"] not in json.dumps([rec, svc.export(rec["id"])]) and rec["assessment"]["statuses"]["attack_validation"]["state"] == "not_run"
    svc.disconnect(conn["id"], delete_assessments=True)


@splunk_live
def test_splunk_a_wrong_token_fails_authentication_after_the_network_check_passed(sp):
    svc, env, cfg, _ = sp
    out = svc.test_new("splunk_enterprise", "token", cfg, {"mode": "paste", "values": {"token": "definitely-not-the-token"}})
    ids = {c["id"]: c["status"] for c in out["report"]["checks"]}
    assert ids["network_tls"] == "pass" and ids["authentication"] == "fail"


# ======================================== Elasticsearch =============================================================
elastic_live = pytest.mark.skipif(os.environ.get("ELASTIC_LIVE_TEST") != "1" or not (ROOT / "data/elastic_live/elastic.env").exists(), reason="set ELASTIC_LIVE_TEST=1 with the throwaway Elasticsearch running")


@pytest.fixture(scope="module")
def es():
    env = {**load(ROOT / "data/elastic_live/elastic.env"), **load(ROOT / "data/elastic_live/accounts.env")}
    svc = make_service(env, RULE.read_text(encoding="utf-8"))
    cfg = {"endpoint": env["ELASTIC_BASE_URL"], "verify_tls": True, "ca_bundle": env["ELASTIC_CA_BUNDLE"]}
    t = svc.test_new("elastic", "api_key", cfg, {"mode": "env", "env": {"api_key": "ELASTIC_API_KEY"}})
    return svc, env, cfg, t


@elastic_live
def test_elastic_certificate_verification_succeeds_with_the_ca_and_fails_without_it(es):
    svc, env, cfg, t = es
    assert t["report"]["ok"] and t["report"]["endpoint"]["tls_verified"] is True and t["report"]["checks"][0]["detail"] == "connected over verified TLS"
    no_ca = svc.test_new("elastic", "api_key", {"endpoint": env["ELASTIC_BASE_URL"], "verify_tls": True}, {"mode": "env", "env": {"api_key": "ELASTIC_API_KEY"}})
    assert no_ca["report"]["checks"][0]["status"] == "fail" and "TLS certificate verification failed" in no_ca["report"]["checks"][0]["detail"]


@elastic_live
def test_elastic_a_read_only_key_authenticates_without_the_monitor_privilege_and_sees_only_its_index(es):
    svc, env, cfg, t = es
    ids = {c["id"]: c["status"] for c in t["report"]["checks"]}
    assert ids == {"network_tls": "pass", "authentication": "pass", "permissions": "pass", "endpoint": "warn"}
    assert [i["name"] for i in t["scopes"]["items"]] == [env["ELASTIC_INDEX"]] and t["report"]["identity"]["authentication_type"] == "api_key"


@elastic_live
def test_elastic_preflight_matches_the_known_events_and_the_bodies_sent_are_the_bodies_previewed(es):
    svc, env, cfg, t = es
    conn = svc.save(t["test_id"], "live elastic", {"indexes": [env["ELASTIC_INDEX"], env["ELASTIC_OTHER_INDEX"]]})
    plan, rec = run(svc, conn, [env["ELASTIC_INDEX"]])
    st = rec["assessment"]["statuses"]["environment_preflight"]
    assert rec["status"] == "potential_matches_found" and st["coverage"]["events_in_scope"] == 4 and st["matches"]["count"] == 2 and st["fields"]["missing"] == []
    assert sorted({e["host.name"] for e in st["matches"]["examples"]}) == ["LAB-W10-01", "LAB-W10-02"] and st["queries"] == plan["queries"]
    assert env["ELASTIC_API_KEY"] not in json.dumps([rec, svc.export(rec["id"])])
    bad = run(svc, conn, [env["ELASTIC_OTHER_INDEX"]])[1]["assessment"]["statuses"]["environment_preflight"]
    assert bad["state"] == "query_failed" and bad["error"]["kind"] == "permission" and "read access" in bad["error"]["message"]
    svc.disconnect(conn["id"], delete_assessments=True)


@elastic_live
def test_elastic_a_caseless_subfield_mapping_is_used_and_checked(es):
    svc, env, cfg, t = es
    text = RULE.read_text(encoding="utf-8").replace("selection_image:\n    OriginalFileName: AdFind.exe", "selection_image:\n    Image|endswith: '\\\\AdFind.exe'")
    svc.rules = Rules(text)
    conn = svc.save(svc.test_new("elastic", "api_key", cfg, {"mode": "env", "env": {"api_key": "ELASTIC_API_KEY"}})["test_id"], "live elastic image", {"indexes": [env["ELASTIC_INDEX"]]})
    plan, rec = run(svc, conn, [env["ELASTIC_INDEX"]])
    st = rec["assessment"]["statuses"]["environment_preflight"]
    assert "process.executable.caseless" in plan["fields"] and st["matches"]["count"] == 1 and st["fields"]["missing"] == []
    svc.disconnect(conn["id"])


@elastic_live
def test_elastic_superuser_is_refused_and_a_no_permission_account_fails_only_when_it_searches(es):
    svc, env, cfg, _ = es
    over = svc.test_new("elastic", "basic", cfg, {"mode": "paste", "values": {"username": "shakedown_overpriv_es", "password": env["ELASTIC_OVERPRIV_PASSWORD"]}})
    assert not over["report"]["ok"] and next(c for c in over["report"]["checks"] if c["id"] == "permissions")["status"] == "fail"
    none = svc.test_new("elastic", "basic", cfg, {"mode": "paste", "values": {"username": "shakedown_noperm_es", "password": env["ELASTIC_NOPERM_PASSWORD"]}})
    assert none["report"]["ok"]
    conn = svc.save(none["test_id"], "no permission", {"indexes": [env["ELASTIC_INDEX"]]})
    err = run(svc, conn, [env["ELASTIC_INDEX"]])[1]["assessment"]["statuses"]["environment_preflight"]
    assert err["state"] == "query_failed" and err["error"]["kind"] == "permission"


@elastic_live
def test_elastic_a_wrong_key_fails_authentication(es):
    svc, env, cfg, _ = es
    out = svc.test_new("elastic", "api_key", cfg, {"mode": "paste", "values": {"api_key": "d3Jvbmcta2V5LXZhbHVlLWZvci10ZXN0"}})
    ids = {c["id"]: c["status"] for c in out["report"]["checks"]}
    assert ids["network_tls"] == "pass" and ids["authentication"] == "fail"
