"""LIVE tests of the Splunk connector against a REAL Splunk Enterprise instance. Nothing here is mocked.

Opt-in: they never run by default (the `live` marker is deselected in pyproject.toml, and SPLUNK_LIVE_TEST=1 is required). They need
the throwaway instance prepared by tools/splunk_live_setup.py, whose labelled events define every expected number below:

    set -a; . data/splunk_live/splunk.env; . data/splunk_live/accounts.env; set +a
    SPLUNK_LIVE_TEST=1 uv run pytest tests/live -m live -q

Mocked tests are in tests/test_splunk*.py. Observed numbers are written to data/splunk_live/live_results.json for the report.
"""
import base64
import json
import os
import ssl
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from shakedown import assess, splunk
from shakedown.splunk import SplunkConfig, SplunkConnector, SplunkError

pytestmark = [pytest.mark.live, pytest.mark.skipif(os.environ.get("SPLUNK_LIVE_TEST") != "1", reason="live Splunk test: set SPLUNK_LIVE_TEST=1")]

ROOT = Path(__file__).resolve().parents[2]
LIVE_DIR = ROOT / "data/splunk_live"
SYSMON = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
BASE = os.environ.get("SPLUNK_BASE_URL", "")
RESULTS: dict = {}


def now_window(hours=6):
    now = datetime.now(timezone.utc)
    return now - timedelta(hours=hours), now


def adfind_rule() -> str:
    rec = json.loads((ROOT / "demo/replay/pua-adfind-exe-execution.json").read_text(encoding="utf-8"))
    return rec["iterations"][rec["best_index"]]["rule_text"]


def make_rule(title: str, category: str, detection: dict) -> str:
    return yaml.safe_dump({"title": title, "id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "status": "test", "description": "live test rule",
                           "author": "test", "date": "2026-10-27", "logsource": {"category": category, "product": "windows"},
                           "detection": {**detection, "condition": "selection"}, "level": "low"})


def token_connector(**kw) -> SplunkConnector:
    cfg = dict(base_url=BASE, token=os.environ.get("SPLUNK_TOKEN"), allowed_indexes=("shakedown_test", "shakedown_bulk"),
               verify_tls=False, search_timeout_s=60)
    cfg.update(kw)
    return SplunkConnector(SplunkConfig(**cfg), poll_interval_s=0.2)


def basic_connector(user: str, **kw) -> SplunkConnector:
    cfg = dict(base_url=BASE, username=user, password=os.environ[f"{user.upper()}_PASSWORD"], allowed_indexes=("shakedown_test", "shakedown_other"),
               verify_tls=False, search_timeout_s=60)
    cfg.update(kw)
    return SplunkConnector(SplunkConfig(**cfg), poll_interval_s=0.2)


def my_jobs(conn) -> list[str]:
    return [e["name"] for e in conn._request("GET", "/services/search/jobs", params={"count": "0"}).get("entry", [])]


def admin_count(spl: str) -> int:
    """Ground truth straight from Splunk as admin (verification only; the connector never uses admin)."""
    pw = (LIVE_DIR / "admin.pw").read_text(encoding="utf-8").strip()
    form = urllib.parse.urlencode({"search": spl, "exec_mode": "oneshot", "earliest_time": "-7d", "latest_time": "now", "output_mode": "json"}).encode()
    req = urllib.request.Request(BASE + "/services/search/jobs", data=form, method="POST",
                                 headers={"Authorization": "Basic " + base64.b64encode(f"admin:{pw}".encode()).decode()})
    return int(json.loads(urllib.request.urlopen(req, timeout=120, context=ssl._create_unverified_context()).read())["results"][0]["count"])


@pytest.fixture(scope="module", autouse=True)
def write_results():
    yield
    out = Path(os.environ.get("SPLUNK_LIVE_RESULTS", LIVE_DIR / "live_results.json"))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(RESULTS, indent=1, default=str), encoding="utf-8")


# --- the instance and the account ------------------------------------------------------------------------------------
def test_the_account_holds_exactly_the_search_capability_and_the_bad_accounts_are_what_they_claim():
    ident = token_connector()._identity()
    assert ident["capabilities"] == ["search"] and ident["warnings"] == [] and ident["roles"] == ["shakedown_preflight"]
    assert basic_connector("shakedown_noperm")._identity()["capabilities"] == []
    RESULTS["account"] = {"username": ident["username"], "roles": ident["roles"], "capabilities": ident["capabilities"], "warnings": ident["warnings"]}


# --- the detection query, end to end -------------------------------------------------------------------------------------
def test_known_matching_events_produce_exactly_the_expected_matches_and_the_decoys_do_not():
    lo, hi = now_window(6)
    out = token_connector().preflight(adfind_rule(), indexes=["shakedown_test"], earliest=lo, latest=hi)

    assert out["status"] == "potential_matches_found" and out["coverage"]["events_in_scope"] == 4 and out["matches"]["count"] == 2
    assert {e["host"] for e in out["matches"]["examples"]} == {"LAB-W10-01", "LAB-W10-02"}
    assert all(e["OriginalFileName"] == "AdFind.exe" and e["EventCode"] == "1" for e in out["matches"]["examples"])
    assert out["fields"]["missing"] == [] and 'index="shakedown_test"' in out["queries"]["detection"]
    assert 'source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"' in out["queries"]["detection"] and "EventCode=1" in out["queries"]["detection"]
    assert my_jobs(token_connector()) == []  # every search job it created was deleted
    RESULTS["adfind_end_to_end"] = {"expected": {"events_in_scope": 4, "matches": 2, "hosts": ["LAB-W10-01", "LAB-W10-02"]},
                                    "observed": {"events_in_scope": out["coverage"]["events_in_scope"], "matches": out["matches"]["count"],
                                                 "hosts": sorted(e["host"] for e in out["matches"]["examples"])},
                                    "queries": out["queries"], "converted_detection": out["converted_detection"], "scope": out["scope"],
                                    "fields": out["fields"], "elapsed_s": out["elapsed_s"], "tls_verified": out["connector"]["tls_verified"]}


def test_an_unrelated_event_matches_only_a_rule_written_for_it():
    lo, hi = now_window(6)
    notepad = make_rule("notepad", "process_creation", {"selection": {"Image|endswith": "\\notepad.exe"}})
    absent = make_rule("absent", "process_creation", {"selection": {"Image|endswith": "\\definitely_absent_tool.exe"}})
    n = token_connector().preflight(notepad, indexes=["shakedown_test"], earliest=lo, latest=hi)
    a = token_connector().preflight(absent, indexes=["shakedown_test"], earliest=lo, latest=hi)

    assert n["status"] == "potential_matches_found" and n["matches"]["count"] == 1 and n["matches"]["examples"][0]["host"] == "LAB-W10-01"
    assert a["status"] == "no_matches_in_window" and a["matches"]["count"] == 0 and a["coverage"]["events_in_scope"] == 4
    RESULTS["unrelated"] = {"notepad_rule": {"expected_matches": 1, "observed": n["matches"]["count"], "detection": n["converted_detection"]},
                            "absent_rule": {"expected_matches": 0, "observed": a["matches"]["count"], "events_in_scope": a["coverage"]["events_in_scope"]}}


def test_index_source_eventcode_and_time_scoping_each_remove_a_decoy():
    rule = adfind_rule()
    conn = token_connector()
    detect = conn.preflight(rule, indexes=["shakedown_test"], earliest=now_window(6)[0], latest=now_window(6)[1])["converted_detection"]
    unscoped = f'search index="shakedown_test" {detect} | stats count'
    lo6, hi = now_window(6)
    lo7d, _ = now_window(24 * 7)
    unscoped_6h = int(conn._search(unscoped, lo6, hi, 1)["rows"][0]["count"])
    unscoped_7d = int(conn._search(unscoped, lo7d, hi, 1)["rows"][0]["count"])
    scoped_6h = conn.preflight(rule, indexes=["shakedown_test"], earliest=lo6, latest=hi)["matches"]["count"]
    scoped_7d = conn.preflight(rule, indexes=["shakedown_test"], earliest=lo7d, latest=hi)["matches"]["count"]

    # 6 h window: two real matches plus the wrong-EventCode decoy and the wrong-source decoy are visible without the scope
    assert (unscoped_6h, scoped_6h) == (4, 2)
    # 7 d window adds only the old event, which the 6 h window correctly excluded
    assert (unscoped_7d, scoped_7d) == (5, 3)
    assert admin_count('search index="shakedown_other" OriginalFileName="AdFind.exe" | stats count') == 1  # the other-index decoy exists...
    other = token_connector(allowed_indexes=("shakedown_test", "shakedown_other")).preflight(rule, indexes=["shakedown_other"], earliest=lo6, latest=hi)
    assert other["status"] == "telemetry_missing_or_unsupported" and other["status_detail"] == "no_events_in_scope"  # ...but this account cannot see it
    with pytest.raises(SplunkError) as exc:  # and the client-side allowlist refuses before any request
        token_connector(allowed_indexes=("shakedown_test",)).preflight(rule, indexes=["shakedown_other"], earliest=lo6, latest=hi)
    assert exc.value.kind == "scope"
    RESULTS["scoping"] = {"rule_equivalent_without_scope_6h": unscoped_6h, "with_source_and_eventcode_scope_6h": scoped_6h,
                          "without_scope_7d": unscoped_7d, "with_scope_7d": scoped_7d,
                          "other_index_events_that_exist_for_admin": 1, "other_index_events_visible_to_the_account": other["coverage"]["events_in_scope"],
                          "client_allowlist_refusal": exc.value.kind}


def test_empty_results_and_unsupported_fields_are_reported_as_what_they_are():
    lo, hi = now_window(6)
    registry = make_rule("registry", "registry_set", {"selection": {"TargetObject|contains": "\\Run"}})
    field = make_rule("field", "process_creation", {"selection": {"NoSuchField|contains": "x"}})
    r = token_connector().preflight(registry, indexes=["shakedown_test"], earliest=lo, latest=hi)
    f = token_connector().preflight(field, indexes=["shakedown_test"], earliest=lo, latest=hi)

    assert r["status"] == "telemetry_missing_or_unsupported" and r["status_detail"] == "no_events_in_scope" and r["coverage"]["events_in_scope"] == 0
    assert f["status"] == "telemetry_missing_or_unsupported" and f["status_detail"] == "fields_not_observed" and f["fields"]["missing"] == ["NoSuchField"]
    assert f["coverage"]["events_in_scope"] == 4  # telemetry exists; the field does not: a different problem from the registry case
    RESULTS["empty_and_unsupported"] = {"registry_set_rule": {"status": r["status"], "detail": r["status_detail"], "events_in_scope": 0},
                                        "unknown_field_rule": {"status": f["status"], "detail": f["status_detail"], "missing": f["fields"]["missing"],
                                                               "events_in_scope": f["coverage"]["events_in_scope"]}}


# --- failures, accurately named ----------------------------------------------------------------------------------------
def test_authentication_permission_privilege_and_query_failures_are_named_correctly():
    lo, hi = now_window(6)
    rule = adfind_rule()
    seen = {}

    def kind(label, fn):
        with pytest.raises(SplunkError) as exc:
            fn()
        seen[label] = {"kind": exc.value.kind, "message": str(exc.value)[:200]}
        return exc.value.kind

    assert kind("wrong_token", lambda: token_connector(token="eyJhbGciOiJIUzUxMiJ9.bad.bad").preflight(rule, indexes=["shakedown_test"], earliest=lo, latest=hi)) == "auth"
    assert kind("wrong_password", lambda: basic_connector("shakedown_svc", password="x" * 12).preflight(rule, indexes=["shakedown_test"], earliest=lo, latest=hi)) == "auth"
    assert kind("no_search_permission", lambda: basic_connector("shakedown_noperm").preflight(rule, indexes=["shakedown_test"], earliest=lo, latest=hi)) == "permission"
    assert kind("admin_class_account", lambda: basic_connector("shakedown_overpriv").preflight(rule, indexes=["shakedown_test"], earliest=lo, latest=hi)) == "privileged_account"
    assert kind("malformed_query", lambda: token_connector()._search('search index="shakedown_test" | where (', lo, hi, 1)) == "query"
    assert "malformed" in seen["malformed_query"]["message"].lower()
    assert kind("write_command_refused_locally", lambda: token_connector()._search('search index="shakedown_test" | outputlookup leak.csv', lo, hi, 1)) == "unsafe_query"
    assert my_jobs(token_connector()) == []  # the refused write command never became a job
    RESULTS["failures"] = seen


def test_tls_verification_is_enforced_and_a_failure_names_the_remedy():
    ca = LIVE_DIR / "splunk_ca.pem"
    if not ca.exists():
        pytest.skip("CA bundle not copied from the container")
    with pytest.raises(SplunkError) as exc:
        token_connector(verify_tls=True, ca_bundle=str(ca))._identity()
    assert exc.value.kind == "tls" and "SPLUNK_CA_BUNDLE" in str(exc.value)  # Splunk's default certificate does not name 127.0.0.1
    RESULTS["tls"] = {"verified_attempt_with_default_cert": {"kind": exc.value.kind, "message": str(exc.value)[:220]},
                      "verification_off_is_recorded": token_connector()._identity() is not None}


def test_a_search_that_runs_past_the_timeout_is_cancelled_and_deleted():
    lo, hi = now_window(3)
    slow = 'search index="shakedown_bulk" | regex _raw="(a|b|c|d|e|f|s|v|c|h|o|t)+zz[0-9]+q" | stats count'
    full = token_connector()
    t0 = time.monotonic()
    done = full._search(slow, lo, hi, 1)  # how long the same search really takes
    natural = time.monotonic() - t0
    assert natural > 2.0, f"the search must genuinely take longer than the timeout (took {natural:.1f}s)"

    conn = token_connector(search_timeout_s=1.0)
    t0 = time.monotonic()
    with pytest.raises(SplunkError) as exc:
        conn._search(slow, lo, hi, 1)
    waited = time.monotonic() - t0
    assert exc.value.kind == "timeout" and waited < natural + 1
    time.sleep(1)
    assert my_jobs(conn) == []  # cancelled and deleted on the real server
    RESULTS["timeout"] = {"search_natural_duration_s": round(natural, 1), "timeout_s": 1.0, "reported_kind": exc.value.kind, "returned_after_s": round(waited, 1),
                          "jobs_left_on_server": 0, "rows_if_it_had_finished": done["rows"]}


def test_a_running_search_can_be_cancelled_and_leaves_no_job():
    lo, hi = now_window(3)
    slow = 'search index="shakedown_bulk" | regex _raw="(a|b|c|d|e|f|s|v|c|h|o|t)+zz[0-9]+q" | stats count'
    conn = token_connector(search_timeout_s=60)
    threading.Timer(1.0, conn.cancel).start()
    t0 = time.monotonic()
    with pytest.raises(SplunkError) as exc:
        conn._search(slow, lo, hi, 1)
    waited = time.monotonic() - t0
    assert exc.value.kind == "cancelled" and waited < 3.0
    time.sleep(1)
    assert my_jobs(conn) == []
    RESULTS["cancel"] = {"cancel_requested_after_s": 1.0, "reported_kind": exc.value.kind, "returned_after_s": round(waited, 1), "jobs_left_on_server": 0}


# --- the whole product path ---------------------------------------------------------------------------------------------
def test_basic_authentication_reaches_the_same_answer_as_the_token():
    lo, hi = now_window(6)
    out = basic_connector("shakedown_svc").preflight(adfind_rule(), indexes=["shakedown_test"], earliest=lo, latest=hi)
    assert out["connector"]["credential_type"] == "basic" and out["matches"]["count"] == 2 and out["coverage"]["events_in_scope"] == 4
    RESULTS["basic_auth"] = {"matches": out["matches"]["count"], "events_in_scope": out["coverage"]["events_in_scope"]}


def test_the_assess_command_builds_a_packet_from_the_real_search(tmp_path):
    rule_file = tmp_path / "rule.yml"
    rule_file.write_text(adfind_rule(), encoding="utf-8")
    out = Path(os.environ.get("SPLUNK_LIVE_PACKET", tmp_path / "packet"))
    code = assess.main(["--rule", str(rule_file), "--splunk", "--splunk-index", "shakedown_test", "--last-hours", "6", "--out", str(out)],
                       env=dict(os.environ), runner_factory=lambda k: None)
    packet = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    env = packet["statuses"]["environment_preflight"]
    assert code == 0 and env["state"] == "potential_matches_found" and env["matches"]["count"] == 2
    assert packet["statuses"]["rule_validity"]["state"] == "valid" and packet["statuses"]["attack_validation"]["state"] == "not_run"
    assert os.environ["SPLUNK_TOKEN"] not in (out / "assessment.json").read_text(encoding="utf-8")
    assert os.environ["SPLUNK_TOKEN"] not in (out / "review_packet.md").read_text(encoding="utf-8")
    RESULTS["assess_cli"] = {"environment_state": env["state"], "matches": env["matches"]["count"], "rule_validity": packet["statuses"]["rule_validity"]["state"],
                             "attack_validation": packet["statuses"]["attack_validation"]["state"], "recommendation": packet["recommendation"]["level"]}
