"""Three independent verdicts, the analyst review packet, and the command line that ties BYO logs and Splunk together.

Splunk here is the mock server from tests/fake_splunk.py; nothing in this file is live verification.
"""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from fake_splunk import TOKEN, FakeSplunk
from test_byo import RULE, RULE_ID, evtx, runner as fake_runner, write_manifest
from test_splunk import DETECT, make_handler

from shakedown import assess, splunk
from shakedown.validate import Validation

OK = Validation(ok=True, sigma_output="No rule errors found.")
BAD = Validation(ok=False, errors=["rule must contain at least one condition"])
VALIDATED = {"verdict": "validated_on_supplied_attack_evidence", "reasons": [], "caveats": [], "samples": [],
             "expected_detections": 1, "expected_detections_met": 1, "negative_controls": 0, "negative_controls_clean": 0}
BENIGN_OK = {"verdict": "no_benign_matches", "supports_false_positive_claim": True, "matching_events": 0, "sets": [], "reasons": []}
ENV = {"status": "no_matches_in_window", "status_detail": "", "explanation": "x", "matches": {"count": 0, "examples": []},
       "scope": {"indexes": ["win"], "earliest": "a", "latest": "b", "logsource_scope": 'source="s" EventCode=1', "logsource_note": "n"},
       "queries": {"detection": "search ...", "coverage": "c", "fields": "f", "sample": "s"}, "coverage": {"events_in_scope": 10},
       "fields": {"rule_fields": ["Image"], "observed": ["Image"], "missing": []}, "notes": ["does not show"],
       "connector": {"live_verified": False, "name": "splunk-rest-read-only"}, "identity": {"username": "svc"}}


def attack(origin="organisation_supplied", result=VALIDATED, benign=BENIGN_OK):
    return {"origin": origin, "result": result, "benign": benign, "record": None}


def keys(node):
    if isinstance(node, dict):
        for k, v in node.items():
            yield k
            yield from keys(v)
    elif isinstance(node, list):
        for v in node:
            yield from keys(v)


def build(**kw):
    base = dict(validation=OK, attack=attack(), environment=ENV)
    base.update(kw)
    return assess.build_assessment(RULE, **base)


# --- R4: three independent verdicts --------------------------------------------------------------------------------
def test_the_three_statuses_are_independent_and_there_is_no_single_pass():
    a = build()
    assert set(a["statuses"]) == {"rule_validity", "attack_validation", "environment_preflight"}
    assert a["statuses"]["rule_validity"]["state"] == "valid"
    assert a["statuses"]["attack_validation"]["state"] == "validated_on_supplied_attack_evidence"
    assert a["statuses"]["environment_preflight"]["state"] == "no_matches_in_window"
    assert not {"pass", "passed", "overall", "overall_status", "ok"} & set(keys(a))  # nothing collapses the three into one flag


def test_a_lab_pass_and_a_clean_siem_window_are_not_combined_into_assurance():
    a = build()
    text = a["recommendation"]["text"].lower()
    assert a["recommendation"]["automatic_deployment"] is False and "nothing was deployed" in text
    assert "does not show" in " ".join(a["limitations"]).lower()
    assert a["recommendation"]["level"] == "review_for_staged_deployment"


@pytest.mark.parametrize("override, expected_level", [
    (dict(validation=BAD), "do_not_deploy"),
    (dict(attack=attack(result={**VALIDATED, "verdict": "attack_not_detected"})), "do_not_deploy"),
    (dict(attack=attack(result={**VALIDATED, "verdict": "insufficient_evidence"})), "needs_more_evidence"),
    (dict(environment={**ENV, "status": "telemetry_missing_or_unsupported"}), "needs_more_evidence"),
    (dict(environment={"status": "query_failed", "error": {"kind": "auth", "message": "Splunk rejected the credentials"}}), "needs_more_evidence"),
    (dict(environment=None), "needs_more_evidence"),
    (dict(attack=attack(benign={**BENIGN_OK, "verdict": "benign_evidence_weak", "supports_false_positive_claim": False})), "needs_more_evidence"),
    (dict(environment={**ENV, "status": "potential_matches_found", "matches": {"count": 3, "examples": [{}]}}), "review_matches_first"),
])
def test_the_recommendation_never_outruns_the_evidence(override, expected_level):
    assert build(**override)["recommendation"]["level"] == expected_level


def test_an_invalid_rule_is_not_tested_or_searched():
    a = build(validation=BAD)
    assert a["statuses"]["rule_validity"]["state"] == "invalid"
    assert a["statuses"]["attack_validation"]["state"] == "not_run" and a["statuses"]["environment_preflight"]["state"] == "not_run"


def test_each_status_says_where_its_evidence_came_from():
    a = build(attack=attack(origin="controlled_lab_fixture"))
    assert a["statuses"]["attack_validation"]["origin"] == "controlled_lab_fixture"
    assert a["statuses"]["environment_preflight"]["origin"] == "splunk_read_only_search"
    assert build()["statuses"]["attack_validation"]["origin"] == "organisation_supplied"


def test_a_failed_search_is_a_failed_search_not_zero_matches():
    a = build(environment={"status": "query_failed", "error": {"kind": "query", "message": "Unable to parse the search"}})
    env = a["statuses"]["environment_preflight"]
    assert env["state"] == "query_failed" and env["error"]["kind"] == "query" and "Unable to parse" in env["detail"]


def test_the_connector_label_is_carried_through():
    assert build()["statuses"]["environment_preflight"]["connector_label"] == "implemented but not live-verified"


# --- lab evidence from a Shakedown run record ------------------------------------------------------------------------
def lab_record(detected=1, best=1, heldout_hits=0):
    return {"iterations": [{"action": "generate", "rule_text": RULE, "evaluation": {"attack_total": 1, "attack_detected": 0, "attack_missed": ["x.evtx"],
                                                                                    "benign": {"dev": {"files_total": 129, "files_with_hits": 0, "hits": 0}}}},
                           {"action": "repair", "rule_text": RULE, "evaluation": {"attack_total": 1, "attack_detected": detected, "attack_missed": [] if detected else ["x.evtx"],
                                                                                  "benign": {"dev": {"files_total": 129, "files_with_hits": 0, "hits": 0}}}}],
            "best_index": best, "heldout": {"win10": {"files_total": 352, "files_with_hits": 1 if heldout_hits else 0, "hits": heldout_hits}},
            "research": {"primary": {"url": "https://example.org/report", "retrieved_at": "t"}, "screening": {"policy": "exclude", "sources": []}},
            "source_mode": {"mode": "leakage-controlled"}, "scenario": {"title": "AdFind"}}


def test_a_run_record_becomes_labelled_lab_evidence_with_the_repair_caveat():
    adapted = assess.lab_attack_from_record(lab_record())
    assert adapted["origin"] == "controlled_lab_fixture" and adapted["result"]["verdict"] == "validated_on_supplied_attack_evidence"
    assert any("not independent" in c.lower() or "not a held-out" in c.lower() for c in adapted["result"]["caveats"])
    assert any("one attack sample" in c.lower() for c in adapted["result"]["caveats"])
    assert assess.lab_attack_from_record(lab_record(detected=0))["result"]["verdict"] == "attack_not_detected"


# --- the packet -----------------------------------------------------------------------------------------------------
def test_the_packet_has_every_section_and_the_files(tmp_path):
    a = build(report={"url": "https://example.org/report", "sources": [{"url": "https://example.org/x", "status": "excluded", "reasons": ["sigma_mirror"]}]})
    assess.write_packet(tmp_path, RULE, a)
    md = (tmp_path / "review_packet.md").read_text(encoding="utf-8")
    for heading in ["Summary", "Source report", "Sigma rule", "Splunk query", "Validation", "Attack-test evidence", "Environment preflight",
                    "Field mapping and telemetry", "Possible false positives", "Limitations", "Handoff"]:
        assert heading in md, heading
    assert "https://example.org/report" in md and "sigma_mirror" in md and "nothing was deployed" in md.lower()
    assert (tmp_path / "rule.yml").read_text(encoding="utf-8") == RULE and (tmp_path / "assessment.json").exists()
    assert (tmp_path / "query.spl").read_text(encoding="utf-8").startswith("search ")


def test_the_three_verdicts_appear_separately_in_the_packet(tmp_path):
    a = build(attack=attack(origin="controlled_lab_fixture"))
    assess.write_packet(tmp_path, RULE, a)
    md = (tmp_path / "review_packet.md").read_text(encoding="utf-8")
    assert "Rule validity" in md and "Attack validation" in md and "Environment preflight" in md
    assert "controlled lab fixture" in md.lower() and "splunk read-only search" in md.lower()
    assert "PASS" not in md and "✅" not in md


def test_the_packet_never_contains_credentials(tmp_path):
    a = build()
    a["statuses"]["environment_preflight"]["note"] = "ok"
    assess.write_packet(tmp_path, RULE, a)
    assert all(TOKEN not in p.read_text(encoding="utf-8") for p in tmp_path.iterdir())


def test_a_packet_with_event_excerpts_warns_that_it_holds_customer_data(tmp_path):
    env = {**ENV, "status": "potential_matches_found", "matches": {"count": 1, "examples": [{"Image": "C:\\x.exe"}], "examples_shown": 1}}
    assess.write_packet(tmp_path, RULE, build(environment=env))
    assert "customer" in (tmp_path / "review_packet.md").read_text(encoding="utf-8").lower()


# --- end to end through the command line --------------------------------------------------------------------------------
def cli_env(fake):
    return {"SPLUNK_BASE_URL": fake.url, "SPLUNK_TOKEN": TOKEN, "SPLUNK_ALLOWED_INDEXES": "win", "SPLUNK_SEARCH_TIMEOUT_S": "3"}


def test_the_cli_runs_byo_logs_and_a_mock_splunk_and_writes_a_packet(tmp_path, monkeypatch):
    monkeypatch.setattr(splunk, "convert_to_spl", lambda rule_text: DETECT)
    manifest = write_manifest(tmp_path / "case")
    (tmp_path / "rule.yml").write_text(RULE, encoding="utf-8")
    out = tmp_path / "out"
    with FakeSplunk(make_handler(matches=0)) as fake:
        code = assess.main(["--rule", str(tmp_path / "rule.yml"), "--manifest", str(manifest), "--splunk", "--splunk-index", "win",
                            "--last-hours", "1", "--out", str(out)],
                           env=cli_env(fake), runner_factory=lambda kind: fake_runner(detected_files={"a1.evtx"}),
                           validator=lambda text: OK, schema_ids=lambda category: {1})
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert code == 0
    assert a["statuses"]["rule_validity"]["state"] == "valid"
    assert a["statuses"]["attack_validation"]["state"] == "validated_on_supplied_attack_evidence"
    assert a["statuses"]["environment_preflight"]["state"] == "no_matches_in_window"
    assert (out / "review_packet.md").exists() and TOKEN not in json.dumps(a)


def test_the_cli_refuses_the_sandbox_for_supplied_logs_without_the_flag(tmp_path, capsys):
    manifest = write_manifest(tmp_path / "case")
    (tmp_path / "rule.yml").write_text(RULE, encoding="utf-8")
    called = []
    code = assess.main(["--rule", str(tmp_path / "rule.yml"), "--manifest", str(manifest), "--runner", "sandbox", "--out", str(tmp_path / "o")],
                       env={}, runner_factory=lambda kind: called.append(kind), validator=lambda t: OK, schema_ids=lambda c: None)
    assert code == 2 and called == [] and "leave this machine" in capsys.readouterr().err


def test_the_cli_reports_an_unconfigured_splunk_as_not_run(tmp_path):
    (tmp_path / "rule.yml").write_text(RULE, encoding="utf-8")
    out = tmp_path / "o"
    code = assess.main(["--rule", str(tmp_path / "rule.yml"), "--splunk", "--splunk-index", "win", "--last-hours", "1", "--out", str(out)],
                       env={}, runner_factory=lambda k: None, validator=lambda t: OK, schema_ids=lambda c: None)
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert code == 0 and a["statuses"]["environment_preflight"]["state"] == "not_run"
    assert "SPLUNK_BASE_URL" in a["statuses"]["environment_preflight"]["detail"]


def test_the_cli_requires_an_explicit_time_window_for_splunk(tmp_path, capsys):
    (tmp_path / "rule.yml").write_text(RULE, encoding="utf-8")
    code = assess.main(["--rule", str(tmp_path / "rule.yml"), "--splunk", "--splunk-index", "win", "--out", str(tmp_path / "o")],
                       env={}, runner_factory=lambda k: None, validator=lambda t: OK, schema_ids=lambda c: None)
    assert code == 2 and "time window" in capsys.readouterr().err.lower()


def test_a_splunk_failure_is_recorded_as_query_failed_in_the_packet(tmp_path, monkeypatch):
    monkeypatch.setattr(splunk, "convert_to_spl", lambda rule_text: DETECT)
    (tmp_path / "rule.yml").write_text(RULE, encoding="utf-8")
    out = tmp_path / "o"
    with FakeSplunk(make_handler(), token="different") as fake:  # the CLI will present the wrong credential
        code = assess.main(["--rule", str(tmp_path / "rule.yml"), "--splunk", "--splunk-index", "win", "--last-hours", "1", "--out", str(out)],
                           env=cli_env(fake), runner_factory=lambda k: None, validator=lambda t: OK, schema_ids=lambda c: None)
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    env = a["statuses"]["environment_preflight"]
    assert code == 0 and env["state"] == "query_failed" and env["error"]["kind"] == "auth"


def test_the_assessment_module_has_no_path_to_the_model():
    source = Path(assess.__file__).read_text(encoding="utf-8")
    assert "shakedown.llm" not in source and "chat_json" not in source and "shakedown.pipeline" not in source
