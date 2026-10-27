"""Bring Your Own Logs: organisation-supplied EVTX evidence, evaluated by the existing evaluator.

The contract: nothing is ground truth unless the user labelled it and said why; every file is hashed; supplied logs stay on
this machine unless the user explicitly allows an upload; and a weak or missing basis can never become an effectiveness claim.
"""
import hashlib
import json
from pathlib import Path

import pytest
import yaml

from shakedown import byo
from shakedown.harness.checker import CheckerRun, Match

MAGIC = b"ElfFile\x00"
RULE = yaml.safe_dump({"title": "T", "id": "11111111-2222-4333-8444-555555555555", "status": "test", "description": "d",
                       "author": "a", "date": "2026-10-27", "logsource": {"category": "process_creation", "product": "windows"},
                       "detection": {"selection": {"Image|endswith": "\\x.exe"}, "condition": "selection"}, "level": "low"})
RULE_ID = "11111111-2222-4333-8444-555555555555"


def evtx(path: Path, body: bytes = b"payload") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(MAGIC + body)
    return path


def write_manifest(tmp_path, **overrides):
    evtx(tmp_path / "attack/a1.evtx", b"attack-one")
    evtx(tmp_path / "attack/a2.evtx", b"attack-two")
    evtx(tmp_path / "benign/b1.evtx", b"benign-one")
    doc = {
        "name": "unit test",
        "logsource": {"category": "process_creation", "product": "windows"},
        "schema": {"source": "Sysmon", "channel": "Microsoft-Windows-Sysmon/Operational"},
        "provenance": {"collected_by": "tester", "method": "detonated in a lab VM"},
        "attack": [{"file": "attack/a1.evtx", "expect": "detect", "label_basis": "x.exe executed by the tester at 10:02"},
                   {"file": "attack/a2.evtx", "expect": "no_detect", "label_basis": "benign admin activity, negative control"}],
        "benign": [{"path": "benign", "label_basis": "known_clean", "description": "fresh install", "attested_by": "tester"}],
    }
    doc.update(overrides)
    path = tmp_path / "manifest.yml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return path


def runner(detected_files=(), benign_hits=0):
    def run(rules, evtx_dirs):
        matches = []
        for d in evtx_dirs:
            for p in Path(d).rglob("*.evtx"):
                if p.name in detected_files:
                    matches.append(Match(RULE_ID, p.name, {"Event": "e"}))
                elif p.name.startswith("b") and benign_hits:
                    matches.append(Match(RULE_ID, p.name, {"Event": "e"}))
        return CheckerRun(matches, [], "", 0.01)
    return run


# --- R1: labels -------------------------------------------------------------------------------------------------
def test_a_valid_manifest_loads_and_every_file_is_hashed(tmp_path):
    m = byo.load_manifest(write_manifest(tmp_path))

    assert [a.name for a in m.attack] == ["a1.evtx", "a2.evtx"] and m.attack[0].expect == "detect"
    assert m.attack[0].sha256 == hashlib.sha256(MAGIC + b"attack-one").hexdigest()
    assert m.benign[0].files[0]["sha256"] == hashlib.sha256(MAGIC + b"benign-one").hexdigest()
    assert m.benign[0].files[0]["name"] == "b1.evtx"


def test_a_benign_set_without_a_label_basis_is_rejected_not_assumed_clean(tmp_path):
    path = write_manifest(tmp_path, benign=[{"path": "benign", "description": "some logs"}])
    with pytest.raises(byo.ManifestError, match="label_basis"):
        byo.load_manifest(path)


def test_an_attack_sample_needs_a_reason_and_a_valid_expectation(tmp_path):
    path = write_manifest(tmp_path, attack=[{"file": "attack/a1.evtx", "expect": "maybe", "label_basis": ""}])
    with pytest.raises(byo.ManifestError) as exc:
        byo.load_manifest(path)
    assert "expect" in str(exc.value) and "label_basis" in str(exc.value)


def test_provenance_is_required(tmp_path):
    with pytest.raises(byo.ManifestError, match="provenance"):
        byo.load_manifest(write_manifest(tmp_path, provenance={}))


def test_every_problem_is_reported_in_one_go(tmp_path):
    path = write_manifest(tmp_path, logsource={"category": "firewall", "product": "windows"},
                          benign=[{"path": "benign"}], provenance={})
    with pytest.raises(byo.ManifestError) as exc:
        byo.load_manifest(path)
    assert len(exc.value.problems) >= 3


# --- inputs: types, sizes, paths -----------------------------------------------------------------------------------
def test_only_real_evtx_files_are_accepted(tmp_path):
    path = write_manifest(tmp_path)
    (tmp_path / "attack/a1.evtx").write_bytes(b"not an evtx file at all")
    with pytest.raises(byo.ManifestError, match="not an EVTX"):
        byo.load_manifest(path)

    path = write_manifest(tmp_path, attack=[{"file": "attack/events.json", "expect": "detect", "label_basis": "twelve chars or more"}])
    (tmp_path / "attack/events.json").write_text("{}", encoding="utf-8")
    with pytest.raises(byo.ManifestError, match=r"\.evtx"):
        byo.load_manifest(path)


def test_oversized_files_are_refused(tmp_path, monkeypatch):
    path = write_manifest(tmp_path)
    monkeypatch.setattr(byo, "MAX_FILE_BYTES", 5)
    with pytest.raises(byo.ManifestError, match="too large"):
        byo.load_manifest(path)


def test_paths_may_not_leave_the_manifest_folder(tmp_path):
    outside = evtx(tmp_path.parent / "outside_elsewhere.evtx")
    inner = tmp_path / "case"
    inner.mkdir()
    evtx(inner / "benign/b.evtx")
    path = write_manifest(inner, attack=[{"file": f"../{outside.name}", "expect": "detect", "label_basis": "twelve chars or more"}])
    with pytest.raises(byo.ManifestError, match="outside"):
        byo.load_manifest(path)


def test_the_same_content_cannot_be_both_attack_and_benign(tmp_path):
    path = write_manifest(tmp_path)
    evtx(tmp_path / "benign/copy.evtx", b"attack-one")
    with pytest.raises(byo.ManifestError, match="both attack and benign"):
        byo.load_manifest(path)


# --- R2: customer logs stay local ------------------------------------------------------------------------------
def test_supplied_logs_use_the_local_runner_and_the_sandbox_needs_an_explicit_acknowledgement(tmp_path):
    with pytest.raises(byo.ExternalUploadRefused, match="leave this machine"):
        byo.choose_runner_kind("sandbox", acknowledged=False)
    assert byo.choose_runner_kind("local", acknowledged=False) == "local"
    assert byo.choose_runner_kind("sandbox", acknowledged=True) == "sandbox"
    assert byo.choose_runner_kind(None, acknowledged=False) == "local"


# --- evaluation and attack verdict --------------------------------------------------------------------------------
def test_expected_detections_and_negative_controls_are_scored_separately(tmp_path):
    m = byo.load_manifest(write_manifest(tmp_path))
    result = byo.evaluate_supplied(RULE, m, runner(detected_files={"a1.evtx"}), schema=None)

    by_name = {s["file"]: s for s in result["attack"]["samples"]}
    assert by_name["a1.evtx"]["outcome"] == "as_expected" and by_name["a1.evtx"]["detected"] is True
    assert by_name["a2.evtx"]["outcome"] == "as_expected" and by_name["a2.evtx"]["detected"] is False
    assert result["attack"]["expected_detections"] == 1 and result["attack"]["expected_detections_met"] == 1
    assert result["attack"]["verdict"] == "validated_on_supplied_attack_evidence"


def test_a_missed_expected_detection_is_not_validated(tmp_path):
    m = byo.load_manifest(write_manifest(tmp_path))
    result = byo.evaluate_supplied(RULE, m, runner(detected_files=set()), schema=None)
    assert result["attack"]["verdict"] == "attack_not_detected"
    assert result["attack"]["samples"][0]["outcome"] == "missed"


def test_a_negative_control_that_matches_is_a_failure(tmp_path):
    m = byo.load_manifest(write_manifest(tmp_path))
    result = byo.evaluate_supplied(RULE, m, runner(detected_files={"a1.evtx", "a2.evtx"}), schema=None)
    assert result["attack"]["verdict"] == "attack_not_detected"
    assert {s["file"]: s["outcome"] for s in result["attack"]["samples"]}["a2.evtx"] == "unexpected_match"


def test_no_attack_sample_labelled_detect_means_insufficient_evidence(tmp_path):
    path = write_manifest(tmp_path, attack=[{"file": "attack/a2.evtx", "expect": "no_detect", "label_basis": "negative control only"}])
    result = byo.evaluate_supplied(RULE, byo.load_manifest(path), runner(), schema=None)
    assert result["attack"]["verdict"] == "insufficient_evidence"
    assert "no attack sample" in " ".join(result["attack"]["reasons"]).lower()


def test_a_single_attack_sample_validates_but_the_caveat_is_recorded(tmp_path):
    path = write_manifest(tmp_path, attack=[{"file": "attack/a1.evtx", "expect": "detect", "label_basis": "x.exe executed by the tester"}])
    result = byo.evaluate_supplied(RULE, byo.load_manifest(path), runner(detected_files={"a1.evtx"}), schema=None)
    assert result["attack"]["verdict"] == "validated_on_supplied_attack_evidence"
    assert any("one attack sample" in n.lower() for n in result["attack"]["caveats"])


# --- benign baseline ---------------------------------------------------------------------------------------------
def test_zero_matches_on_assumed_clean_logs_is_weak_evidence_not_a_clean_bill(tmp_path):
    path = write_manifest(tmp_path, benign=[{"path": "benign", "label_basis": "assumed_clean", "description": "unknown"}])
    result = byo.evaluate_supplied(RULE, byo.load_manifest(path), runner(detected_files={"a1.evtx"}), schema=None)
    assert result["benign"]["verdict"] == "benign_evidence_weak"
    assert result["benign"]["supports_false_positive_claim"] is False


def test_benign_matches_are_reported_with_counts(tmp_path):
    m = byo.load_manifest(write_manifest(tmp_path))
    result = byo.evaluate_supplied(RULE, m, runner(detected_files={"a1.evtx"}, benign_hits=1), schema=None)
    assert result["benign"]["verdict"] == "benign_matches_found" and result["benign"]["matching_events"] == 1


def test_zero_matches_on_known_clean_logs_supports_a_limited_claim(tmp_path):
    result = byo.evaluate_supplied(RULE, byo.load_manifest(write_manifest(tmp_path)), runner(detected_files={"a1.evtx"}), schema=None)
    assert result["benign"]["verdict"] == "no_benign_matches" and result["benign"]["supports_false_positive_claim"] is True


# --- schema compatibility ----------------------------------------------------------------------------------------
def fake_events(ids):
    return lambda path, max_events=20, **kw: [{"EventID": i, "Channel": "Microsoft-Windows-Sysmon/Operational"} for i in ids][:max_events]


def test_an_attack_sample_without_the_required_event_type_cannot_validate_the_rule(tmp_path, monkeypatch):
    monkeypatch.setattr(byo, "summarize_events", fake_events([13, 13, 13]))
    m = byo.load_manifest(write_manifest(tmp_path))
    schema = byo.check_schema(m, required_event_ids={1, 4688})
    result = byo.evaluate_supplied(RULE, m, runner(detected_files=set()), schema=schema)  # missed, and why: wrong telemetry

    assert schema["attack"]["a1.evtx"]["compatible"] is False
    assert result["attack"]["verdict"] == "insufficient_evidence"
    assert "telemetry" in " ".join(result["attack"]["reasons"]).lower()


def test_a_compatible_sample_is_recorded_with_the_event_ids_seen(tmp_path, monkeypatch):
    monkeypatch.setattr(byo, "summarize_events", fake_events([1, 1, 5]))
    schema = byo.check_schema(byo.load_manifest(write_manifest(tmp_path)), required_event_ids={1, 4688})
    assert schema["attack"]["a1.evtx"]["compatible"] is True and schema["attack"]["a1.evtx"]["event_ids"] == {"1": 2, "5": 1}


# --- the record ----------------------------------------------------------------------------------------------------
def test_the_record_carries_what_a_reviewer_needs(tmp_path):
    m = byo.load_manifest(write_manifest(tmp_path))
    result = byo.evaluate_supplied(RULE, m, runner(detected_files={"a1.evtx"}), schema=None)
    rec = byo.build_record(RULE, m, result, runner_description={"kind": "local-docker"})

    assert rec["rule"]["sha256"] == hashlib.sha256(RULE.encode()).hexdigest() and rec["rule"]["id"] == RULE_ID
    assert rec["evaluated_at"].endswith("+00:00") or rec["evaluated_at"].endswith("Z")
    assert rec["provenance"]["collected_by"] == "tester" and rec["inputs"]["attack"][0]["label_basis"].startswith("x.exe")
    assert rec["inputs"]["benign"][0]["files"][0]["sha256"] and rec["normalisation"].startswith("None.")
    assert rec["evidence_origin"] == "organisation_supplied" and rec["evaluator"] == {"kind": "local-docker"}
    assert rec["contains_event_excerpts"] is False and rec["limitations"]  # no benign match, so no excerpt was kept
    json.dumps(rec)  # must be plain JSON


def test_a_record_with_benign_matches_says_it_contains_event_excerpts(tmp_path):
    m = byo.load_manifest(write_manifest(tmp_path))
    result = byo.evaluate_supplied(RULE, m, runner(detected_files={"a1.evtx"}, benign_hits=1), schema=None)
    assert byo.build_record(RULE, m, result, {"kind": "local-docker"})["contains_event_excerpts"] is True


def test_the_module_never_touches_the_model(tmp_path):
    source = Path(byo.__file__).read_text(encoding="utf-8")
    assert "shakedown.llm" not in source and "chat_json" not in source


def test_an_entry_that_cannot_be_read_is_reported_never_silently_skipped(tmp_path, monkeypatch):
    """Seen for real: a path over the Windows length limit made is_file() False, and the file silently dropped out of the hashed inventory."""
    path = write_manifest(tmp_path)
    evtx(tmp_path / "benign/unreadable.evtx", b"benign-two")
    original = Path.is_file
    monkeypatch.setattr(Path, "is_file", lambda self: False if self.name == "unreadable.evtx" else original(self))
    with pytest.raises(byo.ManifestError, match="unreadable.evtx"):
        byo.load_manifest(path)
