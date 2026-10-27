import json

import yaml

from shakedown.scenarios import load_scenarios, scenario_report_text

RULE = {"title": "Test Rule", "id": "11111111-2222-4333-8444-555555555555", "description": "Does a thing.",
        "references": ["https://example.org/a", "https://example.org/b"], "tags": ["attack.t1000"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {"s": {"Image": "x"}, "condition": "s"}}


def _tree(tmp_path):
    sigma = tmp_path / "data/raw/sigma"
    (sigma / "rules").mkdir(parents=True)
    (sigma / "rules/r.yml").write_text(yaml.safe_dump(RULE), encoding="utf-8")
    (sigma / "regression_data").mkdir()
    (sigma / "regression_data/s.evtx").write_bytes(b"x")
    base = tmp_path / "data/raw/evtx-baseline/v0.8.5"
    (base / "win7-x86").mkdir(parents=True)
    (base / "Logs_Client").mkdir()
    (tmp_path / "evaluation").mkdir()
    (tmp_path / "evaluation/tasks.json").write_text(json.dumps({"tasks": [{
        "rule_id": RULE["id"], "rule_path": "rules/r.yml", "title": "Test Rule", "category": "process_creation",
        "sample": "regression_data/s.evtx"}]}), encoding="utf-8")
    return tmp_path


def test_scenarios_resolve_fixture_paths_and_expert_rule(tmp_path):
    root = _tree(tmp_path)
    [s] = load_scenarios(root)

    assert s["id"] == RULE["id"] and s["attack"].name == "s.evtx" and s["attack"].exists()
    assert s["benign_dev"]["benign_dev_win7"].name == "win7-x86"
    assert s["benign_heldout"]["benign_heldout_win10"].name == "Logs_Client"
    assert "Image" in s["expert_text"]
    assert s["reference_urls"] == ["https://example.org/a", "https://example.org/b"]


def test_report_text_uses_descriptive_metadata_only(tmp_path):
    root = _tree(tmp_path)
    [s] = load_scenarios(root)
    text = scenario_report_text(root, s)

    assert "Test Rule" in text and "Does a thing." in text and "https://example.org/a" in text
    assert "detection" not in text.lower().replace("detects", "") or "Image" not in text   # no rule logic leaks
    assert "Image" not in text
