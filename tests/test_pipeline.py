"""End-to-end pipeline with fake model, fake research and fake runner: records what actually happened."""
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from shakedown.harness.checker import CheckerRun, Match
from shakedown.pipeline import PipelineError, run_pipeline
from shakedown.research import Source, TavilyError

STRUCT = {"title": "Pipeline Rule", "description": "d", "tags": [], "logsource_category": "process_creation",
          "groups": [{"name": "selection", "fields": [{"field": "Image", "modifier": "endswith", "values": ["reg.exe"]}]}],
          "condition": "selection", "falsepositives": ["Unknown"], "level": "medium"}
SPEC = {"behavior": "reg abuse", "logsource_category": "process_creation", "observables": [], "techniques": []}


class FakeLLM:
    def __init__(self, rules):
        self.rules = list(rules)

    def chat_json(self, model, messages, schema, name, **kw):
        data = SPEC if name == "detection_spec" else self.rules.pop(0)
        return SimpleNamespace(data=data, usage={"total_tokens": 7}, latency_s=0.01, model=model,
                               response_format="fake", reasoning=None)


def fake_runner(detects_attack: bool):
    def runner(rules, evtx_dirs):
        rule_id = str(yaml.safe_load(rules["candidate"])["id"])
        names = {p.name for d in evtx_dirs for p in Path(d).glob("*.evtx")}
        hit = [Match(rule_id, "attack.evtx", {})] if detects_attack and "attack.evtx" in names else []
        return CheckerRun(hit, [], "", 0.01)
    return runner


@pytest.fixture
def scenario(tmp_path):
    (tmp_path / "attack.evtx").write_bytes(b"x")
    dev, held = tmp_path / "dev", tmp_path / "held"
    for d in (dev, held):
        d.mkdir()
        (d / "b.evtx").write_bytes(b"x")
    return {"id": "s1", "title": "Test scenario", "category": "process_creation", "attack": tmp_path / "attack.evtx",
            "benign_dev": {"benign_dev": dev}, "benign_heldout": {"benign_heldout": held}, "expert_text": None}


def test_run_records_spec_iterations_heldout_and_ordered_events(scenario):
    seen = []
    record = run_pipeline(llm=FakeLLM([STRUCT]), model="m", runner=fake_runner(True), scenario=scenario,
                          report_text="The actor used reg.exe", emit=lambda t, d: seen.append(t))

    assert record["success"] and len(record["iterations"]) == 1
    it = record["iterations"][0]
    assert it["validation"]["ok"] and it["evaluation"]["attack_detected"] == 1 and "Image|endswith" in it["rule_text"]
    assert record["heldout"]["benign_heldout"]["hits"] == 0
    assert record["spec"]["behavior"] == "reg abuse"
    assert [e["type"] for e in record["events"]] == seen
    assert seen[0] == "start" and seen[-1] == "done" and "spec" in seen and "iteration" in seen and "heldout" in seen
    assert record["research"] is None and record["input"]["kind"] == "text"


def test_unsuccessful_run_is_reported_as_unsuccessful(scenario):
    record = run_pipeline(llm=FakeLLM([STRUCT] * 2), model="m", runner=fake_runner(False), scenario=scenario,
                          report_text="r", max_repairs=1)
    assert not record["success"] and record["stop_reason"] == "repair budget exhausted"
    assert len(record["iterations"]) == 2


class FakeTavily:
    def extract(self, url):
        return Source(url=url, title=url, content="Attacker ran reg.exe", retrieved_at="2026-10-27T00:00:00Z", via="extract")

    def search(self, query, max_results=5, include_domains=None):
        return [Source(url="https://other", title="o", content="more", retrieved_at="2026-10-27T00:00:01Z",
                       via="search", score=0.5)]


def test_research_sources_are_recorded_with_urls_and_times(scenario):
    record = run_pipeline(llm=FakeLLM([STRUCT]), model="m", runner=fake_runner(True), scenario=scenario,
                          source_url="https://example.org/report", tavily=FakeTavily())

    assert record["research"]["primary"]["url"] == "https://example.org/report"
    assert record["research"]["primary"]["retrieved_at"] == "2026-10-27T00:00:00Z"
    assert record["research"]["corroboration"][0]["url"] == "https://other"
    assert record["input"]["kind"] == "url"


class BrokenTavily:
    def extract(self, url):
        raise TavilyError("HTTP 432: plan limit", status=432)


def test_research_failure_is_marked_not_faked_and_falls_back_to_given_text(scenario):
    record = run_pipeline(llm=FakeLLM([STRUCT]), model="m", runner=fake_runner(True), scenario=scenario,
                          source_url="https://example.org/r", tavily=BrokenTavily(), report_text="fallback text")

    assert record["research"]["primary"] is None and "432" in record["research"]["error"]
    assert record["input"]["kind"] == "text" and record["success"]


def test_research_failure_without_fallback_text_raises(scenario):
    with pytest.raises(PipelineError, match="no report text"):
        run_pipeline(llm=FakeLLM([STRUCT]), model="m", runner=fake_runner(True), scenario=scenario,
                     source_url="https://example.org/r", tavily=BrokenTavily())
