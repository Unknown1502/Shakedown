"""HTTP API: recorded runs are served read-only; live runs are gated, budgeted and polled."""
import json
import time

import pytest
from fastapi.testclient import TestClient

from shakedown.budget import Budget
from shakedown.server import create_app

RECORD = {"scenario": {"id": "s1", "title": "Test scenario", "category": "process_creation"}, "success": True,
          "iterations": [{"index": 0}, {"index": 1}], "totals": {"tokens": 10, "seconds": 3.0}, "model": "m",
          "events": [], "research": None}
SCENARIOS = [{"id": "s1", "title": "Test scenario", "category": "process_creation", "reference_urls": ["https://x"]},
             {"id": "s2", "title": "Other scenario", "category": "ps_script", "reference_urls": []}]


class FakeLive:
    def __init__(self):
        self.calls = []

    def run(self, scenario, source_url, emit):
        self.calls.append((scenario["id"], source_url))
        emit("start", {"scenario": scenario["id"]})
        return {**RECORD, "scenario": {"id": scenario["id"], "title": scenario["title"], "category": scenario["category"]}}


@pytest.fixture
def root(tmp_path):
    rec = tmp_path / "demo/recorded"
    rec.mkdir(parents=True)
    (rec / "test-scenario.json").write_text(json.dumps(RECORD), encoding="utf-8")
    return tmp_path


def client(root, live=None, budget=None, **kw):
    return TestClient(create_app(root, SCENARIOS, live_runner=live, budget=budget, **kw))


def test_health_reports_live_disabled_without_a_runner(root):
    body = client(root).get("/api/health").json()
    assert body["live_enabled"] is False and body["recorded"] == 1


def test_recorded_list_and_fetch(root):
    c = client(root)
    [item] = c.get("/api/recorded").json()
    assert item["slug"] == "test-scenario" and item["iterations"] == 2 and item["success"] is True
    assert c.get("/api/recorded/test-scenario").json()["scenario"]["id"] == "s1"


@pytest.mark.parametrize("slug", ["missing", "..%2Fsecret", "a.b", "UPPER"])
def test_recorded_rejects_unknown_and_unsafe_slugs(root, slug):
    assert client(root).get(f"/api/recorded/{slug}").status_code in (404, 422)


def test_scenarios_flag_which_have_a_recording(root):
    rows = {r["id"]: r for r in client(root).get("/api/scenarios").json()}
    assert rows["s1"]["recorded_slug"] == "test-scenario" and rows["s2"]["recorded_slug"] is None


def test_live_run_is_refused_when_disabled(root):
    r = client(root).post("/api/runs", json={"scenario_id": "s1"})
    assert r.status_code == 403 and "not enabled" in r.json()["detail"]


def test_live_run_executes_and_is_polled_to_completion(root):
    live = FakeLive()
    c = client(root, live=live, budget=Budget(cooldown_s=0), allow_custom_url=True)
    run_id = c.post("/api/runs", json={"scenario_id": "s1", "source_url": "https://example.org/report"}).json()["run_id"]

    for _ in range(50):
        state = c.get(f"/api/runs/{run_id}").json()
        if state["status"] != "running":
            break
        time.sleep(0.05)

    assert state["status"] == "done" and state["record"]["success"] is True
    assert [e["type"] for e in state["events"]] == ["start"]
    assert live.calls == [("s1", "https://example.org/report")]


def test_unknown_scenario_and_bad_url_are_rejected_before_spending(root):
    c = client(root, live=FakeLive(), budget=Budget(cooldown_s=0), allow_custom_url=True)
    assert c.post("/api/runs", json={"scenario_id": "nope"}).status_code == 404
    assert c.post("/api/runs", json={"scenario_id": "s1", "source_url": "file:///etc/passwd"}).status_code == 422


def test_budget_exhaustion_returns_429_with_the_reason(root):
    c = client(root, live=FakeLive(), budget=Budget(daily_cap=1, cooldown_s=0, max_concurrent=5))
    assert c.post("/api/runs", json={"scenario_id": "s1"}).status_code == 200
    r = c.post("/api/runs", json={"scenario_id": "s1"})
    assert r.status_code == 429 and "daily limit" in r.json()["detail"]


def test_failed_live_run_is_reported_as_error_not_success(root):
    class Boom:
        def run(self, scenario, source_url, emit):
            raise RuntimeError("model unavailable")

    c = client(root, live=Boom(), budget=Budget(cooldown_s=0))
    run_id = c.post("/api/runs", json={"scenario_id": "s1"}).json()["run_id"]
    for _ in range(50):
        state = c.get(f"/api/runs/{run_id}").json()
        if state["status"] != "running":
            break
        time.sleep(0.05)
    assert state["status"] == "error" and "model unavailable" in state["error"] and state["record"] is None
