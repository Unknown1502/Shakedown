"""Hosting controls: client identity, custom report addresses, which recordings are served."""
import json

from fastapi.testclient import TestClient
from test_server import RECORD, FakeLive

from shakedown.budget import Budget
from shakedown.server import create_app


REF = "https://example.org/the-reference"
SCENARIOS = [{"id": "s1", "title": "Test scenario", "category": "process_creation", "reference_urls": [REF]}]


def client(root, **kw):
    return TestClient(create_app(root, SCENARIOS, live_runner=FakeLive(), **kw))


def test_a_spoofed_forwarded_for_header_does_not_get_a_fresh_cooldown_by_default(tmp_path):
    c = client(tmp_path, budget=Budget(cooldown_s=60, max_concurrent=5))
    assert c.post("/api/runs", json={"scenario_id": "s1"}, headers={"x-forwarded-for": "1.1.1.1"}).status_code == 200
    r = c.post("/api/runs", json={"scenario_id": "s1"}, headers={"x-forwarded-for": "2.2.2.2"})
    assert r.status_code == 429


def test_the_forwarded_for_header_is_used_only_behind_a_trusted_proxy(tmp_path):
    c = client(tmp_path, budget=Budget(cooldown_s=60, max_concurrent=5), trust_proxy=True)
    assert c.post("/api/runs", json={"scenario_id": "s1"}, headers={"x-forwarded-for": "1.1.1.1"}).status_code == 200
    assert c.post("/api/runs", json={"scenario_id": "s1"}, headers={"x-forwarded-for": "2.2.2.2"}).status_code == 200


def test_custom_report_addresses_are_refused_unless_enabled_but_scenario_references_are_allowed(tmp_path):
    c = client(tmp_path, budget=Budget(cooldown_s=0, max_concurrent=5))
    refused = c.post("/api/runs", json={"scenario_id": "s1", "source_url": "https://example.org/anything"})
    assert refused.status_code == 403 and "custom report" in refused.json()["detail"].lower()
    assert c.post("/api/runs", json={"scenario_id": "s1", "source_url": REF}).status_code == 200

    open_ = client(tmp_path, budget=Budget(cooldown_s=0, max_concurrent=5), allow_custom_url=True)
    assert open_.post("/api/runs", json={"scenario_id": "s1", "source_url": "https://example.org/anything"}).status_code == 200


def test_health_tells_the_ui_what_is_allowed(tmp_path):
    body = client(tmp_path, budget=Budget(daily_cap=3, total_cap=10)).get("/api/health").json()
    assert body["allow_custom_url"] is False and body["budget"]["total_cap"] == 10


def test_a_chosen_recording_folder_is_the_one_that_is_served(tmp_path):
    chosen = tmp_path / "somewhere/else"
    chosen.mkdir(parents=True)
    (chosen / "only-one.json").write_text(json.dumps(RECORD), encoding="utf-8")
    (tmp_path / "demo/recorded").mkdir(parents=True)
    (tmp_path / "demo/recorded/ignored.json").write_text(json.dumps(RECORD), encoding="utf-8")

    rows = client(tmp_path, recorded_dir=chosen).get("/api/recorded").json()
    assert [r["slug"] for r in rows] == ["only-one"]
