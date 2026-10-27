"""Recordings made before answer-source screening are labelled when served; the file on disk is never changed."""
import json

from fastapi.testclient import TestClient
from test_server import RECORD, SCENARIOS

from shakedown.server import create_app

OLD = {**RECORD, "scenario": {"id": "514e7e3e-b3b4-4a67-af60-be20f139198b", "title": "PUA - AdFind.EXE Execution",
                              "category": "process_creation"},
       "research": {"primary": {"url": "https://example.org/r"}, "error": None, "corroboration": [
           {"url": "https://sigma.nasbench.dev/rules/455b9d50", "title": "Some rule", "retrieved_at": "t", "via": "search"},
           {"url": "https://research.splunk.com/a", "title": "Detection: Windows AdFind Exe", "retrieved_at": "t", "via": "search"}]}}


def serve(tmp_path, record):
    rec = tmp_path / "demo/recorded"
    rec.mkdir(parents=True)
    path = rec / "old.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return TestClient(create_app(tmp_path, SCENARIOS)), path


def test_an_unscreened_recording_lists_its_answer_bearing_sources_when_served(tmp_path):
    client, path = serve(tmp_path, OLD)
    before = path.read_bytes()
    body = client.get("/api/recorded/old").json()

    assert [f["url"] for f in body["answer_screen_legacy"]] == ["https://sigma.nasbench.dev/rules/455b9d50"]
    assert path.read_bytes() == before


def test_a_screened_recording_or_one_without_research_gets_no_label(tmp_path):
    screened = {**OLD, "research": {**OLD["research"], "screening": {"policy": "exclude", "sources": []}}}
    assert "answer_screen_legacy" not in serve(tmp_path / "a", screened)[0].get("/api/recorded/old").json()
    assert "answer_screen_legacy" not in serve(tmp_path / "b", RECORD)[0].get("/api/recorded/old").json()
