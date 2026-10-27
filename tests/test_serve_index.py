"""The scenario index file is a cache. A read-only install (a non-root container) must still start."""
from shakedown import serve


def test_an_unwritable_index_location_does_not_stop_the_server(tmp_path, monkeypatch):
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setattr(serve, "INDEX", blocker / "scenarios.json")  # its parent is a file, so writing must fail

    serve.write_index([{"id": "a", "title": "A", "category": "c", "reference_urls": []}])  # must not raise


def test_the_index_is_written_when_the_location_is_writable(tmp_path, monkeypatch):
    target = tmp_path / "demo" / "scenarios.json"
    monkeypatch.setattr(serve, "INDEX", target)

    serve.write_index([{"id": "a", "title": "A", "category": "c", "reference_urls": ["u"], "extra": 1}])

    assert '"title": "A"' in target.read_text(encoding="utf-8") and "extra" not in target.read_text(encoding="utf-8")
