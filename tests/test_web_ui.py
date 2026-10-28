"""The static UI: the benchmark it prints is the frozen table, it makes no third-party requests, and the server serves it."""
import json
import re
from pathlib import Path

from fastapi.testclient import TestClient

from shakedown.server import create_app

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"


def bench_in_page() -> dict:
    match = re.search(r"const BENCH = (\{.*?\n\});", (WEB / "app.js").read_text(encoding="utf-8"), re.S)
    assert match, "app.js must define const BENCH as plain JSON"
    return json.loads(match.group(1))


def confirmatory_rows() -> dict[str, list[str]]:
    text = (ROOT / "docs/RESULTS_TABLE.md").read_text(encoding="utf-8")
    section = text.split("## Confirmatory set", 1)[1].split("### Confirmatory set by rule date", 1)[0]
    rows = {}
    for line in section.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if cells and cells[0] in ("8", "9"):
            rows[f"Run {cells[0]}"] = cells
    return rows


def test_the_benchmark_in_the_page_is_the_frozen_results_table():
    bench, rows = bench_in_page(), confirmatory_rows()
    assert set(bench) == set(rows) == {"Run 8", "Run 9"}
    for run, cells in rows.items():
        shown = bench[run]
        assert (shown["tasks"], shown["one_shot"], shown["after_repair"], shown["after_repair_errored_as_miss"],
                shown["repair_fixed_first_failure"], shown["heldout_fp"], shown["expert"]) == \
            (cells[2], cells[4], cells[5], cells[6], cells[7], cells[8], cells[10]), run


def test_the_page_makes_no_third_party_requests():
    html = re.sub(r'="data:[^"]*"', '=""', (WEB / "index.html").read_text(encoding="utf-8"))  # an inline icon is not a request
    css = (WEB / "style.css").read_text(encoding="utf-8")
    js = (WEB / "app.js").read_text(encoding="utf-8")
    assert "http://" not in html and "https://" not in html
    assert "@import" not in css and not re.search(r"url\(\s*['\"]?https?:", css)
    for target in re.findall(r"api\(\s*[`\"']([^`\"']+)", js):
        assert target.startswith("/api/"), target
    assert not re.search(r"fetch\(\s*[`\"']https?:", js)


def test_the_server_serves_the_workbench(tmp_path):
    client = TestClient(create_app(tmp_path, [], recorded_dir=tmp_path))
    page = client.get("/")
    assert page.status_code == 200 and 'id="main"' in page.text and "/static/app.js" in page.text
    assert client.get("/static/app.js").status_code == 200 and client.get("/static/style.css").status_code == 200
