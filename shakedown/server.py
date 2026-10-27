"""HTTP API and static UI for Shakedown.

Recorded runs are read-only evidence files. Live runs are off unless a live runner is supplied, are limited by
`Budget`, and execute in a background thread that the UI polls.
"""
import json
import re
import threading
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from shakedown.budget import Budget
from shakedown.research import Source, answer_reasons

SLUG_RE = re.compile(r"^[a-z0-9-]{1,80}$")
URL_RE = re.compile(r"^https?://[^\s]{3,500}$")
MAX_RUNS_KEPT = 50


class RunRequest(BaseModel):
    scenario_id: str
    source_url: str | None = None


def legacy_answer_sources(rec: dict) -> list[dict] | None:
    """For a run recorded before answer-source screening existed: the corroborating sources whose URL or title
    marks them as pages about the target rule. None when the run has no research or was screened when recorded.
    Only URL and title are available (old records kept lengths, not text), so this can under-report."""
    research = rec.get("research") or {}
    if research.get("screening") or not research.get("primary"):
        return None
    target = {"id": rec["scenario"]["id"], "title": rec["scenario"]["title"]}
    flagged = []
    for c in research.get("corroboration") or []:
        reasons = answer_reasons(Source(c["url"], c.get("title", ""), "", c.get("retrieved_at", ""), c.get("via", "search")), target)
        if reasons:
            flagged.append({"url": c["url"], "reasons": reasons})
    return flagged


def _client_id(request: Request, trust_proxy: bool) -> str:
    """The address the cooldown is keyed on. X-Forwarded-For is client-controlled unless a trusted proxy sets it,
    so it is read only when the server was told it sits behind one."""
    if trust_proxy:
        forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        if forwarded:
            return forwarded
    return request.client.host if request.client else "unknown"


def create_app(root: Path, scenarios: list[dict], live_runner=None, budget: Budget | None = None,
               web_dir: Path | None = None, recorded_dir: Path | None = None, allow_custom_url: bool = False,
               trust_proxy: bool = False, live_info: dict | None = None) -> FastAPI:
    """`allow_custom_url`: when False (the hosted default) a live run may only read the scenario's own references,
    so visitors cannot point the paid research tool at arbitrary pages. `live_info` is shown by /api/health."""
    root = Path(root)
    recorded_dir = Path(recorded_dir) if recorded_dir else root / "demo/recorded"
    budget = budget or Budget()
    runs: dict[str, dict] = {}
    runs_lock = threading.Lock()
    app = FastAPI(title="Shakedown", docs_url=None, redoc_url=None)

    def recorded_files() -> dict[str, Path]:
        return {p.stem: p for p in sorted(recorded_dir.glob("*.json"))} if recorded_dir.exists() else {}

    def scenario_slug(scenario_id: str) -> str | None:
        for slug, path in recorded_files().items():
            if json.loads(path.read_text(encoding="utf-8")).get("scenario", {}).get("id") == scenario_id:
                return slug
        return None

    @app.get("/api/health")
    def health():
        return {"live_enabled": live_runner is not None, "recorded": len(recorded_files()), "budget": budget.status(),
                "allow_custom_url": allow_custom_url, "live": live_info or {}}

    @app.get("/api/recorded")
    def list_recorded():
        out = []
        for slug, path in recorded_files().items():
            rec = json.loads(path.read_text(encoding="utf-8"))
            out.append({"slug": slug, "title": rec["scenario"]["title"], "success": rec["success"],
                        "iterations": len(rec["iterations"]), "tokens": rec["totals"]["tokens"],
                        "model": rec["model"], "used_research": bool(rec.get("research") and rec["research"].get("primary"))})
        return out

    @app.get("/api/recorded/{slug}")
    def get_recorded(slug: str):
        if not SLUG_RE.match(slug) or slug not in recorded_files():
            raise HTTPException(404, "No recorded run with that name.")
        rec = json.loads(recorded_files()[slug].read_text(encoding="utf-8"))
        legacy = legacy_answer_sources(rec)
        if legacy is not None:  # the file on disk is untouched; this label is added when it is served
            rec["answer_screen_legacy"] = legacy
        return rec

    @app.get("/api/scenarios")
    def list_scenarios():
        return [{"id": s["id"], "title": s["title"], "category": s["category"],
                 "reference_urls": s.get("reference_urls", []), "recorded_slug": scenario_slug(s["id"])}
                for s in scenarios]

    @app.post("/api/runs")
    def start_run(req: RunRequest, request: Request):
        if live_runner is None:
            raise HTTPException(403, "Live runs are not enabled on this server. Use a recorded run.")
        scenario = next((s for s in scenarios if s["id"] == req.scenario_id), None)
        if scenario is None:
            raise HTTPException(404, "Unknown scenario.")
        if req.source_url is not None and not URL_RE.match(req.source_url):
            raise HTTPException(422, "The report address must start with http:// or https://.")
        if req.source_url is not None and not allow_custom_url and req.source_url not in scenario.get("reference_urls", []):
            raise HTTPException(403, "Custom report addresses are turned off on this server. Pick a scenario and leave the address empty.")
        ok, reason = budget.try_acquire(_client_id(request, trust_proxy))
        if not ok:
            raise HTTPException(429, reason)

        run_id = uuid.uuid4().hex[:12]
        state = {"status": "running", "events": [], "record": None, "error": None, "scenario_id": scenario["id"]}
        with runs_lock:
            runs[run_id] = state
            for old in list(runs)[:-MAX_RUNS_KEPT]:
                runs.pop(old, None)

        def work():
            try:
                state["record"] = live_runner.run(scenario, req.source_url,
                                                  lambda kind, data: state["events"].append({"type": kind, "data": data}))
                state["status"] = "done"
            except Exception as exc:  # aqg: top-level boundary - a failed run is reported to the UI, never hidden
                state["status"], state["error"] = "error", f"{type(exc).__name__}: {str(exc)[:300]}"
            finally:
                budget.release()

        threading.Thread(target=work, daemon=True).start()
        return {"run_id": run_id}

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str):
        state = runs.get(run_id)
        if state is None:
            raise HTTPException(404, "Unknown run.")
        return state

    web = Path(web_dir) if web_dir else Path(__file__).resolve().parents[1] / "web"
    if web.exists():
        app.mount("/static", StaticFiles(directory=web), name="static")

        @app.get("/")
        def index():
            return FileResponse(web / "index.html")

    return app
