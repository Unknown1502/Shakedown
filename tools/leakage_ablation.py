"""Does the AdFind result depend on the web pages that mirror the answer rule?  (exploratory ablation)

Same scenario, model, thinking setting, repair budget, Sandbox evaluator and datasets in every run. Only the research
the model can see changes. Research is replayed from fixed snapshots (a re-run of the original Tavily search and a
snapshot of the report page) so that Tavily's own variation is not a second variable.

    corroboration arm      policy   what the model may see besides the report page
    recorded               flag     the three snippets of the audited run, unscreened
    excluded               exclude  the same three, after the answer-source screen (2 of 3 are dropped)
    no-search              flag     nothing (search integration disabled)

    report page condition  what it is
    clean                  navigation and table of contents stripped; "AdFind.exe" falls inside the 6000 characters
                           the model sees (the original run's extraction was 4348 characters shorter and had it there)
    raw                    the page as Tavily extracts it today; "AdFind.exe" falls outside the visible 6000 characters

Every message sent to the model is captured, so "the exclusion changed the evidence" is checked on the real prompts.
Results are appended to evidence/leakage_audit/ablation_<timestamp>.json. Nothing here is a confirmatory result.

    PYTHONPATH=. uv run python tools/leakage_ablation.py --reps 3
"""
import argparse
import json
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
from leakage_trace import flatten  # noqa: E402

from shakedown.config import load_dotenv  # noqa: E402
from shakedown.llm import TokenFactory, select_model  # noqa: E402
from shakedown.pipeline import run_pipeline  # noqa: E402
from shakedown.research import Source  # noqa: E402
from shakedown.runners import build_runner  # noqa: E402
from shakedown.scenarios import load_scenarios, scenario_report_text  # noqa: E402

AUDIT = ROOT / "evidence/leakage_audit"
TARGET_ID = "514e7e3e-b3b4-4a67-af60-be20f139198b"
SOURCE_URL = ("https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/"
              "atomics/T1087.002/T1087.002.md")
ARMS = {"recorded": ("flag", True), "excluded": ("exclude", True), "no-search": ("flag", False)}
PROBES = ("514e7e3e", "sigmaquery", "detection.fyi", "IMPHASH", "OriginalFileName", "Hashes", "AdFind.exe", "Adfind.exe")


class CachedTavily:
    """Replays fixed research; remembers how many search results were requested."""

    def __init__(self, primary: Source, snippets: list[Source]):
        self.primary, self.snippets, self.asked = primary, snippets, None

    def extract(self, url):
        return self.primary

    def search(self, query, max_results=5, include_domains=None):
        self.asked = max_results
        return list(self.snippets)


class SpyLLM:
    """Delegates to the real client and keeps every message the model was sent."""

    def __init__(self, inner):
        self.inner, self.messages = inner, []

    def chat_json(self, model, messages, *args, **kwargs):
        self.messages.append("\n".join(str(m.get("content", "")) for m in messages))
        return self.inner.chat_json(model, messages, *args, **kwargs)


def load_sources() -> tuple[dict[str, Source], list[Source]]:
    raw = json.loads((AUDIT / "snapshot/primary.json").read_text(encoding="utf-8"))
    text = raw["content"]
    start = text.index("# T1087.002 - Domain Account")
    toc = text.index("## Atomic Tests")
    first_test = text.index("## Atomic Test #1")
    clean = text[start:toc] + text[first_test:]  # drop site navigation and the in-page table of contents
    mk = lambda body: Source(url=raw["url"], title=raw["title"], content=body, retrieved_at=raw["retrieved_at"], via="extract")
    snippets = [Source(url=s["url"], title=s["title"], content=s["content"], retrieved_at=s["retrieved_at"], via="search",
                       score=s["score"]) for s in json.loads(
        (AUDIT / "original/reconstructed_corroboration_search.json").read_text(encoding="utf-8"))]
    return {"clean": mk(clean), "raw": mk(text)}, snippets


def features(rule_text: str, ref_values: list[str]) -> dict:
    try:
        det = yaml.safe_load(rule_text)["detection"]
    except Exception:  # aqg: top-level boundary - an unparsable model rule is recorded, never fatal to the harness
        return {"parsable": False}
    items = flatten(det)
    values = [v for kind, v in items if kind == "value"]
    fields = sorted({v.split("|")[0] for kind, v in items if kind == "field"} - set(det))
    shared = [v for v in values if any(v.strip("\\").lower() == r.strip("\\").lower() for r in ref_values)]
    return {"parsable": True, "fields": fields, "values": values, "values_shared_with_reference": shared,
            "uses_original_filename_or_hashes": any(f in ("OriginalFileName", "Hashes") for f in fields)}


def one_run(job: dict, shared: dict) -> dict:
    arm, cond = job["arm"], job["primary"]
    policy, with_search = ARMS[arm]
    primary = shared["primaries"][cond]
    tavily = CachedTavily(primary, shared["snippets"] if with_search else [])
    llm = SpyLLM(shared["llm"])
    started = time.monotonic()
    row = {**job, "policy": policy}
    try:
        record = run_pipeline(llm=llm, model=shared["model"], runner=shared["runner"], scenario=shared["scenario"],
                              report_text=shared["fallback"], source_url=SOURCE_URL, tavily=tavily, answer_policy=policy)
    except Exception as exc:  # aqg: top-level boundary - an errored run is recorded as errored and counted, not dropped
        return {**row, "errored": f"{type(exc).__name__}: {str(exc)[:300]}", "seconds": round(time.monotonic() - started, 1),
                "probes": {p: any(p in m for m in llm.messages) for p in PROBES}}
    best = record["iterations"][record["best_index"]]
    first = record["iterations"][0]
    ev, ev0 = best["evaluation"] or {}, first["evaluation"] or {}
    benign = lambda e: sum(b["hits"] for b in (e.get("benign") or {}).values())
    held = sum(b["hits"] for b in (record["heldout"] or {}).values())
    return {**row, "errored": None, "success": record["success"], "stop_reason": record["stop_reason"],
            "attempts": len(record["iterations"]),
            "first_attempt": {"valid": first["validation"]["ok"], "attack_detected": ev0.get("attack_detected"),
                              "benign_dev_hits": benign(ev0) if ev0 else None},
            "best_attempt": {"index": record["best_index"], "valid": best["validation"]["ok"],
                             "attack_detected": ev.get("attack_detected"), "attack_total": ev.get("attack_total"),
                             "benign_dev_hits": benign(ev) if ev else None, "rule_text": best["rule_text"]},
            "heldout_hits": held, "tokens": record["totals"]["tokens"], "seconds": record["totals"]["seconds"],
            "model_calls": len(llm.messages), "search_results_requested": tavily.asked,
            "input_sha256": record["input"]["sha256"], "input_chars": record["input"]["chars"],
            "corroboration_urls": [c["url"] for c in record["research"]["corroboration"]],
            "screening": [{k: s[k] for k in ("url", "role", "status", "reasons")} for s in record["research"]["screening"]["sources"]],
            "probes": {p: any(p in m for m in llm.messages) for p in PROBES},
            "rule_features": features(best["rule_text"], shared["ref_values"]),
            "spec_observables": [(o["field"], o["value"]) for o in record["spec"]["observables"]]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reps", type=int, default=3)
    parser.add_argument("--parallel", type=int, default=3)
    parser.add_argument("--seed", type=int, default=20261027)
    parser.add_argument("--arms", nargs="+", default=list(ARMS))
    parser.add_argument("--primaries", nargs="+", default=["clean", "raw"])
    args = parser.parse_args()

    load_dotenv()
    llm = TokenFactory.from_env()
    model = select_model([m["id"] for m in llm.list_models()], ("nemotron-3-super",))
    runner = build_runner(ROOT, "sandbox")
    scenario = next(s for s in load_scenarios(ROOT) if s["id"] == TARGET_ID)
    primaries, snippets = load_sources()
    ref_values = [v for kind, v in flatten(yaml.safe_load(scenario["expert_text"])["detection"]) if kind == "value"]
    shared = {"llm": llm, "model": model, "runner": runner, "scenario": scenario, "primaries": primaries,
              "snippets": snippets, "fallback": scenario_report_text(ROOT, scenario), "ref_values": ref_values}

    jobs = [{"arm": a, "primary": p, "rep": r} for r in range(args.reps) for p in args.primaries for a in args.arms]
    random.Random(args.seed).shuffle(jobs)  # interleaved so time-of-day and rate-limit drift hit all arms alike
    started = datetime.now(timezone.utc)
    print(f"{len(jobs)} runs, {args.parallel} at a time, model {model}", flush=True)
    results = []
    with ThreadPoolExecutor(args.parallel) as pool:
        for row in pool.map(lambda j: one_run(j, shared), jobs):
            results.append(row)
            print(f"  {row['arm']:<9} {row['primary']:<5} rep{row['rep']}: "
                  f"{'ERROR ' + row['errored'] if row['errored'] else ('pass' if row['success'] else 'fail')} "
                  f"attempts={row.get('attempts')} sha={str(row.get('input_sha256'))[:8]}", flush=True)

    out = {"started": started.isoformat(), "finished": datetime.now(timezone.utc).isoformat(), "model": model,
           "scenario": TARGET_ID, "seed": args.seed, "reps": args.reps,
           "snapshots": {"primary_clean_chars": len(primaries["clean"].content), "primary_raw_chars": len(primaries["raw"].content),
                         "snippets": [(s.url, len(s.content)) for s in snippets]},
           "evaluator": runner.describe(), "runs": results}
    path = AUDIT / f"ablation_{started.strftime('%Y%m%d_%H%M%S')}.json"
    path.write_text(json.dumps(out, indent=1, ensure_ascii=False, default=str), encoding="utf-8")
    print("wrote", path.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
