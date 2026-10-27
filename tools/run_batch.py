"""Batch evaluation: one-shot vs repair loop vs expert rule on a pre-registered sample of tasks.

See docs/EVALUATION_METHODOLOGY.md. Live: makes Token Factory calls. Run `--select` first to freeze the
task list in evaluation/tasks.json; `--run` refuses to start without it.
"""
import argparse
import dataclasses
import json
import random
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import yaml

from shakedown.config import load_dotenv
from shakedown.evaluate import benign_by_rule, evaluate_rule
from shakedown.runners import build_runner
from shakedown.llm import TokenFactory, select_model
from shakedown.loop import run_loop
from shakedown.spec import extract_spec

ROOT = Path(__file__).resolve().parents[1]
SIGMA = ROOT / "data/raw/sigma"
BASELINE = ROOT / "data/raw/evtx-baseline/v0.8.5"
TASKS = ROOT / "evaluation/tasks.json"
SEED = 20261027
STRATA = {"process_creation": 14, "ps_script": 3, "registry_set": 3}


def select_tasks() -> list[dict]:
    pairs = json.loads((ROOT / "data/audit/regression_pairs.json").read_text(encoding="utf-8"))["pairs"]
    usable = [p for p in pairs if not p["problems"] and any(t["type"] == "evtx" and t["exists"] for t in p["tests"])]
    rng, chosen = random.Random(SEED), []
    for category, n in STRATA.items():
        pool = sorted((p for p in usable if p.get("category") == category), key=lambda p: p["rule_id"])
        chosen += rng.sample(pool, n)
    return [{"rule_id": p["rule_id"], "rule_path": p["rule_path"], "title": p["title"], "category": p["category"],
             "date": p.get("date"), "year_2026": str(p.get("date", "")).startswith("2026"),
             "sample": next(t["path"] for t in p["tests"] if t["type"] == "evtx"),
             "sample_sha256": next(t["sha256"] for t in p["tests"] if t["type"] == "evtx")} for p in chosen]


def task_report(rule_path: Path) -> str:
    doc = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    refs = "\n".join(f"- {r}" for r in doc.get("references") or [])
    return (f"{doc['title']}\n\n{str(doc.get('description', '')).strip()}\n\nReferences:\n{refs}\n\n"
            f"ATT&CK tags: {', '.join(doc.get('tags') or [])}\n")


def run_task(tf, model, task, runner, max_repairs, rule_format, thinking, fallback):
    try:
        rule_path = SIGMA / task["rule_path"]
        attack = SIGMA / task["sample"]
        dev = {"benign_dev_win7": BASELINE / "win7-x86"}
        report = task_report(rule_path)
        spec = extract_spec(tf, model, report)
        result = run_loop(tf, model, report, spec, max_repairs=max_repairs, rule_format=rule_format,
                          thinking=thinking, fallback_without_thinking=fallback,
                          evaluate=lambda text: evaluate_rule(text, [attack], dev, runner))
        expert_text = rule_path.read_text(encoding="utf-8")
        expert_dev = evaluate_rule(expert_text, [attack], dev, runner)
        return {"task": task, "spec": spec.to_dict(), "spec_dropped": spec.dropped, "history": result.history,
                "best_index": result.best.index, "success": result.success, "stop_reason": result.stop_reason,
                "expert_text": expert_text, "expert_dev": expert_dev, "error": None}
    except Exception as exc:  # aqg: top-level boundary - one failed task must not abort the batch; it is recorded
        return {"task": task, "error": f"{type(exc).__name__}: {str(exc)[:400]}"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--select", action="store_true", help="freeze the task list and exit")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--max-repairs", type=int, default=3)
    parser.add_argument("--rule-format", choices=["structured", "yaml"], default="structured")
    parser.add_argument("--thinking", choices=["on", "off"], default="on", help="model thinking mode for rule generation")
    parser.add_argument("--fallback-thinking-off", action="store_true",
                        help="after the resamples, make one last call with thinking off if the answer is still empty")
    parser.add_argument("--tasks-file", type=Path, help="alternative frozen task list (default evaluation/tasks.json)")
    parser.add_argument("--runner", choices=["sandbox", "local"], default="sandbox",
                        help="evaluator: Token Factory Sandbox (default) or the local Docker runner (Runs 1-5)")
    parser.add_argument("--limit", type=int, help="debug: only the first N tasks (NOT for reported results)")
    args = parser.parse_args()

    if args.select:
        if TASKS.exists():
            print(f"{TASKS} already exists; refusing to overwrite a frozen task list")
            return 1
        tasks = select_tasks()
        TASKS.parent.mkdir(parents=True, exist_ok=True)
        TASKS.write_text(json.dumps({"seed": SEED, "strata": STRATA, "frozen_at": datetime.now(timezone.utc).isoformat(),
                                     "tasks": tasks}, indent=1), encoding="utf-8")
        print(f"froze {len(tasks)} tasks ({sum(t['year_2026'] for t in tasks)} dated 2026) -> {TASKS}")
        return 0
    if not args.run:
        parser.error("choose --select or --run")
    tasks_path = args.tasks_file or TASKS
    if not tasks_path.exists():
        parser.error("run --select first so the task list is frozen before any model call")

    load_dotenv()
    tf = TokenFactory.from_env()
    model = select_model([m["id"] for m in tf.list_models()], ("nemotron-3-super",))
    tasks = json.loads(tasks_path.read_text(encoding="utf-8"))["tasks"][: args.limit]
    runner = build_runner(ROOT, args.runner)

    started = datetime.now(timezone.utc)
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(lambda t: run_task(tf, model, t, runner, args.max_repairs, args.rule_format,
                                                   args.thinking == "on", args.fallback_thinking_off), tasks))
    ok = [r for r in results if not r["error"]]

    # Held-out benign: one checker run per batch of rules with unique ids (iteration 0, final best, expert).
    held = BASELINE / "Logs_Client"
    # only candidates the evaluator could load (evaluation present); an unloadable rule would fail the whole run
    first = {r["task"]["rule_id"]: r["history"][0].rule_text for r in ok if r["history"][0].evaluation is not None}
    expert = {r["task"]["rule_id"]: r["expert_text"] for r in ok}
    best = {r["task"]["rule_id"]: r["history"][r["best_index"]].rule_text for r in ok
            if r["history"][r["best_index"]].evaluation is not None}
    # candidates share the pinned id across iterations of one task, so each group below has unique ids
    ids_first = {tid: _id(text) for tid, text in first.items()}
    ids_best = {tid: _id(text) for tid, text in best.items()}
    h_first = benign_by_rule({ids_first[t]: x for t, x in first.items()}, held, runner)
    h_best = benign_by_rule({ids_best[t]: x for t, x in best.items()}, held, runner)
    h_expert = benign_by_rule({_id(x): x for x in expert.values()}, held, runner)

    out_rows = []
    for r in results:
        if r["error"]:
            out_rows.append({"task": r["task"], "error": r["error"]})
            continue
        tid, hist = r["task"]["rule_id"], r["history"]
        out_rows.append({
            "task": r["task"], "spec": r["spec"], "spec_dropped": r["spec_dropped"], "success": r["success"],
            "stop_reason": r["stop_reason"], "best_index": r["best_index"],
            "history": [dataclasses.asdict(i) for i in hist],
            "oneshot_heldout": dataclasses.asdict(h_first[ids_first[tid]]) if tid in ids_first else None,
            "best_heldout": dataclasses.asdict(h_best[ids_best[tid]]) if tid in ids_best else None,
            "expert_dev": dataclasses.asdict(r["expert_dev"]),
            "expert_heldout": dataclasses.asdict(h_expert[_id(r["expert_text"])]),
            "expert_text": r["expert_text"]})

    record = {"started": started.isoformat(), "finished": datetime.now(timezone.utc).isoformat(), "model": model,
              "max_repairs": args.max_repairs, "rule_format": args.rule_format, "thinking": args.thinking, "limit": args.limit,
              "fallback_thinking_off": args.fallback_thinking_off, "evaluator": runner.describe(),
              "tasks_file": str(Path(tasks_path).resolve().relative_to(ROOT)),
              "rows": out_rows}
    out = ROOT / "data/runs" / f"batch_{started.strftime('%Y%m%d_%H%M%S')}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=1, default=str), encoding="utf-8")
    print(f"tasks={len(tasks)} errors={len(results) - len(ok)} saved {out}")
    return 0


def _id(text: str) -> str:
    return str(yaml.safe_load(text)["id"])


if __name__ == "__main__":
    sys.exit(main())
