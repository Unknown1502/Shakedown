"""Freeze a fresh, never-run task list for the confirmatory evaluation (writes evaluation/tasks_confirmatory.json).

Why: the first 20 tasks (evaluation/tasks.json) were used for six runs while the method was developed, so they are
a development set. This draws 20 *different* tasks, 10 from rules dated 2026 (more likely to postdate the model's
training data, which also covers the temporal-subset claim) and 10 from older rules, same three log sources.
Run once, before any model call on these tasks; refuses to overwrite.
"""
import json
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEED = 20261028
CATEGORIES = ("process_creation", "ps_script", "registry_set")
OUT = ROOT / "evaluation/tasks_confirmatory.json"


def main() -> int:
    if OUT.exists():
        print(f"{OUT} already exists; refusing to overwrite a frozen task list")
        return 1
    used = {t["rule_id"] for t in json.loads((ROOT / "evaluation/tasks.json").read_text(encoding="utf-8"))["tasks"]}
    pairs = json.loads((ROOT / "data/audit/regression_pairs.json").read_text(encoding="utf-8"))["pairs"]
    usable = [p for p in pairs if not p["problems"] and p.get("category") in CATEGORIES and p["rule_id"] not in used
              and any(t["type"] == "evtx" and t["exists"] for t in p["tests"])]
    new = sorted((p for p in usable if str(p.get("date", "")).startswith("2026")), key=lambda p: p["rule_id"])
    old = sorted((p for p in usable if not str(p.get("date", "")).startswith("2026")), key=lambda p: p["rule_id"])
    rng = random.Random(SEED)
    chosen = rng.sample(new, 10) + rng.sample(old, 10)
    tasks = [{"rule_id": p["rule_id"], "rule_path": p["rule_path"], "title": p["title"], "category": p["category"],
              "date": p.get("date"), "year_2026": str(p.get("date", "")).startswith("2026"),
              "sample": next(t["path"] for t in p["tests"] if t["type"] == "evtx"),
              "sample_sha256": next(t["sha256"] for t in p["tests"] if t["type"] == "evtx")} for p in chosen]
    OUT.write_text(json.dumps({"seed": SEED, "pools": {"dated_2026": len(new), "older": len(old)},
                               "frozen_at": datetime.now(timezone.utc).isoformat(), "tasks": tasks}, indent=1),
                   encoding="utf-8")
    print(f"froze {len(tasks)} tasks ({sum(t['year_2026'] for t in tasks)} dated 2026; pools {len(new)} / {len(old)}) -> {OUT}")
    for t in tasks:
        print(f"  {t['date']}  {t['category']:<17} {t['title']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
