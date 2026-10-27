"""Build the cross-run results tables (docs/RESULTS_TABLE.md) from the saved batch files. No hand-copied numbers.

Two sets of tasks: the development set (evaluation/tasks.json, Runs 1-7) and the confirmatory set
(evaluation/tasks_confirmatory.json, Runs 8-9, never used while the method changed).
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEVELOPMENT = [
    ("1", "batch_20261026_194636.json", "free-form YAML, thinking on, loop bug (5 tasks aborted); local Docker"),
    ("2", "batch_20261026_195702.json", "free-form YAML, thinking on, loop bug fixed, no API retry; local Docker"),
    ("3", "batch_20261027_063055.json", "structured JSON + field hints + API retry, thinking on; local Docker"),
    ("4", "batch_20261027_064430.json", "as 3, thinking OFF; local Docker"),
    ("5", "batch_20261027_065412.json", "as 3, thinking on + resample empty skeletons; local Docker"),
    ("6", "batch_20261027_092138.json", "as 5, evaluated in a Token Factory Sandbox"),
    ("7", "batch_20261027_093520.json", "as 6 + last-resort thinking-off call when the answer is still empty; Sandbox"),
]
CONFIRMATORY = [
    ("8", "batch_20261027_093530.json", "Run 7 configuration (with the fallback); Sandbox. Headline run"),
    ("9", "batch_20261027_095239.json", "Run 6 configuration (no fallback); Sandbox. Comparison"),
]
HEADER = ("| Run | Configuration | Tasks with results | First rule valid | One-shot detects (clean) | After repair detects | "
          "After repair, errored tasks counted as misses | Repair fixed first failure | Held-out FP, repaired rules | "
          "Gen. tokens | SigmaHQ expert detects |")


def dev_hits(ev):
    return sum(b["hits"] for b in ev["benign"].values())


def stats(path, keep=lambda task: True):
    d = json.loads(path.read_text(encoding="utf-8"))
    rows = [r for r in d["rows"] if keep(r["task"])]
    ok = [r for r in rows if not r.get("error")]
    first = [r["history"][0] for r in ok]
    best = [r["history"][r["best_index"]] for r in ok]
    det = lambda i: bool(i["evaluation"] and i["evaluation"]["attack_detected"])
    needed = [r for r in ok if not (r["history"][0]["evaluation"] and det(r["history"][0])
                                    and dev_hits(r["history"][0]["evaluation"]) == 0)]
    held = [r["best_heldout"] for r in ok if r.get("best_heldout")]
    n = len(ok)
    repaired = sum(det(i) for i in best)
    return {
        "n": f"{n}/{len(rows)}",
        "valid": f"{sum(i['validation']['ok'] for i in first)}/{n}",
        "oneshot": f"{sum(det(i) for i in first)}/{n}",
        "repaired": f"{repaired}/{n}",
        "repaired_all": f"{repaired}/{len(rows)}",
        "expert": f"{sum(bool(r['expert_dev']['attack_detected']) for r in ok)}/{n}",
        "repair": f"{sum(1 for r in needed if r['success'])}/{len(needed)}",
        "fp": f"{sum(1 for h in held if h['hits'])}/{len(held)} rules, {sum(h['hits'] for h in held)} events",
        "tokens": f"{sum(i['tokens'] for r in ok for i in r['history']):,}",
    }


def table(runs, keep=lambda task: True):
    lines = [HEADER, "|" + "---|" * 11]
    for run, name, cfg in runs:
        path = ROOT / "evidence/runs" / name
        if not path.exists():
            lines.append(f"| {run} | {cfg} | _not run yet_ |" + " |" * 8)
            continue
        s = stats(path, keep)
        lines.append(f"| {run} | {cfg} | {s['n']} | {s['valid']} | {s['oneshot']} | {s['repaired']} | {s['repaired_all']} | "
                     f"{s['repair']} | {s['fp']} | {s['tokens']} | {s['expert']} |")
    return "\n".join(lines)


def main():
    parts = ["## Development set (20 tasks, `evaluation/tasks.json`)", "",
             "Used while the method changed. Run-to-run differences are mostly model noise.", "",
             table(DEVELOPMENT), "",
             "## Confirmatory set (20 new tasks, `evaluation/tasks_confirmatory.json`)", "",
             "Frozen before any model call on them; 10 dated 2026 and 10 older. Plan in `docs/EVALUATION_METHODOLOGY.md`.", "",
             table(CONFIRMATORY), "",
             "### Confirmatory set by rule date", ""]
    for label, keep in (("Rules dated 2026 (10 tasks)", lambda t: t["year_2026"]),
                        ("Older rules (10 tasks)", lambda t: not t["year_2026"])):
        parts += [f"**{label}**", "", table(CONFIRMATORY, keep), ""]
    out = ROOT / "docs/RESULTS_TABLE.md"
    out.write_text("\n".join(parts), encoding="utf-8")
    print("\n".join(parts))


if __name__ == "__main__":
    sys.exit(main())
