"""Tabulate a leakage ablation file: one row per (report page, arm), every run counted, none dropped.

    PYTHONPATH=. uv run python tools/leakage_summary.py evidence/leakage_audit/ablation_<timestamp>.json
"""
import json
import statistics
import sys
from math import comb
from pathlib import Path


def cell(runs: list[dict]) -> dict:
    done = [r for r in runs if not r["errored"]]
    best = [r["best_attempt"] for r in done]
    feats = [r["rule_features"] for r in done if r["rule_features"].get("parsable")]
    return {
        "runs": len(runs), "errored": len(runs) - len(done),
        "passed (attack caught, 0 benign dev events)": sum(1 for r in done if r["success"]),
        "first attempt caught the attack": sum(1 for r in done if r["first_attempt"]["attack_detected"]),
        "best attempt caught the attack": sum(1 for b in best if b["attack_detected"]),
        "attempts (median)": statistics.median(r["attempts"] for r in done) if done else None,
        "held-out benign hits (runs with any)": sum(1 for r in done if r["heldout_hits"]),
        "tokens (mean)": round(statistics.mean(r["tokens"] for r in done)) if done else None,
        "seconds (mean)": round(statistics.mean(r["seconds"] for r in done)) if done else None,
        "rule uses OriginalFileName or Hashes": sum(1 for f in feats if f["uses_original_filename_or_hashes"]),
        "rule contains the AdFind.exe image value": sum(1 for f in feats if any(v.lower().strip("\\") == "adfind.exe" for v in f["values"])),
        "distinct input hashes": len({r["input_sha256"] for r in done}),
        "model saw the target rule id": sum(1 for r in runs if r["probes"]["514e7e3e"]),
        "model saw sigmaquery/detection.fyi": sum(1 for r in runs if r["probes"]["sigmaquery"] or r["probes"]["detection.fyi"]),
        "model saw 'AdFind.exe' (capital F)": sum(1 for r in runs if r["probes"]["AdFind.exe"]),
    }


def fisher(a_pass: int, a_n: int, b_pass: int, b_n: int) -> float:
    """Two-sided Fisher exact test on a 2x2 table (pass/fail by arm)."""
    total, passed = a_n + b_n, a_pass + b_pass

    def prob(k: int) -> float:
        return comb(passed, k) * comb(total - passed, a_n - k) / comb(total, a_n)

    observed = prob(a_pass)
    lo, hi = max(0, passed - b_n), min(passed, a_n)
    return min(1.0, sum(p for k in range(lo, hi + 1) if (p := prob(k)) <= observed + 1e-12))


def main(path: str) -> None:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    cells = {}
    for run in data["runs"]:
        cells.setdefault((run["primary"], run["arm"]), []).append(run)
    keys = sorted(cells, key=lambda k: (k[0], ["recorded", "excluded", "no-search"].index(k[1])))
    table = {k: cell(cells[k]) for k in keys}
    metrics = list(next(iter(table.values())))
    head = "| metric | " + " | ".join(f"{p} / {a}" for p, a in keys) + " |"
    lines = [head, "|---|" + "---|" * len(keys)]
    lines += [f"| {m} | " + " | ".join(str(table[k][m]) for k in keys) + " |" for m in metrics]
    out = "\n".join(lines)
    print(out)
    Path(path).with_suffix(".summary.md").write_text(out + "\n", encoding="utf-8")
    pooled = {}
    for run in data["runs"]:
        pooled.setdefault(run["arm"], []).append(run)
    print("\npooled over both report-page conditions (an errored run counts as not passed):")
    counts = {}
    for arm in ("recorded", "excluded", "no-search"):
        runs = pooled[arm]
        counts[arm] = (sum(1 for r in runs if r.get("success")), len(runs),
                       sum(1 for r in runs if not r["errored"] and r["first_attempt"]["attack_detected"]),
                       sum(1 for r in runs if not r["errored"] and r["heldout_hits"]))
        print(f"  {arm:<9} passed {counts[arm][0]}/{counts[arm][1]}  first attempt caught {counts[arm][2]}/{counts[arm][1]}  "
              f"runs with held-out benign hits {counts[arm][3]}/{counts[arm][1]}")
    print("  two-sided Fisher exact p for 'passed' (small samples: none of these separate the arms):")
    for a, b in (("recorded", "excluded"), ("recorded", "no-search"), ("excluded", "no-search")):
        print(f"    {a} vs {b}: p = {fisher(counts[a][0], counts[a][1], counts[b][0], counts[b][1]):.2f}")
    print("\nerrored runs:")
    for r in data["runs"]:
        if r["errored"]:
            print(" ", r["primary"], r["arm"], r["rep"], r["errored"])


if __name__ == "__main__":
    main(sys.argv[1])
