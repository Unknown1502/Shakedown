"""Harness parity check: run every usable SigmaHQ reference rule through Shakedown's
isolated checker and compare against SigmaHQ's recorded regression expectations.

Optionally also runs all of them against benign baseline directories.
"""
import argparse
import json
import shutil
import tempfile
from collections import Counter
from pathlib import Path

from shakedown.harness.checker import CheckerConfig, run_checker


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sigma-root", type=Path, required=True)
    parser.add_argument("--audit", type=Path, required=True, help="output of tools/dataset_audit.py")
    parser.add_argument("--checker", type=Path, required=True)
    parser.add_argument("--benign", type=Path, action="append", default=[], help="benign EVTX dir (repeatable)")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    root = args.sigma_root.resolve()
    pairs = json.loads(args.audit.read_text(encoding="utf-8"))["pairs"]
    usable = [p for p in pairs if not p["problems"] and any(t["type"] == "evtx" and t["exists"] for t in p["tests"])]
    config = CheckerConfig(checker=args.checker, thor_config=root / "tests/thor.yml")
    rules = {p["rule_id"]: (root / p["rule_path"]).read_text(encoding="utf-8") for p in usable}

    with tempfile.TemporaryDirectory(prefix="shakedown-samples-") as tmp:
        for p in usable:
            for t in p["tests"]:
                if t["type"] == "evtx":
                    shutil.copyfile(root / t["path"], Path(tmp) / Path(t["path"]).name)
        run = run_checker(config, rules, [Path(tmp)])

    own = Counter(m.rule_id for m in run.matches if Path(m.evtx_file).stem == m.rule_id)
    results = []
    for p in usable:
        expected = next(t["match_count"] for t in p["tests"] if t["type"] == "evtx")
        got = own.get(p["rule_id"], 0)
        results.append({"rule_id": p["rule_id"], "rule_path": p["rule_path"], "expected": expected, "got": got,
                        "reproduced": got >= (expected if expected is not None else 1)})

    summary = {
        "rules_evaluated": len(usable),
        "reproduced": sum(r["reproduced"] for r in results),
        "not_reproduced": [r for r in results if not r["reproduced"]],
        "checker_seconds": round(run.duration_s, 1),
        "ignored_output_lines": len(run.ignored_lines),
    }

    benign = {}
    for benign_dir in args.benign:
        brun = run_checker(config, rules, [benign_dir])
        per_rule = Counter(m.rule_id for m in brun.matches)
        benign[benign_dir.name] = {"rules_with_hits": len(per_rule), "total_hits": sum(per_rule.values()),
                                   "per_rule": dict(per_rule.most_common()), "checker_seconds": round(brun.duration_s, 1)}
    summary["benign"] = {k: {kk: vv for kk, vv in v.items() if kk != "per_rule"} for k, v in benign.items()}

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"summary": summary, "results": results, "benign": benign}, indent=1),
                        encoding="utf-8")
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
