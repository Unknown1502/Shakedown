"""Sandbox vs local-runner parity: same rules, same logs, compare what each evaluator reports.

For a seeded random sample of SigmaHQ reference rules (rule + labelled attack EVTX), evaluates each rule with
the local isolated Docker runner and with the Token Factory Sandbox runner, on the attack file and on the
win7 benign development logs, and compares match counts. Any disagreement is listed, not hidden.
Writes data/audit/sandbox_parity.json.
"""
import argparse
import json
import random
import shutil
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from shakedown.config import load_dotenv  # noqa: E402
from shakedown.harness.checker import CheckerConfig, run_checker  # noqa: E402
from shakedown.harness.sandbox import SandboxConfig, SandboxRunner  # noqa: E402

SIGMA = ROOT / "data/raw/sigma"
BASELINE = ROOT / "data/raw/evtx-baseline/v0.8.5"


def counts(run, rule_id):
    mine = [m for m in run.matches if m.rule_id == rule_id]
    return {"events": len(mine), "files": sorted({m.evtx_file for m in mine})}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=20)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()
    load_dotenv()

    pairs = json.loads((ROOT / "data/audit/regression_pairs.json").read_text(encoding="utf-8"))["pairs"]
    usable = [p for p in pairs if not p["problems"] and any(t["type"] == "evtx" and t["exists"] for t in p["tests"])]
    sample = random.Random(args.seed).sample(usable, args.n)

    local_cfg = CheckerConfig(checker=BASELINE / "evtx-sigma-checker", thor_config=SIGMA / "tests/thor.yml")
    dev = BASELINE / "win7-x86"
    sandbox = SandboxRunner(SandboxConfig(datasets={dev.resolve(): "/data/win7-x86",
                                                    (BASELINE / "Logs_Client").resolve(): "/data/Logs_Client"}))

    def one(pair):
        rule = (SIGMA / pair["rule_path"]).read_text(encoding="utf-8")
        attack = SIGMA / next(t["path"] for t in pair["tests"] if t["type"] == "evtx")
        out = {"rule_id": pair["rule_id"], "rule_path": pair["rule_path"]}
        for label, runner in (("local", lambda r, d: run_checker(local_cfg, r, d)), ("sandbox", sandbox)):
            started = time.monotonic()
            try:
                with tempfile.TemporaryDirectory() as tmp:
                    shutil.copyfile(attack, Path(tmp) / attack.name)
                    a = runner({"c": rule}, [Path(tmp)])
                b = runner({"c": rule}, [dev])
                out[label] = {"attack": counts(a, pair["rule_id"]), "benign_dev": counts(b, pair["rule_id"]),
                              "seconds": round(time.monotonic() - started, 1)}
            except Exception as exc:  # aqg: top-level boundary - record per-rule failures instead of aborting the sample
                out[label] = {"error": f"{type(exc).__name__}: {str(exc)[:300]}"}
        out["agree"] = ("error" not in out["local"] and "error" not in out["sandbox"]
                        and out["local"]["attack"] == out["sandbox"]["attack"]
                        and out["local"]["benign_dev"] == out["sandbox"]["benign_dev"])
        print(("OK  " if out["agree"] else "DIFF"), pair["rule_path"][-70:], flush=True)
        return out

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(one, sample))

    summary = {"sample": args.n, "seed": args.seed, "agree": sum(r["agree"] for r in results),
               "disagree": [r for r in results if not r["agree"]], "sandbox_image": sandbox.describe(),
               "results": results}
    out = ROOT / "data/audit/sandbox_parity.json"
    out.write_text(json.dumps(summary, indent=1), encoding="utf-8")
    print(f"agree {summary['agree']}/{args.n}; wrote {out}")


if __name__ == "__main__":
    main()
