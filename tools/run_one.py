"""Run the full Shakedown loop once on a single SigmaHQ-derived task and save the evidence.

Task input is the rule's descriptive metadata only (title, description, references, tags). The expert
rule logic is never shown to the model; it is evaluated separately as a baseline with the same evaluator.
Live: makes Nebius Token Factory calls (a few cents). Needs NEBIUS_API_KEY (env or .env) and Docker.
"""
import argparse
import dataclasses
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

from shakedown.config import load_dotenv
from shakedown.evaluate import evaluate_rule, make_runner
from shakedown.harness.checker import CheckerConfig
from shakedown.llm import TokenFactory, select_model
from shakedown.loop import run_loop
from shakedown.spec import extract_spec

ROOT = Path(__file__).resolve().parents[1]
SIGMA = ROOT / "data/raw/sigma"
BASELINE = ROOT / "data/raw/evtx-baseline/v0.8.5"


def task_from_rule(rule_path: Path) -> tuple[str, dict]:
    doc = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    refs = "\n".join(f"- {r}" for r in doc.get("references") or [])
    tags = ", ".join(doc.get("tags") or [])
    report = (f"{doc['title']}\n\n{doc.get('description', '').strip()}\n\nReferences:\n{refs}\n\nATT&CK tags: {tags}\n")
    return report, doc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rule", required=True, help="path under data/raw/sigma of the reference rule")
    parser.add_argument("--max-repairs", type=int, default=3)
    parser.add_argument("--model", help="exact listed NVIDIA model ID (default: preference order)")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "data/runs")
    args = parser.parse_args()

    load_dotenv()
    tf = TokenFactory.from_env()
    model = select_model([m["id"] for m in tf.list_models()],
                         ("nemotron-3-super", "lightning", "nemotron"), args.model)

    rule_path = SIGMA / args.rule
    report, doc = task_from_rule(rule_path)
    rule_id = str(doc["id"])
    sample_dir = next((SIGMA / "regression_data").rglob(f"{rule_id}.evtx")).parent
    attack = sample_dir / f"{rule_id}.evtx"

    config = CheckerConfig(checker=BASELINE / "evtx-sigma-checker", thor_config=SIGMA / "tests/thor.yml")
    runner = make_runner(config)
    dev = {"benign_dev_win7": BASELINE / "win7-x86"}
    held = {"benign_heldout_win10": BASELINE / "Logs_Client"}

    spec = extract_spec(tf, model, report)
    result = run_loop(tf, model, report, spec, max_repairs=args.max_repairs,
                      evaluate=lambda text: evaluate_rule(text, [attack], dev, runner))

    final = result.best
    heldout = evaluate_rule(final.rule_text, [attack], held, runner) if final.validation.ok else None
    expert_text = rule_path.read_text(encoding="utf-8")
    expert = {"dev": evaluate_rule(expert_text, [attack], dev, runner),
              "heldout": evaluate_rule(expert_text, [attack], held, runner)}

    record = {"at": datetime.now(timezone.utc).isoformat(), "model": model, "rule": args.rule, "task_report": report,
              "spec": spec.to_dict(), "spec_dropped": spec.dropped, "success": result.success,
              "stop_reason": result.stop_reason, "tokens_total": sum(i.tokens for i in result.history),
              "history": [dataclasses.asdict(i) for i in result.history],
              "best_index": final.index, "best_heldout": dataclasses.asdict(heldout) if heldout else None,
              "expert_baseline": {k: dataclasses.asdict(v) for k, v in expert.items()}}
    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{rule_id[:8]}.json"
    out.write_text(json.dumps(record, indent=1, default=str), encoding="utf-8")

    print(f"model={model} success={result.success} stop={result.stop_reason} tokens={record['tokens_total']}")
    for i in result.history:
        ev = i.evaluation
        print(f"  iter {i.index} {i.action:8s} valid={i.validation.ok} "
              + (f"attack {ev.attack_detected}/{ev.attack_total} benign_dev_hits={ev.benign_hits} ({ev.seconds}s)"
                 if ev else "not evaluated"))
    if heldout:
        print(f"best (iter {final.index}) on held-out win10: attack {heldout.attack_detected}/{heldout.attack_total}, "
              f"benign hits {heldout.benign_hits} in {sum(b.files_with_hits for b in heldout.benign.values())} files")
    print(f"expert baseline: dev attack {expert['dev'].attack_detected}/{expert['dev'].attack_total} "
          f"benign_dev_hits={expert['dev'].benign_hits}; heldout attack {expert['heldout'].attack_detected}/"
          f"{expert['heldout'].attack_total} benign_heldout_hits={expert['heldout'].benign_hits}")
    print(f"saved {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
