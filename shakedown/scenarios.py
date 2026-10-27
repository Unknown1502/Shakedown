"""The 20 frozen evaluation tasks as runnable scenarios.

A scenario bundles one attack file with the benign sets it is tested against. Its report text is built from the
SigmaHQ rule's descriptive metadata only; the expert detection logic is kept aside as a baseline and never
put in a prompt.
"""
import json
from pathlib import Path

import yaml


def load_scenarios(root: Path) -> list[dict]:
    root = Path(root)
    sigma = root / "data/raw/sigma"
    base = root / "data/raw/evtx-baseline/v0.8.5"
    tasks = json.loads((root / "evaluation/tasks.json").read_text(encoding="utf-8"))["tasks"]
    out = []
    for t in tasks:
        rule_path = sigma / t["rule_path"]
        doc = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        out.append({
            "id": t["rule_id"], "title": t["title"], "category": t["category"], "rule_path": t["rule_path"],
            "attack": sigma / t["sample"],
            "benign_dev": {"benign_dev_win7": base / "win7-x86"},
            "benign_heldout": {"benign_heldout_win10": base / "Logs_Client"},
            "expert_text": rule_path.read_text(encoding="utf-8"),
            "reference_urls": list(doc.get("references") or []),
        })
    return out


def scenario_report_text(root: Path, scenario: dict) -> str:
    doc = yaml.safe_load((Path(root) / "data/raw/sigma" / scenario["rule_path"]).read_text(encoding="utf-8"))
    refs = "\n".join(f"- {r}" for r in doc.get("references") or [])
    return (f"{doc['title']}\n\n{str(doc.get('description', '')).strip()}\n\nReferences:\n{refs}\n\n"
            f"ATT&CK tags: {', '.join(doc.get('tags') or [])}\n")
