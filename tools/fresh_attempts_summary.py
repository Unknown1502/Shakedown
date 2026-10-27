"""One table over the fresh demo-candidate attempts: outcome, repair path, rule overlap with the reference, source mode.

    PYTHONIOENCODING=utf-8 PYTHONPATH=. uv run python tools/fresh_attempts_summary.py
Writes evidence/demo_decision/fresh_attempts.json (the numbers docs/DEMO_DECISION.md cites).
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from leakage_compare_demos import summarize  # noqa: E402


def main() -> None:
    rows = []
    for path in sorted((ROOT / "demo/fresh_attempts").rglob("*.json")):
        rec = json.loads(path.read_text(encoding="utf-8"))
        s = summarize(str(path))
        s.pop("corroboration")
        path_of_attempts = []
        for it in rec["iterations"]:
            ev = it["evaluation"]
            if not it["validation"]["ok"]:
                path_of_attempts.append("invalid rule")
            elif it["evaluator_error"]:
                path_of_attempts.append("evaluator error")
            elif ev["attack_missed"]:
                path_of_attempts.append("missed attack")
            elif sum(b["hits"] for b in ev["benign"].values()):
                path_of_attempts.append(f"{sum(b['hits'] for b in ev['benign'].values())} benign dev events")
            else:
                path_of_attempts.append("pass")
        screening = rec["research"]["screening"]
        rows.append({"file": str(path.relative_to(ROOT)).replace("\\", "/"), "scenario": rec["scenario"]["title"],
                     "run": path.parent.name, "attempt_outcomes": path_of_attempts, **s,
                     "source_mode": rec.get("source_mode"),
                     "sources_excluded": sum(1 for x in screening["sources"] if x["status"] == "excluded"),
                     "sources_shown": [x["url"].split("/")[2] for x in screening["sources"] if x["role"] == "corroboration" and x["status"] in ("included", "flagged")]})
    out = ROOT / "evidence/demo_decision"
    out.mkdir(parents=True, exist_ok=True)
    (out / "fresh_attempts.json").write_text(json.dumps(rows, indent=1), encoding="utf-8")
    for r in rows:
        print(f"{r['scenario'][:40]:<40} {r['run']}: passed={r['passed']} path={r['attempt_outcomes']} held-out={r['heldout_hits']} "
              f"rule values {r['rule_values']} (in reference {r['rule_values_also_in_reference']} of {r['reference_values']}) "
              f"tokens={r['tokens']} s={r['seconds']} mode={(r['source_mode'] or {}).get('mode')}/{(r['source_mode'] or {}).get('verdict')} "
              f"excluded={r['sources_excluded']} shown={r['sources_shown']}")


if __name__ == "__main__":
    main()
