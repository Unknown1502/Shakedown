"""Compare the screened demo re-recordings with the pre-screen originals, scenario by scenario.

    PYTHONIOENCODING=utf-8 PYTHONPATH=. uv run python tools/leakage_compare_demos.py
"""
import glob
import json
import os
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from leakage_trace import flatten  # noqa: E402

SLASH = chr(92)


def values(rule_text: str) -> set[str]:
    try:
        return {v.strip(SLASH).lower() for kind, v in flatten(yaml.safe_load(rule_text)["detection"]) if kind == "value"}
    except Exception:  # aqg: top-level boundary - an unparsable rule just has no values to compare
        return set()


def summarize(path: str) -> dict:
    rec = json.loads(Path(path).read_text(encoding="utf-8"))
    best = rec["iterations"][rec["best_index"]]
    ref, gen = values(rec["expert"]["rule_text"]), values(best["rule_text"])
    research = rec["research"] or {}
    screening = research.get("screening")
    sources = ([(s["url"].split("/")[2], s["status"], s["reasons"]) for s in screening["sources"] if s["role"] == "corroboration"]
               if screening else [(c["url"].split("/")[2], "pre-screen", "") for c in research.get("corroboration", [])])
    return {"passed": rec["success"], "attempts": len(rec["iterations"]), "tokens": rec["totals"]["tokens"],
            "seconds": rec["totals"]["seconds"], "heldout_hits": sum(b["hits"] for b in (rec["heldout"] or {}).values()),
            "rule_values": len(gen), "reference_values": len(ref), "rule_values_also_in_reference": len(gen & ref),
            "primary": (research.get("primary") or {}).get("url", "")[:70], "research_error": research.get("error"),
            "corroboration": sources}


def main() -> None:
    for path in sorted(glob.glob(str(ROOT / "demo/recorded_screened/*.json"))):
        name = os.path.basename(path)
        print("==", name)
        for label, p in (("screened ", path), ("pre-screen", str(ROOT / "demo/recorded" / name))):
            if os.path.exists(p):
                s = summarize(p)
                src = s.pop("corroboration")
                print(f"  {label}: {s}")
                for item in src:
                    print("      ", item)


if __name__ == "__main__":
    main()
