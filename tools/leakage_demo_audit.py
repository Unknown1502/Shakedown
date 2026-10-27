"""Audit the recorded demos: what did their corroborating web sources reveal about the answer rule?

Old records keep each source's URL and length, not its text. This re-runs the same Tavily search the pipeline ran
(`<title> Windows detection`, 3 results), accepts the result as a reconstruction only if every URL and length equals
the record, and then measures what that text reveals about the SigmaHQ rule (its id, detection field names, detection
values). Where the reconstruction does not match, the demo is reported as "text not recoverable" and only the URLs are
judged. Writes evidence/leakage_audit/demo_audit.json.

    PYTHONIOENCODING=utf-8 PYTHONPATH=. uv run python tools/leakage_demo_audit.py
"""
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
from leakage_trace import flatten  # noqa: E402

from shakedown.config import load_dotenv  # noqa: E402
from shakedown.research import Source, Tavily, answer_reasons  # noqa: E402

DIRS = ("demo/recorded", "demo/recorded_local")


def main() -> None:
    load_dotenv()
    tavily = Tavily.from_env()
    report = []
    for directory in DIRS:
        for path in sorted((ROOT / directory).glob("*.json")):
            rec = json.loads(path.read_text(encoding="utf-8"))
            target = {"id": rec["scenario"]["id"], "title": rec["scenario"]["title"]}
            recorded = [(c["url"], c["chars"]) for c in rec["research"]["corroboration"]]
            ref = yaml.safe_load(rec["expert"]["rule_text"])["detection"]
            items = flatten(ref)
            ref_values = [v for kind, v in items if kind == "value"]
            ref_fields = sorted({v.split("|")[0] for kind, v in items if kind == "field"} - set(ref))
            found = tavily.search(f"{target['title']} Windows detection", max_results=3)
            rebuilt = [(s.url, len(s.content)) for s in found]
            matches = rebuilt == recorded
            entry = {"demo": f"{directory}/{path.name}", "title": target["title"], "success": rec["success"],
                     "attempts": len(rec["iterations"]), "reconstruction_matches": matches, "sources": []}
            sources = found if matches else [Source(c["url"], c.get("title", ""), "", c.get("retrieved_at", ""), "search")
                                             for c in rec["research"]["corroboration"]]
            for s in sources:
                low = s.content.lower()
                entry["sources"].append({
                    "url": s.url, "reasons": answer_reasons(s, target), "text_available": matches,
                    "reference_field_names_in_text": [f for f in ref_fields if f.lower() in low] if matches else None,
                    "reference_values_in_text": [v for v in ref_values if len(v.strip("\\")) > 4 and v.strip("\\").lower() in low] if matches else None,
                    "text": s.content if matches else None})
            report.append(entry)
            flagged = [x for x in entry["sources"] if x["reasons"]]
            print(f"{entry['demo']}: passed={rec['success']} reconstruction_matches={matches} flagged={len(flagged)}/3")
            for x in entry["sources"]:
                print(f"   {x['url'][:95]}\n      reasons={x['reasons']} ref_fields={x['reference_field_names_in_text']} "
                      f"ref_values={x['reference_values_in_text']}")
    (ROOT / "evidence/leakage_audit/demo_audit.json").write_text(json.dumps(report, indent=1, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    main()
