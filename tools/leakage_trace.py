"""Leakage trace for one saved live run: what did each web source reveal, and where does each part of the
generated rule come from?

    PYTHONIOENCODING=utf-8 PYTHONPATH=. uv run python tools/leakage_trace.py \\
        evidence/leakage_audit/original/live_63b72e6e0664.json

Inputs are the saved run record, a snapshot of the primary page and a re-run of the corroboration search
(evidence/leakage_audit/snapshot/ and original/reconstructed_corroboration_search.json). The original record stores only
the length of each source, so the snippet text is a reconstruction: it is accepted only if every URL and length matches
the record. Writes evidence/leakage_audit/trace.json and prints a summary.
"""
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from shakedown.research import Source, answer_reasons  # noqa: E402

VISIBLE_CHARS = 6000  # build_report_text truncates each source to this
AUDIT = ROOT / "evidence/leakage_audit"


def flatten(node):
    """All scalar detection values, field names and modifiers in a Sigma detection block."""
    out = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key != "condition":
                out.append(("field", str(key)))
                out.extend(flatten(value))
    elif isinstance(node, list):
        for item in node:
            out.extend(flatten(item))
    elif node is not None:
        out.append(("value", str(node)))
    return out


def main(record_path: str) -> None:
    rec = json.loads(Path(record_path).read_text(encoding="utf-8"))["record"]
    scenario = rec["scenario"]
    ref_text = rec["expert"]["rule_text"]
    ref = yaml.safe_load(ref_text)
    target = {"id": scenario["id"], "title": scenario["title"]}

    primary = json.loads((AUDIT / "snapshot/primary.json").read_text(encoding="utf-8"))
    snippets = json.loads((AUDIT / "original/reconstructed_corroboration_search.json").read_text(encoding="utf-8"))
    recorded = [(c["url"], c["chars"]) for c in rec["research"]["corroboration"]]
    rebuilt = [(s["url"], len(s["content"])) for s in snippets]
    reconstruction_matches = recorded == rebuilt

    sources = {"primary (first 6000 chars)": primary["content"][:VISIBLE_CHARS], "scenario title": scenario["title"]}
    sources.update({f"snippet: {s['url'][:60]}": s["content"] for s in snippets})

    # 1. what each source reveals about the reference rule's detection logic
    ref_items = flatten(ref["detection"])
    ref_values = [v for kind, v in ref_items if kind == "value"]
    ref_fields = sorted({v.split("|")[0] for kind, v in ref_items if kind == "field" and not v.startswith("selection")})
    reveals = {}
    for name, text in sources.items():
        low = text.lower()
        reveals[name] = {
            "reference_field_names_present": [f for f in ref_fields if f.lower() in low],
            "reference_values_present": [v for v in ref_values if v.strip("\\").lower() in low],
            "rule_id": target["id"] in low, "reasons": answer_reasons(Source(name, name, text, "", "x"), target)}

    # 2. which parts of the generated rule match the reference rule
    gen = yaml.safe_load(rec["iterations"][rec["best_index"]]["rule_text"])
    gen_items = flatten({k: v for k, v in gen["detection"].items()})
    gen_values = [v for kind, v in gen_items if kind == "value"]
    gen_fields = sorted({v.split("|")[0] for kind, v in gen_items if kind == "field"} - {k for k in gen["detection"]})
    shared_values = [v for v in gen_values if any(v.strip("\\").lower() == r.strip("\\").lower() for r in ref_values)]
    provenance = {}
    for value in gen_values:
        provenance[value] = [name for name, text in sources.items() if value.lower() in text.lower()]

    out = {
        "run_record": record_path, "target": target,
        "reconstruction_matches_recorded_urls_and_lengths": reconstruction_matches,
        "recorded_corroboration": recorded, "reveals": reveals,
        "reference_detection_fields": ref_fields, "reference_detection_value_count": len(ref_values),
        "generated_detection_fields": gen_fields, "generated_detection_values": gen_values,
        "values_shared_with_reference": shared_values, "provenance_of_generated_values": provenance,
        "generated_has_original_filename_or_hashes": any(f in ("OriginalFileName", "Hashes") for f in gen_fields),
    }
    (AUDIT / "trace.json").write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print("reconstruction matches recorded urls+lengths:", reconstruction_matches)
    for name, info in reveals.items():
        print(f"- {name}: ref fields {info['reference_field_names_present']} | ref values {info['reference_values_present']} "
              f"| rule id {info['rule_id']} | reasons {info['reasons']}")
    print("reference detection fields:", ref_fields, "| values:", len(ref_values))
    print("generated fields:", gen_fields, "| values shared with reference:", shared_values)
    print("generated has OriginalFileName/Hashes:", out["generated_has_original_filename_or_hashes"])
    for v, where in provenance.items():
        print(f"  value {v!r} appears in: {where or 'NOWHERE visible (model prior)'}")


if __name__ == "__main__":
    main(sys.argv[1])
