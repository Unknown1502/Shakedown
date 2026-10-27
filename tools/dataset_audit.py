"""Audit SigmaHQ regression_data: pair every info.yml with its rule and samples.

Reads only. Writes a JSON audit to --out and prints a summary.
"""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

import yaml

RULE_DIRS = ("rules", "rules-emerging-threats", "rules-threat-hunting")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_rules(root: Path) -> tuple[dict, list]:
    index, errors = {}, []
    for rule_dir in RULE_DIRS:
        for path in (root / rule_dir).rglob("*.yml"):
            try:
                doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            except yaml.YAMLError as exc:
                errors.append({"path": str(path.relative_to(root)), "error": str(exc)[:200]})
                continue
            if isinstance(doc, dict) and doc.get("id"):
                index[str(doc["id"])] = (path, doc)
    return index, errors


def audit_pair(root: Path, info_path: Path, rules: dict) -> dict:
    info = yaml.safe_load(info_path.read_text(encoding="utf-8")) or {}
    meta = info.get("rule_metadata") or []
    rule_id = str(meta[0].get("id")) if meta else None
    rec = {"info": info_path.relative_to(root).as_posix(), "rule_id": rule_id, "problems": []}
    if len(meta) != 1:
        rec["problems"].append(f"rule_metadata_entries={len(meta)}")

    rule = rules.get(rule_id)
    if rule is None:
        rec["problems"].append("rule_not_found")
    else:
        rule_path, doc = rule
        declared = doc.get("regression_tests_path")
        if declared and declared != rec["info"]:
            rec["problems"].append("regression_tests_path_mismatch")
        logsource = doc.get("logsource") or {}
        rec.update(
            rule_path=rule_path.relative_to(root).as_posix(),
            title=doc.get("title"),
            status=doc.get("status"),
            level=doc.get("level"),
            date=str(doc.get("date")) if doc.get("date") else None,
            modified=str(doc.get("modified")) if doc.get("modified") else None,
            product=logsource.get("product"),
            category=logsource.get("category"),
            service=logsource.get("service"),
            tags=doc.get("tags") or [],
        )

    rec["tests"] = []
    for test in info.get("regression_tests_info") or []:
        sample = root / test.get("path", "")
        exists = sample.is_file()
        rec["tests"].append({
            "type": test.get("type"),
            "path": test.get("path"),
            "match_count": test.get("match_count"),
            "provider": test.get("provider"),
            "exists": exists,
            "bytes": sample.stat().st_size if exists else None,
            "sha256": sha256(sample) if exists else None,
            "stem_is_rule_id": sample.stem == rule_id,
        })
        if not exists:
            rec["problems"].append(f"missing_sample:{test.get('path')}")
    return rec


def is_usable_evtx(rec: dict) -> bool:
    return not rec["problems"] and any(t["type"] == "evtx" and t["exists"] for t in rec["tests"])


def summarize(pairs: list, rule_errors: list) -> dict:
    usable = [p for p in pairs if is_usable_evtx(p)]
    year = lambda p: (p.get("date") or "unknown")[:4]
    return {
        "info_files": len(pairs),
        "rules_with_parse_errors": len(rule_errors),
        "pairs_with_problems": sum(1 for p in pairs if p["problems"]),
        "problem_kinds": Counter(k.split(":")[0] for p in pairs for k in p["problems"]),
        "usable_evtx_pairs": len(usable),
        "usable_with_explicit_match_count": sum(
            1 for p in usable if any(t["type"] == "evtx" and t["match_count"] is not None for t in p["tests"])),
        "usable_with_json_sample_too": sum(1 for p in usable if any(t["type"] == "json" for t in p["tests"])),
        "usable_by_logsource": Counter(
            f"{p.get('product')}/{p.get('category') or '-'}/{p.get('service') or '-'}" for p in usable),
        "usable_by_rule_date_year": Counter(year(p) for p in usable),
        "usable_by_status": Counter(str(p.get("status")) for p in usable),
        "usable_2026_dated": [p["rule_path"] for p in usable if year(p) == "2026"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sigma-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    root = args.sigma_root.resolve()
    rules, rule_errors = load_rules(root)
    pairs = [audit_pair(root, p, rules) for p in sorted((root / "regression_data").rglob("info.yml"))]
    summary = summarize(pairs, rule_errors)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"summary": summary, "rule_parse_errors": rule_errors, "pairs": pairs},
                                   indent=1, default=str), encoding="utf-8")
    print(json.dumps(summary, indent=1, default=str))


if __name__ == "__main__":
    main()
