"""Print the attempt-by-attempt trace of a saved run record: what failed, what the evidence said, what changed.

    PYTHONIOENCODING=utf-8 python tools/run_trace.py demo/recorded_screened/pua-adfind-exe-execution.json [more.json ...]
"""
import json
import sys
from pathlib import Path


def trace(path: str) -> None:
    rec = json.loads(Path(path).read_text(encoding="utf-8"))
    sm = rec.get("source_mode")
    screening = (rec.get("research") or {}).get("screening")
    print(f"== {path}\n   {rec['scenario']['title']} | created {rec['created_at']} | evaluator {rec['evaluator'].get('kind')} | "
          f"input {rec['input']['kind']} {rec['input'].get('url')}")
    print(f"   source mode: {sm or ('policy ' + screening['policy'] if screening else 'none recorded')}")
    if screening:
        for s in screening["sources"]:
            print(f"     {s['role']:<13} {s['status']:<9} {s['reasons']} {s['url'][:80]}")
    print(f"   spec: {len(rec['spec']['observables'])} observables, {len(rec['spec_dropped'])} dropped")
    for it in rec["iterations"]:
        ev = it["evaluation"]
        line = f"   attempt {it['index'] + 1} ({it['action']}): valid={it['validation']['ok']}"
        if not it["validation"]["ok"]:
            line += f" errors={it['validation']['errors'][:1]}"
        if it["evaluator_error"]:
            line += f" evaluator_error={it['evaluator_error'][:120]!r}"
        if ev:
            benign = {k: v["hits"] for k, v in ev["benign"].items()}
            line += f" attack={ev['attack_detected']}/{ev['attack_total']} missed={ev['attack_missed']} benign_dev_hits={benign}"
        line += f" tokens={it['tokens']} resamples={it['resamples']}"
        print(line)
    held = {k: v["hits"] for k, v in (rec["heldout"] or {}).items()}
    expert = rec["expert"]["dev"] if rec.get("expert") else None
    print(f"   result: success={rec['success']} ({rec['stop_reason']}) best attempt {rec['best_index'] + 1}; held-out hits {held}; "
          f"tokens {rec['totals']['tokens']}; {rec['totals']['seconds']} s; expert detects "
          f"{expert['attack_detected'] if expert else '-'}/{expert['attack_total'] if expert else '-'}")


if __name__ == "__main__":
    for p in sys.argv[1:]:
        trace(p)
