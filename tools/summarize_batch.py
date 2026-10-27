"""Compute the pre-registered metrics (docs/EVALUATION_METHODOLOGY.md) from a batch result file."""
import json
import sys
from pathlib import Path


def dev_hits(ev: dict) -> int:
    return sum(b["hits"] for b in ev["benign"].values())


def main(path: Path) -> None:
    d = json.loads(path.read_text(encoding="utf-8"))
    rows = d["rows"]
    ok = [r for r in rows if not r.get("error")]
    n = len(rows)
    print(f"file={path.name} model={d['model']} tasks={n} errored={n - len(ok)} limit={d['limit']}")

    first = [r["history"][0] for r in ok]
    best = [r["history"][r["best_index"]] for r in ok]
    print(f"\nfirst candidate passed sigma check: {sum(i['validation']['ok'] for i in first)}/{len(ok)}; "
          f"loadable by the evaluator: {sum(i['evaluation'] is not None for i in first)}/{len(ok)}")
    print(f"tasks whose first candidate passed acceptance: "
          f"{sum(1 for i in first if i['evaluation'] and i['evaluation']['attack_detected'] and dev_hits(i['evaluation']) == 0)}/{len(ok)}")

    def det(i):
        return bool(i["evaluation"] and i["evaluation"]["attack_detected"])

    print("\nATTACK DETECTION (unit: attack file; one-shot is clean, repaired saw the missed sample)")
    print(f"  one-shot : {sum(det(i) for i in first)}/{len(ok)}")
    print(f"  repaired : {sum(det(i) for i in best)}/{len(ok)}")
    print(f"  expert   : {sum(bool(r['expert_dev']['attack_detected']) for r in ok)}/{len(ok)}")

    def fp(rows_, key):
        vals = [r[key] for r in rows_ if r.get(key)]
        return f"{sum(1 for v in vals if v['hits'] > 0)}/{len(vals)} rules with any hit, {sum(v['hits'] for v in vals)} events"

    print("\nBENIGN HITS, held-out win10 (never shown to the model; rules lacking a valid candidate are excluded)")
    print(f"  one-shot : {fp(ok, 'oneshot_heldout')}")
    print(f"  repaired : {fp(ok, 'best_heldout')}")
    print(f"  expert   : {fp(ok, 'expert_heldout')}")
    print("BENIGN HITS, development win7 (the repair loop saw these)")
    print(f"  expert   : {sum(1 for r in ok if dev_hits(r['expert_dev']) > 0)}/{len(ok)} rules, "
          f"{sum(dev_hits(r['expert_dev']) for r in ok)} events")

    needed = [r for r in ok if not (first_ok(r))]
    fixed = [r for r in needed if r["success"]]
    print(f"\nREPAIR: first candidate failed acceptance on {len(needed)}/{len(ok)} tasks; "
          f"repair succeeded on {len(fixed)}/{len(needed)}")
    print(f"  iterations to success (successful tasks): {sorted(len(r['history']) for r in ok if r['success'])}")
    print(f"  stop reasons: " + ", ".join(f"{k}={sum(1 for r in ok if r['stop_reason'] == k)}"
                                          for k in sorted({r['stop_reason'] for r in ok})))

    tokens = sum(i["tokens"] for r in ok for i in r["history"])
    print(f"\nCOST: {tokens} generation tokens (excl. spec extraction); "
          f"upper bound ${tokens * 0.9 / 1e6:.3f} at the output price")
    print("\nPER TASK")
    for r in rows:
        if r.get("error"):
            print(f"  ERROR {r['task']['title'][:50]}: {r['error'][:120]}")
            continue
        h = r["history"]
        trail = " -> ".join(("INVALID" if not i["validation"]["ok"] else
                             "UNLOADABLE" if i["evaluation"] is None else
                             f"{i['evaluation']['attack_detected']}/{i['evaluation']['attack_total']}atk,{dev_hits(i['evaluation'])}fp")
                            for i in h)
        print(f"  {r['task']['title'][:48]:48s} {'OK ' if r['success'] else 'FAIL'} {trail} | expert atk "
              f"{r['expert_dev']['attack_detected']}, heldout fp {r['expert_heldout']['hits']}")


def first_ok(r) -> bool:
    ev = r["history"][0]["evaluation"]
    return bool(ev and ev["attack_detected"] and dev_hits(ev) == 0)


if __name__ == "__main__":
    main(Path(sys.argv[1]))
