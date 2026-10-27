"""Acceptance checks for a running Shakedown server (local or hosted). Standard library only.

    python tools/smoke_hosted.py http://127.0.0.1:8013            # free: reads, refusals, no model call
    python tools/smoke_hosted.py https://<host> --run             # also starts ONE live run (spends model and Tavily credit)

Exit code 0 only if every check passed. Never prints a credential (none is read).
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request


def call(base: str, path: str, body: dict | None = None, timeout: int = 30) -> tuple[int, dict]:
    req = urllib.request.Request(base.rstrip("/") + path, method="POST" if body is not None else "GET",
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


class Checks:
    def __init__(self):
        self.failed = 0

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        print(f"  [{'ok' if ok else 'FAIL'}] {name}{' - ' + detail if detail else ''}")
        self.failed += 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("base")
    parser.add_argument("--run", action="store_true", help="start one live run and verify its record (spends credit)")
    args = parser.parse_args()
    c = Checks()

    status, health = call(args.base, "/api/health")
    c.check("health answers", status == 200)
    live = health.get("live", {})
    c.check("live mode is on", health.get("live_enabled") is True)
    c.check("evaluator is a Token Factory Sandbox with the network off",
            live.get("evaluator", {}).get("kind") == "token-factory-sandbox" and "disabled" in live.get("evaluator", {}).get("network", ""))
    c.check("model is an NVIDIA Nemotron", str(live.get("model", "")).startswith("nvidia/nemotron"), str(live.get("model")))
    c.check("answer screening is on (exclude)", live.get("answer_policy") == "exclude")
    c.check("research (Tavily) is configured", live.get("research") is True)
    c.check("custom report addresses are off", health.get("allow_custom_url") is False)
    budget = health.get("budget", {})
    c.check("a total spending cap is set", budget.get("total_cap") is not None, f"total_cap={budget.get('total_cap')}")

    status, recorded = call(args.base, "/api/recorded")
    c.check("recorded runs are listed", status == 200 and len(recorded) > 0, f"{len(recorded)} runs")
    status, scenarios = call(args.base, "/api/scenarios")
    c.check("scenarios are listed", status == 200 and len(scenarios) > 0)
    for row in recorded[:50]:
        _, rec = call(args.base, f"/api/recorded/{row['slug']}")
        legacy = rec.get("answer_screen_legacy")
        screened = bool((rec.get("research") or {}).get("screening"))
        c.check(f"recording {row['slug'][:40]} is leakage-controlled or labelled", screened or legacy is not None or not rec.get("research"))

    status, _ = call(args.base, "/api/runs", {"scenario_id": "does-not-exist"})
    c.check("an unknown scenario is refused before spending", status == 404)
    if scenarios:
        status, body = call(args.base, "/api/runs", {"scenario_id": scenarios[0]["id"], "source_url": "https://example.org/not-a-reference"})
        c.check("a custom report address is refused", status == 403, body.get("detail", "")[:60])

    if args.run:
        scenario = next(s for s in scenarios if "AdFind.EXE Execution" in s["title"]) if any("AdFind.EXE Execution" in s["title"] for s in scenarios) else scenarios[0]
        status, started = call(args.base, "/api/runs", {"scenario_id": scenario["id"]})
        c.check("a live run starts", status == 200, str(started)[:80])
        if status == 200:
            for _ in range(120):
                _, state = call(args.base, f"/api/runs/{started['run_id']}")
                if state["status"] != "running":
                    break
                time.sleep(5)
            c.check("the run finished", state["status"] == "done", str(state.get("error")))
            rec = state.get("record") or {}
            c.check("record names the Sandbox evaluator", rec.get("evaluator", {}).get("kind") == "token-factory-sandbox")
            c.check("record says leakage-controlled", (rec.get("source_mode") or {}).get("mode") == "leakage-controlled")
            c.check("Tavily read the reference", bool((rec.get("research") or {}).get("primary")))
            c.check("token usage is recorded", (rec.get("usage") or {}).get("total_tokens", 0) > 0, str(rec.get("usage")))
            print(f"  run result: success={rec.get('success')} attempts={len(rec.get('iterations', []))} (a failed run is a valid result)")

    print("PASS" if c.failed == 0 else f"{c.failed} check(s) FAILED")
    return 1 if c.failed else 0


if __name__ == "__main__":
    sys.exit(main())
