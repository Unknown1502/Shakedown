"""Run the Shakedown web app: `python -m shakedown.serve [--live] [--port 8000]`.

Without --live only recorded runs are served and no credentials are needed. Scenario titles come from the
datasets when they are present locally, otherwise from demo/scenarios.json.
"""
import argparse
import json
import os
from pathlib import Path

import uvicorn

from shakedown.budget import Budget
from shakedown.config import load_dotenv
from shakedown.integrations.api import HOSTED_REASON, IntegrationsConfig
from shakedown.scenarios import load_scenarios
from shakedown.server import create_app

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "demo/scenarios.json"
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
OFF_REASON = "SIEM integrations are off. Start this server with --integrations (on this machine only) to connect a SIEM."


def write_index(scenarios: list[dict]) -> None:
    """Cache the scenario list for installs without the datasets. Best effort: a read-only install (for example a
    non-root container) must still start, so a write failure is ignored."""
    try:
        INDEX.parent.mkdir(parents=True, exist_ok=True)
        INDEX.write_text(json.dumps([{k: s[k] for k in ("id", "title", "category", "reference_urls")} for s in scenarios],
                                    indent=1), encoding="utf-8")
    except OSError:
        pass


def scenarios_for(root: Path) -> list[dict]:
    if (root / "data/raw/sigma").exists() and (root / "evaluation/tasks.json").exists():
        full = load_scenarios(root)
        write_index(full)
        return full
    return json.loads(INDEX.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--live", action="store_true", help="enable live runs (needs credentials, Docker and datasets)")
    parser.add_argument("--daily-cap", type=int, default=25)
    parser.add_argument("--runner", choices=["sandbox", "local"], default="sandbox",
                        help="where live runs are evaluated: Token Factory Sandbox (default) or local Docker")
    parser.add_argument("--answer-policy", choices=["exclude", "flag"], default="exclude",
                        help="web sources that look like the rule being written: leave them out (default) or only flag them")
    parser.add_argument("--total-cap", type=int, default=None,
                        help="hard limit on live runs for the whole life of the budget file (bounds the worst-case spend)")
    parser.add_argument("--budget-file", type=Path, default=None,
                        help="keep the run counts here so a restart cannot reset the caps")
    parser.add_argument("--cooldown", type=float, default=60.0, help="seconds between live runs from one client")
    parser.add_argument("--max-concurrent", type=int, default=1, help="live runs allowed at the same time")
    parser.add_argument("--allow-custom-url", action="store_true",
                        help="let visitors give any report address (default: only the scenario's own references)")
    parser.add_argument("--trust-proxy", action="store_true",
                        help="read the client address from X-Forwarded-For (only behind a proxy that sets it)")
    parser.add_argument("--recorded-dir", type=Path, default=None,
                        help="folder of recorded runs to play back (default: demo/replay, the approved set)")
    parser.add_argument("--integrations", action="store_true",
                        help="enable the SIEM Integrations workspace. Local use only: needs a loopback --host, because this server has no accounts or secret vault")
    parser.add_argument("--secret-store", choices=["auto", "memory", "keyring"], default="auto",
                        help="where saved SIEM credentials live: the OS credential store when `keyring` is installed, otherwise memory only")
    parser.add_argument("--allowed-host", action="append", default=[], help="an extra Host header value (host:port) the integrations API accepts")
    args = parser.parse_args()
    if args.integrations and args.host not in LOOPBACK_HOSTS:
        parser.error("--integrations is refused on a non-loopback --host: this server has no user accounts, tenant isolation or secret vault, so it must not hold SIEM credentials")

    load_dotenv()
    live = None
    if args.live:
        from shakedown.live import LiveRunner
        live = LiveRunner(ROOT, args.runner, args.answer_policy)
    recorded = args.recorded_dir or (ROOT / "demo/replay" if (ROOT / "demo/replay").exists() else None)
    budget = Budget(daily_cap=args.daily_cap, cooldown_s=args.cooldown, max_concurrent=args.max_concurrent, total_cap=args.total_cap, state_path=args.budget_file)
    if args.integrations:
        hosts = {f"127.0.0.1:{args.port}", f"localhost:{args.port}", f"[::1]:{args.port}", *args.allowed_host}
        integrations = IntegrationsConfig(enabled=True, reason="", data_dir=ROOT / "data/integrations", secret_store=args.secret_store, mode="local",
                                          allowed_hosts=hosts, environ=os.environ)
    else:
        integrations = IntegrationsConfig.disabled(OFF_REASON if args.host in LOOPBACK_HOSTS else HOSTED_REASON)
    app = create_app(ROOT, scenarios_for(ROOT), live_runner=live, budget=budget, recorded_dir=recorded,
                     allow_custom_url=args.allow_custom_url, trust_proxy=args.trust_proxy,
                     live_info=live.info() if live else None, integrations=integrations)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
