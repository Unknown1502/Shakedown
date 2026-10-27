"""Record real pipeline runs (live Nemotron + Tavily + isolated evaluator) as demo evidence in demo/recorded/.

Each saved file is an unedited run record. Which scenarios get recorded is a choice made after seeing earlier
results; the UI labels these as recorded examples, and the aggregate numbers live in docs/RESULTS.md.
"""
import argparse
import json
import re
import sys
from pathlib import Path

from shakedown.config import load_dotenv
from shakedown.runners import build_runner
from shakedown.llm import TokenFactory, select_model
from shakedown.pipeline import run_pipeline
from shakedown.research import Tavily, TavilyError
from shakedown.scenarios import load_scenarios, scenario_report_text

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--title", action="append", required=True, help="substring of a frozen task title (repeatable)")
    parser.add_argument("--no-research", action="store_true")
    parser.add_argument("--max-repairs", type=int, default=3)
    parser.add_argument("--runner", choices=["sandbox", "local"], default="sandbox")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "demo/recorded")
    parser.add_argument("--answer-policy", choices=["exclude", "flag"], default="exclude",
                        help="leave out web sources that look like the rule being written (default) or only flag them")
    args = parser.parse_args()

    load_dotenv()
    tf = TokenFactory.from_env()
    model = select_model([m["id"] for m in tf.list_models()], ("nemotron-3-super",))
    runner = build_runner(ROOT, args.runner)
    tavily = None if args.no_research else Tavily.from_env()
    scenarios = load_scenarios(ROOT)
    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    for wanted in args.title:
        scenario = next(s for s in scenarios if wanted.lower() in s["title"].lower())
        url, fallback = None, scenario_report_text(ROOT, scenario)
        if tavily:
            for candidate in scenario["reference_urls"]:  # first reference Tavily can actually read
                try:
                    tavily.extract(candidate)
                    url = candidate
                    break
                except TavilyError as exc:
                    print(f"  skip {candidate}: {str(exc)[:90]}")
        print(f"recording: {scenario['title']} (source: {url or 'SigmaHQ metadata text'})")
        record = run_pipeline(llm=tf, model=model, runner=runner, scenario=scenario, report_text=fallback,
                              source_url=url, tavily=tavily if url else None, max_repairs=args.max_repairs,
                              answer_policy=args.answer_policy,
                              emit=lambda kind, data: print(f"    {kind}"))
        slug = re.sub(r"[^a-z0-9]+", "-", scenario["title"].lower()).strip("-")[:60]
        (out_dir / f"{slug}.json").write_text(json.dumps(record, indent=1, default=str), encoding="utf-8")
        print(f"  success={record['success']} iterations={len(record['iterations'])} "
              f"tokens={record['totals']['tokens']} seconds={record['totals']['seconds']} -> demo/recorded/{slug}.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
