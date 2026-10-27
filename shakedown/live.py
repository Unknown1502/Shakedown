"""Production wiring for live runs: Token Factory model, Tavily research and the isolated checker."""
from pathlib import Path

from shakedown.llm import TokenFactory, select_model
from shakedown.pipeline import run_pipeline
from shakedown.research import Source, Tavily, TavilyError
from shakedown.runners import build_runner
from shakedown.scenarios import scenario_report_text


class _Prefetched:
    """Returns the page already read while choosing the source, so it is not fetched (and billed) a second time."""

    def __init__(self, tavily, url: str, source: Source):
        self._tavily, self._url, self._source = tavily, url, source

    def extract(self, url: str) -> Source:
        return self._source if url == self._url else self._tavily.extract(url)

    def search(self, *args, **kwargs):
        return self._tavily.search(*args, **kwargs)


def resolve_source(tavily, scenario: dict, source_url: str | None):
    """(report address, research client) for a live run.

    An address given by the visitor is used as given. Otherwise the run reads the scenario's own first reference
    that Tavily can read, so a plain "Run live" does real web research. With no client, no reference or none readable
    the address is None and the run uses the scenario's description only; the record says so."""
    if source_url:
        return source_url, tavily
    if tavily is None:
        return None, None
    for url in scenario.get("reference_urls") or []:
        try:
            source = tavily.extract(url)
        except TavilyError:
            continue  # a failed extraction is not billed; try the next reference
        return url, _Prefetched(tavily, url, source)
    return None, tavily


class LiveRunner:
    def __init__(self, root: Path, runner_kind: str = "sandbox", answer_policy: str = "exclude"):
        self.root = Path(root)
        self.answer_policy = answer_policy  # live scenarios are SigmaHQ rules, so their own mirrors are kept out
        self.llm = TokenFactory.from_env()
        self.model = select_model([m["id"] for m in self.llm.list_models()], ("nemotron-3-super",))
        self.runner = build_runner(self.root, runner_kind)
        try:
            self.tavily = Tavily.from_env()
        except TavilyError:
            self.tavily = None  # live runs still work from the scenario text; research is marked unavailable

    def info(self) -> dict:
        return {"model": self.model, "answer_policy": self.answer_policy, "research": self.tavily is not None,
                "evaluator": self.runner.describe() if hasattr(self.runner, "describe") else {"kind": "unknown"}}

    def run(self, scenario: dict, source_url: str | None, emit) -> dict:
        url, research = resolve_source(self.tavily, scenario, source_url)
        return run_pipeline(llm=self.llm, model=self.model, runner=self.runner, scenario=scenario,
                            report_text=scenario_report_text(self.root, scenario), source_url=url,
                            tavily=research, answer_policy=self.answer_policy, emit=emit)
