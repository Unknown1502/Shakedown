"""One Shakedown run: research -> spec -> generate/test/repair loop -> held-out check -> evidence record.

The returned record is plain JSON-able data. Everything in it was observed during the run: model output,
validator output, checker results, Tavily retrievals (with URLs and times). Nothing is filled in from elsewhere.
"""
import dataclasses
import hashlib
import re
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from shakedown.evaluate import Evaluation, Runner, evaluate_rule
from shakedown.harness.checker import CheckerError
from shakedown.loop import Iteration, run_loop
from shakedown.research import (POLICIES, SEARCH_EXTRA, AnswerSourceError, TavilyError, build_report_text,
                                screen_sources)
from shakedown.spec import extract_spec

CORROBORATING = 3  # corroborating sources shown to the model


class PipelineError(RuntimeError):
    pass


class LeakGuardError(PipelineError):
    """A model request would have carried an identifier of the rule being reproduced."""


_MIN_STEM_CHARS = 32  # an attack file stem this long is an id (SigmaHQ names samples after the rule id), not a word


def _identifiers(scenario: dict, attack: Path) -> tuple[list[str], list[str]]:
    """(attack-file identifiers, rule-id identifiers), lower case, that must never reach the model."""
    files = [attack.name.lower()] + ([attack.stem.lower()] if len(attack.stem) >= _MIN_STEM_CHARS else [])
    return sorted(set(files), key=len, reverse=True), [str(scenario["id"]).lower()]


def _scrub(text: str, files: list[str], ids: list[str]) -> str:
    for name in files:
        text = re.sub(re.escape(name), "attack sample 1", text, flags=re.IGNORECASE)
    for rule_id in ids:
        text = re.sub(re.escape(rule_id), "[rule id]", text, flags=re.IGNORECASE)
    return text


class LeakGuard:
    """Wraps the model client for leakage-controlled runs: a request whose messages contain the target rule id or the
    attack file name is refused before it is sent. The source screen should make this unreachable; the guard
    makes sure that if the screen ever misses, the run fails instead of quietly reporting a clean result."""

    def __init__(self, inner, forbidden: list[str]):
        self._inner, self._forbidden = inner, [f for f in forbidden if f]

    def chat_json(self, model, messages, *args, **kwargs):
        text = "\n".join(str(m.get("content", "")) for m in messages).lower()
        hits = sum(1 for f in self._forbidden if f in text)
        if hits:
            raise LeakGuardError(f"model request blocked: it contained {hits} identifier(s) of the rule being reproduced")
        return self._inner.chat_json(model, messages, *args, **kwargs)


class _Metered:
    """Counts every model call and its tokens (spec extraction, generation, repairs, resamples), so a run's cost is
    read from its record. A call that the guard refuses never reaches this wrapper and is not counted."""

    def __init__(self, inner):
        self._inner = inner
        self.totals = {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    def chat_json(self, model, messages, *args, **kwargs):
        completion = self._inner.chat_json(model, messages, *args, **kwargs)
        usage = getattr(completion, "usage", None) or {}
        self.totals["calls"] += 1
        for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
            self.totals[key] += int(usage.get(key, 0) or 0)
        return completion


def _source_mode(policy: str, research: dict | None) -> dict:
    sources = ((research or {}).get("screening") or {}).get("sources", [])
    excluded = sum(1 for s in sources if s["status"] == "excluded")
    flagged = sum(1 for s in sources if s["status"] == "flagged")
    if research is None:
        verdict = "no_web_research"
    elif policy == "exclude":
        verdict = "controlled"
    else:
        verdict = "flagged_sources_shown" if flagged else "no_flagged_sources"
    return {"policy": policy, "mode": "leakage-controlled" if policy == "exclude" else "research", "verdict": verdict,
            "excluded": excluded, "flagged_shown": flagged}


def _evaluation_dict(ev: Evaluation | None) -> dict | None:
    return None if ev is None else dataclasses.asdict(ev)


def iteration_dict(it: Iteration) -> dict:
    return {"index": it.index, "action": it.action, "resamples": it.resamples, "thinking_fallback": it.thinking_fallback, "rule_text": it.rule_text,
            "sha256": it.sha256,
            "validation": {"ok": it.validation.ok, "errors": it.validation.errors,
                           "sigma_output": it.validation.sigma_output[-1500:]},
            "evaluator_error": it.evaluator_error, "tokens": it.tokens, "latency_s": it.latency_s,
            "evaluation": _evaluation_dict(it.evaluation)}


def run_pipeline(*, llm, model: str, runner: Runner, scenario: dict, report_text: str | None = None,
                 source_url: str | None = None, tavily=None, max_repairs: int = 3, rule_format: str = "structured",
                 thinking: bool = True, fallback_without_thinking: bool = True, answer_policy: str = "flag",
                 emit: Callable[[str, dict], None] | None = None) -> dict:
    """`answer_policy` decides what happens to web sources that look like the rule being written (see
    research.screen_sources): "flag" shows them to the model and records the flag, "exclude" removes them."""
    if answer_policy not in POLICIES:
        raise ValueError(f"answer policy must be one of {POLICIES}, got {answer_policy!r}")
    target = {"id": scenario["id"], "title": scenario["title"]}
    started = time.monotonic()
    events: list[dict] = []

    def note(kind: str, data: dict) -> None:
        events.append({"type": kind, "t": round(time.monotonic() - started, 2), "data": data})
        if emit:
            emit(kind, data)

    note("start", {"scenario": scenario["id"], "title": scenario["title"], "model": model})

    research, input_kind, report = None, "text", report_text
    if source_url:
        research = {"primary": None, "corroboration": [], "error": None,
                    "screening": {"policy": answer_policy, "target": target, "sources": []}}
        sources = research["screening"]["sources"]
        try:
            if tavily is None:
                raise TavilyError("no Tavily client configured")
            primary = tavily.extract(source_url)
            _, decisions = screen_sources([primary], answer_policy, target, "primary")
            sources.extend(decisions)
            if decisions[0]["status"] == "excluded":
                raise AnswerSourceError(f"the report at {source_url} is answer-bearing "
                                        f"({', '.join(decisions[0]['reasons'])}) and was not used")
            try:
                found = tavily.search(f"{scenario['title']} Windows detection",
                                      max_results=CORROBORATING + (SEARCH_EXTRA if answer_policy == "exclude" else 0))
                extra, decisions = screen_sources(found, answer_policy, target, "corroboration", limit=CORROBORATING)
                sources.extend(decisions)
            except TavilyError as exc:  # corroboration is optional; the primary source is enough
                extra, research["error"] = [], f"corroboration search failed: {exc}"
            research["primary"] = primary.to_dict()
            research["corroboration"] = [s.to_dict() for s in extra]
            report, input_kind = build_report_text(primary, extra), "url"
        except TavilyError as exc:
            research["error"] = str(exc)
        note("research", research)
    if not report or not report.strip():
        raise PipelineError("no report text: research failed and no fallback text was given")

    attack = Path(scenario["attack"])
    files, ids = _identifiers(scenario, attack)
    meter = _Metered(llm)
    llm = LeakGuard(meter, files + ids) if answer_policy == "exclude" else meter

    spec = extract_spec(llm, model, report)
    note("spec", {**spec.to_dict(), "dropped": spec.dropped})

    dev = {k: Path(v) for k, v in scenario["benign_dev"].items()}

    def evaluate(text: str) -> Evaluation:
        try:
            return evaluate_rule(text, [attack], dev, runner)
        except CheckerError as exc:  # the checker's own messages can contain the attack file's path
            raise CheckerError(_scrub(str(exc), files, ids)) from None
    result = run_loop(
        llm, model, report, spec, max_repairs=max_repairs, rule_format=rule_format, thinking=thinking,
        fallback_without_thinking=fallback_without_thinking,
        evaluate=evaluate,
        on_iteration=lambda it: note("iteration", iteration_dict(it)))

    best = result.best
    heldout = None
    if best.evaluation is not None:
        held = evaluate_rule(best.rule_text, [], {k: Path(v) for k, v in scenario["benign_heldout"].items()}, runner)
        heldout = {k: dataclasses.asdict(v) for k, v in held.benign.items()}
        note("heldout", heldout)

    expert = None
    if scenario.get("expert_text"):
        e_dev = evaluate_rule(scenario["expert_text"], [attack], dev, runner)
        e_held = evaluate_rule(scenario["expert_text"], [], {k: Path(v) for k, v in scenario["benign_heldout"].items()}, runner)
        expert = {"dev": _evaluation_dict(e_dev), "heldout": {k: dataclasses.asdict(v) for k, v in e_held.benign.items()},
                  "rule_text": scenario["expert_text"]}
        note("expert", {"detected": e_dev.attack_detected, "total": e_dev.attack_total})

    record = {
        "created_at": datetime.now(timezone.utc).isoformat(), "model": model, "rule_format": rule_format,
        "thinking": thinking,
        "evaluator": runner.describe() if hasattr(runner, "describe") else {"kind": "unknown"},
        "scenario":{k: scenario[k] for k in ("id", "title", "category")},
        "input": {"kind": input_kind, "url": source_url if input_kind == "url" else None, "chars": len(report),
                  "sha256": hashlib.sha256(report.encode("utf-8")).hexdigest()},
        "source_mode": _source_mode(answer_policy, research), "usage": dict(meter.totals),
        "research": research, "spec": spec.to_dict(), "spec_dropped": spec.dropped,
        "iterations": [iteration_dict(i) for i in result.history], "best_index": best.index,
        "success": result.success, "stop_reason": result.stop_reason, "heldout": heldout, "expert": expert,
        "totals": {"tokens": sum(i.tokens for i in result.history),
                   "seconds": round(time.monotonic() - started, 1)},
    }
    note("done", {"success": result.success, "stop_reason": result.stop_reason})
    record["events"] = events
    return record
