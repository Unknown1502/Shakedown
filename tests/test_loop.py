"""Bounded generate -> validate -> evaluate -> repair loop, with a fake model and a fake evaluator."""
from types import SimpleNamespace

from functools import partial

from shakedown.evaluate import BenignResult, Evaluation
from shakedown.llm import NoJSONError
from shakedown.loop import run_loop as _run_loop
from shakedown.spec import DetectionSpec

run_loop = partial(_run_loop, rule_format="yaml")   # the original free-form YAML mode (Runs 1 and 2)

GOOD = """\
title: Shakedown Loop Rule
id: 6f0c1c3e-8f4a-4a57-9d5e-2a3b4c5d6e7f
status: experimental
description: test
author: shakedown
date: 2026-10-27
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\x.exe'
    condition: selection
level: medium
"""
BETTER = GOOD.replace("x.exe", "reg.exe")
SPEC = DetectionSpec(behavior="b", logsource_category="process_creation", observables=[], techniques=[], dropped=[])


class ScriptedLLM:
    def __init__(self, rules):
        self.rules, self.prompts = list(rules), []

    def chat_json(self, model, messages, schema, name, **kw):
        self.prompts.append(messages[-1]["content"])
        return SimpleNamespace(data={"rule_yaml": self.rules.pop(0)}, usage={"total_tokens": 10},
                               latency_s=0.0, model=model, response_format="fake", reasoning=None)


def _evaluation(detected: int, benign_hits: int = 0) -> Evaluation:
    missed = [] if detected else ["a.evtx"]
    return Evaluation(attack_total=1, attack_detected=detected, attack_missed=missed, attack_events_hit=detected,
                      benign={"dev": BenignResult(files_total=5, files_with_hits=int(benign_hits > 0),
                                                  hits=benign_hits, examples=[])},
                      attack_events=[{"EventID": 1, "Image": "C:\\Windows\\reg.exe"}], seconds=0.1)


def _rule_id(text: str) -> str:
    return next(l.split(":", 1)[1].strip() for l in text.splitlines() if l.startswith("id:"))


def test_rule_id_is_assigned_by_code_and_stable_across_repairs():
    llm = ScriptedLLM([GOOD, BETTER.replace("6f0c1c3e-8f4a-4a57-9d5e-2a3b4c5d6e7f", "a1b2c3d4-e5f6-7890-abcd-ef1234567890")])
    evals = iter([_evaluation(0), _evaluation(1)])

    result = run_loop(llm, "m", "report", SPEC, evaluate=lambda text: next(evals), max_repairs=1, rule_id="11111111-2222-4333-8444-555555555555")

    assert [_rule_id(i.rule_text) for i in result.history] == ["11111111-2222-4333-8444-555555555555"] * 2


def test_repairs_a_miss_and_stops_when_acceptance_passes():
    llm = ScriptedLLM([GOOD, BETTER])
    evals = iter([_evaluation(0), _evaluation(1)])

    result = run_loop(llm, "m", "report", SPEC, evaluate=lambda text: next(evals), max_repairs=3)

    assert result.success
    assert [it.action for it in result.history] == ["generate", "repair"]
    assert "reg.exe" in result.best.rule_text
    assert "attack sample 1" in llm.prompts[1]   # the repair prompt carries the concrete miss, under a neutral label
    assert "a.evtx" not in llm.prompts[1]
    assert result.history[0].evaluation.attack_detected == 0
    assert result.history[1].evaluation.attack_detected == 1


def test_repair_feedback_does_not_reveal_which_rule_an_attack_file_belongs_to():
    """SigmaHQ names each attack sample after its rule id, so the file name is a benchmark identifier."""
    rule_file = "514e7e3e-b3b4-4a67-af60-be20f139198b.evtx"
    missed = Evaluation(attack_total=2, attack_detected=0, attack_missed=[rule_file, "other.evtx"], attack_events_hit=0,
                        benign={"dev": BenignResult(files_total=5, files_with_hits=0, hits=0, examples=[])},
                        attack_events=[{"EventID": 1}], seconds=0.1)
    llm = ScriptedLLM([GOOD, BETTER])
    evals = iter([missed, _evaluation(1)])

    run_loop(llm, "m", "report", SPEC, evaluate=lambda text: next(evals), max_repairs=1)

    assert "514e7e3e" not in llm.prompts[1] and "other.evtx" not in llm.prompts[1]
    assert "attack sample 1, attack sample 2" in llm.prompts[1]


def test_stops_at_budget_and_reports_failure_honestly():
    llm = ScriptedLLM([GOOD, GOOD, GOOD])
    result = run_loop(llm, "m", "report", SPEC, evaluate=lambda text: _evaluation(0), max_repairs=2)

    assert not result.success
    assert len(result.history) == 3              # 1 generate + 2 repairs, then stop
    assert result.stop_reason == "repair budget exhausted"


def test_keeps_best_candidate_not_the_latest():
    llm = ScriptedLLM([GOOD, BETTER, GOOD.replace("x.exe", "y.exe")])
    evals = iter([_evaluation(0), _evaluation(1, benign_hits=3), _evaluation(0)])

    result = run_loop(llm, "m", "report", SPEC, evaluate=lambda text: next(evals), max_repairs=2)

    assert not result.success
    assert "reg.exe" in result.best.rule_text    # detected the attack; later worse candidate is not preferred


def test_rule_the_evaluator_cannot_load_is_repaired_not_a_crash():
    from shakedown.harness.checker import CheckerError

    llm = ScriptedLLM([GOOD, BETTER])
    calls = iter([CheckerError("checker exited 1: could not parse rules: invalid definition"), _evaluation(1)])

    def evaluate(text):
        item = next(calls)
        if isinstance(item, Exception):
            raise item
        return item

    result = run_loop(llm, "m", "report", SPEC, evaluate=evaluate, max_repairs=2)

    assert result.success
    first = result.history[0]
    assert first.evaluation is None and "invalid definition" in first.evaluator_error
    assert "invalid definition" in llm.prompts[1]        # the repair prompt carries the evaluator's error


def test_invalid_rule_is_sent_back_with_validation_errors_and_never_evaluated():
    llm = ScriptedLLM(["title: broken\n", BETTER])
    calls = []

    def evaluate(text):
        calls.append(text)
        return _evaluation(1)

    result = run_loop(llm, "m", "report", SPEC, evaluate=evaluate, max_repairs=2)

    assert result.success
    assert len(calls) == 1 and "reg.exe" in calls[0]   # the invalid first candidate never reached the evaluator
    assert result.history[0].evaluation is None
    assert "missing required field" in llm.prompts[1]


# ---- structured mode: the model returns JSON fields, code renders the YAML ----------------------------------

def _struct(image="reg.exe", condition="selection"):
    return {"title": "Struct Rule", "description": "d", "tags": [], "logsource_category": "process_creation",
            "groups": [{"name": "selection", "fields": [{"field": "Image", "modifier": "endswith", "values": [image]}]}],
            "condition": condition, "falsepositives": ["Unknown"], "level": "medium"}


class ScriptedStructLLM:
    def __init__(self, items):
        self.items, self.prompts, self.schemas = list(items), [], []

    def chat_json(self, model, messages, schema, name, **kw):
        self.prompts.append(messages[-1]["content"])
        self.schemas.append(name)
        return SimpleNamespace(data=self.items.pop(0), usage={"total_tokens": 5}, latency_s=0.0, model=model,
                               response_format="fake", reasoning=None)


def test_structured_mode_renders_yaml_in_code_and_pins_the_id():
    llm = ScriptedStructLLM([_struct()])
    result = _run_loop(llm, "m", "report", SPEC, evaluate=lambda text: _evaluation(1), max_repairs=1,
                       rule_id="11111111-2222-4333-8444-555555555555")

    assert result.success
    text = result.best.rule_text
    assert "id: 11111111-2222-4333-8444-555555555555" in text and "Image|endswith" in text
    assert llm.schemas == ["sigma_rule_fields"]


def test_structured_mode_sends_render_errors_back_without_evaluating():
    bad = _struct()
    bad["groups"][0]["fields"].append({"field": "Image", "modifier": "endswith", "values": ["other.exe"]})
    llm = ScriptedStructLLM([bad, _struct()])
    calls = []

    def evaluate(text):
        calls.append(text)
        return _evaluation(1)

    result = _run_loop(llm, "m", "report", SPEC, evaluate=evaluate, max_repairs=2)

    assert result.success and len(calls) == 1
    assert result.history[0].evaluation is None and not result.history[0].validation.ok
    assert "duplicate" in llm.prompts[1]


def test_structured_mode_undefined_condition_group_is_caught_by_sigma_check_and_repaired():
    llm = ScriptedStructLLM([_struct(condition="selection and missing"), _struct()])
    result = _run_loop(llm, "m", "report", SPEC, evaluate=lambda text: _evaluation(1), max_repairs=2)

    assert result.success and not result.history[0].validation.ok
    assert "missing" in llm.prompts[1]


def test_generation_prompt_lists_known_fields_for_the_log_source():
    llm = ScriptedStructLLM([_struct()])
    _run_loop(llm, "m", "report", SPEC, evaluate=lambda text: _evaluation(1), max_repairs=0)

    assert "CommandLine" in llm.prompts[0] and "ParentImage" in llm.prompts[0]


# ---- empty skeletons are resampled, not spent as repair attempts ---------------------------------------------

EMPTY = {"title": "t", "description": "d", "tags": [], "logsource_category": "process_creation",
         "groups": [], "condition": "", "falsepositives": [], "level": "low"}


def test_empty_skeleton_is_resampled_without_using_a_repair_attempt():
    llm = ScriptedStructLLM([EMPTY, EMPTY, _struct()])
    result = _run_loop(llm, "m", "report", SPEC, evaluate=lambda text: _evaluation(1), max_repairs=0)

    assert result.success
    assert len(llm.prompts) == 3 and len(result.history) == 1     # 2 resamples, still one iteration
    assert result.history[0].resamples == 2 and result.history[0].tokens == 15   # tokens of all 3 calls are counted


def test_resampling_is_bounded_then_the_empty_rule_goes_to_repair():
    llm = ScriptedStructLLM([EMPTY] * 4 + [_struct()])
    result = _run_loop(llm, "m", "report", SPEC, evaluate=lambda text: _evaluation(1), max_repairs=1, max_resamples=3)

    assert result.success
    assert result.history[0].resamples == 3 and not result.history[0].validation.ok
    assert "could not be built" in llm.prompts[4]                 # the repair prompt names the problem


class ThinkingAwareLLM:
    """Empty skeleton whenever thinking is on (the measured Nemotron Super failure); a real rule when it is off."""
    def __init__(self):
        self.calls = []

    def chat_json(self, model, messages, schema, name, **kw):
        self.calls.append(kw.get("thinking", True))
        data = EMPTY if kw.get("thinking", True) else _struct()
        return SimpleNamespace(data=data, usage={"total_tokens": 5}, latency_s=0.0, model=model,
                               response_format="fake", reasoning=None)


def test_thinking_off_fallback_rescues_a_persistently_empty_answer():
    llm = ThinkingAwareLLM()
    result = _run_loop(llm, "m", "report", SPEC, evaluate=lambda text: _evaluation(1), max_repairs=0,
                       max_resamples=2, fallback_without_thinking=True)

    assert llm.calls == [True, True, True, False]            # 1 try + 2 resamples, then one thinking-off call
    first = result.history[0]
    assert first.thinking_fallback and first.validation.ok and result.success
    assert first.tokens == 20                                 # every call's tokens are counted


def test_thinking_off_fallback_is_opt_in():
    llm = ThinkingAwareLLM()
    result = _run_loop(llm, "m", "report", SPEC, evaluate=lambda text: _evaluation(1), max_repairs=0, max_resamples=2)

    assert llm.calls == [True, True, True]
    assert not result.history[0].thinking_fallback and not result.history[0].validation.ok


def test_thinking_off_fallback_is_not_used_when_thinking_is_already_off():
    llm = ThinkingAwareLLM()
    _run_loop(llm, "m", "report", SPEC, evaluate=lambda text: _evaluation(1), max_repairs=0, max_resamples=1,
              thinking=False, fallback_without_thinking=True)

    assert llm.calls == [False]                               # a real rule at once; nothing to fall back from


class FlakyLLM:
    """Raises the 'no JSON in the answer' error (the client already retried it three times), then answers."""
    def __init__(self, fails):
        self.fails, self.calls = fails, 0

    def chat_json(self, model, messages, schema, name, **kw):
        self.calls += 1
        if self.fails:
            self.fails -= 1
            raise NoJSONError("model returned non-JSON content: ''")
        return SimpleNamespace(data=_struct(), usage={"total_tokens": 5}, latency_s=0.0, model=model,
                               response_format="fake", reasoning=None)


def test_an_answer_with_no_json_is_resampled_not_a_crash():
    llm = FlakyLLM(fails=2)
    result = _run_loop(llm, "m", "report", SPEC, evaluate=lambda text: _evaluation(1), max_repairs=0, max_resamples=3)

    assert result.success and llm.calls == 3
    assert result.history[0].resamples == 2


def test_persistent_no_json_ends_as_a_failed_attempt_not_an_exception():
    llm = FlakyLLM(fails=99)
    result = _run_loop(llm, "m", "report", SPEC, evaluate=lambda text: _evaluation(1), max_repairs=0, max_resamples=1)

    assert not result.success and not result.history[0].validation.ok


def test_yaml_mode_never_resamples():
    llm = ScriptedLLM(["title: broken\n", BETTER])
    result = _run_loop(llm, "m", "report", SPEC, evaluate=lambda text: _evaluation(1), max_repairs=1, rule_format="yaml")

    assert result.history[0].resamples == 0 and len(llm.prompts) == 2


def test_on_iteration_callback_sees_every_iteration_in_order():
    seen = []
    llm = ScriptedLLM([GOOD, BETTER])
    evals = iter([_evaluation(0), _evaluation(1)])

    result = run_loop(llm, "m", "report", SPEC, evaluate=lambda text: next(evals), max_repairs=2,
                      on_iteration=lambda it: seen.append((it.index, it.action)))

    assert result.success and seen == [(0, "generate"), (1, "repair")]
