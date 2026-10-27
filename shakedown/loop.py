"""Bounded generate -> validate -> evaluate -> repair loop.

Deterministic code decides validity, test outcomes, the best candidate and when to stop. The model
only proposes rule content. A later candidate is never preferred just because it is later.

Two generation formats:
- "structured" (default): the model returns JSON fields and code renders the Sigma YAML, so the model
  never writes YAML syntax.
- "yaml": the model writes the whole YAML file (the format used in evaluation Runs 1 and 2).
"""
import hashlib
import json
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from types import SimpleNamespace

from shakedown.evaluate import Evaluation
from shakedown.harness.checker import CheckerError
from shakedown.llm import NoJSONError
from shakedown.rule_render import RULE_JSON_SCHEMA, RenderError, render_rule
from shakedown.spec import DetectionSpec
from shakedown.validate import Validation, validate_rule

RULE_SCHEMA = {
    "type": "object",
    "properties": {"rule_yaml": {"type": "string"}},
    "required": ["rule_yaml"],
    "additionalProperties": False,
}

SYSTEM_YAML = (
    "You are a senior detection engineer writing Sigma rules. Reply only with JSON: {\"rule_yaml\": \"...\"}. "
    "The rule must have title, id (a fresh UUID), status, description, author, date, logsource, detection, "
    "condition, falsepositives and level. Use only Sigma field names that exist in the log source. "
    "Never write a rule that matches everything."
)

SYSTEM_STRUCT = (
    "You are a senior detection engineer writing Sigma rules. Reply only with JSON matching the schema; "
    "code will turn it into the Sigma file, so do not write YAML. Semantics: a detection group is a named set "
    "of field conditions that must ALL match (AND); the values listed for one field are alternatives (OR). "
    "Modifiers: exact, contains, contains|all (every value must appear), startswith, endswith, re. "
    "'condition' combines group names, e.g. 'selection' or 'selection and not filter' or '1 of selection_*'. "
    "Group names are lowercase letters, digits and underscores. Use only field names that exist in the log "
    "source. Never write a rule that matches everything, and prefer specific values over broad ones."
)

# Standard Sysmon-style Sigma field names per log source (general Sigma knowledge, not task-specific).
FIELD_HINTS = {
    "process_creation": "Image, OriginalFileName, CommandLine, ParentImage, ParentCommandLine, User, "
                        "IntegrityLevel, CurrentDirectory, Description, Product, Company",
    "ps_script": "ScriptBlockText (the PowerShell script block content), Path",
    "registry_set": "TargetObject (the registry key path), Details (the value written), EventType, Image",
    "file_event": "TargetFilename, Image",
    "network_connection": "DestinationIp, DestinationPort, DestinationHostname, Image, Initiated",
    "image_load": "ImageLoaded, Image, Signed, OriginalFileName",
}


@dataclass(frozen=True)
class Iteration:
    index: int
    action: str  # "generate" or "repair"
    rule_text: str
    sha256: str
    validation: Validation
    evaluation: Evaluation | None
    tokens: int
    latency_s: float
    evaluator_error: str | None = None  # set when the rule passed validation but the evaluator could not run it
    resamples: int = 0  # extra model calls made because the answer was an empty skeleton
    thinking_fallback: bool = False  # the answer came from a last-resort call with thinking off


@dataclass(frozen=True)
class LoopResult:
    history: list[Iteration]
    best: Iteration
    success: bool
    stop_reason: str


def _strip_fences(text: str) -> str:
    m = re.match(r"^\s*```(?:ya?ml)?\s*\n(.*?)\n```\s*$", text, re.S)
    return m.group(1) if m else text


def _pin_id(rule_text: str, rule_id: str) -> str:
    """The rule id is assigned by code: models tend to emit placeholder-looking UUIDs."""
    return re.sub(r"(?m)^id:.*$", f"id: {rule_id}", rule_text, count=1)


def _score(it: Iteration) -> tuple[int, int, int]:
    if it.evaluation is None:
        return (-1, 0, 0)
    ev = it.evaluation
    return (1, ev.attack_detected, -ev.benign_hits)


def _generate_prompt(report: str, spec: DetectionSpec, events: list[dict] | None, structured: bool) -> str:
    parts = [f"Threat report:\n{report}", f"Extracted requirements (grounded in the report):\n"
             f"{json.dumps(spec.to_dict(), indent=1)}"]
    if structured and spec.logsource_category in FIELD_HINTS:
        parts.append(f"Log source: {spec.logsource_category} (Windows). Field names available in this log source: "
                     f"{FIELD_HINTS[spec.logsource_category]}.")
    if events:
        parts.append("Example attack events from the analyst's logs (real field names and values):\n"
                     + json.dumps(events, indent=1))
    parts.append("Write one Sigma rule that detects this behavior without matching normal activity.")
    return "\n\n".join(parts)


def _repair_prompt(it: Iteration, structured: bool) -> str:
    lines = ["Your previous rule:" if it.validation.ok or not structured or not it.rule_text.lstrip().startswith("{")
             else "Your previous rule (it could not be turned into a Sigma file):", it.rule_text, "",
             "It has these problems. Fix only what the evidence shows."]
    if not it.validation.ok:
        lines += ["Validation failed:", *it.validation.errors, it.validation.sigma_output]
    elif it.evaluator_error:
        lines += ["The test runner could not load or run this rule:", it.evaluator_error]
    else:
        ev = it.evaluation
        if ev.attack_missed:
            # SigmaHQ names each attack sample after its rule id, so real file names would tell the model which
            # published rule it is reproducing. The events below are what it needs.
            labels = ", ".join(f"attack sample {i}" for i, _ in enumerate(ev.attack_missed, 1))
            lines += [f"It did NOT detect these attack files: {labels}.",
                      "Events from those files (real fields and values):", json.dumps(ev.attack_events, indent=1)]
        for label, b in ev.benign.items():
            if b.hits:
                lines += [f"It matched {b.hits} benign event(s) in {b.files_with_hits} of {b.files_total} "
                          f"benign files ({label}). Examples:", json.dumps(b.examples, indent=1)]
    lines += ["", "Keep detecting everything it already detected. Make the smallest change that removes the "
              "problems; do not make the rule match more broadly. Return the full corrected rule in the same format."]
    return "\n".join(lines)


def _is_empty_skeleton(data: dict) -> bool:
    """Valid JSON with no detection content. Measured: Nemotron Super with thinking on returns this in
    roughly 3 of 8 calls under a strict schema. It carries no information, so it is resampled."""
    return not data.get("groups") or not str(data.get("condition", "")).strip()


def _build_candidate(data: dict, rule_format: str, rule_id: str) -> tuple[str, Validation]:
    if rule_format == "yaml":
        text = _pin_id(_strip_fences(str(data.get("rule_yaml", ""))), rule_id)
        return text, validate_rule(text)
    try:
        text = render_rule(data, rule_id, today=date.today().isoformat())
    except RenderError as exc:
        return json.dumps(data, indent=1), Validation(ok=False, errors=[f"rule could not be built: {exc}"])
    return text, validate_rule(text)


def run_loop(llm, model: str, report: str, spec: DetectionSpec, evaluate: Callable[[str], Evaluation],
             max_repairs: int = 3, attack_events: list[dict] | None = None,
             rule_id: str | None = None, rule_format: str = "structured", thinking: bool = True,
             max_resamples: int = 3, fallback_without_thinking: bool = False,
             on_iteration: Callable[[Iteration], None] | None = None) -> LoopResult:
    if rule_format not in ("structured", "yaml"):
        raise ValueError(f"unknown rule_format {rule_format!r}")
    structured = rule_format == "structured"
    schema, schema_name, system = ((RULE_JSON_SCHEMA, "sigma_rule_fields", SYSTEM_STRUCT) if structured
                                   else (RULE_SCHEMA, "sigma_rule", SYSTEM_YAML))
    max_repairs = max(0, min(max_repairs, 5))
    rule_id = rule_id or str(uuid.uuid4())
    history: list[Iteration] = []
    user_prompt = _generate_prompt(report, spec, attack_events, structured)
    action = "generate"

    for index in range(max_repairs + 1):
        resamples, tokens, latency, fell_back = 0, 0, 0.0, False
        use_thinking = thinking
        while True:
            try:
                completion = llm.chat_json(model, [{"role": "system", "content": system},
                                                   {"role": "user", "content": user_prompt}],
                                           schema, name=schema_name, max_tokens=6000, thinking=use_thinking)
            except NoJSONError:
                # No JSON at all is an empty answer: same remedy (resample, then the fallback), same bounded cost.
                completion = SimpleNamespace(data={}, usage={}, latency_s=0.0)
            tokens += int((completion.usage or {}).get("total_tokens", 0))
            latency += completion.latency_s
            if structured and _is_empty_skeleton(completion.data):
                if resamples < max_resamples:
                    resamples += 1
                    continue
                if fallback_without_thinking and use_thinking:
                    # Measured: thinking off never returned an empty skeleton (0 of 8), at some cost in rule quality.
                    use_thinking, fell_back = False, True
                    continue
            break
        rule_text, validation = _build_candidate(completion.data, rule_format, rule_id)
        evaluation, evaluator_error = None, None
        if validation.ok:
            try:
                evaluation = evaluate(rule_text)
            except CheckerError as exc:
                evaluator_error = str(exc)[:1500]
        it = Iteration(index=index, action=action, rule_text=rule_text,
                       sha256=hashlib.sha256(rule_text.encode()).hexdigest(), validation=validation,
                       evaluation=evaluation, tokens=tokens, latency_s=round(latency, 2),
                       evaluator_error=evaluator_error, resamples=resamples, thinking_fallback=fell_back)
        history.append(it)
        if on_iteration:
            on_iteration(it)
        if evaluation is not None and evaluation.passed:
            return LoopResult(history, it, True, "acceptance criteria passed")
        user_prompt = _repair_prompt(it, structured)
        action = "repair"

    best = max(history, key=lambda i: (_score(i), -i.index))
    return LoopResult(history, best, False, "repair budget exhausted")
