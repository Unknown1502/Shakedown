"""Typed detection specification extracted from a threat report.

Observed facts stay separate from inferred logic: an observable or technique survives only if
the model supplied a quote that appears verbatim (whitespace-normalised) in the report and
contains the claimed value. Everything else is recorded in `dropped`, never silently kept.
"""
from dataclasses import dataclass, field

from shakedown.llm import NoJSONError

SPEC_ATTEMPTS = 3
CATEGORIES = ["process_creation", "ps_script", "registry_set", "file_event", "network_connection", "image_load"]
MATCHES = ["equals", "contains", "startswith", "endswith"]

SPEC_SCHEMA = {
    "type": "object",
    "properties": {
        "behavior": {"type": "string"},
        "logsource_category": {"type": "string", "enum": CATEGORIES},
        "observables": {"type": "array", "items": {
            "type": "object",
            "properties": {"field": {"type": "string"}, "match": {"type": "string", "enum": MATCHES},
                           "value": {"type": "string"}, "quote": {"type": "string"}},
            "required": ["field", "match", "value", "quote"], "additionalProperties": False}},
        "techniques": {"type": "array", "items": {
            "type": "object",
            "properties": {"id": {"type": "string"}, "quote": {"type": "string"}},
            "required": ["id", "quote"], "additionalProperties": False}},
    },
    "required": ["behavior", "logsource_category", "observables", "techniques"],
    "additionalProperties": False,
}

SYSTEM = (
    "You extract detection requirements from a threat report. Reply only with JSON matching the schema. "
    "Every observable and every ATT&CK technique id MUST come with a 'quote': text copied exactly from the "
    "report that contains the value or id. Do not add indicators, technique ids or details that the report "
    "does not state. If the report does not state something, leave it out."
)


@dataclass(frozen=True)
class Observable:
    field: str
    match: str
    value: str
    quote: str


@dataclass(frozen=True)
class Technique:
    id: str
    quote: str


@dataclass(frozen=True)
class DetectionSpec:
    behavior: str
    logsource_category: str
    observables: list[Observable]
    techniques: list[Technique]
    dropped: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"behavior": self.behavior, "logsource_category": self.logsource_category,
                "observables": [o.__dict__ for o in self.observables],
                "techniques": [t.__dict__ for t in self.techniques]}


def _norm(text: str) -> str:
    return " ".join(text.split()).lower()


def _grounded(report_norm: str, quote: str, value: str) -> str | None:
    """Return None if grounded, else the reason it is not."""
    q = _norm(quote)
    if not q or q not in report_norm:
        return "quote not found verbatim in report"
    if _norm(value) not in q:
        return "value not contained in its quote"
    return None


def extract_spec(llm, model: str, report_text: str) -> DetectionSpec:
    for attempt in range(SPEC_ATTEMPTS):
        try:
            completion = llm.chat_json(
                model,
                [{"role": "system", "content": SYSTEM}, {"role": "user", "content": f"Threat report:\n\n{report_text}"}],
                SPEC_SCHEMA, name="detection_spec", max_tokens=4096)
            break
        except NoJSONError:
            if attempt == SPEC_ATTEMPTS - 1:  # measured: an empty answer happens now and then; three in a row is a failure
                raise
    data = completion.data
    report_norm = _norm(report_text)
    observables, techniques, dropped = [], [], []
    for item in data.get("observables", []):
        reason = _grounded(report_norm, item["quote"], item["value"])
        if reason:
            dropped.append({"kind": "observable", "item": item, "reason": reason})
        else:
            observables.append(Observable(**item))
    for item in data.get("techniques", []):
        reason = _grounded(report_norm, item["quote"], item["id"])
        if reason:
            dropped.append({"kind": "technique", "item": item, "reason": reason})
        else:
            techniques.append(Technique(**item))
    return DetectionSpec(behavior=data["behavior"], logsource_category=data["logsource_category"],
                         observables=observables, techniques=techniques, dropped=dropped)
