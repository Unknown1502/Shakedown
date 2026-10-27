"""Render a Sigma rule from model-written JSON, so the model never writes YAML syntax.

Semantics follow Sigma: fields within a group are ANDed; the values of one field are ORed; groups are
combined by `condition`. Anything malformed raises RenderError, which the loop feeds back to the model.
"""
import re

import yaml

from shakedown.spec import CATEGORIES

MODIFIERS = ["exact", "contains", "contains|all", "startswith", "endswith", "re"]
LEVELS = ["informational", "low", "medium", "high", "critical"]
NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")

RULE_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "title": {"type": "string"},
        "description": {"type": "string"},
        "tags": {"type": "array", "items": {"type": "string"}},
        "logsource_category": {"type": "string", "enum": CATEGORIES},
        "groups": {"type": "array", "items": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "fields": {"type": "array", "items": {
                    "type": "object",
                    "properties": {"field": {"type": "string"}, "modifier": {"type": "string", "enum": MODIFIERS},
                                   "values": {"type": "array", "items": {"type": "string"}}},
                    "required": ["field", "modifier", "values"], "additionalProperties": False}}},
            "required": ["name", "fields"], "additionalProperties": False}},
        "condition": {"type": "string"},
        "falsepositives": {"type": "array", "items": {"type": "string"}},
        "level": {"type": "string", "enum": LEVELS},
    },
    "required": ["title", "description", "tags", "logsource_category", "groups", "condition", "falsepositives", "level"],
    "additionalProperties": False,
}


class RenderError(ValueError):
    pass


def _detection(groups: list[dict]) -> dict:
    if not groups:
        raise RenderError("rule has no detection groups")
    detection: dict = {}
    for group in groups:
        name = str(group.get("name", ""))
        if not NAME_RE.match(name):
            raise RenderError(f"group name {name!r} must be lowercase letters, digits and underscores, starting with a letter")
        if name in detection or name == "condition":
            raise RenderError(f"group name {name!r} is duplicated or reserved")
        fields = group.get("fields") or []
        if not fields:
            raise RenderError(f"group {name!r} has no fields")
        body: dict = {}
        for item in fields:
            values = [str(v) for v in item.get("values") or []]
            if not values:
                raise RenderError(f"group {name!r}: field {item.get('field')!r} has no values")
            if not str(item.get("field", "")).strip():
                raise RenderError(f"group {name!r} has a field with no name")
            key = item["field"] if item.get("modifier") in (None, "", "exact") else f"{item['field']}|{item['modifier']}"
            if key in body:
                raise RenderError(f"group {name!r}: duplicate field/modifier {key!r}; put all its values in one entry")
            body[key] = values[0] if len(values) == 1 else values
        detection[name] = body
    return detection


def render_rule(data: dict, rule_id: str, today: str) -> str:
    condition = str(data.get("condition", "")).strip()
    if not condition:
        raise RenderError("rule has no condition")
    detection = _detection(data.get("groups") or [])
    detection["condition"] = condition
    rule = {
        "title": str(data.get("title", "")).strip(),
        "id": rule_id,
        "status": "experimental",
        "description": str(data.get("description", "")).strip(),
        "author": "Shakedown",
        "date": today,
        "tags": list(data.get("tags") or []),
        "logsource": {"category": data.get("logsource_category"), "product": "windows"},
        "detection": detection,
        "falsepositives": list(data.get("falsepositives") or []) or ["Unknown"],
        "level": data.get("level", "medium"),
    }
    if not rule["tags"]:
        del rule["tags"]
    return yaml.safe_dump(rule, sort_keys=False, allow_unicode=True, width=120)
