"""Model-written JSON -> valid Sigma YAML rendered by code (no model-authored YAML syntax)."""
import pytest
import yaml

from shakedown.rule_render import RenderError, render_rule
from shakedown.validate import validate_rule

RULE_ID = "11111111-2222-4333-8444-555555555555"


def _data(**over):
    base = {
        "title": "Reg Disables AMSI",
        "description": "Detects reg.exe changing AMSI values.",
        "tags": ["attack.t1562.001"],
        "logsource_category": "process_creation",
        "groups": [{"name": "selection", "fields": [
            {"field": "Image", "modifier": "endswith", "values": ["\\reg.exe"]},
            {"field": "CommandLine", "modifier": "contains", "values": ["AmsiEnable", "AMSI"]}]}],
        "condition": "selection",
        "falsepositives": ["Administrative scripts"],
        "level": "high",
    }
    base.update(over)
    return base


def test_rendered_rule_is_valid_sigma_and_keeps_semantics():
    text = render_rule(_data(), RULE_ID, today="2026-10-27")

    assert validate_rule(text).ok
    doc = yaml.safe_load(text)
    assert doc["id"] == RULE_ID
    assert str(doc["date"]) == "2026-10-27"
    sel = doc["detection"]["selection"]
    assert sel["Image|endswith"] == "\\reg.exe"       # a single value is written as a scalar
    assert sel["CommandLine|contains"] == ["AmsiEnable", "AMSI"]
    assert doc["logsource"] == {"category": "process_creation", "product": "windows"}
    assert doc["detection"]["condition"] == "selection"


def test_exact_and_all_modifiers_map_to_sigma_keys():
    data = _data(groups=[{"name": "selection", "fields": [
        {"field": "EventType", "modifier": "exact", "values": ["SetValue"]},
        {"field": "CommandLine", "modifier": "contains|all", "values": ["a", "b"]}]}])
    sel = yaml.safe_load(render_rule(data, RULE_ID, today="2026-10-27"))["detection"]["selection"]
    assert "EventType" in sel and "CommandLine|contains|all" in sel


def test_duplicate_field_and_modifier_in_a_group_is_an_error_not_silently_merged():
    data = _data(groups=[{"name": "selection", "fields": [
        {"field": "Image", "modifier": "endswith", "values": ["a"]},
        {"field": "Image", "modifier": "endswith", "values": ["b"]}]}])
    with pytest.raises(RenderError, match="duplicate"):
        render_rule(data, RULE_ID, today="2026-10-27")


@pytest.mark.parametrize("bad", [{"groups": []}, {"condition": ""},
                                 {"groups": [{"name": "Bad Name", "fields": [{"field": "Image", "modifier": "exact", "values": ["x"]}]}]},
                                 {"groups": [{"name": "selection", "fields": [{"field": "Image", "modifier": "exact", "values": []}]}]}])
def test_malformed_structures_raise_render_error(bad):
    with pytest.raises(RenderError):
        render_rule(_data(**bad), RULE_ID, today="2026-10-27")


def test_undefined_group_in_condition_is_caught_by_validation_not_hidden():
    text = render_rule(_data(condition="selection and missing"), RULE_ID, today="2026-10-27")
    assert not validate_rule(text).ok
