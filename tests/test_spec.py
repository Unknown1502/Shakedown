"""The typed detection spec must be grounded: no observable survives without a verbatim source quote."""
from types import SimpleNamespace

from shakedown.spec import extract_spec

REPORT = (
    "The actor runs reg.exe add HKCU\\Software\\Microsoft\\Windows Script\\Settings /v AmsiEnable /t REG_DWORD /d 0 /f "
    "to disable AMSI for script hosts. This maps to MITRE ATT&CK T1562.001."
)


class FakeLLM:
    def __init__(self, data):
        self.data = data

    def chat_json(self, model, messages, schema, name, **kw):
        return SimpleNamespace(data=self.data, usage={}, latency_s=0.0, model=model, response_format="fake", reasoning=None)


def test_grounded_observables_are_kept_and_invented_ones_dropped():
    llm = FakeLLM({
        "behavior": "Disable AMSI via registry",
        "logsource_category": "process_creation",
        "observables": [
            {"field": "CommandLine", "match": "contains", "value": "AmsiEnable", "quote": "/v AmsiEnable /t REG_DWORD"},
            {"field": "Image", "match": "endswith", "value": "\\evil.exe", "quote": "evil.exe was dropped"},
        ],
        "techniques": [
            {"id": "T1562.001", "quote": "MITRE ATT&CK T1562.001"},
            {"id": "T1059", "quote": "never mentioned"},
        ],
    })

    spec = extract_spec(llm, "m", REPORT)

    assert [o.value for o in spec.observables] == ["AmsiEnable"]
    assert [t.id for t in spec.techniques] == ["T1562.001"]
    assert len(spec.dropped) == 2
    assert spec.logsource_category == "process_creation"


def test_quote_matching_ignores_whitespace_differences():
    llm = FakeLLM({
        "behavior": "x", "logsource_category": "process_creation",
        "observables": [{"field": "CommandLine", "match": "contains", "value": "AmsiEnable",
                         "quote": "/v   AmsiEnable\n/t REG_DWORD"}],
        "techniques": [],
    })
    assert len(extract_spec(llm, "m", REPORT).observables) == 1
