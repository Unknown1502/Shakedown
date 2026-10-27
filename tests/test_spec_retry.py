"""An answer with no JSON at all is retried a bounded number of times, then reported (never swallowed)."""
from types import SimpleNamespace

import pytest

from shakedown.llm import NoJSONError
from shakedown.spec import extract_spec

GOOD = SimpleNamespace(data={"behavior": "b", "logsource_category": "process_creation", "observables": [], "techniques": []},
                       usage={}, latency_s=0.0)


class Flaky:
    def __init__(self, outcomes):
        self.outcomes, self.calls = list(outcomes), 0

    def chat_json(self, *args, **kwargs):
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def test_one_empty_answer_is_retried():
    llm = Flaky([NoJSONError("empty"), GOOD])
    assert extract_spec(llm, "m", "report").behavior == "b" and llm.calls == 2


def test_three_empty_answers_in_a_row_raise_instead_of_inventing_a_spec():
    llm = Flaky([NoJSONError("empty")] * 3)
    with pytest.raises(NoJSONError):
        extract_spec(llm, "m", "report")
    assert llm.calls == 3
