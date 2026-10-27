"""Every model call is counted, so the cost of a run is measured from the record and never guessed."""
from test_pipeline import STRUCT, FakeLLM, fake_runner, scenario  # noqa: F401 (scenario is a fixture)

from shakedown.pipeline import run_pipeline


def test_the_record_counts_every_model_call_and_its_tokens(scenario):
    record = run_pipeline(llm=FakeLLM([STRUCT]), model="m", runner=fake_runner(True), scenario=scenario, report_text="r")
    # one spec extraction and one rule generation, 7 tokens each in the fake
    assert record["usage"] == {"calls": 2, "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 14}
