"""Model selection must come from the live Token Factory listing, never a hard-coded guess."""
import pytest

from shakedown.llm import ModelSelectionError, select_model

LISTED = ["meta-llama/Llama-3.3-70B-Instruct", "nvidia/Nemotron-3_5-Lightning", "nvidia/nemotron-3-super-120b-a12b"]


def test_prefers_earlier_preference_among_listed_ids():
    assert select_model(LISTED, preferences=("nemotron-3-super", "lightning")) == "nvidia/nemotron-3-super-120b-a12b"


def test_falls_back_to_later_preference_when_earlier_is_not_listed():
    listed = ["nvidia/Nemotron-3_5-Lightning"]
    assert select_model(listed, preferences=("nemotron-3-super", "lightning")) == "nvidia/Nemotron-3_5-Lightning"


def test_override_must_be_listed():
    with pytest.raises(ModelSelectionError):
        select_model(LISTED, preferences=(), override="nvidia/made-up-model")


def test_refuses_non_nvidia_models_even_if_preferred():
    with pytest.raises(ModelSelectionError):
        select_model(["meta-llama/Llama-3.3-70B-Instruct"], preferences=("llama",))
