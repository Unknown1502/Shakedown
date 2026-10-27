"""Pipeline level: what the model is allowed to see, and what the run record says about it."""
import pytest
from test_pipeline import STRUCT, FakeLLM, FakeTavily, fake_runner, scenario  # noqa: F401 (scenario is a fixture)

from shakedown.pipeline import run_pipeline
from shakedown.research import Source

MIRROR_TEXT = "title: Mirror rule id: 514e7e3e-b3b4-4a67-af60-be20f139198b detection: selection: Image|endswith: x.exe"
LEAK_SCENARIO = {"id": "514e7e3e-b3b4-4a67-af60-be20f139198b", "title": "PUA - AdFind.EXE Execution"}
MIRROR_URL = "https://sigmaquery.com/rule.php?id=93"


class SpyLLM(FakeLLM):
    def __init__(self, rules):
        super().__init__(rules)
        self.seen = []

    def chat_json(self, model, messages, schema, name, **kw):
        self.seen.append("\n".join(m["content"] for m in messages))
        return super().chat_json(model, messages, schema, name, **kw)


def web(url, content):
    return Source(url=url, title=url, content=content, retrieved_at="2026-10-27T00:00:01Z", via="search", score=0.5)


class LeakyTavily(FakeTavily):
    def __init__(self):
        self.asked = None

    def search(self, query, max_results=5, include_domains=None):
        self.asked = max_results
        return [web(MIRROR_URL, MIRROR_TEXT), web("https://research.splunk.com/a", "general prose about the tool"),
                web("https://blog.example/b", "more prose"), web("https://blog.example/c", "even more prose"),
                web("https://blog.example/d", "last prose")]


def run(scenario, *, llm=None, tavily=None, **kw):
    return run_pipeline(llm=llm or FakeLLM([STRUCT]), model="m", runner=fake_runner(True),
                        scenario={**scenario, **LEAK_SCENARIO}, source_url="https://example.org/report",
                        tavily=tavily or LeakyTavily(), **kw)


def test_exclude_policy_keeps_the_answer_page_out_of_every_model_message(scenario):
    llm, tavily = SpyLLM([STRUCT]), LeakyTavily()
    record = run(scenario, llm=llm, tavily=tavily, answer_policy="exclude")

    assert llm.seen and not any("514e7e3e" in m or "sigmaquery" in m or "Mirror rule" in m for m in llm.seen)
    assert any("general prose about the tool" in m for m in llm.seen)
    assert tavily.asked > 3  # asks for extra results so an excluded one can be replaced
    assert [c["url"] for c in record["research"]["corroboration"]] == [
        "https://research.splunk.com/a", "https://blog.example/b", "https://blog.example/c"]
    screening = record["research"]["screening"]
    by_url = {s["url"]: s for s in screening["sources"]}
    assert screening["policy"] == "exclude" and screening["target"] == LEAK_SCENARIO
    assert by_url[MIRROR_URL]["status"] == "excluded" and "target_rule_id" in by_url[MIRROR_URL]["reasons"]
    assert by_url["https://blog.example/d"]["status"] == "not_used"
    assert by_url["https://example.org/report"]["role"] == "primary"


def test_flag_policy_shows_the_page_to_the_model_but_records_the_flag(scenario):
    llm, tavily = SpyLLM([STRUCT]), LeakyTavily()
    record = run(scenario, llm=llm, tavily=tavily)

    assert any("Mirror rule" in m for m in llm.seen) and tavily.asked == 3
    by_url = {s["url"]: s for s in record["research"]["screening"]["sources"]}
    assert record["research"]["screening"]["policy"] == "flag"
    assert by_url[MIRROR_URL]["status"] == "flagged"


def test_the_exclusion_changes_the_recorded_input_hash(scenario):
    flag, exclude = run(scenario), run(scenario, answer_policy="exclude")
    assert len(flag["input"]["sha256"]) == 64 and flag["input"]["sha256"] != exclude["input"]["sha256"]


class AnswerPrimaryTavily(FakeTavily):
    def extract(self, url):
        return Source(url=url, title=url, content=MIRROR_TEXT, retrieved_at="2026-10-27T00:00:00Z", via="extract")


def test_an_answer_bearing_report_url_is_not_used_in_exclude_mode(scenario):
    llm = SpyLLM([STRUCT])
    record = run_pipeline(llm=llm, model="m", runner=fake_runner(True), scenario={**scenario, **LEAK_SCENARIO},
                          source_url=MIRROR_URL, tavily=AnswerPrimaryTavily(), report_text="fallback description",
                          answer_policy="exclude")

    assert record["research"]["primary"] is None and "answer-bearing" in record["research"]["error"]
    assert record["input"]["kind"] == "text" and not any("Mirror rule" in m for m in llm.seen)
    assert record["research"]["screening"]["sources"][0]["status"] == "excluded"


def test_unknown_policy_is_rejected_before_any_model_call(scenario):
    llm = SpyLLM([STRUCT])
    with pytest.raises(ValueError, match="policy"):
        run_pipeline(llm=llm, model="m", runner=fake_runner(True), scenario=scenario, report_text="r",
                     answer_policy="hide")
    assert llm.seen == []


# --- last line of defence: nothing identifying the target may reach the model in leakage-controlled mode ----------
from shakedown.harness.checker import CheckerError, CheckerRun  # noqa: E402
from shakedown.pipeline import LeakGuardError  # noqa: E402

RULE_FILE = "514e7e3e-b3b4-4a67-af60-be20f139198b.evtx"


@pytest.fixture
def named_scenario(scenario, tmp_path):
    """Like SigmaHQ: the attack sample is named after the rule id."""
    attack = tmp_path / RULE_FILE
    attack.write_bytes(b"x")
    return {**scenario, **LEAK_SCENARIO, "attack": attack}


def test_the_model_never_sees_the_attack_file_name_even_when_the_evaluator_reports_it(named_scenario):
    """The checker's stderr can contain the path of the attack file; the repair prompt must not."""
    calls = {"n": 0}

    def runner(rules, evtx_dirs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise CheckerError(f"checker exited 2: cannot parse /work/evtx/0/{RULE_FILE}: bad chunk")
        return CheckerRun([], [], "", 0.01)

    llm = SpyLLM([STRUCT, STRUCT])
    record = run_pipeline(llm=llm, model="m", runner=runner, scenario=named_scenario, report_text="r",
                          answer_policy="exclude", max_repairs=1)

    assert len(llm.seen) >= 3 and not any("514e7e3e" in m or RULE_FILE in m for m in llm.seen)
    assert "attack sample 1" in llm.seen[-1]
    assert "514e7e3e" not in record["iterations"][0]["evaluator_error"]


def test_a_request_that_would_carry_the_target_id_is_blocked_before_it_is_sent(named_scenario):
    llm = SpyLLM([STRUCT])
    with pytest.raises(LeakGuardError, match="blocked"):
        run_pipeline(llm=llm, model="m", runner=fake_runner(True), scenario=named_scenario,
                     report_text=f"Notes. Rule {LEAK_SCENARIO['id']} describes it.", answer_policy="exclude")
    assert llm.seen == []


def test_research_mode_does_not_block_but_says_it_is_not_controlled(named_scenario):
    llm = SpyLLM([STRUCT])
    record = run_pipeline(llm=llm, model="m", runner=fake_runner(True), scenario=named_scenario, max_repairs=0,
                          report_text=f"Notes. Rule {LEAK_SCENARIO['id']} describes it.")
    assert llm.seen and record["source_mode"]["mode"] == "research"
    assert record["source_mode"]["verdict"] == "no_web_research"


def test_the_record_states_the_source_mode_and_never_calls_a_flagged_run_clean(scenario):
    controlled = run(scenario, answer_policy="exclude")
    research = run(scenario)

    assert controlled["source_mode"] == {"policy": "exclude", "mode": "leakage-controlled", "verdict": "controlled",
                                         "excluded": 1, "flagged_shown": 0}
    assert research["source_mode"] == {"policy": "flag", "mode": "research", "verdict": "flagged_sources_shown",
                                       "excluded": 0, "flagged_shown": 1}
