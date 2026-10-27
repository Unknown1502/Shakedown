"""Answer-source screening: web research must not hand the model the detection rule it is asked to write.

Background: an audit found that the corroboration search ("<rule title> Windows detection") returns mirrors of the
target SigmaHQ rule itself. These tests pin the screen (what counts as answer-bearing) and the policy (flag keeps,
exclude removes), at the research layer.
"""
import pytest

from shakedown.research import Source, screen_sources

TARGET = {"id": "514e7e3e-b3b4-4a67-af60-be20f139198b", "title": "PUA - AdFind.EXE Execution"}


def src(url, content, title="t", via="search"):
    return Source(url=url, title=title, content=content, retrieved_at="2026-10-27T00:00:00Z", via=via, score=0.5)


def reasons_of(source, target=TARGET):
    _, decisions = screen_sources([source], "flag", target, "corroboration")
    return decisions[0]["reasons"]


def test_a_source_that_contains_the_target_rule_id_is_flagged():
    page = src("https://example.org/x", f"rule id: {TARGET['id'].upper()} detects things")
    assert "target_rule_id" in reasons_of(page)


def test_known_sigma_rule_mirrors_are_flagged_but_ordinary_github_pages_are_not():
    assert "sigma_mirror" in reasons_of(src("https://sigmaquery.com/rule.php?id=93", "x"))
    assert "sigma_mirror" in reasons_of(src("https://detection.fyi/sigmahq/sigma/windows/process_creation/a", "x"))
    assert "sigma_mirror" in reasons_of(src("https://github.com/SigmaHQ/sigma/blob/master/rules/a.yml", "x"))
    assert "sigma_mirror" in reasons_of(src("https://sigma.nasbench.dev/rules/455b9d50", "x"))
    assert reasons_of(src("https://github.com/redcanaryco/atomic-red-team/blob/x/T1087.002.md", "x")) == []
    assert reasons_of(src("https://detection.fyi/about", "x")) == []


def test_a_page_titled_like_the_target_rule_is_flagged_even_on_an_unknown_host():
    page = src("https://vendor.example/rules/pua-adfind-exe-execution.html", "x", title="PUA - AdFind.EXE Execution | Vendor")
    assert "target_rule_title" in reasons_of(page)
    assert "target_rule_title" in reasons_of(src("https://vendor.example/pua-adfind-exe-execution", "x"))


def test_a_very_short_target_title_does_not_match_everything():
    short = {"id": "514e7e3e-b3b4-4a67-af60-be20f139198b", "title": "Run"}
    assert reasons_of(src("https://example.org/run-the-numbers", "x", title="Run it"), short) == []


def test_a_target_id_that_is_not_a_rule_id_is_ignored():
    assert reasons_of(src("https://example.org/x", "x marks the spot"), {"id": "x", "title": "Run"}) == []


def test_sigma_rule_text_is_flagged_and_prose_is_not():
    rule = ("title: A\nid: 1\nstatus: test\ndescription: d\nlogsource:\n  product: windows\ndetection:\n"
            "  selection:\n    Image|endswith: a.exe\n  condition: selection\nlevel: high")
    assert "sigma_rule_text" in reasons_of(src("https://example.org/r", rule))
    flattened = "1title: PUA 2id: abc 6status: experimental 7description: Detects x 8references: - y"
    assert "sigma_rule_text" in reasons_of(src("https://example.org/r", flattened))
    prose = ("The following analytic identifies the execution of adfind.exe. This activity is significant because "
             "threat actors use it. Status: confirmed. Level of risk: medium.")
    assert reasons_of(src("https://research.splunk.com/endpoint/bd3b", prose)) == []


def test_flag_policy_keeps_everything_and_records_why():
    clean, mirror = src("https://a", "prose only"), src("https://sigmaquery.com/rule.php?id=93", f"id {TARGET['id']}")
    kept, decisions = screen_sources([clean, mirror], "flag", TARGET, "corroboration")

    assert kept == [clean, mirror]
    assert [d["status"] for d in decisions] == ["included", "flagged"]
    assert decisions[1]["reasons"] == ["sigma_mirror", "target_rule_id"] and decisions[1]["url"] == mirror.url
    assert decisions[1]["retrieved_at"] == "2026-10-27T00:00:00Z" and len(decisions[1]["sha256"]) == 64
    assert decisions[1]["role"] == "corroboration"


def test_exclude_policy_drops_flagged_sources_and_keeps_the_first_clean_ones_up_to_the_limit():
    clean = [src(f"https://c{i}", f"prose {i}") for i in range(4)]
    mirror = src("https://sigmaquery.com/rule.php?id=93", "x")
    kept, decisions = screen_sources([mirror] + clean, "exclude", TARGET, "corroboration", limit=3)

    assert kept == clean[:3]
    assert [d["status"] for d in decisions] == ["excluded", "included", "included", "included", "not_used"]
    assert decisions[0]["content"] == "x"  # the dropped text stays in the record for audit


def test_only_search_snippets_are_stored_in_full():
    page = src("https://p", "A" * 50000, via="extract")
    _, decisions = screen_sources([page], "flag", TARGET, "primary")
    assert "content" not in decisions[0] and decisions[0]["chars"] == 50000


def test_unknown_policy_is_rejected():
    with pytest.raises(ValueError, match="policy"):
        screen_sources([], "hide", TARGET, "corroboration")


def test_a_page_about_detecting_the_tool_is_not_a_page_about_the_rule():
    guide = src("https://blog.example/how-to-detect-adfind", "How defenders can detect AdFind execution on Windows.",
                title="How to detect AdFind execution in your SOC")
    assert reasons_of(guide) == []
