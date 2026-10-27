"""Evaluation metrics are computed from observed checker output, never from model claims."""
from pathlib import Path

from shakedown.evaluate import evaluate_rule, rate
from shakedown.harness.checker import CheckerRun, Match

RULE_ID = "6f0c1c3e-8f4a-4a57-9d5e-2a3b4c5d6e7f"
RULE = f"title: t\nid: {RULE_ID}\nlogsource: {{category: process_creation, product: windows}}\ndetection: {{s: {{Image: x}}, condition: s}}\n"


def _make_evtx(directory: Path, *names: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for name in names:
        (directory / name).write_bytes(b"x")
    return directory


class FakeChecker:
    """Returns hits for staged file names listed in `hits` (by their original names)."""

    def __init__(self, hits_by_dir_name: dict[str, list[str]] | None = None):
        self.hits = hits_by_dir_name or {}
        self.calls = []

    def __call__(self, rules, evtx_dirs):
        self.calls.append(evtx_dirs)
        matches = []
        for d in evtx_dirs:
            for name in self.hits.get(Path(d).name, []):
                matches.append(Match(rule_id=RULE_ID, evtx_file=name, event={"Event": f"e-{name}"}))
        return CheckerRun(matches=matches, ignored_lines=[], stderr="", duration_s=0.1)


def test_rate_reports_none_for_empty_denominator():
    assert rate(0, 0) is None
    assert rate(1, 4) == 0.25


def test_attack_detection_and_misses_are_counted_per_file(tmp_path):
    attacks = [tmp_path / "a1.evtx", tmp_path / "a2.evtx"]
    for a in attacks:
        a.write_bytes(b"x")
    benign = _make_evtx(tmp_path / "benign", "b1.evtx", "b2.evtx", "b3.evtx")

    class StagedAware(FakeChecker):
        def __call__(self, rules, evtx_dirs):
            names = {p.name for d in evtx_dirs for p in Path(d).glob("*.evtx")}
            self.calls.append(sorted(names))
            if "a1.evtx" in names:  # the attack run: only a1 matches
                return CheckerRun([Match(RULE_ID, "a1.evtx", {})], [], "", 0.1)
            return CheckerRun([Match(RULE_ID, "b2.evtx", {"Event": "benign hit"}),
                               Match(RULE_ID, "b2.evtx", {"Event": "benign hit 2"})], [], "", 0.1)

    result = evaluate_rule(RULE, attacks, {"dev": benign}, runner=StagedAware())

    assert result.attack_total == 2
    assert result.attack_detected == 1
    assert result.attack_missed == ["a2.evtx"]
    b = result.benign["dev"]
    assert (b.files_total, b.files_with_hits, b.hits) == (3, 1, 2)
    assert not result.passed


def test_passes_only_when_all_attacks_detected_and_zero_benign_hits(tmp_path):
    a = tmp_path / "a.evtx"
    a.write_bytes(b"x")
    benign = _make_evtx(tmp_path / "benign", "b1.evtx")

    class Clean(FakeChecker):
        def __call__(self, rules, evtx_dirs):
            names = {p.name for d in evtx_dirs for p in Path(d).glob("*.evtx")}
            return CheckerRun([Match(RULE_ID, "a.evtx", {})] if "a.evtx" in names else [], [], "", 0.1)

    result = evaluate_rule(RULE, [a], {"dev": benign}, runner=Clean())
    assert result.passed
    assert result.benign["dev"].hits == 0


def test_benign_by_rule_attributes_hits_to_each_rule_in_one_run(tmp_path):
    from shakedown.evaluate import benign_by_rule

    benign = _make_evtx(tmp_path / "benign", "b1.evtx", "b2.evtx")
    calls = []

    def runner(rules, evtx_dirs):
        calls.append(len(rules))
        return CheckerRun([Match("rule-a", "b1.evtx", {"Event": "e1"}), Match("rule-a", "b1.evtx", {"Event": "e2"}),
                           Match("rule-b", "b2.evtx", {"Event": "e3"})], [], "", 0.1)

    texts = {"rule-a": "id: rule-a\n", "rule-b": "id: rule-b\n", "rule-c": "id: rule-c\n"}
    result = benign_by_rule(texts, benign, runner)

    assert calls == [3]                                   # one checker run for all rules
    assert (result["rule-a"].hits, result["rule-a"].files_with_hits) == (2, 1)
    assert (result["rule-b"].hits, result["rule-b"].files_total) == (1, 2)
    assert result["rule-c"].hits == 0


def test_matches_from_other_rule_ids_are_ignored(tmp_path):
    a = tmp_path / "a.evtx"
    a.write_bytes(b"x")

    def runner(rules, evtx_dirs):
        return CheckerRun([Match("some-other-id", "a.evtx", {})], [], "", 0.1)

    result = evaluate_rule(RULE, [a], {}, runner=runner)
    assert result.attack_detected == 0
