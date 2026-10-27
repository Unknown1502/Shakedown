"""Evaluate one Sigma rule against labelled attack files and benign directories.

Every number comes from the checker's observed output. Units are stated explicitly:
attack results are per EVTX *file* (one scenario per file); benign results are per file
with hits plus the total number of matching events.
"""
import shutil
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from shakedown.evtx_events import summarize_events
from shakedown.harness.checker import CheckerConfig, CheckerRun, run_checker

Runner = Callable[[dict[str, str], list[Path]], CheckerRun]


def rate(numerator: int, denominator: int) -> float | None:
    return None if denominator == 0 else numerator / denominator


@dataclass(frozen=True)
class BenignResult:
    files_total: int
    files_with_hits: int
    hits: int
    examples: list[dict] = field(default_factory=list)


@dataclass(frozen=True)
class Evaluation:
    attack_total: int
    attack_detected: int
    attack_missed: list[str]
    attack_events_hit: int
    benign: dict[str, BenignResult]
    attack_events: list[dict]  # events from missed attack files, for repair evidence
    seconds: float

    @property
    def benign_hits(self) -> int:
        return sum(b.hits for b in self.benign.values())

    @property
    def passed(self) -> bool:
        return self.attack_total > 0 and not self.attack_missed and self.benign_hits == 0


def make_runner(config: CheckerConfig) -> Runner:
    from shakedown.runners import LocalRunner
    return LocalRunner(config)


def _missed_events(files: list[Path], per_file: int = 5) -> list[dict]:
    events: list[dict] = []
    for path in files[:2]:
        try:
            events.extend(summarize_events(path, max_events=per_file))
        except Exception:  # aqg: top-level boundary - evidence is best-effort, never fatal to the evaluation
            continue
    return events


def benign_by_rule(rules: dict[str, str], directory: Path, runner: Runner) -> dict[str, BenignResult]:
    """Run many rules against one benign directory in a single checker run. Keys are the rules' ids,
    which must be unique within the call (the checker reports hits by rule id)."""
    run = runner(rules, [Path(directory)])
    files_total = sum(1 for _ in Path(directory).rglob("*.evtx"))
    out = {}
    for rule_id in rules:
        hits = [m for m in run.matches if m.rule_id == rule_id]
        out[rule_id] = BenignResult(
            files_total=files_total, files_with_hits=len({m.evtx_file for m in hits}), hits=len(hits),
            examples=[{"file": m.evtx_file, "event": str(m.event.get("Event", ""))[:600],
                       "matched": m.event.get("MatchStrings")} for m in hits[:3]])
    return out


def evaluate_rule(rule_text: str, attack_files: list[Path], benign_dirs: dict[str, Path], runner: Runner) -> Evaluation:
    rule_id = str(yaml.safe_load(rule_text)["id"])
    started = time.monotonic()

    names = [Path(p).name for p in attack_files]
    if len(set(names)) != len(names):
        raise ValueError("attack fixture file names must be unique")
    detected: set[str] = set()
    events_hit = 0
    if attack_files:
        with tempfile.TemporaryDirectory(prefix="shakedown-attack-") as tmp:
            for path in attack_files:
                shutil.copyfile(path, Path(tmp) / Path(path).name)
            run = runner({"candidate": rule_text}, [Path(tmp)])
        for match in run.matches:
            if match.rule_id == rule_id and match.evtx_file in names:
                detected.add(match.evtx_file)
                events_hit += 1
    missed = [n for n in names if n not in detected]

    benign: dict[str, BenignResult] = {}
    for label, directory in benign_dirs.items():
        run = runner({"candidate": rule_text}, [Path(directory)])
        hits = [m for m in run.matches if m.rule_id == rule_id]
        benign[label] = BenignResult(
            files_total=sum(1 for _ in Path(directory).rglob("*.evtx")),
            files_with_hits=len({m.evtx_file for m in hits}),
            hits=len(hits),
            examples=[{"file": m.evtx_file, "event": str(m.event.get("Event", ""))[:600],
                       "matched": m.event.get("MatchStrings")} for m in hits[:3]],
        )

    missed_paths = [Path(p) for p in attack_files if Path(p).name in missed]
    return Evaluation(attack_total=len(names), attack_detected=len(detected), attack_missed=missed,
                      attack_events_hit=events_hit, benign=benign,
                      attack_events=_missed_events(missed_paths) if missed_paths else [],
                      seconds=round(time.monotonic() - started, 2))
