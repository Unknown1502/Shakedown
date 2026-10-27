"""Run SigmaHQ's evtx-sigma-checker on staged rules inside an isolated container.

The checker is a third-party binary and the rules may be model-written, so it only
runs in a container with no network, a read-only root filesystem, no capabilities,
a non-root user and read-only inputs. Invocation mirrors SigmaHQ's own regression
runner (tests/regression_tests_runner.py): --log-source thor.yml, --rule-level
informational, one JSON object per match on stdout.
"""
import json
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

# debian:bookworm-slim pinned by digest (pulled 2026-10-26); the checker is a static Go binary.
DEFAULT_IMAGE = "debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8"


class CheckerError(RuntimeError):
    """The checker did not produce a result that can be trusted."""


@dataclass(frozen=True)
class CheckerConfig:
    checker: Path
    thor_config: Path
    image: str = DEFAULT_IMAGE
    rule_level: str = "informational"
    timeout_s: int = 600
    memory: str = "2g"


@dataclass(frozen=True)
class Match:
    rule_id: str
    evtx_file: str
    event: dict = field(repr=False, compare=False)


@dataclass(frozen=True)
class CheckerRun:
    matches: list[Match]
    ignored_lines: list[str]
    stderr: str
    duration_s: float


def build_docker_command(config: CheckerConfig, rules_dir: Path, evtx_dirs: list[Path],
                         name: str | None = None) -> list[str]:
    cmd = ["docker", "run", "--rm"]
    if name:
        cmd += ["--name", name]
    cmd += [
        "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--user", "65534:65534", "--pids-limit", "256", "--memory", config.memory,
        "-v", f"{Path(config.checker).resolve()}:/opt/checker:ro",
        "-v", f"{Path(config.thor_config).resolve()}:/work/thor.yml:ro",
        "-v", f"{Path(rules_dir).resolve()}:/work/rules:ro",
    ]
    evtx_args = []
    for i, evtx_dir in enumerate(evtx_dirs):
        cmd += ["-v", f"{Path(evtx_dir).resolve()}:/work/evtx/{i}:ro"]
        evtx_args += ["--evtx-path", f"/work/evtx/{i}"]
    return cmd + [config.image, "/opt/checker", "--log-source", "/work/thor.yml",
                  "--rule-level", config.rule_level, "--rule-path", "/work/rules", *evtx_args]


def parse_output(stdout: str) -> tuple[list[Match], list[str]]:
    matches, ignored = [], []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            ignored.append(line)
            continue
        if not isinstance(obj, dict) or not obj.get("RuleId"):
            raise CheckerError(f"checker emitted JSON without RuleId: {line[:200]}")
        matches.append(Match(rule_id=str(obj["RuleId"]), evtx_file=Path(str(obj.get("File", ""))).name, event=obj))
    return matches, ignored


def run_checker(config: CheckerConfig, rules: dict[str, str], evtx_dirs: list[Path]) -> CheckerRun:
    """Evaluate `rules` (label -> Sigma YAML text) against every EVTX file under `evtx_dirs`."""
    if not rules:
        raise ValueError("no rules to evaluate")
    for evtx_dir in evtx_dirs:
        if not Path(evtx_dir).is_dir():
            raise CheckerError(f"evtx directory not found: {evtx_dir}")

    with tempfile.TemporaryDirectory(prefix="shakedown-rules-") as tmp:
        rules_dir = Path(tmp)
        # Labels may come from model output, so never use them as file names.
        for i, text in enumerate(rules.values()):
            (rules_dir / f"r{i:04d}.yml").write_text(text, encoding="utf-8")

        name = f"shakedown-checker-{uuid.uuid4().hex[:12]}"
        cmd = build_docker_command(config, rules_dir, evtx_dirs, name=name)
        started = time.monotonic()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                                  timeout=config.timeout_s)
        except subprocess.TimeoutExpired as exc:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
            raise CheckerError(f"checker timed out after {config.timeout_s}s") from exc
        duration = time.monotonic() - started

    if proc.returncode != 0:
        raise CheckerError(f"checker exited {proc.returncode}: {proc.stderr.strip()[-2000:]}")
    matches, ignored = parse_output(proc.stdout)
    return CheckerRun(matches=matches, ignored_lines=ignored, stderr=proc.stderr, duration_s=duration)
