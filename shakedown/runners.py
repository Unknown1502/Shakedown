"""The two evaluators behind one interface: `(rules, evtx_dirs) -> CheckerRun`, plus `describe()` for provenance.

`sandbox` is the Nebius Token Factory Sandbox (the submission's evaluator); `local` is the isolated Docker
container used before Sandboxes access arrived and kept for offline development. Records say which one ran.
"""
from pathlib import Path

from shakedown.harness.checker import DEFAULT_IMAGE, CheckerConfig, CheckerRun, run_checker

BASELINE = "data/raw/evtx-baseline/v0.8.5"


class LocalRunner:
    def __init__(self, config: CheckerConfig):
        self.config = config

    def __call__(self, rules: dict[str, str], evtx_dirs: list[Path]) -> CheckerRun:
        return run_checker(self.config, rules, evtx_dirs)

    def describe(self) -> dict:
        return {"kind": "local-docker", "image": self.config.image, "network": "disabled (--network none)",
                "isolation": "Docker container, read-only root, no capabilities, non-root",
                "note": "Not a Token Factory Sandbox."}


def build_runner(root: Path, kind: str = "sandbox"):
    root = Path(root)
    base = root / BASELINE
    if kind == "local":
        return LocalRunner(CheckerConfig(checker=base / "evtx-sigma-checker",
                                         thor_config=root / "data/raw/sigma/tests/thor.yml", image=DEFAULT_IMAGE))
    if kind == "sandbox":
        from shakedown.harness.sandbox import SandboxConfig, SandboxRunner
        runner = SandboxRunner(SandboxConfig(datasets={(base / "win7-x86").resolve(): "/data/win7-x86",
                                                       (base / "Logs_Client").resolve(): "/data/Logs_Client"}))
        runner.check()  # fail now, with an actionable message, not in the middle of a run
        return runner
    raise ValueError(f"unknown runner kind: {kind}")
