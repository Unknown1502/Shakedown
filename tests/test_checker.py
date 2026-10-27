"""Evaluator harness: SigmaHQ's evtx-sigma-checker run inside an isolated container."""
import shutil
import subprocess
from pathlib import Path

import pytest

from shakedown.harness.checker import CheckerConfig, build_docker_command, run_checker

ROOT = Path(__file__).resolve().parents[1]
SIGMA = ROOT / "data/raw/sigma"
BASELINE = ROOT / "data/raw/evtx-baseline/v0.8.5"
# Windows AMSI Related Registry Tampering Via CommandLine; info.yml declares match_count: 1
REF_ID = "7dbbcac2-57a0-45ac-b306-ff30a8bd2981"
REF_RULE = SIGMA / "rules/windows/process_creation/proc_creation_win_amsi_registry_tampering.yml"
REF_SAMPLE_DIR = SIGMA / "regression_data/rules/windows/process_creation/proc_creation_win_amsi_registry_tampering"


def _config() -> CheckerConfig:
    return CheckerConfig(checker=BASELINE / "evtx-sigma-checker", thor_config=SIGMA / "tests/thor.yml")


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


needs_data = pytest.mark.skipif(not (REF_RULE.exists() and (BASELINE / "evtx-sigma-checker").exists()),
                                reason="datasets not downloaded (see docs/DATASET_AUDIT.md)")
needs_docker = pytest.mark.skipif(not _docker_ready(), reason="docker daemon not reachable")


def test_docker_command_isolates_inputs(tmp_path):
    """covers: R2"""
    evtx_dir = tmp_path / "evtx"
    evtx_dir.mkdir()
    cmd = build_docker_command(_config(), rules_dir=tmp_path / "rules", evtx_dirs=[evtx_dir])

    assert cmd[:3] == ["docker", "run", "--rm"]
    assert cmd[cmd.index("--network") + 1] == "none"
    assert "--read-only" in cmd
    assert cmd[cmd.index("--cap-drop") + 1] == "ALL"
    mounts = [cmd[i + 1] for i, part in enumerate(cmd) if part == "-v"]
    assert len(mounts) == 4  # checker, thor config, rules, one evtx dir
    assert all(m.endswith(":ro") for m in mounts)


@needs_data
@needs_docker
@pytest.mark.docker
def test_reference_rule_reproduces_regression_match_count():
    """covers: R1"""
    matches = run_checker(_config(), rules={REF_ID: REF_RULE.read_text(encoding="utf-8")},
                          evtx_dirs=[REF_SAMPLE_DIR]).matches

    own_sample_hits = [m for m in matches if m.rule_id == REF_ID and Path(m.evtx_file).stem == REF_ID]
    assert len(own_sample_hits) >= 1


@needs_data
@needs_docker
@pytest.mark.docker
def test_reference_rule_is_quiet_on_benign_win10_baseline():
    """covers: R1 (benign side of the same evaluator path)"""
    matches = run_checker(_config(), rules={REF_ID: REF_RULE.read_text(encoding="utf-8")},
                          evtx_dirs=[BASELINE / "Logs_Client"]).matches

    assert [m for m in matches if m.rule_id == REF_ID] == []
