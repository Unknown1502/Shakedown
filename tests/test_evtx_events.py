from pathlib import Path

import pytest

from shakedown.evtx_events import summarize_events

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = (ROOT / "data/raw/sigma/regression_data/rules/windows/process_creation/"
          "proc_creation_win_amsi_registry_tampering/7dbbcac2-57a0-45ac-b306-ff30a8bd2981.evtx")

pytestmark = pytest.mark.skipif(not SAMPLE.exists(), reason="SigmaHQ data not downloaded")


def test_extracts_sysmon_process_creation_fields():
    events = summarize_events(SAMPLE)

    assert len(events) == 1
    ev = events[0]
    assert ev["EventID"] == 1
    assert ev["Image"].lower().endswith("reg.exe")
    assert "AmsiEnable" in ev["CommandLine"]


def test_values_are_truncated():
    ev = summarize_events(SAMPLE, max_value_chars=20)[0]
    assert all(len(v) <= 20 + 3 for v in ev.values() if isinstance(v, str))


def test_event_limit():
    assert len(summarize_events(SAMPLE, max_events=0)) == 0
