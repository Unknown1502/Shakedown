"""Hosting: the spending cap must survive a restart and bound the whole judging period."""
import json

import pytest
from test_budget import make

from shakedown.budget import Budget


def test_the_daily_count_survives_a_restart(tmp_path):
    state = tmp_path / "budget.json"
    first, clock = make(daily_cap=2, cooldown_s=0, max_concurrent=5, state_path=state)
    assert first.try_acquire("a")[0] and first.try_acquire("b")[0]

    second = Budget(daily_cap=2, cooldown_s=0, max_concurrent=5, clock=clock.time, today=clock.today, state_path=state)
    ok, reason = second.try_acquire("c")
    assert not ok and "daily" in reason


def test_total_cap_holds_across_days_and_restarts(tmp_path):
    state = tmp_path / "budget.json"
    b, clock = make(daily_cap=5, total_cap=2, cooldown_s=0, max_concurrent=5, state_path=state)
    assert b.try_acquire("a")[0] and b.try_acquire("b")[0]
    clock.day = "2026-10-29"
    again = Budget(daily_cap=5, total_cap=2, cooldown_s=0, max_concurrent=5, clock=clock.time, today=clock.today,
                   state_path=state)
    ok, reason = again.try_acquire("c")
    assert not ok and "total" in reason
    assert again.status()["total_used"] == 2 and again.status()["total_cap"] == 2


def test_an_unreadable_state_file_stops_the_server_instead_of_resetting_the_cap(tmp_path):
    state = tmp_path / "budget.json"
    state.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="budget state"):
        Budget(state_path=state)


def test_state_file_holds_counts_only(tmp_path):
    state = tmp_path / "budget.json"
    b, _ = make(state_path=state)
    b.try_acquire("203.0.113.9")
    saved = json.loads(state.read_text(encoding="utf-8"))
    assert set(saved) == {"day", "used", "total_used"}  # no client addresses are written to disk
