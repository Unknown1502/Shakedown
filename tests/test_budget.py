"""Live-mode guard: the public demo must not be able to spend unbounded credits."""
from shakedown.budget import Budget


class Clock:
    def __init__(self):
        self.now, self.day = 1000.0, "2026-10-27"

    def time(self):
        return self.now

    def today(self):
        return self.day


def make(**kw):
    c = Clock()
    return Budget(clock=c.time, today=c.today, **kw), c


def test_daily_cap_blocks_further_runs_and_resets_next_day():
    b, c = make(daily_cap=2, cooldown_s=0, max_concurrent=5)
    assert b.try_acquire("a")[0] and b.try_acquire("b")[0]
    ok, reason = b.try_acquire("c")
    assert not ok and "daily" in reason
    c.day = "2026-10-28"
    assert b.try_acquire("c")[0]


def test_per_client_cooldown():
    b, c = make(daily_cap=10, cooldown_s=60, max_concurrent=5)
    assert b.try_acquire("a")[0]
    ok, reason = b.try_acquire("a")
    assert not ok and "wait" in reason
    assert b.try_acquire("other")[0]
    c.now += 61
    assert b.try_acquire("a")[0]


def test_concurrency_limit_and_release():
    b, _ = make(daily_cap=10, cooldown_s=0, max_concurrent=1)
    assert b.try_acquire("a")[0]
    ok, reason = b.try_acquire("b")
    assert not ok and "busy" in reason
    b.release()
    assert b.try_acquire("b")[0]


def test_rejected_attempts_do_not_consume_the_daily_cap():
    b, _ = make(daily_cap=1, cooldown_s=0, max_concurrent=1)
    assert b.try_acquire("a")[0]
    assert not b.try_acquire("b")[0]          # busy, not counted
    b.release()
    assert not b.try_acquire("b")[0]          # cap of 1 is used up by the first run only
