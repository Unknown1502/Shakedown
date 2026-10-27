"""Spending guard for the public live mode: a daily run cap, a total cap, a per-client cooldown and a concurrency limit.

Only accepted runs count. With `state_path` the day's count and the total survive a restart (counts only: no client
addresses are written), so restarting the server cannot reset the cap. An unreadable state file raises instead of
starting from zero. The caps bound the worst-case spend: total_cap x the cost of one run.
"""
import json
import threading
import time
from collections.abc import Callable
from datetime import date
from pathlib import Path


class Budget:
    def __init__(self, daily_cap: int = 25, cooldown_s: float = 60.0, max_concurrent: int = 1,
                 total_cap: int | None = None, state_path: Path | None = None,
                 clock: Callable[[], float] = time.time, today: Callable[[], str] = lambda: date.today().isoformat()):
        self.daily_cap, self.cooldown_s, self.max_concurrent, self.total_cap = daily_cap, cooldown_s, max_concurrent, total_cap
        self._clock, self._today = clock, today
        self._state_path = Path(state_path) if state_path else None
        self._lock = threading.Lock()
        self._day, self._used, self._total_used, self._running = today(), 0, 0, 0
        self._last: dict[str, float] = {}
        if self._state_path and self._state_path.exists():
            try:
                saved = json.loads(self._state_path.read_text(encoding="utf-8"))
                self._day, self._used, self._total_used = str(saved["day"]), int(saved["used"]), int(saved["total_used"])
            except (ValueError, KeyError, TypeError) as exc:
                raise ValueError(f"budget state file {self._state_path} is unreadable ({exc}); fix or remove it") from exc

    def _save(self) -> None:
        if self._state_path:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            self._state_path.write_text(json.dumps({"day": self._day, "used": self._used, "total_used": self._total_used}),
                                        encoding="utf-8")

    def try_acquire(self, client: str) -> tuple[bool, str]:
        with self._lock:
            now, today = self._clock(), self._today()
            if today != self._day:
                self._day, self._used = today, 0
            if self.total_cap is not None and self._total_used >= self.total_cap:
                return False, f"The total limit of {self.total_cap} live runs for this demo has been reached. The recorded runs are still available."
            if self._used >= self.daily_cap:
                return False, f"The daily limit of {self.daily_cap} live runs has been reached. Try the recorded runs, or come back tomorrow."
            if self._running >= self.max_concurrent:
                return False, "Another live run is in progress and the demo is busy. Try again in a minute."
            wait = self.cooldown_s - (now - self._last.get(client, -1e18))
            if wait > 0:
                return False, f"Please wait {int(wait) + 1} seconds before starting another live run."
            self._used += 1
            self._total_used += 1
            self._running += 1
            self._last[client] = now
            self._save()
            return True, ""

    def release(self) -> None:
        with self._lock:
            self._running = max(0, self._running - 1)

    def status(self) -> dict:
        with self._lock:
            return {"daily_cap": self.daily_cap, "used_today": self._used, "running": self._running,
                    "total_cap": self.total_cap, "total_used": self._total_used}
