"""Timed sweeps: schedule maths, validation and the thread that fires due schedules.

A schedule is persisted in sqlite (so it survives restarts and is shared with the daemon's
database) and repeats one job type, a sweep, with the parameters chosen in the dashboard.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable

from netscan.store import Schedule, Store

log = logging.getLogger("netscan.schedule")

KINDS = ("interval", "daily", "once")
MIN_INTERVAL = 30
MAX_INTERVAL = 7 * 86400


def parse_hhmm(value: str) -> tuple[int, int]:
    try:
        hh, mm = str(value).strip().split(":")
        h, m = int(hh), int(mm)
    except ValueError:
        raise ValueError("at_time must look like HH:MM (24 hour clock)") from None
    if not (0 <= h <= 23 and 0 <= m <= 59):
        raise ValueError("at_time must look like HH:MM (24 hour clock)")
    return h, m


def next_daily(now: float, hhmm: str) -> float:
    """Next occurrence of HH:MM in the machine's local time, strictly after `now`."""
    h, m = parse_hhmm(hhmm)
    lt = time.localtime(now)
    for day_offset in (0, 1):
        # mktime normalises day overflow, so day+1 rolls into the next month correctly
        cand = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday + day_offset, h, m, 0, 0, 0, -1))
        if cand > now:
            return cand
    return cand  # pragma: no cover  (unreachable: day+1 is always later)


def _int(raw: dict, key: str, default: int, lo: int, hi: int) -> int:
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != int(value):
        raise ValueError(f"{key} must be a whole number")
    value = int(value)
    if not lo <= value <= hi:
        raise ValueError(f"{key} must be between {lo} and {hi}")
    return value


def _float(raw: dict, key: str, default: float, lo: float, hi: float) -> float:
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{key} must be a number")
    if not lo <= value <= hi:
        raise ValueError(f"{key} must be between {lo:g} and {hi:g}")
    return float(value)


def normalise_sweep_params(raw: dict | None, default_offline_after: int = 0) -> dict:
    """Validate sweep parameters (shared by manual scans and schedules)."""
    raw = raw or {}
    if not isinstance(raw, dict):
        raise ValueError("params must be an object")
    hostnames = raw.get("hostnames", True)
    if not isinstance(hostnames, bool):
        raise ValueError("hostnames must be true or false")
    return {
        "timeout": _float(raw, "timeout", 3.0, 1.0, 30.0),
        "hostnames": hostnames,
        "offline_after": _int(raw, "offline_after", default_offline_after, 0, MAX_INTERVAL),
        "capture_seconds": _int(raw, "capture_seconds", 0, 0, 3600),
        "flush": _float(raw, "flush", 5.0, 1.0, 60.0),
    }


def initial_next_run(kind: str, every_seconds: int, at_time: str, run_at: float | None, now: float) -> float | None:
    if kind == "interval":
        return now + every_seconds
    if kind == "daily":
        return next_daily(now, at_time)
    return run_at


def after_trigger(s: Schedule, now: float) -> tuple[float | None, bool]:
    """(next_run, still_enabled) once a schedule has fired at `now`."""
    if s.kind == "once":
        return None, False
    return initial_next_run(s.kind, s.every_seconds, s.at_time, None, now), True


def validate_schedule(data: dict, now: float, default_offline_after: int, existing: Schedule | None = None) -> dict:
    """Merge a request body over an existing schedule (if any) and return normalised column values.

    Raises ValueError with a message fit to show the user.
    """
    if not isinstance(data, dict):
        raise ValueError("expected a JSON object")
    base = {
        "name": existing.name if existing else "Timed sweep",
        "kind": existing.kind if existing else "interval",
        "every_seconds": existing.every_seconds if existing else 3600,
        "at_time": existing.at_time if existing else "",
        "run_at": existing.run_at if existing else None,
        "params": existing.params if existing else {},
        "enabled": existing.enabled if existing else True,
    }
    merged = {**base, **{k: v for k, v in data.items() if k in base}}

    name = str(merged["name"]).strip()
    if not 1 <= len(name) <= 60:
        raise ValueError("name must be 1 to 60 characters")
    kind = merged["kind"]
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {', '.join(KINDS)}")
    enabled = merged["enabled"]
    if not isinstance(enabled, bool):
        raise ValueError("enabled must be true or false")

    every, at_time, run_at = 0, "", None
    if kind == "interval":
        every = _int(merged, "every_seconds", 3600, MIN_INTERVAL, MAX_INTERVAL)
    elif kind == "daily":
        h, m = parse_hhmm(merged["at_time"])
        at_time = f"{h:02d}:{m:02d}"
    else:
        value = merged["run_at"]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("run_at must be a unix timestamp")
        run_at = float(value)
        if enabled and run_at <= now:
            raise ValueError("run_at is in the past")
    # a body that omits params keeps the stored ones; a body that includes them replaces them
    params = normalise_sweep_params(merged["params"], default_offline_after)
    return {"name": name, "kind": kind, "every_seconds": every, "at_time": at_time, "run_at": run_at, "params": params, "enabled": enabled}


def timing_changed(existing: Schedule, new: dict) -> bool:
    return any(getattr(existing, k) != new[k] for k in ("kind", "every_seconds", "at_time", "run_at")) or (new["enabled"] and not existing.enabled)


SubmitFn = Callable[[dict, str], int]


class Scheduler:
    """Fires due schedules by submitting sweep jobs; the job queue serialises the actual work."""

    def __init__(self, store: Store, submit: SubmitFn, clock: Callable[[], float] = time.time, tick_seconds: float = 1.0):
        self.store = store
        self.submit = submit
        self.clock = clock
        self.tick_seconds = tick_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def tick(self, now: float | None = None) -> list[int]:
        """Fire everything due; returns the ids of the schedules that submitted a job."""
        now = self.clock() if now is None else now
        fired: list[int] = []
        for s in self.store.due_schedules(now):
            source = f"schedule:{s.id}"
            next_run, enabled = after_trigger(s, now)
            if self.store.active_jobs(source):
                # the previous run is still queued/running (slow network or tiny interval): do not pile up
                self.store.update_schedule(s.id, next_run=next_run, enabled=enabled, last_status="skipped", last_message="previous run still in progress")
                continue
            try:
                self.submit(s.params, source)
            except Exception as exc:  # noqa: BLE001 a bad schedule must not stop the others
                log.exception("could not start schedule %s", s.id)
                self.store.update_schedule(s.id, next_run=next_run, enabled=enabled, last_status="error", last_message=str(exc))
                continue
            self.store.update_schedule(s.id, last_run=now, next_run=next_run, enabled=enabled, last_status="queued", last_message="")
            fired.append(s.id)
        return fired

    def _loop(self) -> None:
        while not self._stop.wait(self.tick_seconds):
            try:
                self.tick()
            except Exception:  # noqa: BLE001
                log.exception("scheduler tick failed")

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="netscan-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
