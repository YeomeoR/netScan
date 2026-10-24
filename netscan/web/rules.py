"""Block rules: weekly timetables ("kids' devices off 22:00-07:00") and one-off timers ("block for 30 minutes").

Time maths is pure and local-time based so it can be tested without a clock. The engine
applies blocks through the same BlockManager as a manual block, so every safety guard holds.
"""

from __future__ import annotations

import datetime as dt
import logging
import re
from typing import TYPE_CHECKING

from netscan.store import BlockRule
from netscan.web.errors import ApiError

if TYPE_CHECKING:
    from netscan.web.controller import Controller

log = logging.getLogger("netscan.rules")

DAY_NAMES = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
MAX_RULE_DEVICES = 50
MAX_TIMER_MINUTES = 7 * 24 * 60
TIME_RE = re.compile(r"^(\d{1,2}):(\d{2})$")
RULE_PREFIX = "rule: "


def parse_hhmm(value, allow_24: bool = False) -> int:
    """'HH:MM' -> minutes since midnight. '24:00' (end of day) only when allow_24."""
    m = TIME_RE.match(str(value or "").strip())
    if not m:
        raise ValueError("times must look like 22:30")
    h, mi = int(m.group(1)), int(m.group(2))
    if mi > 59 or h > 24 or (h == 24 and (mi != 0 or not allow_24)):
        raise ValueError(f"{value!r} is not a valid time")
    return h * 60 + mi


def fmt_hhmm(minutes: int) -> str:
    return f"{minutes // 60:02d}:{minutes % 60:02d}"


def window_active(days: list[int], start: str, end: str, when: dt.datetime) -> bool:
    """True when `when` (local time) falls inside the weekly window. Overnight windows belong to the day they start on."""
    s, e = parse_hhmm(start), parse_hhmm(end, allow_24=True)
    minute = when.hour * 60 + when.minute
    today = when.weekday()
    if s < e:
        return today in days and s <= minute < e
    return (today in days and minute >= s) or ((today - 1) % 7 in days and minute < e)


def next_transition(rule: BlockRule, now: float) -> float | None:
    """Epoch seconds of the next time this rule turns on or off; None for a disabled rule or a timer without an end."""
    if not rule.enabled:
        return None
    if rule.kind == "timer":
        return rule.until
    here = dt.datetime.fromtimestamp(now)
    current = window_active(rule.days, rule.start, rule.end, here)
    s, e = parse_hhmm(rule.start), parse_hhmm(rule.end, allow_24=True)
    base = here.replace(hour=0, minute=0, second=0, microsecond=0)
    candidates = []
    for offset in range(-1, 9):
        day = base + dt.timedelta(days=offset)
        for minute in (s, e):
            candidates.append(day + dt.timedelta(minutes=minute))
    for moment in sorted(candidates):
        if moment.timestamp() > now and window_active(rule.days, rule.start, rule.end, moment) != current:
            return moment.timestamp()
    return None


def validate_rule(body: dict, now: float, existing: BlockRule | None = None) -> dict:
    """Return clean field values for add/update. Raises ValueError with a user-facing message."""
    if not isinstance(body, dict):
        raise ValueError("body must be an object")
    kind = body.get("kind", existing.kind if existing else "window")
    if kind not in ("window", "timer"):
        raise ValueError("kind must be window or timer")
    name = body.get("name", existing.name if existing else "")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("give the rule a name")
    if len(name.strip()) > 60:
        raise ValueError("name must be 60 characters or fewer")
    macs = body.get("macs", existing.macs if existing else [])
    if not isinstance(macs, list) or not macs or not all(isinstance(m, str) for m in macs):
        raise ValueError("choose at least one device")
    if len(set(macs)) > MAX_RULE_DEVICES:
        raise ValueError(f"at most {MAX_RULE_DEVICES} devices per rule")
    enabled = body.get("enabled", existing.enabled if existing else True)
    if not isinstance(enabled, bool):
        raise ValueError("enabled must be true or false")
    out: dict = {"name": name.strip(), "kind": kind, "macs": list(dict.fromkeys(macs)), "enabled": enabled, "days": [], "start": "", "end": "", "until": None}
    if kind == "window":
        days = body.get("days", existing.days if existing else [])
        if not isinstance(days, list) or not days or not all(isinstance(d, int) and not isinstance(d, bool) and 0 <= d <= 6 for d in days):
            raise ValueError("choose at least one day (0 = Monday ... 6 = Sunday)")
        start = str(body.get("start", existing.start if existing else "")).strip()
        end = str(body.get("end", existing.end if existing else "")).strip()
        s, e = parse_hhmm(start), parse_hhmm(end, allow_24=True)
        if s == e:
            raise ValueError("start and end must differ")
        out.update(days=sorted(set(days)), start=fmt_hhmm(s), end=fmt_hhmm(e))
    else:
        if "minutes" in body:
            minutes = body["minutes"]
            if isinstance(minutes, bool) or not isinstance(minutes, int) or not 1 <= minutes <= MAX_TIMER_MINUTES:
                raise ValueError(f"minutes must be a whole number between 1 and {MAX_TIMER_MINUTES}")
            out["until"] = now + minutes * 60
        elif existing and existing.until:
            out["until"] = existing.until
        else:
            raise ValueError("minutes is required for a timer")
    return out


class RuleEngine:
    """Applies and releases blocks as rules switch on and off. `tick` is idempotent and safe to call often."""

    def __init__(self, ctl: "Controller"):
        self.ctl = ctl
        self._warned = ""

    def tick(self, now: float) -> None:
        for rule in self.ctl.store.list_rules():
            try:
                self._tick_rule(rule, now)
            except Exception:  # noqa: BLE001 one broken rule must not stop the others
                log.exception("rule %s failed", rule.id)

    def _wanted(self, rule: BlockRule, now: float) -> bool:
        if not rule.enabled:
            return False
        if rule.kind == "timer":
            return rule.until is not None and now < rule.until
        return window_active(rule.days, rule.start, rule.end, dt.datetime.fromtimestamp(now))

    def _tick_rule(self, rule: BlockRule, now: float) -> None:
        store = self.ctl.store
        if rule.kind == "timer" and rule.until is not None and now >= rule.until:
            if self.release(rule):
                store.delete_rule(rule.id)
            return
        want = self._wanted(rule, now)
        if want and not rule.active:
            self.activate(rule)
        elif want:
            self.reassert(rule)
        elif rule.active:
            self.release(rule)

    def _context(self):
        try:
            return self.ctl._runtime()
        except ApiError as exc:
            if exc.message != self._warned:
                log.warning("rules waiting: %s", exc.message)
                self._warned = exc.message
            return None

    def activate(self, rule: BlockRule) -> None:
        rt = self._context()
        if rt is None:
            return
        mgr = self.ctl._manager(rt)
        already = {b.mac for b in self.ctl.store.list_blocks()}
        held, events = [], []
        for mac in rule.macs:
            if mac in already:
                held_elsewhere = any(r.id != rule.id and r.active and mac in r.held for r in self.ctl.store.list_rules())
                if held_elsewhere:
                    held.append(mac)
                continue
            try:
                _blk, ev = mgr.block(mac, RULE_PREFIX + rule.name)
            except Exception as exc:  # noqa: BLE001 protected / unknown / backend failure: skip this device
                log.warning("rule %r could not block %s: %s", rule.name, mac, exc)
                continue
            held.append(mac)
            events.append(ev)
        self.ctl.store.update_rule(rule.id, active=True, held=held)
        rt.alerter.dispatch(events)
        self.ctl.ensure_enforcer()

    def reassert(self, rule: BlockRule) -> None:
        if not rule.held:
            return
        rt = self._context()
        if rt is None:
            return
        blocked = {b.mac for b in self.ctl.store.list_blocks()}
        mgr = self.ctl._manager(rt)
        for mac in rule.held:
            if mac not in blocked:
                try:
                    mgr.block(mac, RULE_PREFIX + rule.name)
                except Exception as exc:  # noqa: BLE001
                    log.warning("rule %r could not re-apply block on %s: %s", rule.name, mac, exc)

    def release(self, rule: BlockRule) -> bool:
        """Unblock only the devices this rule blocked; blocks someone placed by hand stay. False when the network is not ready."""
        if rule.held:
            rt = self._context()
            if rt is None:
                return False
            others = {m for r in self.ctl.store.list_rules() if r.id != rule.id and r.active for m in r.held}
            events = []
            for mac in rule.held:
                if mac in others:
                    continue
                ev = self.ctl._unblock_mac(rt, mac)
                if ev:
                    events.append(ev)
            rt.alerter.dispatch(events)
        self.ctl.store.update_rule(rule.id, active=False, held=[])
        return True
