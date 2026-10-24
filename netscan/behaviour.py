"""Habits worked out from data netScan already keeps: when a device is on the network, how often it drops, where its traffic goes.

Pure functions over the presence segments and traffic rows; no probing.
"""

from __future__ import annotations

import time

from netscan.monitor import ago

FLAKY_DROPS_PER_DAY = 3.0
MIN_HISTORY_HOURS = 24


def hourly_profile(segments: list[dict], since: float, until: float) -> list[float | None]:
    """Share of observed time online for each local hour of day (0-23). None where there is no history."""
    online = [0.0] * 24
    total = [0.0] * 24
    step = 3600.0
    t = since - (since % step)
    while t < until:
        a, b = max(t, since), min(t + step, until)
        if b > a:
            hour = time.localtime(a).tm_hour
            seen = sum(max(0.0, min(s["end"], b) - max(s["start"], a)) for s in segments if s["online"])
            total[hour] += b - a
            online[hour] += min(seen, b - a)
        t += step
    return [round(online[h] / total[h], 2) if total[h] > 0 else None for h in range(24)]


def usual_hours(profile: list[float | None], threshold: float = 0.5) -> str:
    """'07:00-23:00' style summary of the hours the device is usually online; '' when it never is or always is."""
    on = [p is not None and p >= threshold for p in profile]
    if not any(on):
        return ""
    if all(on):
        return "around the clock"
    start = next(h for h in range(24) if on[h] and not on[h - 1])
    ranges, h = [], start
    for _ in range(24):
        if on[h] and not on[h - 1]:
            run = 0
            while on[(h + run) % 24] and run < 24:
                run += 1
            ranges.append(f"{h:02d}:00-{(h + run) % 24:02d}:00")
        h = (h + 1) % 24
    return ", ".join(ranges[:3])


def traffic_destinations(rows, limit: int = 6) -> list[dict]:
    """Where a device's recorded traffic goes, grouped by remote name (or address) and ordered by bytes."""
    merged: dict[str, dict] = {}
    for r in rows:
        key = r.peer_host or r.peer_ip
        entry = merged.setdefault(key, {"host": key, "ip": r.peer_ip, "bytes": 0, "services": set(), "last_seen": 0.0})
        entry["bytes"] += r.bytes
        entry["last_seen"] = max(entry["last_seen"], r.last_seen)
        if r.peer_port:
            entry["services"].add(r.peer_port)
    top = sorted(merged.values(), key=lambda e: -e["bytes"])[:limit]
    return [{"host": e["host"], "ip": e["ip"], "bytes": e["bytes"], "last_seen": e["last_seen"], "ports": sorted(e["services"])[:4]} for e in top]


def summarise(*, online: bool, last_seen: float, first_seen: float, segments: list[dict], since: float, now: float, private_mac: bool, traffic_rows=()) -> dict:
    history = now - max(since, first_seen)
    online_secs = sum(s["end"] - s["start"] for s in segments if s["online"])
    offline = [s for s in segments if not s["online"]]
    # a gap at the very start of the window is just "before we knew the device", not a drop
    drops = sum(1 for s in offline if s["start"] > max(since, first_seen) + 1)
    days = max(history / 86400, 1 / 24)
    enough = history >= MIN_HISTORY_HOURS * 3600
    profile = hourly_profile(segments, max(since, first_seen), now)
    per_day = round(drops / days, 1)
    out = {
        "history_days": round(history / 86400, 1),
        "online_percent": round(100 * online_secs / history) if history > 0 else 0,
        "drops": drops, "drops_per_day": per_day,
        "drops_often": enough and per_day >= FLAKY_DROPS_PER_DAY,
        "longest_offline": round(max((s["end"] - s["start"] for s in offline), default=0)),
        "offline_for": round(now - last_seen) if not online else 0,
        "offline_for_text": ago(now - last_seen) if not online else "",
        "hourly": profile, "usual_hours": usual_hours(profile) if enough else "",
        "private_mac": private_mac,
        "mac_note": "Uses a private (randomised) MAC address, so the same phone may appear under a different MAC on other networks or after a reset." if private_mac else "",
        "destinations": traffic_destinations(traffic_rows),
        "enough_history": enough,
    }
    return out
