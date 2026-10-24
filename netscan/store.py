"""SQLite persistence: devices, block state, traffic metadata counters, event log.

One sqlite file is shared by the CLI and the daemon, so a block made from the CLI
is picked up by the daemon's enforcer on its next cycle.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    vendor TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    online INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS blocks (
    mac TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    method TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    blocked_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS traffic (
    mac TEXT NOT NULL,
    direction TEXT NOT NULL,
    proto TEXT NOT NULL,
    peer_ip TEXT NOT NULL,
    peer_port INTEGER NOT NULL,
    peer_host TEXT NOT NULL DEFAULT '',
    bytes INTEGER NOT NULL DEFAULT 0,
    packets INTEGER NOT NULL DEFAULT 0,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    PRIMARY KEY (mac, direction, proto, peer_ip, peer_port)
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    mac TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    kind TEXT NOT NULL,
    every_seconds INTEGER NOT NULL DEFAULT 0,
    at_time TEXT NOT NULL DEFAULT '',
    run_at REAL,
    params TEXT NOT NULL DEFAULT '{}',
    next_run REAL,
    last_run REAL,
    last_status TEXT NOT NULL DEFAULT '',
    last_message TEXT NOT NULL DEFAULT '',
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'manual',
    params TEXT NOT NULL DEFAULT '{}',
    state TEXT NOT NULL,
    created REAL NOT NULL,
    started REAL,
    finished REAL,
    summary TEXT NOT NULL DEFAULT '{}',
    error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS device_meta (
    mac TEXT PRIMARY KEY,
    label TEXT NOT NULL DEFAULT '',
    owner TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT '',
    trust TEXT NOT NULL DEFAULT 'unknown',
    notes TEXT NOT NULL DEFAULT '',
    track INTEGER NOT NULL DEFAULT 0,
    alert TEXT NOT NULL DEFAULT 'default',
    updated REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS block_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    macs TEXT NOT NULL DEFAULT '[]',
    days TEXT NOT NULL DEFAULT '[]',
    start TEXT NOT NULL DEFAULT '',
    end TEXT NOT NULL DEFAULT '',
    until REAL,
    held TEXT NOT NULL DEFAULT '[]',
    active INTEGER NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT '',
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS port_scans (
    mac TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    ts REAL NOT NULL,
    open TEXT NOT NULL DEFAULT '[]'
);
"""


@dataclass
class Device:
    mac: str
    ip: str
    vendor: str
    hostname: str
    first_seen: float
    last_seen: float
    online: bool


@dataclass
class Block:
    mac: str
    ip: str
    method: str
    reason: str
    blocked_at: float


@dataclass
class Schedule:
    id: int
    name: str
    enabled: bool
    kind: str  # interval | daily | once
    every_seconds: int
    at_time: str
    run_at: float | None
    params: dict
    next_run: float | None
    last_run: float | None
    last_status: str
    last_message: str
    created: float


@dataclass
class JobRow:
    id: int
    kind: str
    source: str
    params: dict
    state: str  # queued | running | done | error | cancelled | interrupted
    created: float
    started: float | None
    finished: float | None
    summary: dict
    error: str


@dataclass
class DeviceMeta:
    mac: str
    label: str = ""
    owner: str = ""
    category: str = ""
    trust: str = "unknown"  # unknown (not reviewed yet) | known | guest
    notes: str = ""
    track: bool = False  # show in "who is home"
    alert: str = "default"  # default | always | mute
    updated: float = 0.0


@dataclass
class BlockRule:
    id: int
    name: str
    kind: str  # window (weekly timetable) | timer (block until a moment)
    enabled: bool
    macs: list
    days: list  # 0=Monday .. 6=Sunday
    start: str
    end: str
    until: float | None
    held: list  # macs this rule blocked itself, and so will release
    active: bool
    note: str
    created: float


@dataclass
class TrafficRow:
    mac: str
    direction: str
    proto: str
    peer_ip: str
    peer_port: int
    peer_host: str
    bytes: int
    packets: int
    first_seen: float
    last_seen: float


class Store:
    def __init__(self, path: Path | str):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False, timeout=10)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            # WAL lets the CLI read while the daemon writes
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _exec(self, sql: str, args: tuple = ()):
        with self._lock:
            cur = self._conn.execute(sql, args)
            self._conn.commit()
            return cur

    def _all(self, sql: str, args: tuple = ()):
        with self._lock:
            return self._conn.execute(sql, args).fetchall()

    # devices
    @staticmethod
    def _device(row: sqlite3.Row) -> Device:
        return Device(row["mac"], row["ip"], row["vendor"], row["hostname"], row["first_seen"], row["last_seen"], bool(row["online"]))

    def get_device(self, mac: str) -> Device | None:
        rows = self._all("SELECT * FROM devices WHERE mac=?", (mac,))
        return self._device(rows[0]) if rows else None

    def find_device(self, ident: str) -> Device | None:
        """Look up by mac or ip (ip prefers the most recently seen holder)."""
        dev = self.get_device(ident.lower())
        if dev:
            return dev
        rows = self._all("SELECT * FROM devices WHERE ip=? ORDER BY last_seen DESC LIMIT 1", (ident,))
        return self._device(rows[0]) if rows else None

    def list_devices(self) -> list[Device]:
        devices = [self._device(r) for r in self._all("SELECT * FROM devices")]
        return sorted(devices, key=lambda d: int(ipaddress.ip_address(d.ip)))

    def count_devices(self) -> int:
        return self._all("SELECT COUNT(*) AS n FROM devices")[0]["n"]

    def upsert_device(self, mac: str, ip: str, vendor: str, hostname: str, now: float) -> Device:
        # sweep and ARP-watch threads (and the CLI) can race on the same mac, so the upsert is one statement
        self._exec(
            """INSERT INTO devices(mac, ip, vendor, hostname, first_seen, last_seen, online) VALUES (?,?,?,?,?,?,1)
               ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip,
                 vendor=CASE WHEN excluded.vendor != '' THEN excluded.vendor ELSE vendor END,
                 hostname=CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE hostname END,
                 last_seen=excluded.last_seen, online=1""",
            (mac, ip, vendor, hostname, now, now),
        )
        return self.get_device(mac)  # type: ignore[return-value]

    def set_offline(self, mac: str) -> None:
        self._exec("UPDATE devices SET online=0 WHERE mac=?", (mac,))

    # blocks
    def add_block(self, mac: str, ip: str, method: str, reason: str, now: float | None = None) -> None:
        self._exec(
            "INSERT OR REPLACE INTO blocks(mac, ip, method, reason, blocked_at) VALUES (?,?,?,?,?)",
            (mac, ip, method, reason, now if now is not None else time.time()),
        )

    def remove_block(self, mac: str) -> bool:
        return self._exec("DELETE FROM blocks WHERE mac=?", (mac,)).rowcount > 0

    def list_blocks(self) -> list[Block]:
        return [Block(r["mac"], r["ip"], r["method"], r["reason"], r["blocked_at"]) for r in self._all("SELECT * FROM blocks ORDER BY blocked_at")]

    def is_blocked(self, mac: str) -> bool:
        return bool(self._all("SELECT 1 FROM blocks WHERE mac=?", (mac,)))

    # traffic
    def add_traffic(self, rows: list[TrafficRow]) -> None:
        with self._lock:
            for r in rows:
                self._conn.execute(
                    """INSERT INTO traffic(mac, direction, proto, peer_ip, peer_port, peer_host, bytes, packets, first_seen, last_seen)
                       VALUES (?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(mac, direction, proto, peer_ip, peer_port) DO UPDATE SET
                         bytes = bytes + excluded.bytes,
                         packets = packets + excluded.packets,
                         peer_host = CASE WHEN excluded.peer_host != '' THEN excluded.peer_host ELSE peer_host END,
                         last_seen = MAX(last_seen, excluded.last_seen),
                         first_seen = MIN(first_seen, excluded.first_seen)""",
                    (r.mac, r.direction, r.proto, r.peer_ip, r.peer_port, r.peer_host, r.bytes, r.packets, r.first_seen, r.last_seen),
                )
            self._conn.commit()

    def traffic_for(self, mac: str) -> list[TrafficRow]:
        rows = self._all("SELECT * FROM traffic WHERE mac=? ORDER BY bytes DESC", (mac,))
        return [TrafficRow(**{k: r[k] for k in r.keys()}) for r in rows]

    def traffic_totals(self) -> dict[str, tuple[int, int]]:
        rows = self._all("SELECT mac, SUM(bytes) AS b, SUM(packets) AS p FROM traffic GROUP BY mac")
        return {r["mac"]: (r["b"], r["p"]) for r in rows}

    # events
    def has_recent_event(self, kind: str, ip: str, message: str, since: float) -> bool:
        return bool(self._all("SELECT 1 FROM events WHERE kind=? AND ip=? AND message=? AND ts>=? LIMIT 1", (kind, ip, message, since)))

    def events_for_mac(self, mac: str, limit: int = 2000) -> list[sqlite3.Row]:
        return self._all("SELECT * FROM events WHERE mac=? ORDER BY id ASC LIMIT ?", (mac, limit))

    def events_of_kinds(self, kinds: tuple[str, ...], limit: int = 100) -> list[sqlite3.Row]:
        marks = ",".join("?" for _ in kinds)
        return self._all(f"SELECT * FROM events WHERE kind IN ({marks}) ORDER BY id DESC LIMIT ?", (*kinds, limit))

    def add_event(self, kind: str, mac: str = "", ip: str = "", message: str = "", now: float | None = None) -> None:
        self._exec(
            "INSERT INTO events(ts, kind, mac, ip, message) VALUES (?,?,?,?,?)",
            (now if now is not None else time.time(), kind, mac, ip, message),
        )

    def recent_events(self, limit: int = 20) -> list[sqlite3.Row]:
        return self._all("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))

    # schedules
    @staticmethod
    def _schedule(r: sqlite3.Row) -> Schedule:
        return Schedule(
            r["id"], r["name"], bool(r["enabled"]), r["kind"], r["every_seconds"], r["at_time"], r["run_at"],
            json.loads(r["params"] or "{}"), r["next_run"], r["last_run"], r["last_status"], r["last_message"], r["created"],
        )

    def add_schedule(self, name: str, kind: str, every_seconds: int, at_time: str, run_at: float | None, params: dict, next_run: float | None, now: float | None = None) -> Schedule:
        cur = self._exec(
            """INSERT INTO schedules(name, enabled, kind, every_seconds, at_time, run_at, params, next_run, created)
               VALUES (?,1,?,?,?,?,?,?,?)""",
            (name, kind, every_seconds, at_time, run_at, json.dumps(params), next_run, now if now is not None else time.time()),
        )
        return self.get_schedule(cur.lastrowid)  # type: ignore[return-value]

    def get_schedule(self, sid: int) -> Schedule | None:
        rows = self._all("SELECT * FROM schedules WHERE id=?", (sid,))
        return self._schedule(rows[0]) if rows else None

    def list_schedules(self) -> list[Schedule]:
        return [self._schedule(r) for r in self._all("SELECT * FROM schedules ORDER BY id")]

    def update_schedule(self, sid: int, **fields) -> Schedule | None:
        allowed = {"name", "enabled", "kind", "every_seconds", "at_time", "run_at", "params", "next_run", "last_run", "last_status", "last_message"}
        bad = set(fields) - allowed
        if bad:
            raise ValueError(f"cannot update {sorted(bad)}")
        if not fields:
            return self.get_schedule(sid)
        if "params" in fields:
            fields["params"] = json.dumps(fields["params"])
        if "enabled" in fields:
            fields["enabled"] = int(bool(fields["enabled"]))
        sets = ", ".join(f"{k}=?" for k in fields)
        self._exec(f"UPDATE schedules SET {sets} WHERE id=?", (*fields.values(), sid))
        return self.get_schedule(sid)

    def delete_schedule(self, sid: int) -> bool:
        return self._exec("DELETE FROM schedules WHERE id=?", (sid,)).rowcount > 0

    def due_schedules(self, now: float) -> list[Schedule]:
        rows = self._all("SELECT * FROM schedules WHERE enabled=1 AND next_run IS NOT NULL AND next_run<=? ORDER BY next_run", (now,))
        return [self._schedule(r) for r in rows]

    # jobs
    @staticmethod
    def _job(r: sqlite3.Row) -> JobRow:
        return JobRow(
            r["id"], r["kind"], r["source"], json.loads(r["params"] or "{}"), r["state"], r["created"],
            r["started"], r["finished"], json.loads(r["summary"] or "{}"), r["error"],
        )

    def add_job(self, kind: str, params: dict, source: str = "manual", now: float | None = None) -> JobRow:
        cur = self._exec(
            "INSERT INTO jobs(kind, source, params, state, created) VALUES (?,?,?,?,?)",
            (kind, source, json.dumps(params), "queued", now if now is not None else time.time()),
        )
        return self.get_job(cur.lastrowid)  # type: ignore[return-value]

    def get_job(self, jid: int) -> JobRow | None:
        rows = self._all("SELECT * FROM jobs WHERE id=?", (jid,))
        return self._job(rows[0]) if rows else None

    def update_job(self, jid: int, **fields) -> JobRow | None:
        allowed = {"state", "started", "finished", "summary", "error"}
        bad = set(fields) - allowed
        if bad:
            raise ValueError(f"cannot update {sorted(bad)}")
        if "summary" in fields:
            fields["summary"] = json.dumps(fields["summary"])
        sets = ", ".join(f"{k}=?" for k in fields)
        self._exec(f"UPDATE jobs SET {sets} WHERE id=?", (*fields.values(), jid))
        return self.get_job(jid)

    def recent_jobs(self, limit: int = 30) -> list[JobRow]:
        return [self._job(r) for r in self._all("SELECT * FROM jobs ORDER BY id DESC LIMIT ?", (limit,))]

    def active_jobs(self, source: str | None = None) -> list[JobRow]:
        sql, args = "SELECT * FROM jobs WHERE state IN ('queued','running')", ()
        if source is not None:
            sql, args = sql + " AND source=?", (source,)
        return [self._job(r) for r in self._all(sql + " ORDER BY id", args)]

    def interrupt_stale_jobs(self, now: float | None = None) -> int:
        """Jobs left queued/running by a crash or restart can never finish; close them out."""
        return self._exec(
            "UPDATE jobs SET state='interrupted', finished=?, error='interrupted by restart' WHERE state IN ('queued','running')",
            (now if now is not None else time.time(),),
        ).rowcount

    def prune_jobs(self, keep: int = 200) -> None:
        self._exec("DELETE FROM jobs WHERE id <= (SELECT COALESCE(MAX(id), 0) FROM jobs) - ?", (keep,))


    # settings (small JSON blobs edited from the dashboard)
    def get_setting(self, key: str, default=None):
        rows = self._all("SELECT value FROM settings WHERE key=?", (key,))
        if not rows:
            return default
        try:
            return json.loads(rows[0]["value"])
        except json.JSONDecodeError:
            return default

    def set_setting(self, key: str, value) -> None:
        self._exec("INSERT INTO settings(key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, json.dumps(value)))

    # device metadata
    @staticmethod
    def _meta(r: sqlite3.Row) -> DeviceMeta:
        return DeviceMeta(r["mac"], r["label"], r["owner"], r["category"], r["trust"], r["notes"], bool(r["track"]), r["alert"], r["updated"])

    def get_meta(self, mac: str) -> DeviceMeta:
        rows = self._all("SELECT * FROM device_meta WHERE mac=?", (mac,))
        return self._meta(rows[0]) if rows else DeviceMeta(mac)

    def list_meta(self) -> dict[str, DeviceMeta]:
        return {r["mac"]: self._meta(r) for r in self._all("SELECT * FROM device_meta")}

    META_FIELDS = ("label", "owner", "category", "trust", "notes", "track", "alert")

    def set_meta(self, mac: str, now: float | None = None, **fields) -> DeviceMeta:
        bad = set(fields) - set(self.META_FIELDS)
        if bad:
            raise ValueError(f"unknown meta fields {sorted(bad)}")
        cur = self.get_meta(mac)
        for k, v in fields.items():
            setattr(cur, k, v)
        self._exec(
            """INSERT INTO device_meta(mac, label, owner, category, trust, notes, track, alert, updated) VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(mac) DO UPDATE SET label=excluded.label, owner=excluded.owner, category=excluded.category,
                 trust=excluded.trust, notes=excluded.notes, track=excluded.track, alert=excluded.alert, updated=excluded.updated""",
            (mac, cur.label, cur.owner, cur.category, cur.trust, cur.notes, int(cur.track), cur.alert, now if now is not None else time.time()),
        )
        return self.get_meta(mac)

    # block rules (timetables and timers)
    @staticmethod
    def _rule(r: sqlite3.Row) -> BlockRule:
        return BlockRule(
            r["id"], r["name"], r["kind"], bool(r["enabled"]), json.loads(r["macs"]), json.loads(r["days"]), r["start"], r["end"],
            r["until"], json.loads(r["held"]), bool(r["active"]), r["note"], r["created"],
        )

    def add_rule(self, name: str, kind: str, macs: list, days: list, start: str, end: str, until: float | None, enabled: bool = True, now: float | None = None) -> BlockRule:
        cur = self._exec(
            "INSERT INTO block_rules(name, kind, enabled, macs, days, start, end, until, created) VALUES (?,?,?,?,?,?,?,?,?)",
            (name, kind, int(enabled), json.dumps(macs), json.dumps(days), start, end, until, now if now is not None else time.time()),
        )
        return self.get_rule(cur.lastrowid)  # type: ignore[return-value]

    def get_rule(self, rid: int) -> BlockRule | None:
        rows = self._all("SELECT * FROM block_rules WHERE id=?", (rid,))
        return self._rule(rows[0]) if rows else None

    def list_rules(self) -> list[BlockRule]:
        return [self._rule(r) for r in self._all("SELECT * FROM block_rules ORDER BY id")]

    RULE_FIELDS = {"name", "kind", "enabled", "macs", "days", "start", "end", "until", "held", "active", "note"}

    def update_rule(self, rid: int, **fields) -> BlockRule | None:
        bad = set(fields) - self.RULE_FIELDS
        if bad:
            raise ValueError(f"unknown rule fields {sorted(bad)}")
        if fields:
            enc = {k: (json.dumps(v) if k in ("macs", "days", "held") else int(v) if k in ("enabled", "active") else v) for k, v in fields.items()}
            self._exec(f"UPDATE block_rules SET {', '.join(f'{k}=?' for k in enc)} WHERE id=?", (*enc.values(), rid))
        return self.get_rule(rid)

    def delete_rule(self, rid: int) -> bool:
        return self._exec("DELETE FROM block_rules WHERE id=?", (rid,)).rowcount > 0

    # open-port scan results (latest per device)
    def get_port_scan(self, mac: str) -> dict | None:
        rows = self._all("SELECT * FROM port_scans WHERE mac=?", (mac,))
        if not rows:
            return None
        return {"mac": mac, "ip": rows[0]["ip"], "ts": rows[0]["ts"], "open": json.loads(rows[0]["open"])}

    def set_port_scan(self, mac: str, ip: str, open_ports: list, now: float | None = None) -> None:
        self._exec(
            "INSERT INTO port_scans(mac, ip, ts, open) VALUES (?,?,?,?) ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip, ts=excluded.ts, open=excluded.open",
            (mac, ip, now if now is not None else time.time(), json.dumps(open_ports)),
        )

    def list_port_scans(self) -> list[dict]:
        return [{"mac": r["mac"], "ip": r["ip"], "ts": r["ts"], "open": json.loads(r["open"])} for r in self._all("SELECT * FROM port_scans")]
