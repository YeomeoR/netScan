"""The dashboard's brain: one object that owns the runtime, a serial job queue, background services and the scheduler.

Everything the terminal program can do is reachable from here, through the same core
(`Runtime`, `BlockManager`, `ArpEnforcer`, `TrafficCollector`...), so the safety guards
(allow-list, protected gateway/host, notice) apply identically to the web UI.
"""

from __future__ import annotations

import logging
import queue
import secrets
import threading
import time
from collections import Counter
from typing import Callable

from netscan import __version__
from netscan.blocker import ArpEnforcer, BlockError, BlockManager, make_firewall
from netscan.config import Config, ConfigError, load_config, parse_subnets
from netscan.daemon import Daemon
from netscan.behaviour import summarise
from netscan.discover import guess as dguess
from netscan.discover.engine import identify, stale_devices
from netscan.macutil import is_locally_administered, normalise_mac
from netscan.monitor import BASELINE, DEVICE_OFFLINE, DEVICE_ONLINE, IP_CHANGED, NEW_DEVICE
from netscan.net import ScapyTransport, Transport
from netscan.oui import OuiDb, update_oui
from netscan.profiles import legacy_home, network_db_path, open_store
from netscan.runtime import Runtime, build_runtime, reverse_dns, sweep, write_initial_config
from netscan.safety import NOTICE, SafetyError
from netscan.store import Block, Device, DeviceMeta, JobRow, Schedule, Store
from netscan.traffic import TrafficCollector, run_capture, service_name
from netscan.web.errors import ApiError
from netscan.portscan import port_info, tcp_connect
from netscan.web.features import FeatureMixin, display_name, meta_dict, presence_segments
from netscan.spoof import Spoofer
from netscan.update import Updater
from netscan.web.rules import RuleEngine
from netscan.web.macspoof import SpoofMixin
from netscan.web.networking import NetworkMixin
from netscan.wifi import WifiManager
from netscan.web.selfupdate import UpdateMixin
from netscan.web.schedule import (
    Scheduler, initial_next_run, normalise_sweep_params, timing_changed, validate_schedule,
)

log = logging.getLogger("netscan.web")

CAPTURE_LIMITS = (
    "On a switched network this host only sees its own and broadcast/multicast traffic. "
    "Other devices' traffic is visible only if this machine is in the path (gateway) or a switch mirrors ports. "
    "Metadata only: addresses, ports and sizes, never payloads."
)

SERVICES = {
    "enforce": ("ARP cutoff enforcer", "Keeps ARP cutoff alive for blocked devices and restores their ARP tables when stopped."),
    "watch": ("ARP watch", "Listens for ARP between sweeps and alerts the moment an unknown device appears."),
    "capture": ("Traffic capture", "Continuously records per-device traffic metadata (no payloads)."),
}


class _Service:
    def __init__(self, name: str):
        self.name = name
        self.thread: threading.Thread | None = None
        self.stop = threading.Event()
        self.started: float | None = None
        self.error = ""
        self.enforcer: ArpEnforcer | None = None

    @property
    def running(self) -> bool:
        return bool(self.thread and self.thread.is_alive())


def device_dict(
    d: Device, blocked: dict[str, Block], totals: dict[str, tuple[int, int]], metas: dict[str, DeviceMeta] | None = None,
    infos: dict[str, dict[str, dict]] | None = None,
) -> dict:
    b, p = totals.get(d.mac, (0, 0))
    blk = blocked.get(d.mac)
    meta = (metas or {}).get(d.mac)
    rows = (infos or {}).get(d.mac, {})
    private = is_locally_administered(d.mac)
    ident = dguess.identity(dguess.flat(rows), d.vendor, private) if rows else {"name": "", "name_source": "", "category": "", "os": "", "model": ""}
    return {
        "mac": d.mac, "ip": d.ip, "vendor": d.vendor, "hostname": d.hostname,
        "first_seen": d.first_seen, "last_seen": d.last_seen, "online": d.online,
        "blocked": blk is not None, "block": block_dict(blk) if blk else None,
        "bytes": b, "packets": p,
        **meta_dict(meta), "name": display_name(d, meta, found=ident["name"]),
        "found_name": ident["name"], "found_source": ident["name_source"], "guess_category": ident["category"],
        "guess_os": ident["os"], "guess_model": ident["model"], "private_mac": private,
        "identified": (rows.get("checked") or {}).get("ts"),
    }


def block_dict(b: Block) -> dict:
    return {"mac": b.mac, "ip": b.ip, "method": b.method, "reason": b.reason, "blocked_at": b.blocked_at}


def schedule_dict(s: Schedule) -> dict:
    return {
        "id": s.id, "name": s.name, "enabled": s.enabled, "kind": s.kind, "every_seconds": s.every_seconds,
        "at_time": s.at_time, "run_at": s.run_at, "params": s.params, "next_run": s.next_run if s.enabled else None,
        "last_run": s.last_run, "last_status": s.last_status, "last_message": s.last_message,
    }


def job_dict(j: JobRow) -> dict:
    return {
        "id": j.id, "kind": j.kind, "source": j.source, "params": j.params, "state": j.state, "created": j.created,
        "started": j.started, "finished": j.finished, "summary": j.summary, "error": j.error,
    }


def describe_summary(kind: str, summary: dict) -> str:
    if kind == "sweep":
        bits = [f"{summary.get('seen', 0)} devices seen"]
        for key, label in (("new", "new"), ("online", "back online"), ("offline", "went offline"), ("ip_changed", "IP changed")):
            if summary.get(key):
                bits.append(f"{summary[key]} {label}")
        if summary.get("baseline"):
            bits.append("baseline recorded")
        if "capture" in summary:
            bits.append(f"captured {summary['capture'].get('packets', 0)} packets")
        return ", ".join(bits)
    if kind == "traffic":
        return f"{summary.get('packets', 0)} packets, {summary.get('bytes', 0)} bytes"
    if kind == "update_oui":
        return f"{summary.get('prefixes', 0)} vendor prefixes"
    if kind == "update":
        return f"updated {summary.get('from')} to {summary.get('to')}" + (", restarting" if summary.get("restarting") else ", restart netScan to use it")
    if kind == "spoof":
        return f"{summary.get('interface')} now uses {summary.get('mac')}"
    if kind == "unspoof":
        return f"{summary.get('interface')} is back to {summary.get('mac')}"
    if kind == "dhcp":
        n, bad = summary.get("offers", 0), summary.get("problems", 0)
        return f"{n} DHCP server{'s' if n != 1 else ''} answered" + (f", {bad} problem{'s' if bad != 1 else ''} found" if bad else ", looks normal")
    if kind == "identify":
        return f"{summary.get('devices', 0)} devices asked, {summary.get('named', 0)} with a name"
    if kind == "ports":
        text = f"{summary.get('devices', 0)} devices checked, {summary.get('open', 0)} open ports"
        return text + (f", {summary['findings']} new finding(s)" if summary.get("findings") else "")
    return ""


class Controller(FeatureMixin, UpdateMixin, SpoofMixin, NetworkMixin):
    _device_dict = staticmethod(device_dict)

    def __init__(
        self,
        cfg: Config,
        transport: Transport | None = None,
        *,
        daemon: bool = False,
        resolver: Callable[[str], str] = reverse_dns,
        clock: Callable[[], float] = time.time,
        scheduler_tick: float = 1.0,
        rules_tick: float = 5.0,
        updater: Updater | None = None,
        spoofer: Spoofer | None = None,
        update_tick: float = 300.0,
        prober=None,
        wifi: WifiManager | None = None,
    ):
        self.prober = prober
        self.wifi = wifi or WifiManager()
        self.cfg = cfg
        self.raw = transport or ScapyTransport()
        self.daemon_mode = daemon
        self.resolver = resolver
        self.clock = clock
        self.store = open_store(cfg)
        self._rt: Runtime | None = None
        self._rt_error = ""
        self._rt_tried = 0.0
        self._rt_lock = threading.RLock()
        self._queue: queue.Queue[int | None] = queue.Queue()
        self._cancel: dict[int, threading.Event] = {}
        self._services = {name: _Service(name) for name in SERVICES}
        self._svc_lock = threading.Lock()
        self._worker: threading.Thread | None = None
        self._bootstrap: threading.Thread | None = None
        self._closed = threading.Event()
        self.scheduler = Scheduler(self.store, self._submit_scheduled, clock, scheduler_tick)
        self.rule_engine = RuleEngine(self)
        self._rules_tick = rules_tick
        self._rules_thread: threading.Thread | None = None
        self.updater = updater or Updater()
        self.spoofer = spoofer or Spoofer(self.store)
        self._update_tick = update_tick
        self._update_thread: threading.Thread | None = None
        self.on_restart = None
        self.boot_id = secrets.token_hex(4)

    # lifecycle
    def start(self) -> None:
        self.store.interrupt_stale_jobs(self.clock())
        self._worker = threading.Thread(target=self._worker_loop, name="netscan-jobs", daemon=True)
        self._worker.start()
        if self.daemon_mode:
            self._bootstrap = threading.Thread(target=self._bootstrap_daemon, name="netscan-bootstrap", daemon=True)
            self._bootstrap.start()
        self.scheduler.start()
        self._rules_thread = threading.Thread(target=self._rules_loop, name="netscan-rules", daemon=True)
        self._rules_thread.start()
        self.spoof_startup()
        self._update_thread = threading.Thread(target=self._update_loop, name="netscan-update", daemon=True)
        self._update_thread.start()

    def _update_loop(self) -> None:
        """With automatic updates on, a headless machine (the Pi) follows GitHub without anyone opening the page."""
        while not self._closed.wait(self._update_tick):
            try:
                if self.update_auto():
                    self.update_status(force=True)
            except Exception:  # noqa: BLE001 a failed check must never stop the loop
                log.exception("automatic update check failed")

    def _rules_loop(self) -> None:
        while not self._closed.wait(self._rules_tick):
            try:
                self.rule_engine.tick(self.clock())
                self.spoof_tick()
            except Exception:  # noqa: BLE001 the timetable thread must outlive any single failure
                log.exception("rule engine tick failed")

    def close(self) -> None:
        self._closed.set()
        self.scheduler.stop()
        if self._rules_thread:
            self._rules_thread.join(timeout=10)
        for name in self._services:
            self._stop_service(name)
        for ev in self._cancel.values():
            ev.set()
        self._queue.put(None)
        if self._worker:
            self._worker.join(timeout=15)
        with self._rt_lock:
            if self._rt:
                self._rt.store.close()
                self._rt = None
        self.store.close()

    def _bootstrap_daemon(self) -> None:
        """What the headless daemon does at start-up: baseline sweep first, then the always-on watchers."""
        try:
            rt = self._runtime()
        except ApiError as exc:
            log.error("daemon start-up: %s", exc.message)
            return
        BlockManager(rt.store, rt.scope, self.cfg.block_method, make_firewall(self.cfg.block_method)).reapply()
        if not self.store.list_schedules():
            params = normalise_sweep_params({}, self.cfg.daemon.offline_after)
            now = self.clock()
            self.store.add_schedule(
                "Periodic sweep", "interval", self.cfg.daemon.sweep_interval, "", None, params,
                initial_next_run("interval", self.cfg.daemon.sweep_interval, "", None, now), now,
            )
        job = self._submit("sweep", normalise_sweep_params({}, self.cfg.daemon.offline_after), "startup")
        while not self._closed.is_set():
            row = self.store.get_job(job["id"])
            if row and row.state not in ("queued", "running"):
                break
            time.sleep(0.2)
        if self._closed.is_set():
            return
        wanted = []
        if self.cfg.daemon.arp_watch:
            wanted.append("watch")
        if self.cfg.block_method == "arp":
            wanted.append("enforce")
        if self.cfg.daemon.capture_traffic:
            wanted.append("capture")
        for name in wanted:
            try:
                self.start_service(name)
            except ApiError as exc:
                log.error("could not start %s: %s", name, exc.message)

    # runtime
    def _runtime(self, fresh: bool = False) -> Runtime:
        with self._rt_lock:
            running = any(s.running for s in self._services.values())
            if self._rt is not None and not (fresh and not running):
                return self._rt
            try:
                rt = build_runtime(self.cfg, self.raw, self.resolver)
            except SafetyError as exc:
                self._rt_error = str(exc)
                raise ApiError(403, str(exc)) from exc
            except ConfigError as exc:
                self._rt_error = str(exc)
                raise ApiError(409, str(exc)) from exc
            except Exception as exc:  # noqa: BLE001 no route, no interface, scapy missing...
                self._rt_error = str(exc) or type(exc).__name__
                raise ApiError(409, self._rt_error) from exc
            if rt.network_id and rt.store.network_path is not None:
                self.store.attach_network(rt.network_id, rt.store.network_path, legacy_home(self.cfg))
            # the previous runtime's store is left to the garbage collector: another thread may still hold it
            self._rt, self._rt_error = rt, ""
            return rt

    def refresh_runtime(self) -> dict:
        with self._rt_lock:
            if any(s.running for s in self._services.values()):
                raise ApiError(409, "stop the running services before re-detecting the network")
            self._rt = None
        self._runtime()
        return self.status()

    def networks_summary(self) -> list[dict]:
        """Every network this machine has kept a device list for, newest first."""
        current = self._rt.network_id if self._rt else ""
        out = []
        for row in self.store.list_networks():
            try:
                path = network_db_path(self.cfg, row["id"])
            except ValueError:
                continue
            count = self.store.count_devices() if row["id"] == current else Store.count_devices_in(path)
            out.append({
                "id": row["id"], "label": row["label"] or (f"Network {row['subnet']}" if row["subnet"] else row["id"]),
                "subnet": row["subnet"], "devices": count, "last_seen": row["last_seen"], "current": row["id"] == current,
            })
        return out

    # status / reads
    def status(self) -> dict:
        rt = self._rt
        err = self._rt_error
        if rt is None and (not err or self.clock() - self._rt_tried > 15):
            self._rt_tried = self.clock()
            try:
                rt = self._runtime()
                err = ""
            except ApiError as exc:
                err = exc.message
        network = None
        try:
            local = rt.local if rt else self.raw.local_net(self.cfg.interface)
            network = {
                "interface": local.interface, "ip": local.ip, "mac": local.mac, "network": str(local.network),
                "gateway": local.gateway_ip, "in_scope": rt is not None, "id": rt.network_id if rt else "",
            }
        except Exception:  # noqa: BLE001 offline / no route: the UI shows the runtime error instead
            pass
        devices = self.store.list_devices()
        blocks = self.store.list_blocks()
        metas = self.store.list_meta()
        can_raw = rt.transport.can_raw() if rt else bool(getattr(self.raw, "is_root", lambda: True)())
        now = self.clock()
        return {
            "version": __version__,
            "boot_id": self.boot_id,
            "spoof": self.spoof_status(),
            "wifi": self.wifi_status(),
            "now": now,
            "tz": time.strftime("%Z", time.localtime(now)),
            "utc_offset": -(time.altzone if time.localtime(now).tm_isdst > 0 else time.timezone),
            "daemon": self.daemon_mode,
            "ready": rt is not None,
            "error": err,
            "configured": self.cfg.config_path.exists(),
            "config_path": str(self.cfg.config_path),
            "network": network,
            "allowed_subnets": [str(n) for n in self.cfg.allowed_subnets],
            "gateway_pinned": bool(self.cfg.gateway_mac),
            "follow_network": self.cfg.follow_network,
            "networks": self.networks_summary(),
            "privileged": can_raw,
            "block_method": self.cfg.block_method,
            "counts": {
                "devices": len(devices), "online": sum(1 for d in devices if d.online),
                "offline": sum(1 for d in devices if not d.online), "blocked": len(blocks),
                "unreviewed": sum(1 for d in devices if metas.get(d.mac, DeviceMeta(d.mac)).trust == "unknown"),
                "rules_active": sum(1 for r in self.store.list_rules() if r.active),
            },
            "services": self.services_status(),
            "active_jobs": [job_dict(j) for j in self.store.active_jobs()],
            "notice": NOTICE,
            "capture_limits": CAPTURE_LIMITS,
        }

    def devices(self) -> list[dict]:
        blocked = {b.mac: b for b in self.store.list_blocks()}
        totals = self.store.traffic_totals()
        metas = self.store.list_meta()
        infos = self.store.all_info()
        return [device_dict(d, blocked, totals, metas, infos) for d in self.store.list_devices()]

    def device_detail(self, ident: str) -> dict:
        dev = self.store.find_device(normalise_mac(ident) or ident)
        if dev is None:
            raise ApiError(404, f"unknown device {ident!r}; run a scan first")
        blocked = {b.mac: b for b in self.store.list_blocks()}
        totals = self.store.traffic_totals()
        traffic = [
            {
                "direction": r.direction, "proto": r.proto, "service": service_name(r.proto, r.peer_port),
                "peer_ip": r.peer_ip, "peer_host": r.peer_host, "peer_port": r.peer_port,
                "bytes": r.bytes, "packets": r.packets, "first_seen": r.first_seen, "last_seen": r.last_seen,
            }
            for r in self.store.traffic_for(dev.mac)[:200]
        ]
        events = [dict(r) for r in self.store.recent_events(500) if r["mac"] == dev.mac][:30]
        scan = self.store.get_port_scan(dev.mac)
        ports = {"ts": scan["ts"], "open": [port_info(p) for p in scan["open"]]} if scan else None
        now = self.clock()
        segs = presence_segments(
            [(r["ts"], r["kind"]) for r in self.store.events_for_mac(dev.mac)], dev.first_seen, now - 7 * 86400, now, self.cfg.daemon.offline_after,
        )
        rule = self.rule_holding(dev.mac)
        return {
            "device": device_dict(dev, blocked, totals, self.store.list_meta(), self.store.all_info()), "traffic": traffic, "events": events,
            "ports": ports, "presence": {"since": now - 7 * 86400, "until": now, "segments": segs},
            "held_by_rule": {"id": rule.id, "name": rule.name} if rule else None,
            "identity": self._identity(dev), "behaviour": self._behaviour(dev, now),
        }

    def _identity(self, dev: Device) -> dict:
        rows = self.store.get_info(dev.mac)
        found = dguess.identity(dguess.flat(rows), dev.vendor, is_locally_administered(dev.mac))
        sources = {k: v for k, v in rows.items() if k != "checked"}
        return {**found, "sources": sources, "checked": (rows.get("checked") or {}).get("ts"), "can_identify": self.prober is not None}

    def _behaviour(self, dev: Device, now: float) -> dict:
        since = now - 14 * 86400
        segs = presence_segments(
            [(r["ts"], r["kind"]) for r in self.store.events_for_mac(dev.mac)], dev.first_seen, since, now, self.cfg.daemon.offline_after,
        )
        return summarise(
            online=dev.online, last_seen=dev.last_seen, first_seen=dev.first_seen, segments=segs, since=since, now=now,
            private_mac=is_locally_administered(dev.mac), traffic_rows=self.store.traffic_for(dev.mac),
        )

    # device identification
    def identify_settings(self) -> dict:
        saved = self.store.get_setting("identify", {}) or {}
        return {"auto": bool(saved.get("auto", True)), "available": self.prober is not None}

    def set_identify_settings(self, body: dict) -> dict:
        if not isinstance(body, dict) or not isinstance(body.get("auto"), bool):
            raise ApiError(400, "auto must be true or false")
        self.store.set_setting("identify", {"auto": body["auto"]})
        return self.identify_settings()

    def submit_identify(self, body: dict) -> dict:
        if self.prober is None:
            raise ApiError(409, "device identification is not available in this session")
        if not isinstance(body, dict):
            raise ApiError(400, "body must be an object")
        raw = body.get("macs")
        if raw is None:
            macs = [d.mac for d in self.store.list_devices() if d.online]
        elif isinstance(raw, list) and raw and all(isinstance(m, str) for m in raw) and len(raw) <= 256:
            macs = [self._require_device(m).mac for m in raw]
        else:
            raise ApiError(400, "macs must be a list of device MAC addresses")
        if not macs:
            raise ApiError(400, "no online devices to identify; run a scan first or pick devices")
        deep = body.get("deep", True)
        if not isinstance(deep, bool):
            raise ApiError(400, "deep must be true or false")
        return self._submit("identify", {"macs": list(dict.fromkeys(macs)), "deep": deep})

    def _auto_identify(self) -> None:
        """After a sweep, quietly ask devices nobody has asked in the last few hours what they are."""
        if self.prober is None or not self.identify_settings()["auto"] or self._closed.is_set():
            return
        if any(j.kind == "identify" for j in self.store.active_jobs()):
            return
        due = stale_devices(self.store, self.store.list_devices(), self.clock())
        if due:
            self._submit("identify", {"macs": [d.mac for d in due], "deep": False}, "auto")

    def _do_identify(self, params: dict, cancel: threading.Event) -> dict:
        if self.prober is None:
            raise ApiError(409, "device identification is not available in this session")
        rt = self._runtime()
        devices = [d for d in (self.store.get_device(m) for m in params.get("macs", [])) if d]
        deep = bool(params.get("deep"))
        return identify(
            self.prober, self.store, rt.scope, devices, local_ip=rt.local.ip, now=self.clock(), deep=deep,
            connect=getattr(self.raw, "port_connect", tcp_connect) if deep else None, cancel=cancel,
        )

    def blocks(self) -> list[dict]:
        return [block_dict(b) for b in self.store.list_blocks()]

    def events(self, limit: int = 50) -> list[dict]:
        return [dict(r) for r in self.store.recent_events(max(1, min(limit, 500)))]

    def config_view(self) -> dict:
        cfg = self.cfg

        from netscan.alerts import effective_alert_config

        eff = effective_alert_config(cfg.alerts, self.store)

        return {
            "path": str(cfg.config_path), "home": str(cfg.home), "db_path": str(cfg.db_path),
            "allowed_subnets": [str(n) for n in cfg.allowed_subnets], "follow_network": cfg.follow_network, "interface": cfg.interface or "auto",
            "gateway": cfg.gateway or "auto", "gateway_mac": cfg.gateway_mac, "extra_protected": cfg.extra_protected,
            "block_method": cfg.block_method,
            "alerts": {
                "webhook": "configured" if eff.webhook_url else "", "ntfy": "configured" if eff.ntfy_url else "", "notify_on": list(eff.notify_on),
            },
            "daemon": {
                "sweep_interval": cfg.daemon.sweep_interval, "offline_after": cfg.daemon.offline_after,
                "arp_watch": cfg.daemon.arp_watch, "capture_traffic": cfg.daemon.capture_traffic,
                "silent_baseline": cfg.daemon.silent_baseline,
            },
        }

    def init_config(self, body: dict) -> dict:
        """Dashboard equivalent of `netscan init`."""
        subnets = body.get("subnets") or None
        if subnets is not None and (not isinstance(subnets, list) or not all(isinstance(x, str) for x in subnets)):
            raise ApiError(400, "subnets must be a list of CIDR strings")
        force = body.get("force", False)
        if not isinstance(force, bool):
            raise ApiError(400, "force must be true or false")
        follow = body.get("follow_network", False)
        if not isinstance(follow, bool):
            raise ApiError(400, "follow_network must be true or false")
        if any(s.running for s in self._services.values()):
            raise ApiError(409, "stop the running services before changing the config")
        try:
            if subnets:
                parse_subnets(subnets)
            chosen, gw_mac, local = write_initial_config(self.cfg, self.raw, subnets, force, follow)
        except ConfigError as exc:
            raise ApiError(409 if "already exists" in str(exc) else 400, str(exc)) from exc
        except Exception as exc:  # noqa: BLE001
            raise ApiError(409, str(exc) or type(exc).__name__) from exc
        with self._rt_lock:
            self.cfg = load_config(self.cfg.config_path, self.cfg.home)
            self._rt = None
            self._rt_error = ""
        return {"subnets": chosen, "gateway_mac": gw_mac, "network": str(local.network)}

    # jobs
    def _submit(self, kind: str, params: dict, source: str = "manual") -> dict:
        if self._closed.is_set():
            raise ApiError(503, "shutting down")
        job = self.store.add_job(kind, params, source, self.clock())
        self._cancel[job.id] = threading.Event()
        self._queue.put(job.id)
        return job_dict(job)

    def _submit_scheduled(self, params: dict, source: str) -> int:
        return self._submit("sweep", params, source)["id"]

    def submit_scan(self, body: dict) -> dict:
        try:
            params = normalise_sweep_params(body, 0)
        except ValueError as exc:
            raise ApiError(400, str(exc)) from exc
        return self._submit("sweep", params)

    def submit_traffic(self, body: dict) -> dict:
        try:
            raw = body if isinstance(body, dict) else {}
            duration = normalise_sweep_params({"capture_seconds": raw.get("duration", 30), "flush": raw.get("flush", 5.0)})
        except ValueError as exc:
            raise ApiError(400, str(exc).replace("capture_seconds", "duration")) from exc
        if duration["capture_seconds"] < 1:
            raise ApiError(400, "duration must be between 1 and 3600")
        return self._submit("traffic", {"duration": duration["capture_seconds"], "flush": duration["flush"]})

    def submit_update_oui(self) -> dict:
        return self._submit("update_oui", {})

    def jobs(self, limit: int = 30) -> list[dict]:
        return [job_dict(j) for j in self.store.recent_jobs(max(1, min(limit, 200)))]

    def cancel_job(self, jid: int) -> dict:
        job = self.store.get_job(jid)
        if job is None:
            raise ApiError(404, f"no such job {jid}")
        if job.state == "queued":
            self.store.update_job(jid, state="cancelled", finished=self.clock())
            self._cancel.pop(jid, None)
            self._finish(self.store.get_job(jid))  # type: ignore[arg-type]
        elif job.state == "running":
            ev = self._cancel.get(jid)
            if ev:
                ev.set()
        else:
            raise ApiError(409, f"job {jid} already {job.state}")
        return job_dict(self.store.get_job(jid))  # type: ignore[arg-type]

    def _worker_loop(self) -> None:
        while True:
            jid = self._queue.get()
            if jid is None:
                return
            try:
                self._run_job(jid)
            except Exception:  # noqa: BLE001 the worker must outlive any single job
                log.exception("job %s crashed", jid)

    def _run_job(self, jid: int) -> None:
        job = self.store.get_job(jid)
        if job is None or job.state != "queued":
            return
        cancel = self._cancel.setdefault(jid, threading.Event())
        self.store.update_job(jid, state="running", started=self.clock())
        try:
            if job.kind == "sweep":
                summary = self._do_sweep(job.params, cancel)
            elif job.kind == "traffic":
                summary = self._do_traffic(job.params, cancel)
            elif job.kind == "update_oui":
                summary = self._do_update_oui()
            elif job.kind == "update":
                summary = self._do_update()
            elif job.kind == "spoof":
                summary = self._do_spoof(job.params)
            elif job.kind == "unspoof":
                summary = self._do_unspoof()
            elif job.kind == "dhcp":
                summary = self._do_dhcp()
            elif job.kind == "ports":
                summary = self._do_ports(job.params, cancel)
            elif job.kind == "identify":
                summary = self._do_identify(job.params, cancel)
            else:
                raise ApiError(400, f"unknown job kind {job.kind!r}")
            state = "cancelled" if cancel.is_set() else "done"
            self.store.update_job(jid, state=state, finished=self.clock(), summary=summary)
        except ApiError as exc:
            self.store.update_job(jid, state="error", finished=self.clock(), error=exc.message)
        except Exception as exc:  # noqa: BLE001
            log.exception("job %s failed", jid)
            self.store.update_job(jid, state="error", finished=self.clock(), error=str(exc) or type(exc).__name__)
        finally:
            self._cancel.pop(jid, None)
            row = self.store.get_job(jid)
            if row:
                self._finish(row)
            self.store.prune_jobs()

    def _finish(self, job: JobRow) -> None:
        if job.source.startswith("schedule:"):
            try:
                sid = int(job.source.split(":", 1)[1])
            except ValueError:
                return
            if self.store.get_schedule(sid):
                message = job.error if job.state in ("error", "interrupted") else describe_summary(job.kind, job.summary)
                self.store.update_schedule(sid, last_status=job.state, last_message=message)

    def _do_sweep(self, params: dict, cancel: threading.Event) -> dict:
        rt = self._runtime(fresh=True)
        t0 = self.clock()
        hosts, events = sweep(rt, params["timeout"], now=t0, resolve_names=params["hostnames"])
        events += rt.tracker.mark_offline(params["offline_after"], now=t0)
        rt.alerter.dispatch(events)
        kinds = Counter(e.kind for e in events)
        summary: dict = {
            "mode": "arp" if rt.transport.can_raw() else "nudge",
            "seen": len(hosts), "new": kinds[NEW_DEVICE], "online": kinds[DEVICE_ONLINE],
            "offline": kinds[DEVICE_OFFLINE], "ip_changed": kinds[IP_CHANGED], "baseline": bool(kinds[BASELINE]),
            "duration": round(self.clock() - t0, 1),
        }
        if params.get("capture_seconds") and not cancel.is_set():
            summary["capture"] = self._capture(rt, params["capture_seconds"], params.get("flush", 5.0), cancel)
        if not cancel.is_set():
            self._auto_identify()
        return summary

    def _do_traffic(self, params: dict, cancel: threading.Event) -> dict:
        return self._capture(self._runtime(), params["duration"], params.get("flush", 5.0), cancel)

    def _capture(self, rt: Runtime, seconds: int, flush: float, cancel: threading.Event) -> dict:
        if self._services["capture"].running:
            raise ApiError(409, "continuous capture is already running; its counters update live")
        if not rt.transport.can_raw():
            raise ApiError(409, "packet capture needs root (sudo) or CAP_NET_RAW")
        before = self.store.traffic_totals()
        collector = TrafficCollector(rt.store, resolver=self.resolver)
        stop = threading.Event()

        def timeout_or_cancel() -> None:
            cancel.wait(seconds)
            stop.set()

        threading.Thread(target=timeout_or_cancel, daemon=True, name="netscan-capture-timer").start()
        run_capture(rt.transport, rt.local.interface, collector, stop, flush)
        after = self.store.traffic_totals()
        gained = {m: (a[0] - before.get(m, (0, 0))[0], a[1] - before.get(m, (0, 0))[1]) for m, a in after.items()}
        return {
            "seconds": seconds,
            "bytes": sum(b for b, _ in gained.values()),
            "packets": sum(p for _, p in gained.values()),
            "devices": sum(1 for _, p in gained.values() if p),
        }

    def _do_update_oui(self) -> dict:
        n = update_oui(self.cfg.oui_path)
        with self._rt_lock:
            if self._rt:
                self._rt.oui.table = OuiDb.load(self.cfg.oui_path).table
        return {"prefixes": n}

    # blocking
    def _manager(self, rt: Runtime) -> BlockManager:
        return BlockManager(rt.store, rt.scope, self.cfg.block_method, make_firewall(self.cfg.block_method))

    def block(self, body: dict) -> dict:
        target, reason = body.get("target"), body.get("reason", "")
        if not isinstance(target, str) or not target.strip():
            raise ApiError(400, "target (ip or mac) is required")
        if not isinstance(reason, str) or len(reason) > 200:
            raise ApiError(400, "reason must be text up to 200 characters")
        rt = self._runtime()
        try:
            blk, ev = self._manager(rt).block(target.strip(), reason.strip())
        except BlockError as exc:
            raise ApiError(404, str(exc)) from exc
        except SafetyError as exc:
            raise ApiError(403, str(exc)) from exc
        except Exception as exc:  # noqa: BLE001 e.g. iptables/nft missing
            raise ApiError(500, f"could not apply block: {exc}") from exc
        rt.alerter.dispatch([ev])
        out = block_dict(blk)
        out["enforcer_running"] = self._services["enforce"].running
        out["note"] = (
            "ARP cutoff only holds while the enforcer runs; start it under Services."
            if blk.method == "arp" and not out["enforcer_running"] else ""
        )
        return out

    def unblock(self, body: dict) -> dict:
        target = body.get("target")
        if not isinstance(target, str) or not target.strip():
            raise ApiError(400, "target (ip or mac) is required")
        rt = self._runtime()
        mac = normalise_mac(target.strip())
        blk = next((b for b in self.store.list_blocks() if b.mac == mac or b.ip == target.strip()), None)
        rule = self.rule_holding(blk.mac) if blk else None
        if rule:
            raise ApiError(409, f"{blk.ip} is blocked by the rule \"{rule.name}\"; pause or delete that rule to release it")
        ev = self._unblock_mac(rt, target.strip())
        if ev is None:
            raise ApiError(404, f"{target} is not blocked")
        rt.alerter.dispatch([ev])
        return {"mac": ev.mac, "ip": ev.ip}

    def _unblock_mac(self, rt: Runtime, ident: str):
        enforcer = ArpEnforcer(rt.store, rt.scope, rt.transport, rt.local.interface, rt.scope.gateway_ip)
        return self._manager(rt).unblock(ident, restore=enforcer.restore_block if self.cfg.block_method == "arp" else None)

    # services
    def services_status(self) -> dict:
        out = {}
        for name, (label, desc) in SERVICES.items():
            svc = self._services[name]
            available, why = True, ""
            if name == "enforce" and self.cfg.block_method != "arp":
                available, why = False, f"block method is {self.cfg.block_method}; rules are applied directly, no enforcer needed"
            out[name] = {
                "label": label, "description": desc, "running": svc.running, "since": svc.started if svc.running else None,
                "error": svc.error, "available": available, "unavailable_reason": why,
            }
        return out

    def start_service(self, name: str) -> dict:
        if name not in SERVICES:
            raise ApiError(404, f"unknown service {name!r}")
        rt = self._runtime()
        with self._svc_lock:
            svc = self._services[name]
            if svc.running:
                raise ApiError(409, f"{SERVICES[name][0]} is already running")
            if name == "enforce" and self.cfg.block_method != "arp":
                raise ApiError(409, f"block method is {self.cfg.block_method}; no enforcer is needed")
            if not rt.transport.can_raw():
                raise ApiError(409, f"{SERVICES[name][0]} needs root (sudo) or CAP_NET_RAW; restart netscan with sufficient privileges")
            if name == "capture" and any(j.kind == "traffic" or j.params.get("capture_seconds") for j in self.store.active_jobs() if j.state == "running"):
                raise ApiError(409, "a timed capture is running; wait for it or cancel it first")
            svc.stop = threading.Event()
            svc.error = ""
            svc.started = self.clock()
            target = {"enforce": self._run_enforce, "watch": self._run_watch, "capture": self._run_capture}[name]
            svc.thread = threading.Thread(target=self._guard(svc, target), args=(svc, rt), name=f"netscan-{name}", daemon=True)
            svc.thread.start()
        return self.services_status()[name]

    def stop_service(self, name: str) -> dict:
        if name not in SERVICES:
            raise ApiError(404, f"unknown service {name!r}")
        self._stop_service(name)
        return self.services_status()[name]

    def _stop_service(self, name: str) -> None:
        svc = self._services[name]
        svc.stop.set()
        if svc.thread and svc.thread.is_alive():
            svc.thread.join(timeout=15)

    @staticmethod
    def _guard(svc: _Service, fn):
        def run(*args):
            try:
                fn(*args)
            except Exception as exc:  # noqa: BLE001 surfaced in the UI instead of dying silently
                log.exception("service %s crashed", svc.name)
                svc.error = str(exc) or type(exc).__name__

        return run

    @staticmethod
    def _run_enforce(svc: _Service, rt: Runtime) -> None:
        svc.enforcer = ArpEnforcer(rt.store, rt.scope, rt.transport, rt.local.interface, rt.scope.gateway_ip)
        svc.enforcer.run(svc.stop, 2.0)

    @staticmethod
    def _run_watch(svc: _Service, rt: Runtime) -> None:
        daemon = Daemon(rt, svc.stop)
        rt.transport.sniff(rt.local.interface, Daemon.WATCH_FILTER, daemon.handle_packet, svc.stop)

    def _run_capture(self, svc: _Service, rt: Runtime) -> None:
        collector = TrafficCollector(rt.store, resolver=self.resolver)
        run_capture(rt.transport, rt.local.interface, collector, svc.stop, 5.0)

    # schedules
    def schedules(self) -> list[dict]:
        return [schedule_dict(s) for s in self.store.list_schedules()]

    def create_schedule(self, body: dict) -> dict:
        now = self.clock()
        try:
            v = validate_schedule(body, now, self.cfg.daemon.offline_after)
        except ValueError as exc:
            raise ApiError(400, str(exc)) from exc
        next_run = initial_next_run(v["kind"], v["every_seconds"], v["at_time"], v["run_at"], now) if v["enabled"] else None
        s = self.store.add_schedule(v["name"], v["kind"], v["every_seconds"], v["at_time"], v["run_at"], v["params"], next_run, now)
        if not v["enabled"]:
            s = self.store.update_schedule(s.id, enabled=False)  # type: ignore[assignment]
        if body.get("run_now") is True:
            self._submit("sweep", s.params, f"schedule:{s.id}")
            s = self.store.update_schedule(s.id, last_run=now, last_status="queued")  # type: ignore[assignment]
        return schedule_dict(s)

    def update_schedule(self, sid: int, body: dict) -> dict:
        existing = self.store.get_schedule(sid)
        if existing is None:
            raise ApiError(404, f"no such schedule {sid}")
        now = self.clock()
        try:
            v = validate_schedule(body, now, self.cfg.daemon.offline_after, existing)
        except ValueError as exc:
            raise ApiError(400, str(exc)) from exc
        fields = dict(v)
        if timing_changed(existing, v):
            fields["next_run"] = initial_next_run(v["kind"], v["every_seconds"], v["at_time"], v["run_at"], now) if v["enabled"] else None
        elif not v["enabled"]:
            fields["next_run"] = None
        return schedule_dict(self.store.update_schedule(sid, **fields))  # type: ignore[arg-type]

    def delete_schedule(self, sid: int) -> dict:
        if not self.store.delete_schedule(sid):
            raise ApiError(404, f"no such schedule {sid}")
        return {"deleted": sid}

    def run_schedule_now(self, sid: int) -> dict:
        s = self.store.get_schedule(sid)
        if s is None:
            raise ApiError(404, f"no such schedule {sid}")
        if self.store.active_jobs(f"schedule:{sid}"):
            raise ApiError(409, "this schedule is already running")
        job = self._submit("sweep", s.params, f"schedule:{sid}")
        self.store.update_schedule(sid, last_run=self.clock(), last_status="queued", last_message="")
        return job
