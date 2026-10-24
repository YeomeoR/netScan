"""Device inventory tracking and event generation (new / online / offline / ip change)."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Iterable

from netscan.oui import OuiDb
from netscan.parsing import Host
from netscan.safety import Scope
from netscan.store import Device, Store

NEW_DEVICE = "new_device"
DEVICE_ONLINE = "device_online"
DEVICE_OFFLINE = "device_offline"
IP_CHANGED = "ip_changed"
BLOCKED = "blocked"
UNBLOCKED = "unblocked"
BASELINE = "baseline"


@dataclass
class Event:
    kind: str
    mac: str = ""
    ip: str = ""
    message: str = ""
    vendor: str = ""
    hostname: str = ""

    def describe(self) -> str:
        who = " ".join(x for x in (self.ip, self.mac, f"({self.vendor})" if self.vendor else "", self.hostname) if x)
        return f"{self.message}: {who}" if who else self.message


class DeviceTracker:
    def __init__(
        self,
        store: Store,
        oui: OuiDb,
        scope: Scope,
        resolve_hostname: Callable[[str], str] | None = None,
        silent_baseline: bool = True,
    ):
        self.store = store
        self.oui = oui
        self.scope = scope
        self.resolve_hostname = resolve_hostname or (lambda ip: "")
        self.silent_baseline = silent_baseline
        self._lock = threading.Lock()  # sweep and ARP-watch threads must not both announce the same new device

    def observe(self, hosts: Iterable[Host], now: float | None = None, allow_baseline: bool = False, resolve_names: bool = True) -> list[Event]:
        with self._lock:
            return self._observe(hosts, now, allow_baseline, resolve_names)

    def _observe(self, hosts: Iterable[Host], now: float | None, allow_baseline: bool, resolve_names: bool = True) -> list[Event]:
        now = time.time() if now is None else now
        hosts = [h for h in hosts if self.scope.contains(h.ip)]  # never record anything outside the allow-list
        baseline = allow_baseline and self.silent_baseline and self.store.count_devices() == 0 and bool(hosts)
        names = self._resolve_names(hosts) if resolve_names else {}
        events: list[Event] = []
        for host in hosts:
            events.extend(self._observe_host(host, now, baseline, names.get(host.ip, "")))
        if baseline:
            events.append(Event(BASELINE, message=f"baseline inventory recorded ({len(hosts)} devices); future new devices will alert"))
        for ev in events:
            self.store.add_event(ev.kind, ev.mac, ev.ip, ev.message, now)
        return events

    def observe_one(self, ip: str, mac: str, now: float | None = None) -> list[Event]:
        return self.observe([Host(ip, mac)], now)

    def _needs_name(self, host: Host) -> bool:
        prev = self.store.get_device(host.mac)
        return prev is None or not prev.hostname or prev.ip != host.ip

    def _resolve_names(self, hosts: list[Host]) -> dict[str, str]:
        """Reverse-DNS only devices that are new/moved/nameless, in parallel since lookups can stall."""
        ips = [h.ip for h in hosts if self._needs_name(h)]
        if not ips:
            return {}
        with ThreadPoolExecutor(max_workers=16) as pool:
            return dict(zip(ips, pool.map(self.resolve_hostname, ips)))

    def _observe_host(self, host: Host, now: float, baseline: bool, hostname: str) -> list[Event]:
        prev = self.store.get_device(host.mac)
        vendor = self.oui.lookup(host.mac)
        dev = self.store.upsert_device(host.mac, host.ip, vendor, hostname, now)
        out: list[Event] = []
        if prev is None:
            if not baseline:
                out.append(self._event(NEW_DEVICE, dev, "new device on network"))
            return out
        if not prev.online:
            out.append(self._event(DEVICE_ONLINE, dev, "device back online"))
        if prev.ip != host.ip:
            out.append(self._event(IP_CHANGED, dev, f"ip changed {prev.ip} -> {host.ip}"))
        return out

    @staticmethod
    def _event(kind: str, dev: Device, message: str) -> Event:
        return Event(kind, dev.mac, dev.ip, message, dev.vendor, dev.hostname)

    def mark_offline(self, offline_after: float, now: float | None = None) -> list[Event]:
        now = time.time() if now is None else now
        events = []
        for dev in self.store.list_devices():
            if dev.online and now - dev.last_seen > offline_after:
                self.store.set_offline(dev.mac)
                ev = self._event(DEVICE_OFFLINE, dev, "device went offline")
                self.store.add_event(ev.kind, ev.mac, ev.ip, ev.message, now)
                events.append(ev)
        return events
