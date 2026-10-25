"""Run the probes against devices and keep what comes back.

Every unicast target is checked against the allow-list first. Multicast queries stay on the local link.
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from netscan.discover.guess import best_name, flat
from netscan.discover.probes import GREETING_PORTS, HTTP_PORTS, TLS_PORTS
from netscan.safety import SafetyError, Scope
from netscan.store import Device, Store

log = logging.getLogger("netscan.discover")

BANNER_PORTS = sorted(set(GREETING_PORTS) | HTTP_PORTS | TLS_PORTS)
STALE_AFTER = 6 * 3600
MAX_TARGETS = 256


def stale_devices(store: Store, devices: list[Device], now: float, max_age: float = STALE_AFTER) -> list[Device]:
    """Online devices nobody has asked recently."""
    info = store.all_info()
    return [d for d in devices if d.online and now - info.get(d.mac, {}).get("checked", {}).get("ts", 0) > max_age]


def identify(
    prober,
    store: Store,
    scope: Scope,
    devices: list[Device],
    *,
    local_ip: str = "",
    now: float,
    deep: bool = False,
    connect: Callable[[str, int, float], bool] | None = None,
    cancel: threading.Event | None = None,
) -> dict:
    """Probe `devices`, store the answers and return a summary.

    With `deep` the banner step first checks which web/SSH ports are open; otherwise it only visits ports a
    previous port scan found open, so a background run never port-scans anything.
    """
    targets: list[Device] = []
    skipped = 0
    for d in devices[:MAX_TARGETS]:
        try:
            scope.check_ip(d.ip)
        except SafetyError:
            skipped += 1
            continue
        targets.append(d)
    by_ip = {d.ip: d for d in targets}
    ips = list(by_ip)
    counts = {"mdns": 0, "ssdp": 0, "netbios": 0, "ttl": 0, "banners": 0}
    if not ips:
        return {"devices": 0, "named": 0, "skipped": skipped, "found": counts}

    def keep(source: str, results: dict[str, dict]) -> None:
        for ip, data in results.items():
            dev = by_ip.get(ip)
            if dev and data:
                store.set_info(dev.mac, source, data, now)
                counts[source] += 1

    def stopped() -> bool:
        return bool(cancel and cancel.is_set())

    steps = (
        ("mdns", lambda: prober.mdns(ips, local_ip=local_ip, cancel=cancel)),
        ("ssdp", lambda: prober.ssdp(ips, local_ip=local_ip, cancel=cancel)),
        ("netbios", lambda: prober.netbios(ips, cancel=cancel)),
        ("ttl", lambda: prober.ttl(ips, cancel=cancel)),
    )
    for source, run in steps:
        if stopped():
            break
        try:
            keep(source, run())
        except Exception:  # noqa: BLE001 one broken probe must not lose the others
            log.exception("%s probe failed", source)

    if not stopped():
        ports: dict[str, list[int]] = {}
        if deep and connect:
            pairs = [(d.ip, p) for d in targets for p in BANNER_PORTS]
            with ThreadPoolExecutor(max_workers=64) as pool:
                for (ip, port), is_open in zip(pairs, pool.map(lambda pair: not stopped() and connect(pair[0], pair[1], 0.6), pairs)):
                    if is_open:
                        ports.setdefault(ip, []).append(port)
        else:
            for d in targets:
                scan = store.get_port_scan(d.mac)
                found = [p for p in (scan["open"] if scan else []) if p in BANNER_PORTS]
                if found:
                    ports[d.ip] = found
        if ports:
            try:
                keep("banners", prober.banners(ports, cancel=cancel))
            except Exception:  # noqa: BLE001
                log.exception("banner grab failed")

    if not stopped():
        for d in targets:
            store.set_info(d.mac, "checked", {}, now)
    info = store.all_info()
    named = sum(1 for d in targets if best_name(flat(info.get(d.mac, {})))[0])
    return {"devices": len(targets), "named": named, "skipped": skipped, "found": counts}
