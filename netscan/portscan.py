"""TCP connect scan of common ports on devices in the allow-list. Explicit, user-triggered, never automatic."""

from __future__ import annotations

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable

from netscan.monitor import PORT_OPENED
from netscan.safety import OutOfScopeError, Scope

MAX_TARGETS = 64

# port -> (service, risk, why). risk: high = commonly attacked or sends credentials in clear
COMMON_PORTS: dict[int, tuple[str, str, str]] = {
    21: ("ftp", "high", "cleartext logins"),
    22: ("ssh", "info", "remote shell"),
    23: ("telnet", "high", "cleartext remote shell"),
    25: ("smtp", "warn", "mail relay"),
    53: ("dns", "info", "name server"),
    80: ("http", "info", "web interface"),
    110: ("pop3", "warn", "cleartext mail"),
    135: ("msrpc", "warn", "windows RPC"),
    139: ("netbios", "warn", "windows file sharing"),
    143: ("imap", "warn", "mail"),
    443: ("https", "info", "secure web interface"),
    445: ("smb", "warn", "windows file sharing"),
    515: ("lpd", "warn", "printing"),
    554: ("rtsp", "warn", "camera / video stream"),
    631: ("ipp", "info", "printing"),
    1883: ("mqtt", "warn", "unauthenticated IoT bus"),
    1900: ("upnp", "warn", "UPnP control"),
    3306: ("mysql", "high", "database exposed on the LAN"),
    3389: ("rdp", "high", "remote desktop"),
    5000: ("upnp/http", "info", "web interface"),
    5432: ("postgres", "high", "database exposed on the LAN"),
    5900: ("vnc", "high", "remote desktop"),
    6379: ("redis", "high", "database, usually unauthenticated"),
    8000: ("http-alt", "info", "web interface"),
    8080: ("http-alt", "info", "web interface"),
    8443: ("https-alt", "info", "web interface"),
    8883: ("mqtts", "info", "IoT bus"),
    9100: ("jetdirect", "warn", "raw printing"),
    27017: ("mongodb", "high", "database, often unauthenticated"),
    32400: ("plex", "info", "media server"),
    49152: ("upnp", "warn", "UPnP"),
}

ConnectFn = Callable[[str, int, float], bool]


def tcp_connect(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def port_info(port: int) -> dict:
    service, risk, why = COMMON_PORTS.get(port, ("unknown", "info", ""))
    return {"port": port, "service": service, "risk": risk, "why": why}


def scan_ports(
    targets: Iterable[tuple[str, str]],
    scope: Scope,
    ports: Iterable[int] = tuple(COMMON_PORTS),
    timeout: float = 0.6,
    workers: int = 64,
    connect: ConnectFn = tcp_connect,
    cancel: threading.Event | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> dict[str, list[int]]:
    """targets are (mac, ip). Returns {mac: sorted open ports}. Out-of-scope targets raise before anything is sent."""
    targets = list(targets)
    if len(targets) > MAX_TARGETS:
        raise ValueError(f"at most {MAX_TARGETS} devices per port scan")
    for _mac, ip in targets:
        scope.check_ip(ip)
    ports = sorted(set(ports))
    jobs = [(mac, ip, p) for mac, ip in targets for p in ports]
    found: dict[str, list[int]] = {mac: [] for mac, _ip in targets}
    done = [0]
    lock = threading.Lock()

    def probe(job):
        mac, ip, port = job
        if cancel is not None and cancel.is_set():
            return
        ok = connect(ip, port, timeout)
        with lock:
            done[0] += 1
            if ok:
                found[mac].append(port)
            if progress:
                progress(done[0], len(jobs))

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(jobs) or 1))) as pool:
        list(pool.map(probe, jobs))
    return {mac: sorted(v) for mac, v in found.items()}


def record_scans(rt, targets: list[tuple[str, str]], results: dict[str, list[int]], now: float | None = None) -> list:
    """Persist results and raise port_opened findings for newly opened ports and first-seen risky ones."""
    now = time.time() if now is None else now
    events = []
    for mac, ip in targets:
        open_now = results.get(mac, [])
        prev = rt.store.get_port_scan(mac)
        prev_open = set(prev["open"]) if prev else None
        rt.store.set_port_scan(mac, ip, open_now, now)
        for port in open_now:
            info = port_info(port)
            newly = prev_open is not None and port not in prev_open
            first_risky = prev_open is None and info["risk"] == "high"
            if newly or first_risky:
                what = f"{ip} now has port {port}/{info['service']} open" if newly else f"{ip} has risky port {port}/{info['service']} open ({info['why']})"
                ev = rt.tracker.security_event(PORT_OPENED, what, mac=mac, ip=ip, now=now)
                if ev:
                    events.append(ev)
    return events


__all__ = ["COMMON_PORTS", "MAX_TARGETS", "OutOfScopeError", "port_info", "record_scans", "scan_ports", "tcp_connect"]
