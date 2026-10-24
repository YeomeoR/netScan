"""`netscan web --demo`: a simulated network so the dashboard can be tried with no root and no real LAN.

Nothing here touches the wire or your real config/database: it runs against a throwaway data dir.
"""

from __future__ import annotations

import ipaddress
import random
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable

from netscan.config import Config, load_config
from netscan.net import LocalNet
from netscan.parsing import Host
from netscan.safety import record_acceptance
from netscan.store import Store, TrafficRow

NETWORK = "192.168.77.0/24"
HOST = Host("192.168.77.10", "dc:a6:32:00:77:10")
GATEWAY = Host("192.168.77.1", "e8:94:f6:00:77:01")
DEVICES = [
    Host("192.168.77.20", "b8:27:eb:00:77:20"),  # Raspberry Pi
    Host("192.168.77.21", "3c:5a:b4:00:77:21"),  # Google
    Host("192.168.77.22", "44:65:0d:00:77:22"),  # Amazon
    Host("192.168.77.23", "f0:18:98:00:77:23"),  # Apple
    Host("192.168.77.24", "94:a9:90:00:77:24"),  # Espressif
    Host("192.168.77.25", "7e:11:22:33:77:25"),  # randomised MAC
]
LATE_ARRIVAL = Host("192.168.77.99", "00:11:32:00:77:99")  # shows up on the 4th sweep to demo new-device alerts


class DemoTransport:
    def __init__(self, seed: int = 7):
        self.local = LocalNet("demo0", HOST.ip, HOST.mac, ipaddress.ip_network(NETWORK), GATEWAY.ip)
        self.sweeps = 0
        self.sent: list[tuple] = []
        self._rng = random.Random(seed)

    def is_root(self) -> bool:
        return True

    def local_net(self, interface: str = "") -> LocalNet:
        return self.local

    def local_ips(self) -> set[str]:
        return {HOST.ip}

    def arp_sweep(self, network, interface, timeout):
        self.sweeps += 1
        time.sleep(min(timeout, 1.0) * 0.4)
        present = [GATEWAY] + [d for d in DEVICES if self._rng.random() > 0.15]
        if self.sweeps >= 4:
            present.append(LATE_ARRIVAL)
        return present

    def send_arp_reply(self, interface, hwsrc, psrc, hwdst, pdst):
        self.sent.append((hwsrc, psrc, hwdst, pdst))

    def resolve_mac(self, ip, interface):
        return {h.ip: h.mac for h in [GATEWAY, HOST, *DEVICES, LATE_ARRIVAL]}.get(ip)

    def sniff(self, interface, bpf, callback, stop: threading.Event) -> None:
        stop.wait()


NAMES = {
    GATEWAY.ip: "router.lan", HOST.ip: "netscan-pi.lan", "192.168.77.20": "pihole.lan", "192.168.77.21": "nest-mini.lan",
    "192.168.77.22": "echo-dot.lan", "192.168.77.23": "janes-iphone.lan", "192.168.77.24": "esp32-sensor.lan",
}


def demo_resolver(ip: str) -> str:
    return NAMES.get(ip, "")


def seed_traffic(store: Store) -> None:
    now = time.time()
    rows = []
    for i, dev in enumerate(DEVICES[:4]):
        for proto, host, ip, port, nbytes in (
            ("TCP", "api.example-cloud.net", "203.0.113.10", 443, 4_200_000 * (i + 1)),
            ("UDP", "time.example.org", "203.0.113.20", 123, 9_000),
            ("UDP", "", "239.255.255.250", 1900, 31_000),
            ("UDP", "dns.example.net", "203.0.113.53", 53, 120_000),
        ):
            rows.append(TrafficRow(dev.mac, "out", proto, ip, port, host, nbytes, max(1, nbytes // 900), now - 3600, now - 30 * i))
    store.add_traffic(rows)


def demo_setup() -> tuple[Config, DemoTransport, Callable[[str], str]]:
    """A throwaway home dir with an allow-list covering the fake network."""
    from netscan.config import render_config

    home = Path(tempfile.mkdtemp(prefix="netscan-demo-"))
    (home / "config.toml").write_text(render_config([NETWORK], GATEWAY.mac), encoding="utf-8")
    record_acceptance(home / "notice_accepted")
    cfg = load_config(None, home)
    store = Store(cfg.db_path)
    seed_traffic(store)
    store.close()
    return cfg, DemoTransport(), demo_resolver
