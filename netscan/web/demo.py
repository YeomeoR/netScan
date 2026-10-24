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
from netscan.net import DhcpOffer, LocalNet
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
IMPOSTOR = Host(DEVICES[1].ip, "de:ad:77:00:77:aa")  # answers for a taken address on the 6th sweep to demo ip_conflict
ROGUE_DHCP_SERVER = Host("192.168.77.66", "02:aa:bb:cc:77:66")
DEMO_OPEN_PORTS = {
    GATEWAY.ip: [53, 80, 443, 1900],
    "192.168.77.20": [22, 53, 80, 443],
    "192.168.77.21": [8008, 8443],
    "192.168.77.22": [554, 8080],
    "192.168.77.24": [23, 80],
    "192.168.77.99": [21, 80, 3389],
}
LATE_ARRIVAL = Host("192.168.77.99", "00:11:32:00:77:99")  # shows up on the 4th sweep to demo new-device alerts


class DemoTransport:
    def __init__(self, seed: int = 7):
        self.local = LocalNet("demo0", HOST.ip, HOST.mac, ipaddress.ip_network(NETWORK), GATEWAY.ip)
        self.sweeps = 0
        self.dhcp_probes = 0
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
        if self.sweeps == 6:
            present.append(IMPOSTOR)
        return present

    def dhcp_discover(self, interface, timeout):
        self.dhcp_probes += 1
        time.sleep(0.5)
        offers = [DhcpOffer(GATEWAY.ip, GATEWAY.mac, "192.168.77.150", GATEWAY.ip, (GATEWAY.ip,), 86400)]
        if self.dhcp_probes >= 2:  # the first probe looks healthy; later ones show a second server that plugged in
            offers.append(DhcpOffer(ROGUE_DHCP_SERVER.ip, ROGUE_DHCP_SERVER.mac, "192.168.77.151", ROGUE_DHCP_SERVER.ip, ("203.0.113.53",), 600))
        return offers

    def port_connect(self, ip: str, port: int, timeout: float) -> bool:
        return port in DEMO_OPEN_PORTS.get(ip, [])

    def send_arp_reply(self, interface, hwsrc, psrc, hwdst, pdst):
        self.sent.append((hwsrc, psrc, hwdst, pdst))

    def resolve_mac(self, ip, interface):
        return {h.ip: h.mac for h in [GATEWAY, HOST, *DEVICES, LATE_ARRIVAL]}.get(ip)

    def sniff(self, interface, bpf, callback, stop: threading.Event) -> None:
        stop.wait()


class DemoProber:
    """Plausible answers for the simulated devices, so the identification screens have something to show."""

    MDNS = {
        "192.168.77.21": {"hostname": "Nest-Mini-4f2a", "friendly": "Kitchen speaker", "services": ["_googlecast", "_spotify-connect"], "instances": [], "txt": {"md": "Google Nest Mini", "fn": "Kitchen speaker"}, "ports": {}},
        "192.168.77.23": {"hostname": "Janes-iPhone", "friendly": "", "services": ["_companion-link", "_airplay"], "instances": [], "txt": {"model": "iPhone14,5"}, "ports": {}},
        "192.168.77.20": {"hostname": "pihole", "friendly": "", "services": ["_ssh", "_http"], "instances": [], "txt": {}, "ports": {}},
    }
    SSDP = {
        GATEWAY.ip: {"server": "Linux/5.4 UPnP/1.1 MiniUPnPd/2.2", "st": ["upnp:rootdevice"], "friendly": "Home router", "manufacturer": "Netgear", "model": "R7000", "device_type": "InternetGatewayDevice"},
        "192.168.77.22": {"server": "Linux UPnP/1.0", "st": ["upnp:rootdevice"], "friendly": "Echo Dot (Lounge)", "manufacturer": "Amazon", "model": "Echo Dot", "device_type": "MediaRenderer"},
    }
    NETBIOS = {"192.168.77.99": {"name": "ACCOUNTS-PC", "workgroup": "WORKGROUP", "mac": "", "services": [0, 32]}}
    TTL = {
        GATEWAY.ip: 64, "192.168.77.20": 64, "192.168.77.21": 64, "192.168.77.22": 64, "192.168.77.23": 64, "192.168.77.24": 64,
        "192.168.77.25": 64, "192.168.77.99": 128,
    }
    BANNERS = {
        "192.168.77.20": {"22": {"proto": "ssh", "banner": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"}, "80": {"proto": "http", "status": "HTTP/1.1 200 OK", "server": "lighttpd", "title": "Pi-hole admin"}},
        "192.168.77.24": {"80": {"proto": "http", "status": "HTTP/1.1 200 OK", "title": "ESP32 sensor"}},
    }

    def mdns(self, ips, local_ip="", timeout=2.5, cancel=None):
        return {ip: v for ip, v in self.MDNS.items() if ip in ips}

    def ssdp(self, ips, local_ip="", timeout=3.0, cancel=None):
        return {ip: v for ip, v in self.SSDP.items() if ip in ips}

    def netbios(self, ips, timeout=1.0, cancel=None):
        return {ip: v for ip, v in self.NETBIOS.items() if ip in ips}

    def ttl(self, ips, timeout=1.0, cancel=None):
        return {ip: {"ttl": self.TTL[ip], "initial": self.TTL[ip]} for ip in ips if ip in self.TTL}

    def banners(self, targets, timeout=2.0, cancel=None):
        return {ip: {p: v for p, v in pages.items() if int(p) in targets.get(ip, [])} for ip, pages in self.BANNERS.items() if ip in targets and any(int(p) in targets[ip] for p in pages)}


def seed_identity(store: Store) -> None:
    """A phone that announced itself over DHCP before the first sweep, as it would on a real network."""
    store.set_info(DEVICES[3].mac, "dhcp", {"hostname": "Janes-iPhone", "vendor_class": "", "params": "1,121,3,6,15,119,252", "os": "iOS / iPadOS / macOS"})


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
    seed_identity(store)
    store.close()
    return cfg, DemoTransport(), demo_resolver
