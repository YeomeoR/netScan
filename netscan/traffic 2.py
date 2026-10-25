"""Per-device traffic metadata: counters by protocol and destination. Never payload contents.

`PacketMeta` deliberately has no payload field: only addresses, ports, protocol, frame size
and DNS names (the names a device looks up are connection metadata, like a destination host).
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable

from netscan.macutil import normalise_mac
from netscan.store import Store, TrafficRow

log = logging.getLogger("netscan.traffic")

SERVICES = {
    ("TCP", 22): "SSH", ("TCP", 80): "HTTP", ("TCP", 443): "HTTPS", ("TCP", 8080): "HTTP-alt",
    ("TCP", 853): "DoT", ("TCP", 993): "IMAPS", ("TCP", 587): "SMTP", ("TCP", 5222): "XMPP",
    ("UDP", 53): "DNS", ("TCP", 53): "DNS", ("UDP", 67): "DHCP", ("UDP", 68): "DHCP",
    ("UDP", 123): "NTP", ("UDP", 137): "NetBIOS", ("UDP", 443): "QUIC", ("UDP", 1900): "SSDP",
    ("UDP", 5353): "mDNS", ("UDP", 5355): "LLMNR", ("TCP", 8009): "Chromecast", ("TCP", 1883): "MQTT",
    ("TCP", 8883): "MQTT-TLS",
}


@dataclass(frozen=True)
class PacketMeta:
    src_mac: str = ""
    dst_mac: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    proto: str = "OTHER"
    sport: int = 0
    dport: int = 0
    size: int = 0
    dns_names: tuple[tuple[str, str], ...] = ()  # (ip, name) pairs learned from DNS answers


def service_name(proto: str, port: int) -> str:
    return SERVICES.get((proto, port), "")


def extract_meta(pkt) -> PacketMeta | None:
    """Reduce a scapy packet to metadata. Returns None for frames we do not account for."""
    from scapy.layers.dns import DNS
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP, Ether

    src_mac = dst_mac = ""
    if pkt.haslayer(Ether):
        src_mac = normalise_mac(pkt[Ether].src) or ""
        dst_mac = normalise_mac(pkt[Ether].dst) or ""
    size = len(pkt)

    if pkt.haslayer(ARP):
        a = pkt[ARP]
        return PacketMeta(src_mac, dst_mac, a.psrc, a.pdst, "ARP", size=size)

    if pkt.haslayer(IP):
        ip = pkt[IP]
        src_ip, dst_ip, num = ip.src, ip.dst, ip.proto
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        src_ip, dst_ip, num = ip6.src, ip6.dst, ip6.nh
    else:
        return None

    proto, sport, dport = {1: "ICMP", 2: "IGMP", 58: "ICMPv6", 47: "GRE", 50: "ESP"}.get(num, "OTHER"), 0, 0
    if pkt.haslayer(TCP):
        proto, sport, dport = "TCP", pkt[TCP].sport, pkt[TCP].dport
    elif pkt.haslayer(UDP):
        proto, sport, dport = "UDP", pkt[UDP].sport, pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        proto = "ICMP"

    names: list[tuple[str, str]] = []
    if proto == "UDP" and pkt.haslayer(DNS) and pkt[DNS].qr == 1 and pkt[DNS].ancount:
        dns = pkt[DNS]
        for i in range(dns.ancount):
            rr = dns.an[i] if hasattr(dns.an, "__getitem__") else None
            if rr is not None and getattr(rr, "type", None) == 1 and isinstance(getattr(rr, "rdata", None), str):
                names.append((rr.rdata, _name(rr.rrname)))
    return PacketMeta(src_mac, dst_mac, src_ip, dst_ip, proto, sport, dport, size, tuple(names))


def _name(raw) -> str:
    text = raw.decode("ascii", "replace") if isinstance(raw, bytes) else str(raw)
    return text.rstrip(".")


@dataclass
class _Bucket:
    bytes: int = 0
    packets: int = 0
    first: float = 0.0
    last: float = 0.0
    host: str = ""


class TrafficCollector:
    def __init__(self, store: Store, resolver: Callable[[str], str] | None = None, clock: Callable[[], float] = time.time):
        self.store = store
        self.resolver = resolver
        self.clock = clock
        self._lock = threading.Lock()
        self._buckets: dict[tuple[str, str, str, str, int], _Bucket] = {}
        self._dns: dict[str, str] = {}
        self._known: set[str] = set()
        self._rdns_done: set[str] = set()
        self.refresh_devices()

    def refresh_devices(self) -> None:
        self._known = {d.mac for d in self.store.list_devices()}

    def handle(self, pkt) -> None:
        meta = extract_meta(pkt)
        if meta:
            self.record(meta)

    def record(self, m: PacketMeta) -> None:
        now = self.clock()
        with self._lock:
            for ip, name in m.dns_names:
                self._dns[ip] = name
            if m.src_mac in self._known:
                self._add(m.src_mac, "out", m.proto, m.dst_ip, m.dport, m.size, now)
            if m.dst_mac in self._known and m.dst_mac != m.src_mac:
                self._add(m.dst_mac, "in", m.proto, m.src_ip, m.sport, m.size, now)

    def _add(self, mac: str, direction: str, proto: str, peer_ip: str, peer_port: int, size: int, now: float) -> None:
        b = self._buckets.setdefault((mac, direction, proto, peer_ip, peer_port), _Bucket(first=now))
        b.bytes += size
        b.packets += 1
        b.last = now

    def flush(self) -> int:
        with self._lock:
            buckets, self._buckets = self._buckets, {}
            dns = dict(self._dns)
        if not buckets:
            return 0
        hosts = self._hostnames({k[3] for k in buckets}, dns)
        rows = [
            TrafficRow(mac, d, proto, ip, port, hosts.get(ip, ""), b.bytes, b.packets, b.first, b.last)
            for (mac, d, proto, ip, port), b in buckets.items()
        ]
        self.store.add_traffic(rows)
        self.refresh_devices()
        return len(rows)

    def _hostnames(self, ips: set[str], dns: dict[str, str]) -> dict[str, str]:
        out = {ip: dns[ip] for ip in ips if ip in dns}
        todo = [ip for ip in ips if ip not in out and ip not in self._rdns_done and self.resolver]
        if todo:
            with ThreadPoolExecutor(max_workers=8) as pool:
                for ip, name in zip(todo, pool.map(self.resolver, todo)):  # type: ignore[arg-type]
                    self._rdns_done.add(ip)
                    if name:
                        out[ip] = name
        return out


def run_capture(transport, interface: str, collector: TrafficCollector, stop: threading.Event, flush_every: float = 10.0) -> None:
    """Sniff in a helper thread, flushing counters periodically and once more on exit."""
    sniffer = threading.Thread(
        target=transport.sniff, args=(interface, "ip or ip6 or arp", collector.handle, stop), daemon=True, name="netscan-sniff"
    )
    sniffer.start()
    try:
        while not stop.wait(flush_every):
            collector.flush()
    finally:
        stop.set()
        sniffer.join(timeout=5)
        collector.flush()
