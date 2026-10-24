import dataclasses

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from conftest import GW_MAC, PHONE, TV
from netscan.traffic import PacketMeta, TrafficCollector, extract_meta, service_name


def tcp(src_mac, dst_mac, src, dst, sport, dport, payload=b""):
    return Ether(src=src_mac, dst=dst_mac) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport) / Raw(payload)


def test_extract_tcp_metadata():
    m = extract_meta(tcp(PHONE.mac, GW_MAC, PHONE.ip, "93.184.216.34", 50000, 443, b"x" * 100))
    assert (m.proto, m.src_ip, m.dst_ip, m.sport, m.dport) == ("TCP", PHONE.ip, "93.184.216.34", 50000, 443)
    assert m.src_mac == PHONE.mac and m.dst_mac == GW_MAC
    assert m.size > 100, "frame size is recorded"
    assert service_name(m.proto, m.dport) == "HTTPS"


def test_extract_udp_icmp_arp_and_unknown():
    udp = Ether(src=PHONE.mac, dst=GW_MAC) / IP(src=PHONE.ip, dst="1.1.1.1") / UDP(sport=4000, dport=123)
    assert extract_meta(udp).proto == "UDP"
    icmp = Ether(src=PHONE.mac, dst=GW_MAC) / IP(src=PHONE.ip, dst="1.1.1.1") / ICMP()
    assert extract_meta(icmp).proto == "ICMP"
    arp = Ether(src=PHONE.mac, dst="ff:ff:ff:ff:ff:ff") / ARP(psrc=PHONE.ip, pdst="192.168.1.1")
    m = extract_meta(arp)
    assert (m.proto, m.dst_ip) == ("ARP", "192.168.1.1")
    assert extract_meta(Ether(src=PHONE.mac, dst=GW_MAC, type=0x1234)) is None, "frames we cannot attribute are skipped"


def test_dns_answers_yield_ip_to_name_pairs():
    dns = (
        Ether(src=GW_MAC, dst=PHONE.mac) / IP(src="192.168.1.1", dst=PHONE.ip) / UDP(sport=53, dport=40000)
        / DNS(qr=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com.", type="A", rdata="93.184.216.34"), ancount=1)
    )
    assert extract_meta(dns).dns_names == (("93.184.216.34", "example.com"),)


def test_metadata_never_carries_payload():
    secret = b"password=hunter2"
    pkt = tcp(PHONE.mac, GW_MAC, PHONE.ip, "93.184.216.34", 1, 80, secret)
    m = extract_meta(pkt)
    assert "payload" not in {f.name for f in dataclasses.fields(PacketMeta)} and not any(
        isinstance(v, (bytes, bytearray)) for v in dataclasses.astuple(m)
    ), "PacketMeta must hold no bytes fields"
    assert secret.decode() not in repr(m)


def test_collector_counts_both_directions_for_known_devices_only(rt):
    rt.tracker.observe([PHONE], now=1)
    c = TrafficCollector(rt.store, clock=lambda: 50)
    out = tcp(PHONE.mac, GW_MAC, PHONE.ip, "93.184.216.34", 50000, 443, b"a" * 10)
    back = tcp(GW_MAC, PHONE.mac, "93.184.216.34", PHONE.ip, 443, 50000, b"b" * 20)
    stranger = tcp(TV.mac, GW_MAC, TV.ip, "1.1.1.1", 1, 53)  # TV is not in the inventory
    for p in (out, out, back, stranger):
        c.handle(p)
    assert c.flush() == 2
    rows = {(r.direction, r.peer_ip, r.peer_port): r for r in rt.store.traffic_for(PHONE.mac)}
    assert rows[("out", "93.184.216.34", 443)].packets == 2
    assert rows[("in", "93.184.216.34", 443)].packets == 1 and rows[("in", "93.184.216.34", 443)].bytes == len(back)
    assert rt.store.traffic_for(TV.mac) == [], "traffic is only attributed to devices already in the inventory"
    assert rt.store.traffic_totals()[PHONE.mac][1] == 3


def test_flush_accumulates_and_learns_hostnames_from_dns(rt):
    rt.tracker.observe([PHONE], now=1)
    c = TrafficCollector(rt.store, clock=lambda: 50)
    dns = (
        Ether(src=GW_MAC, dst=PHONE.mac) / IP(src="192.168.1.1", dst=PHONE.ip) / UDP(sport=53, dport=40000)
        / DNS(qr=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com.", type="A", rdata="93.184.216.34"), ancount=1)
    )
    c.handle(dns)
    c.handle(tcp(PHONE.mac, GW_MAC, PHONE.ip, "93.184.216.34", 5, 443))
    c.flush()
    c.handle(tcp(PHONE.mac, GW_MAC, PHONE.ip, "93.184.216.34", 6, 443))
    c.flush()
    row = next(r for r in rt.store.traffic_for(PHONE.mac) if r.direction == "out" and r.peer_port == 443)
    assert row.packets == 2, "counters accumulate across flushes"
    assert row.peer_host == "example.com", "destination hostname learned from observed DNS answers"


def test_reverse_dns_fallback_runs_once_per_ip(rt):
    rt.tracker.observe([PHONE], now=1)
    seen = []
    c = TrafficCollector(rt.store, resolver=lambda ip: seen.append(ip) or "rev.example", clock=lambda: 1)
    for _ in range(2):
        c.handle(tcp(PHONE.mac, GW_MAC, PHONE.ip, "9.9.9.9", 5, 443))
        c.flush()
    assert seen == ["9.9.9.9"]
    assert rt.store.traffic_for(PHONE.mac)[0].peer_host == "rev.example"
