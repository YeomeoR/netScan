"""Device identification: wire parsing, probers with fake sockets, naming/guessing, behaviour, controller wiring. No real network."""

from __future__ import annotations

import struct
import threading
import time

import pytest
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from netscan.behaviour import hourly_profile, summarise, traffic_destinations, usual_hours
from netscan.config import Config
from netscan.daemon import Daemon
from netscan.discover import dnswire, probes
from netscan.discover.dhcpfp import parse_options
from netscan.discover.engine import identify, stale_devices
from netscan.discover.guess import best_name, flat, guess_type, identity
from netscan.discover.util import clean
from netscan.monitor import Event
from netscan.store import Store, TrafficRow
from netscan.web.controller import Controller
from netscan.web.errors import ApiError
from conftest import GW_IP, HOST_IP, PHONE, TV, FakeTransport


# ------------------------------------------------------------------ builders

def _rr(name: str, rtype: int, rdata: bytes) -> bytes:
    return dnswire.encode_name(name) + struct.pack(">HHIH", rtype, 1, 120, len(rdata)) + rdata


def mdns_response(*records: bytes) -> bytes:
    return struct.pack(">HHHHHH", 0, 0x8400, 0, len(records), 0, 0) + b"".join(records)


def txt_rdata(**kv) -> bytes:
    out = b""
    for k, v in kv.items():
        item = f"{k}={v}".encode()
        out += bytes([len(item)]) + item
    return out


# ------------------------------------------------------------------ text cleaning and wire format

def test_clean_strips_control_and_bidi_characters_and_caps_length():
    assert clean("a\x00b\r\nc\u202ed") == "a b c d"
    assert len(clean("x" * 500, 40)) == 40
    assert clean(b"caf\xc3\xa9") == "café"


def test_dns_reader_survives_hostile_packets():
    loop = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0) + b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 1, 4) + b"\x01\x02\x03\x04"
    assert dnswire.parse_message(loop) == []
    assert dnswire.parse_message(b"\x00" * 5) == []
    assert dnswire.parse_message(struct.pack(">HHHHHH", 0, 0, 0, 1, 0, 0) + b"\x3fshort") == []


def test_mdns_records_fold_into_one_summary():
    ip = "192.168.1.30"
    cast = "Living Room TV._googlecast._tcp.local"
    pkt = mdns_response(
        _rr("_services._dns-sd._udp.local", dnswire.PTR, dnswire.encode_name("_googlecast._tcp.local")),
        _rr("_googlecast._tcp.local", dnswire.PTR, dnswire.encode_name(cast)),
        _rr(cast, dnswire.TXT, txt_rdata(fn="Living Room TV", md="Chromecast Ultra")),
        _rr(cast, dnswire.SRV, struct.pack(">HHH", 0, 0, 8009) + dnswire.encode_name("Chromecast-abc.local")),
        _rr("Chromecast-abc.local", dnswire.A, bytes([192, 168, 1, 30])),
    )
    out = probes.aggregate_mdns({ip: dnswire.parse_message(pkt)})[ip]
    assert out["friendly"] == "Living Room TV"
    assert out["hostname"] == "Chromecast-abc"
    assert "_googlecast" in out["services"]
    assert out["txt"]["md"] == "Chromecast Ultra"
    assert out["ports"]["Living Room TV"] == 8009


def test_airplay_instance_label_drops_the_hex_id_prefix():
    assert probes._instance_label("AABBCCDDEEFF@Bedroom._raop._tcp.local", "_raop._tcp.local") == "Bedroom"


def test_nbstat_reply_gives_name_and_workgroup():
    names = [(b"ACCOUNTS-PC    ", 0x00, 0x0400), (b"WORKGROUP      ", 0x00, 0x8400), (b"ACCOUNTS-PC    ", 0x20, 0x0400)]
    body = b"".join(n + bytes([suffix]) + struct.pack(">H", flags) for n, suffix, flags in names)
    reply = (
        struct.pack(">HHHHHH", 0x4E53, 0x8400, 0, 1, 0, 0) + b"\x20" + b"CK" + b"AA" * 15 + b"\x00"
        + struct.pack(">HHIH", 0x21, 1, 0, 1 + len(body) + 6) + bytes([len(names)]) + body + bytes.fromhex("aabbccddeeff")
    )
    parsed = probes.parse_nbstat(reply)
    assert parsed["name"] == "ACCOUNTS-PC" and parsed["workgroup"] == "WORKGROUP"
    assert probes.parse_nbstat(reply[:20]) == {}
    assert probes.parse_nbstat(b"") == {}


def test_ssdp_response_and_upnp_description():
    raw = b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nSERVER: Linux UPnP/1.0\r\nLOCATION: http://192.168.1.30:49152/desc.xml\r\n\r\n"
    info = probes.parse_ssdp_response(raw)
    assert info["st"] == "upnp:rootdevice" and info["location"].endswith("desc.xml")
    assert probes.parse_ssdp_response(b"garbage") == {}
    xml = (
        "<root><device><deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>"
        "<friendlyName>Den &amp; Bar TV</friendlyName><manufacturer>Sony</manufacturer><modelName>BRAVIA</modelName></device></root>"
    )
    parsed = probes.parse_upnp_xml(xml)
    assert parsed == {"friendly": "Den & Bar TV", "manufacturer": "Sony", "model": "BRAVIA", "device_type": "MediaRenderer"}


def test_upnp_location_must_point_back_at_the_announcing_host():
    assert probes.location_allowed("http://192.168.1.30:49152/d.xml", "192.168.1.30")
    assert not probes.location_allowed("http://192.168.1.99/d.xml", "192.168.1.30")
    assert not probes.location_allowed("http://169.254.169.254/latest", "192.168.1.30")
    assert not probes.location_allowed("file:///etc/passwd", "192.168.1.30")
    assert not probes.location_allowed("https://192.168.1.30/d.xml", "192.168.1.30")


def test_ttl_and_http_banner_parsing():
    assert probes.parse_ttl("64 bytes from 192.168.1.9: icmp_seq=1 ttl=117 time=10 ms") == 117
    assert probes.parse_ttl("Reply from x: bytes=32 time=1ms TTL=127") == 127
    assert probes.parse_ttl("no answer") is None
    assert [probes.initial_ttl(n) for n in (60, 117, 250, 30)] == [64, 128, 255, 32]
    page = probes.parse_http_response(
        b'HTTP/1.1 401 Unauthorized\r\nServer: lighttpd\r\nWWW-Authenticate: Basic realm="Cam 7"\r\n\r\n<title> Door\x00 cam </title>'
    )
    assert page["server"] == "lighttpd" and page["realm"] == "Cam 7" and page["title"] == "Door cam"
    assert probes.parse_http_response(b"SSH-2.0-x") == {}


# ------------------------------------------------------------------ probers with fake sockets

class FakeUdp:
    def __init__(self, replies):
        self.replies, self.sent, self.closed = replies, [], False

    def send(self, data, addr):
        self.sent.append((data, addr))

    def listen(self, seconds, cancel=None):
        yield from self.replies

    def close(self):
        self.closed = True


def test_mdns_prober_ignores_hosts_that_were_not_asked():
    reply = mdns_response(_rr("tv.local", dnswire.A, bytes([192, 168, 1, 30])))
    udp = FakeUdp([("192.168.1.30", reply), ("192.168.1.99", mdns_response(_rr("evil.local", dnswire.A, bytes([192, 168, 1, 99]))))])
    out = probes.NetworkProber(open_udp=lambda *a: udp).mdns(["192.168.1.30"])
    assert list(out) == ["192.168.1.30"] and out["192.168.1.30"]["hostname"] == "tv"
    assert udp.closed
    destinations = {addr for _d, addr in udp.sent}
    assert ("224.0.0.251", 5353) in destinations and ("192.168.1.30", 5353) in destinations
    assert not any(a[0] == "192.168.1.99" for a in destinations)


def test_ssdp_prober_fetches_description_only_from_the_announcer():
    good = b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nLOCATION: http://192.168.1.30:80/d.xml\r\n\r\n"
    sneaky = b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nLOCATION: http://10.0.0.5/d.xml\r\n\r\n"
    udp = FakeUdp([("192.168.1.30", good), ("192.168.1.31", sneaky)])
    fetched = []

    def fetch(url, timeout, limit):
        fetched.append(url)
        return "<friendlyName>Bedroom TV</friendlyName>"

    out = probes.NetworkProber(open_udp=lambda *a: udp, fetch=fetch).ssdp(["192.168.1.30", "192.168.1.31"])
    assert fetched == ["http://192.168.1.30:80/d.xml"]
    assert out["192.168.1.30"]["friendly"] == "Bedroom TV"
    assert "friendly" not in out["192.168.1.31"]


def test_ttl_and_banner_probers_use_injected_helpers():
    prober = probes.NetworkProber(ping=lambda ip, t: "ttl=125" if ip.endswith(".30") else "", grab=lambda ip, port, t: {"proto": "http", "title": f"t{port}"} if port in (80, 22) else {})
    assert prober.ttl(["192.168.1.30", "192.168.1.31"]) == {"192.168.1.30": {"ttl": 125, "initial": 128}}
    got = prober.banners({"192.168.1.30": [22, 80, 3306], "192.168.1.31": [9999]})
    assert set(got["192.168.1.30"]) == {"22", "80"} and "192.168.1.31" not in got


# ------------------------------------------------------------------ naming and guessing

def test_best_name_prefers_what_a_person_typed_and_skips_junk():
    assert best_name({"mdns": {"friendly": "Kitchen speaker", "hostname": "x"}, "dhcp": {"hostname": "foo"}}) == ("Kitchen speaker", "Bonjour")
    assert best_name({"dhcp": {"hostname": "Janes-iPhone"}, "netbios": {"name": "PC1"}}) == ("Janes-iPhone", "DHCP hostname")
    assert best_name({"mdns": {"hostname": "localhost"}, "dhcp": {"hostname": "AABBCCDDEEFF"}, "netbios": {"name": "NAS"}}) == ("NAS", "NetBIOS")
    assert best_name({"banners": {"80": {"title": "Login"}}}) == ("", "")
    assert best_name({"banners": {"80": {"title": "Pi-hole admin"}}})[0] == "Pi-hole admin"
    assert best_name({}) == ("", "")


def test_guess_from_services_models_and_banners():
    tv = guess_type({"mdns": {"services": ["_googlecast", "_airplay"], "txt": {"md": "Chromecast Ultra"}}})
    assert tv["category"] == "media" and tv["model"] == "Chromecast Ultra" and tv["reasons"]
    printer = guess_type({"mdns": {"services": ["_ipp", "_printer"]}, "banners": {"80": {"title": "HP LaserJet 400"}}})
    assert printer["category"] == "printer"
    pi = guess_type({"banners": {"22": {"banner": "SSH-2.0-OpenSSH_9.2p1 Raspbian-2"}}})
    assert pi["os"] == "Raspberry Pi OS" and pi["category"] == "server"
    router = guess_type({"ssdp": {"device_type": "InternetGatewayDevice"}, "ttl": {"initial": 64}})
    assert router["category"] == "network"
    win = guess_type({"ttl": {"initial": 128}, "netbios": {"name": "X"}})
    assert win["os"] == "Windows" and win["category"] == "computer"
    nothing = guess_type({}, private_mac=True)
    assert nothing["category"] == "" and any("private" in r for r in nothing["reasons"])


def test_identity_combines_name_and_guess_and_flat_drops_checked_marker():
    rows = {"dhcp": {"data": {"hostname": "Janes-iPhone", "os": "iOS / iPadOS / macOS"}, "ts": 1}, "checked": {"data": {}, "ts": 2}}
    assert "checked" not in flat(rows)
    ident = identity(flat(rows), "Apple", True)
    assert ident["name"] == "Janes-iPhone" and ident["category"] == "phone"


# ------------------------------------------------------------------ DHCP

def dhcp_request(mac: str, options: list, op_msg: int = 3) -> object:
    return (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67)
        / BOOTP(op=1, chaddr=bytes.fromhex(mac.replace(":", ""))) / DHCP(options=[("message-type", op_msg), *options, "end"])
    )


def test_dhcp_options_only_count_for_client_requests():
    opts = [("message-type", 3), ("hostname", b"Janes-iPhone"), ("vendor_class_id", b"MSFT 5.0"), ("param_req_list", [1, 3, 6])]
    got = parse_options(opts)
    assert got["hostname"] == "Janes-iPhone" and got["os"] == "Windows" and got["params"] == "1,3,6"
    assert parse_options([("message-type", 2), ("hostname", b"router")]) == {}
    assert parse_options([("message-type", 1)]) == {}
    assert parse_options([("message-type", 3), ("param_req_list", bytes([1, 121, 3, 6, 15, 119, 252])), ("hostname", b"x")])["os"] == "iOS / iPadOS / macOS"


def test_watch_records_dhcp_hostname_from_request(rt):
    d = Daemon(rt)
    d.handle_packet(dhcp_request("00:11:22:aa:bb:01", [("hostname", b"Janes-iPhone"), ("param_req_list", [1, 121, 3, 6, 15, 119, 252])]))
    info = rt.store.get_info("00:11:22:aa:bb:01")["dhcp"]["data"]
    assert info["hostname"] == "Janes-iPhone" and info["os"] == "iOS / iPadOS / macOS"


def test_watch_ignores_our_own_dhcp_probe_and_replies_and_empty_requests(rt):
    d = Daemon(rt)
    d.handle_packet(dhcp_request(rt.local.mac, [("hostname", b"me")]))
    d.handle_packet(dhcp_request("00:11:22:aa:bb:02", [("hostname", b"router")], op_msg=2))
    d.handle_packet(dhcp_request("00:11:22:aa:bb:03", []))
    assert rt.store.all_info() == {}


def test_watch_still_routes_arp_frames(rt):
    from test_monitor import arp_frame

    Daemon(rt).handle_packet(arp_frame("192.168.1.90", "00:11:22:aa:bb:cc", op=1))
    assert rt.store.get_device("00:11:22:aa:bb:cc") is not None


# ------------------------------------------------------------------ store

def test_info_rows_replace_per_source_and_reject_unknown_sources(tmp_path):
    s = Store(tmp_path / "x.db")
    s.set_info("aa:aa:aa:aa:aa:aa", "mdns", {"hostname": "a"}, 1)
    s.set_info("aa:aa:aa:aa:aa:aa", "mdns", {"hostname": "b"}, 2)
    s.set_info("aa:aa:aa:aa:aa:aa", "ttl", {"ttl": 64}, 2)
    assert s.get_info("aa:aa:aa:aa:aa:aa")["mdns"] == {"data": {"hostname": "b"}, "ts": 2}
    assert set(s.all_info()["aa:aa:aa:aa:aa:aa"]) == {"mdns", "ttl"}
    assert s.count_info("mdns") == 1
    with pytest.raises(ValueError):
        s.set_info("aa:aa:aa:aa:aa:aa", "bogus", {})


# ------------------------------------------------------------------ engine

class FakeProber:
    def __init__(self):
        self.calls = []

    def mdns(self, ips, local_ip="", timeout=2.5, cancel=None):
        self.calls.append(("mdns", list(ips)))
        return {PHONE.ip: {"hostname": "Janes-iPhone", "friendly": "", "services": ["_companion-link"], "txt": {}}}

    def ssdp(self, ips, local_ip="", timeout=3.0, cancel=None):
        self.calls.append(("ssdp", list(ips)))
        return {TV.ip: {"friendly": "Den TV", "device_type": "MediaRenderer"}}

    def netbios(self, ips, timeout=1.0, cancel=None):
        self.calls.append(("netbios", list(ips)))
        return {}

    def ttl(self, ips, timeout=1.0, cancel=None):
        self.calls.append(("ttl", list(ips)))
        return {PHONE.ip: {"ttl": 64, "initial": 64}}

    def banners(self, targets, timeout=2.0, cancel=None):
        self.calls.append(("banners", dict(targets)))
        return {ip: {str(p): {"proto": "http", "title": "Hello"} for p in ports} for ip, ports in targets.items()}


def seed(rt):
    for h in (PHONE, TV):
        rt.store.upsert_device(h.mac, h.ip, "", "", 1000.0)


def test_identify_stores_answers_per_device_and_marks_them_checked(rt):
    seed(rt)
    prober = FakeProber()
    devices = rt.store.list_devices()
    out = identify(prober, rt.store, rt.scope, devices, local_ip=HOST_IP, now=2000.0)
    assert out["devices"] == 2 and out["named"] == 2 and out["found"]["mdns"] == 1 and out["found"]["ssdp"] == 1
    assert rt.store.get_info(PHONE.mac)["mdns"]["data"]["hostname"] == "Janes-iPhone"
    assert rt.store.get_info(TV.mac)["checked"]["ts"] == 2000.0
    assert not [c for c in prober.calls if c[0] == "banners"]


def test_identify_never_probes_addresses_outside_the_allow_list(rt):
    rt.store.upsert_device("00:11:22:33:44:55", "8.8.8.8", "", "", 1000.0)
    rt.store.upsert_device("00:11:22:33:44:56", "192.168.1.255", "", "", 1000.0)
    seed(rt)
    prober = FakeProber()
    out = identify(prober, rt.store, rt.scope, rt.store.list_devices(), local_ip=HOST_IP, now=1.0)
    assert out["skipped"] == 2 and out["devices"] == 2
    for _kind, args in prober.calls:
        assert "8.8.8.8" not in args and "192.168.1.255" not in args


def test_background_identify_only_reads_banners_from_ports_a_scan_found_open(rt):
    seed(rt)
    rt.store.set_port_scan(TV.mac, TV.ip, [80, 3306], 1500.0)
    prober = FakeProber()
    identify(prober, rt.store, rt.scope, rt.store.list_devices(), local_ip=HOST_IP, now=2000.0, deep=False)
    banner_calls = [c for c in prober.calls if c[0] == "banners"]
    assert banner_calls == [("banners", {TV.ip: [80]})]


def test_deep_identify_checks_which_ports_are_open_first(rt):
    seed(rt)
    prober = FakeProber()
    asked = []

    def connect(ip, port, timeout):
        asked.append((ip, port))
        return ip == TV.ip and port == 8080

    identify(prober, rt.store, rt.scope, rt.store.list_devices(), local_ip=HOST_IP, now=1.0, deep=True, connect=connect)
    assert ("banners", {TV.ip: [8080]}) in prober.calls
    assert all(rt.scope.contains(ip) for ip, _ in asked)


def test_a_probe_that_crashes_does_not_lose_the_others(rt):
    seed(rt)
    prober = FakeProber()
    prober.mdns = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    out = identify(prober, rt.store, rt.scope, rt.store.list_devices(), local_ip=HOST_IP, now=1.0)
    assert out["found"]["ssdp"] == 1


def test_cancel_stops_before_marking_devices_checked(rt):
    seed(rt)
    cancel = threading.Event()
    cancel.set()
    identify(FakeProber(), rt.store, rt.scope, rt.store.list_devices(), local_ip=HOST_IP, now=1.0, cancel=cancel)
    assert "checked" not in rt.store.get_info(PHONE.mac)


def test_stale_devices_skips_recently_checked_and_offline_ones(rt):
    seed(rt)
    rt.store.set_info(PHONE.mac, "checked", {}, 99_000.0)
    devices = rt.store.list_devices()
    assert [d.mac for d in stale_devices(rt.store, devices, 100_000.0)] == [TV.mac]
    assert {d.mac for d in stale_devices(rt.store, devices, 99_000.0 + 7 * 3600)} == {PHONE.mac, TV.mac}
    rt.store.set_offline(TV.mac)
    assert [d.mac for d in stale_devices(rt.store, rt.store.list_devices(), 99_000.0 + 7 * 3600)] == [PHONE.mac]


# ------------------------------------------------------------------ behaviour

def test_usual_hours_summary():
    profile = [0.0] * 24
    for h in range(7, 23):
        profile[h] = 0.9
    assert usual_hours(profile) == "07:00-23:00"
    assert usual_hours([1.0] * 24) == "around the clock"
    assert usual_hours([0.0] * 24) == ""
    wrap = [1.0 if h >= 22 or h < 6 else 0.0 for h in range(24)]
    assert usual_hours(wrap) == "22:00-06:00"


def test_hourly_profile_counts_only_observed_hours():
    now = time.time()
    since = now - 3 * 3600
    segs = [{"start": since, "end": now, "online": True}]
    profile = hourly_profile(segs, since, now)
    assert sum(1 for p in profile if p is not None) >= 3
    assert all(p in (None, 1.0) or 0 < p <= 1 for p in profile)


def test_behaviour_summary_flags_flaky_devices_and_lists_destinations():
    now = 30 * 86400.0
    since = now - 14 * 86400
    segs, t = [], since
    for _ in range(14 * 4):
        segs.append({"start": t, "end": t + 5 * 3600, "online": True})
        segs.append({"start": t + 5 * 3600, "end": t + 6 * 3600, "online": False})
        t += 6 * 3600
    rows = [
        TrafficRow("m", "out", "TCP", "1.1.1.1", 443, "cloud.example", 900, 3, 0, 5),
        TrafficRow("m", "out", "UDP", "1.1.1.2", 123, "cloud.example", 100, 1, 0, 9),
        TrafficRow("m", "out", "TCP", "2.2.2.2", 80, "", 50, 1, 0, 1),
    ]
    out = summarise(online=False, last_seen=now - 7200, first_seen=0, segments=segs, since=since, now=now, private_mac=True, traffic_rows=rows)
    assert out["drops_often"] and out["drops_per_day"] >= 3
    assert out["offline_for"] == 7200 and out["offline_for_text"] == "2.0 h".replace(".0 ", " ")
    assert out["private_mac"] and out["mac_note"]
    assert out["destinations"][0]["host"] == "cloud.example" and out["destinations"][0]["bytes"] == 1000
    assert out["destinations"][0]["ports"] == [123, 443]
    assert out["usual_hours"] in ("around the clock", "") or "-" in out["usual_hours"]


def test_behaviour_is_cautious_with_little_history():
    now = 1_000_000.0
    out = summarise(online=True, last_seen=now, first_seen=now - 3600, segments=[{"start": now - 3600, "end": now, "online": True}], since=now - 14 * 86400, now=now, private_mac=False)
    assert not out["enough_history"] and not out["drops_often"] and out["usual_hours"] == ""
    assert out["offline_for"] == 0 and out["offline_for_text"] == ""


def test_traffic_destinations_groups_by_host():
    rows = [TrafficRow("m", "out", "TCP", "1.1.1.1", 443, "a.example", 10, 1, 0, 1), TrafficRow("m", "in", "TCP", "1.1.1.1", 443, "a.example", 20, 1, 0, 2)]
    assert traffic_destinations(rows) == [{"host": "a.example", "ip": "1.1.1.1", "bytes": 30, "last_seen": 2, "ports": [443]}]


# ------------------------------------------------------------------ controller and alerts

@pytest.fixture
def ctl(tmp_path):
    cfg = Config(allowed_subnets=[__import__("ipaddress").ip_network("192.168.1.0/24")], home=tmp_path)
    fake = FakeTransport()
    fake.port_connect = lambda ip, port, timeout: False
    c = Controller(cfg, fake, resolver=lambda ip: "", prober=FakeProber(), scheduler_tick=3600, rules_tick=3600, update_tick=3600)
    c.start()
    yield c
    c.close()


def wait_jobs(c, kind, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        rows = [j for j in c.store.recent_jobs() if j.kind == kind]
        if rows and all(j.state not in ("queued", "running") for j in rows):
            return rows
        time.sleep(0.05)
    raise AssertionError(f"{kind} job did not finish")


def test_identify_job_names_devices_in_the_list_and_detail(ctl):
    ctl.submit_scan({"timeout": 1})
    wait_jobs(ctl, "sweep")
    wait_jobs(ctl, "identify")  # the sweep queues a background identify
    rows = {d["mac"]: d for d in ctl.devices()}
    assert rows[TV.mac]["name"] == "Den TV" and rows[TV.mac]["found_source"] == "UPnP"
    assert rows[PHONE.mac]["name"] == "Janes-iPhone"
    detail = ctl.device_detail(TV.mac)
    assert detail["identity"]["category"] == "media" and "ssdp" in detail["identity"]["sources"]
    assert detail["behaviour"]["destinations"] == [] and detail["behaviour"]["private_mac"] is False


def test_user_label_beats_a_found_name(ctl):
    ctl.submit_scan({"timeout": 1})
    wait_jobs(ctl, "sweep")
    wait_jobs(ctl, "identify")
    ctl.set_meta(TV.mac, {"label": "Dad's TV"})
    assert {d["mac"]: d["name"] for d in ctl.devices()}[TV.mac] == "Dad's TV"


def test_auto_identify_can_be_switched_off_and_is_throttled(ctl):
    assert ctl.identify_settings() == {"auto": True, "available": True}
    ctl.set_identify_settings({"auto": False})
    ctl.submit_scan({"timeout": 1})
    wait_jobs(ctl, "sweep")
    assert not [j for j in ctl.store.recent_jobs() if j.kind == "identify"]
    ctl.set_identify_settings({"auto": True})
    ctl.submit_scan({"timeout": 1})
    wait_jobs(ctl, "sweep")
    wait_jobs(ctl, "identify")
    count = len([j for j in ctl.store.recent_jobs() if j.kind == "identify"])
    ctl.submit_scan({"timeout": 1})
    time.sleep(0.5)
    wait_jobs(ctl, "sweep")
    assert len([j for j in ctl.store.recent_jobs() if j.kind == "identify"]) == count


def test_manual_identify_validates_input_and_runs(ctl):
    ctl.submit_scan({"timeout": 1})
    wait_jobs(ctl, "sweep")
    with pytest.raises(ApiError):
        ctl.submit_identify({"macs": []})
    with pytest.raises(ApiError):
        ctl.submit_identify({"macs": ["not-a-device"]})
    with pytest.raises(ApiError):
        ctl.submit_identify({"deep": "yes"})
    with pytest.raises(ApiError):
        ctl.set_identify_settings({"auto": "yes"})
    job = ctl.submit_identify({"macs": [TV.mac]})
    assert job["params"]["deep"] is True
    rows = wait_jobs(ctl, "identify")
    assert all(r.state == "done" for r in rows)


def test_identify_is_refused_when_no_prober(tmp_path):
    cfg = Config(allowed_subnets=[__import__("ipaddress").ip_network("192.168.1.0/24")], home=tmp_path)
    c = Controller(cfg, FakeTransport(), resolver=lambda ip: "", scheduler_tick=3600, rules_tick=3600, update_tick=3600)
    try:
        assert c.identify_settings()["available"] is False
        with pytest.raises(ApiError):
            c.submit_identify({})
    finally:
        c.close()


def test_port_scan_also_reads_banners(ctl):
    ctl.submit_scan({"timeout": 1})
    wait_jobs(ctl, "sweep")
    ctl.raw.port_connect = lambda ip, port, timeout: ip == TV.ip and port == 80
    ctl.submit_ports({"macs": [TV.mac]})
    wait_jobs(ctl, "ports")
    assert ctl.store.get_info(TV.mac)["banners"]["data"]["80"]["title"] == "Hello"


def test_alert_headline_uses_the_name_the_device_announced(rt):
    from netscan.alerts import describe_device

    seed(rt)
    rt.store.set_info(PHONE.mac, "dhcp", {"hostname": "Janes-iPhone", "os": "iOS / iPadOS / macOS"}, 1)
    info = describe_device(Event("device_online", PHONE.mac, PHONE.ip, "back online"), rt.store, 5000.0)
    assert info["name"] == "Janes-iPhone" and info["category"] == "phone" and info["guessed"]
    rt.store.set_meta(PHONE.mac, label="Jane's phone", category="phone")
    info = describe_device(Event("device_online", PHONE.mac, PHONE.ip, "back online"), rt.store, 5000.0)
    assert info["name"] == "Jane's phone" and not info["guessed"]


def test_cli_show_and_identify(tmp_path, monkeypatch, capsys):
    import ipaddress

    from netscan import cli
    from netscan.config import render_config
    from netscan.safety import record_acceptance

    (tmp_path / "config.toml").write_text(render_config(["192.168.1.0/24"], ""), encoding="utf-8")
    record_acceptance(tmp_path / "notice_accepted")
    monkeypatch.setattr(cli, "make_prober", FakeProber)
    fake = FakeTransport()
    assert cli.main(["--home", str(tmp_path), "scan", "--no-hostnames", "--timeout", "1"], transport=fake) == 0
    assert cli.main(["--home", str(tmp_path), "identify", "--no-ports"], transport=fake) == 0
    out = capsys.readouterr().out
    assert "Den TV" in out and "Janes-iPhone" in out
    assert cli.main(["--home", str(tmp_path), "show", TV.ip], transport=fake) == 0
    assert "Den TV" in capsys.readouterr().out
    assert cli.main(["--home", str(tmp_path), "identify", "10.9.9.9"], transport=fake) == 1
    assert ipaddress  # keep import used
