"""Read-only network probes. Each takes a list of device IPs the caller has already checked against the allow-list.

`NetworkProber` is the real thing; tests and the demo substitute an object with the same methods. The parsing
helpers are pure functions so they can be tested with captured or hand-built packets.
"""

from __future__ import annotations

import html
import logging
import re
import select
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable
from urllib.parse import urlsplit

from netscan.discover import dnswire
from netscan.discover.util import clean

log = logging.getLogger("netscan.discover")

MDNS_GROUP = ("224.0.0.251", 5353)
SSDP_GROUP = ("239.255.255.250", 1900)
SERVICE_ENUM = "_services._dns-sd._udp.local"
MAX_SERVICE_TYPES = 12
MAX_TXT_KEYS = 30
HTTP_PORTS = {80, 81, 631, 5000, 8000, 8008, 8080, 8081, 8888, 9090, 32400}
TLS_PORTS = {443, 8443, 9443}
GREETING_PORTS = {21: "ftp", 22: "ssh", 25: "smtp", 110: "pop3", 143: "imap"}
MAX_BANNER_PORTS = 8
MAX_HTTP_BYTES = 16384
MAX_XML_BYTES = 65536

HEX_ID = re.compile(r"^[0-9a-fA-F:\-]{12,}$")
RICH_SERVICES = ("_googlecast", "_airplay", "_raop", "_companion-link", "_spotify-connect", "_hap", "_homekit", "_ipp", "_printer", "_smb", "_afpovertcp", "_workstation")


# ---------------------------------------------------------------- mDNS parsing

def reverse_name(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def _strip_local(name: str) -> str:
    return re.sub(r"\.local\.?$", "", name, flags=re.I)


def _instance_label(instance: str, service: str) -> str:
    label = instance[: -(len(service) + 1)] if instance.lower().endswith("." + service.lower()) else instance.split("._", 1)[0]
    if "@" in label and HEX_ID.match(label.split("@", 1)[0] or "x"):  # AirPlay audio: "AABBCCDDEEFF@Living Room"
        label = label.split("@", 1)[1]
    return clean(label, 80)


def aggregate_mdns(records_by_ip: dict[str, list[dict]]) -> dict[str, dict]:
    """Fold the records heard from each address into one summary per device."""
    out: dict[str, dict] = {}
    for ip, records in records_by_ip.items():
        hostnames: list[str] = []
        types: list[str] = []
        instances: list[dict] = []
        txt: dict[str, str] = {}
        ports: dict[str, int] = {}
        for rec in records:
            name, rtype, rdata = rec["name"], rec["type"], rec["rdata"]
            low = name.lower()
            if rtype == dnswire.A and rdata == ip and low.endswith(".local"):
                hostnames.append(_strip_local(name))
            elif rtype == dnswire.PTR and low == reverse_name(ip):
                hostnames.append(_strip_local(str(rdata)))
            elif rtype == dnswire.PTR and low == SERVICE_ENUM:
                types.append(str(rdata))
            elif rtype == dnswire.PTR and re.match(r"^_[^.]+\._(tcp|udp)\.local$", low):
                types.append(name)
                instances.append({"service": name.split(".")[0], "name": _instance_label(str(rdata), name)})
            elif rtype == dnswire.TXT and isinstance(rdata, dict):
                for k, v in rdata.items():
                    if len(txt) < MAX_TXT_KEYS:
                        txt.setdefault(clean(k, 30), clean(v, 100))
            elif rtype == dnswire.SRV and isinstance(rdata, dict):
                ports[name.split(".")[0]] = int(rdata["port"])
                target = _strip_local(str(rdata["target"]))
                if target and target not in hostnames and rdata["target"].lower().endswith(".local"):
                    hostnames.append(target)
        if not (hostnames or types or instances or txt):
            continue
        short = [t.split(".")[0] for t in dict.fromkeys(types)]
        friendly = clean(txt.get("fn") or "", 80)
        if not friendly:
            for pref in RICH_SERVICES:
                friendly = next((i["name"] for i in instances if i["service"] == pref and i["name"] and not HEX_ID.match(i["name"])), "")
                if friendly:
                    break
        hosts = list(dict.fromkeys(clean(h, 80) for h in hostnames if h))
        out[ip] = {
            "hostname": hosts[0] if hosts else "", "friendly": friendly, "services": short[:30],
            "instances": instances[:20], "txt": txt, "ports": ports,
        }
    return out


def mdns_queries(ips: Iterable[str]) -> list[tuple[bytes, tuple[str, int]]]:
    qs = [(dnswire.build_query(SERVICE_ENUM, dnswire.PTR, unicast_response=True), MDNS_GROUP)]
    for ip in ips:
        qs.append((dnswire.build_query(SERVICE_ENUM, dnswire.PTR, unicast_response=True), (ip, 5353)))
        qs.append((dnswire.build_query(reverse_name(ip), dnswire.PTR, unicast_response=True), (ip, 5353)))
    return qs


# ---------------------------------------------------------------- SSDP / UPnP parsing

def msearch_packet(mx: int = 2) -> bytes:
    return (
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
        f"MX: {mx}\r\nST: ssdp:all\r\nUSER-AGENT: netScan/1.0\r\n\r\n"
    ).encode("ascii")


def parse_ssdp_response(data: bytes) -> dict:
    text = data.decode("utf-8", "replace")
    head = text.split("\r\n\r\n", 1)[0].split("\r\n")
    if not head or not head[0].upper().startswith(("HTTP/1.1 200", "NOTIFY")):
        return {}
    headers = {}
    for line in head[1:]:
        key, _, val = line.partition(":")
        if val:
            headers[key.strip().lower()] = val.strip()
    return {
        "server": clean(headers.get("server", ""), 120), "st": clean(headers.get("st") or headers.get("nt") or "", 120),
        "location": clean(headers.get("location", ""), 300),
    }


def _tag(xml: str, name: str) -> str:
    m = re.search(rf"<{name}>\s*(.*?)\s*</{name}>", xml, flags=re.I | re.S)
    return clean(html.unescape(re.sub(r"<[^>]+>", "", m.group(1))), 100) if m else ""


def parse_upnp_xml(xml: str) -> dict:
    """Pull the identifying fields from a UPnP device description with regexes (no XML parser: no entity tricks)."""
    out = {
        "friendly": _tag(xml, "friendlyName"), "manufacturer": _tag(xml, "manufacturer"), "model": _tag(xml, "modelName"),
        "model_number": _tag(xml, "modelNumber"), "description": _tag(xml, "modelDescription"),
        "device_type": _tag(xml, "deviceType").split(":device:")[-1].split(":")[0],
    }
    return {k: v for k, v in out.items() if v}


def location_allowed(location: str, ip: str) -> bool:
    """Only fetch a description from the device that announced it; never follow a LOCATION to another host."""
    try:
        u = urlsplit(location)
        return u.scheme == "http" and u.hostname == ip and (u.port is None or 0 < u.port < 65536)
    except ValueError:
        return False


def http_get_limited(url: str, timeout: float, limit: int) -> str:
    import http.client

    u = urlsplit(url)
    conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    try:
        conn.request("GET", (u.path or "/") + (f"?{u.query}" if u.query else ""), headers={"User-Agent": "netScan/1.0", "Connection": "close"})
        resp = conn.getresponse()
        if resp.status != 200:
            return ""
        return resp.read(limit).decode("utf-8", "replace")
    finally:
        conn.close()


# ---------------------------------------------------------------- NetBIOS parsing

def nbstat_query(txid: int = 0x4E53) -> bytes:
    encoded = b"CK" + b"AA" * 15
    return struct.pack(">HHHHHH", txid, 0, 1, 0, 0, 0) + b"\x20" + encoded + b"\x00" + struct.pack(">HH", 0x0021, 0x0001)


def parse_nbstat(data: bytes, txid: int = 0x4E53) -> dict:
    try:
        rid, flags, _qd, an = struct.unpack(">HHHH", data[:8])
        if rid != txid or not flags & 0x8000 or an < 1:
            return {}
        pos = 12
        while data[pos] != 0:  # the echoed name: one length-prefixed label
            pos += data[pos] + 1
        pos += 1 + 2 + 2 + 4 + 2  # terminator, type, class, ttl, rdlength
        count = data[pos]
        pos += 1
        names = []
        for _ in range(min(count, 40)):
            raw, suffix, nflags = data[pos : pos + 15], data[pos + 15], struct.unpack(">H", data[pos + 16 : pos + 18])[0]
            names.append({"name": clean(raw.decode("ascii", "replace").rstrip(), 30), "suffix": suffix, "group": bool(nflags & 0x8000)})
            pos += 18
        mac = ":".join(f"{b:02x}" for b in data[pos : pos + 6]) if len(data) >= pos + 6 else ""
    except (IndexError, struct.error):
        return {}
    unique = next((n["name"] for n in names if n["suffix"] == 0x00 and not n["group"]), "")
    group = next((n["name"] for n in names if n["suffix"] == 0x00 and n["group"]), "")
    if not unique and not group:
        return {}
    return {"name": unique, "workgroup": group, "mac": mac if mac != "00:00:00:00:00:00" else "", "services": sorted({n["suffix"] for n in names})}


# ---------------------------------------------------------------- TTL, banners

def parse_ttl(output: str) -> int | None:
    m = re.search(r"ttl[=:](\d+)", output, flags=re.I)
    return int(m.group(1)) if m else None


def initial_ttl(seen: int) -> int:
    for start in (32, 64, 128, 255):
        if seen <= start:
            return start
    return 255


def parse_http_response(raw: bytes) -> dict:
    text = raw.decode("utf-8", "replace")
    head, _, body = text.partition("\r\n\r\n")
    lines = head.split("\r\n")
    if not lines or not lines[0].upper().startswith("HTTP/"):
        return {}
    headers = {}
    for line in lines[1:]:
        key, _, val = line.partition(":")
        if val:
            headers[key.strip().lower()] = val.strip()
    title = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.I | re.S)
    realm = re.search(r'realm="?([^",]+)', headers.get("www-authenticate", ""), flags=re.I)
    out = {
        "status": clean(lines[0], 40), "server": clean(headers.get("server", ""), 100),
        "title": clean(html.unescape(title.group(1)), 100) if title else "", "realm": clean(realm.group(1), 80) if realm else "",
    }
    return {k: v for k, v in out.items() if v}


def grab_one(ip: str, port: int, timeout: float) -> dict:
    """First line of a greeting service, or the head of a web page. Only reads; sends nothing but a GET /."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            if port in GREETING_PORTS:
                line = raw.recv(256).split(b"\n", 1)[0]
                return {"proto": GREETING_PORTS[port], "banner": clean(line, 120)} if line else {}
            if port in TLS_PORTS:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(raw, server_hostname=None)
                proto = "https"
            elif port in HTTP_PORTS:
                sock, proto = raw, "http"
            else:
                return {}
            sock.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: netScan/1.0\r\nConnection: close\r\n\r\n".encode("ascii"))
            buf = b""
            while len(buf) < MAX_HTTP_BYTES:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
            info = parse_http_response(buf)
            return {"proto": proto, **info} if info else {}
    except (OSError, ssl.SSLError, ValueError):
        return {}


# ---------------------------------------------------------------- the real prober

class _Udp:
    """A UDP socket we can send from and read from until a deadline. Replaced wholesale in tests."""

    def __init__(self, local_ip: str = "", multicast: bool = False):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setblocking(False)
        if multicast:
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            if local_ip:
                try:
                    self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
                except OSError:
                    pass
        self.sock.bind(("", 0))

    def send(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            self.sock.sendto(data, addr)
        except OSError:
            pass

    def listen(self, seconds: float, cancel: threading.Event | None = None):
        end = time.monotonic() + seconds
        while time.monotonic() < end and not (cancel and cancel.is_set()):
            ready, _, _ = select.select([self.sock], [], [], min(0.2, max(0.0, end - time.monotonic())))
            if not ready:
                continue
            try:
                data, (src, _port) = self.sock.recvfrom(9000)
            except OSError:
                continue
            yield src, data

    def close(self) -> None:
        self.sock.close()


class NetworkProber:
    def __init__(self, open_udp: Callable[..., _Udp] = _Udp, ping: Callable[[str, float], str] | None = None, grab: Callable[[str, int, float], dict] = grab_one,
                 fetch: Callable[[str, float, int], str] = http_get_limited):
        self._open_udp = open_udp
        self._ping = ping or self._system_ping
        self._grab = grab
        self._fetch = fetch

    # mDNS: multicast plus a direct query to every device, then ask each for the services it advertises
    def mdns(self, ips: list[str], local_ip: str = "", timeout: float = 2.5, cancel: threading.Event | None = None) -> dict[str, dict]:
        wanted = set(ips)
        heard: dict[str, list[dict]] = {}
        udp = self._open_udp(local_ip, True)
        try:
            for data, addr in mdns_queries(ips):
                udp.send(data, addr)
            for src, data in udp.listen(timeout, cancel):
                if src in wanted:
                    heard.setdefault(src, []).extend(dnswire.parse_message(data))
            asked = 0
            for ip, records in list(heard.items()):
                types = [str(r["rdata"]) for r in records if r["type"] == dnswire.PTR and r["name"].lower() == SERVICE_ENUM][:MAX_SERVICE_TYPES]
                for t in types:
                    udp.send(dnswire.build_query(t, dnswire.PTR, unicast_response=True), (ip, 5353))
                    asked += 1
            if asked:
                for src, data in udp.listen(min(timeout, 1.5), cancel):
                    if src in wanted:
                        heard.setdefault(src, []).extend(dnswire.parse_message(data))
        finally:
            udp.close()
        return aggregate_mdns(heard)

    def ssdp(self, ips: list[str], local_ip: str = "", timeout: float = 3.0, cancel: threading.Event | None = None) -> dict[str, dict]:
        wanted = set(ips)
        found: dict[str, dict] = {}
        locations: dict[str, list[str]] = {}
        udp = self._open_udp(local_ip, True)
        try:
            for _ in range(2):
                udp.send(msearch_packet(), SSDP_GROUP)
            for src, data in udp.listen(timeout, cancel):
                if src not in wanted:
                    continue
                info = parse_ssdp_response(data)
                if not info:
                    continue
                entry = found.setdefault(src, {"server": "", "st": []})
                entry["server"] = entry["server"] or info["server"]
                if info["st"] and info["st"] not in entry["st"] and len(entry["st"]) < 12:
                    entry["st"].append(info["st"])
                if info["location"] and location_allowed(info["location"], src) and info["location"] not in locations.setdefault(src, []):
                    locations[src].append(info["location"])
        finally:
            udp.close()

        def describe(item):
            ip, urls = item
            for url in urls[:2]:
                try:
                    parsed = parse_upnp_xml(self._fetch(url, 3.0, MAX_XML_BYTES))
                except (OSError, ValueError):
                    continue
                if parsed:
                    found[ip].update(parsed)
                    return

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(describe, locations.items()))
        return {ip: {k: v for k, v in d.items() if v} for ip, d in found.items()}

    def netbios(self, ips: list[str], timeout: float = 1.0, cancel: threading.Event | None = None) -> dict[str, dict]:
        def ask(ip: str) -> tuple[str, dict]:
            if cancel and cancel.is_set():
                return ip, {}
            udp = self._open_udp("", False)
            try:
                udp.send(nbstat_query(), (ip, 137))
                for src, data in udp.listen(timeout, cancel):
                    if src == ip:
                        return ip, parse_nbstat(data)
            finally:
                udp.close()
            return ip, {}

        with ThreadPoolExecutor(max_workers=24) as pool:
            return {ip: d for ip, d in pool.map(ask, ips) if d}

    @staticmethod
    def _system_ping(ip: str, timeout: float) -> str:
        exe = shutil.which("ping")
        if not exe:
            return ""
        wait = str(max(1, int(round(timeout))))
        cmd = [exe, "-c", "1", "-t", wait, ip] if sys.platform == "darwin" else [exe, "-c", "1", "-W", wait, ip]
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3, check=False).stdout
        except (OSError, subprocess.SubprocessError):
            return ""

    def ttl(self, ips: list[str], timeout: float = 1.0, cancel: threading.Event | None = None) -> dict[str, dict]:
        def one(ip: str) -> tuple[str, dict]:
            if cancel and cancel.is_set():
                return ip, {}
            seen = parse_ttl(self._ping(ip, timeout))
            return ip, ({"ttl": seen, "initial": initial_ttl(seen)} if seen else {})

        with ThreadPoolExecutor(max_workers=16) as pool:
            return {ip: d for ip, d in pool.map(one, ips) if d}

    def banners(self, targets: dict[str, list[int]], timeout: float = 2.0, cancel: threading.Event | None = None) -> dict[str, dict]:
        jobs = []
        for ip, ports in targets.items():
            usable = [p for p in ports if p in GREETING_PORTS or p in HTTP_PORTS or p in TLS_PORTS][:MAX_BANNER_PORTS]
            jobs += [(ip, p) for p in usable]

        def one(job):
            if cancel and cancel.is_set():
                return job, {}
            return job, self._grab(job[0], job[1], timeout)

        out: dict[str, dict] = {}
        with ThreadPoolExecutor(max_workers=16) as pool:
            for (ip, port), info in pool.map(one, jobs):
                if info:
                    out.setdefault(ip, {})[str(port)] = info
        return out
