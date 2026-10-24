"""Parsers for OS neighbour/ARP table output (no network I/O here)."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from netscan.macutil import is_multicast, normalise_mac


@dataclass(frozen=True)
class Host:
    ip: str
    mac: str


# macOS/BSD: "? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]"
# linux net-tools: "? (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0"
_ARP_AN = re.compile(r"\((?P<ip>\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+(?P<mac>\S+)")
# linux iproute2: "192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE"
_IP_NEIGH = re.compile(r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+dev\s+\S+\s+lladdr\s+(?P<mac>\S+)(?:\s+.*?)?\s+(?P<state>[A-Z]+)$")


def _valid(ip: str, mac_raw: str) -> Host | None:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return None
    mac = normalise_mac(mac_raw)
    if not mac or is_multicast(mac) or addr.is_multicast or addr.is_unspecified:
        return None
    return Host(str(addr), mac)


def parse_arp_an(text: str) -> list[Host]:
    hosts: list[Host] = []
    for line in text.splitlines():
        if "incomplete" in line:
            continue
        m = _ARP_AN.search(line)
        if m and (h := _valid(m["ip"], m["mac"])):
            hosts.append(h)
    return hosts


def parse_ip_neigh(text: str) -> list[Host]:
    hosts: list[Host] = []
    for line in text.splitlines():
        m = _IP_NEIGH.match(line.strip())
        if m and m["state"] not in ("FAILED", "INCOMPLETE") and (h := _valid(m["ip"], m["mac"])):
            hosts.append(h)
    return hosts


def parse_neighbours(text: str) -> list[Host]:
    """Auto-detect the format; de-duplicate by ip (last wins)."""
    by_ip: dict[str, Host] = {}
    for h in parse_ip_neigh(text) + parse_arp_an(text):
        by_ip[h.ip] = h
    return list(by_ip.values())
