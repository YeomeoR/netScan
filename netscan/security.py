"""Passive and explicit security checks: rogue DHCP analysis and ARP spoof detection.

Everything here is pure analysis over data the transport already collected, so it is
testable without a network. Probing (DHCP DISCOVER, port scans) is only ever started by
an explicit user action.
"""

from __future__ import annotations

import time
from dataclasses import asdict

from netscan.monitor import ARP_SPOOF, ROGUE_DHCP, Event
from netscan.net import DhcpOffer

DHCP_PROBE_TIMEOUT = 4.0


def analyse_dhcp(offers: list[DhcpOffer], gateway_ip: str, gateway_mac: str = "") -> list[str]:
    """Return human readable problems found in the DHCP offers seen on the LAN."""
    problems: list[str] = []
    servers = {(o.server_ip, o.server_mac) for o in offers}
    if len(servers) > 1:
        listed = ", ".join(f"{ip} ({mac or 'unknown mac'})" for ip, mac in sorted(servers))
        problems.append(f"{len(servers)} DHCP servers answered: {listed}. Only your router should hand out addresses")
    for o in offers:
        if o.router and gateway_ip and o.router != gateway_ip:
            problems.append(f"DHCP server {o.server_ip} ({o.server_mac or 'unknown mac'}) offers {o.router} as the default gateway instead of {gateway_ip}")
        if gateway_mac and o.server_mac and o.server_mac != gateway_mac and o.server_ip == gateway_ip:
            problems.append(f"{o.server_ip} answered DHCP from {o.server_mac}, but your router's MAC is {gateway_mac}")
    return problems


def run_dhcp_probe(rt, timeout: float = DHCP_PROBE_TIMEOUT, now: float | None = None) -> dict:
    """One DISCOVER broadcast. Stores the result and raises rogue_dhcp findings. Returns the stored result."""
    now = time.time() if now is None else now
    offers = rt.transport.dhcp_discover(rt.local.interface, timeout)
    problems = analyse_dhcp(offers, rt.scope.gateway_ip or "", rt.gateway_mac)
    events: list[Event] = []
    for problem in problems:
        ev = rt.tracker.security_event(ROGUE_DHCP, problem, ip=rt.scope.gateway_ip or "", now=now)
        if ev:
            events.append(ev)
    result = {"ts": now, "offers": [asdict(o) | {"dns": list(o.dns)} for o in offers], "problems": problems}
    rt.store.set_setting("last_dhcp", result)
    rt.alerter.dispatch(events)
    return result


def check_gateway_claim(rt, ip: str, mac: str, now: float | None = None) -> Event | None:
    """An ARP frame claiming the gateway's ip from a different MAC is the classic man-in-the-middle."""
    gw_ip, gw_mac = rt.scope.gateway_ip, rt.gateway_mac
    if not gw_ip or not gw_mac or ip != gw_ip or mac == gw_mac:
        return None
    return rt.tracker.security_event(
        ARP_SPOOF, f"{mac} is claiming to be the gateway {gw_ip} (the real router is {gw_mac}): possible ARP spoofing", mac=mac, ip=ip, now=now
    )
