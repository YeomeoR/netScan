"""Scope guard: every scan, probe and block passes through here.

netScan is for the user's own home network only. The allow-list is mandatory and
checked at the lowest layers (transport sends too), not just in the CLI, so a bug
higher up cannot reach a third-party network. The gateway and the host itself can
never be blocked.
"""

from __future__ import annotations

import ipaddress
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from netscan.macutil import normalise_mac

NOTICE = (
    "netScan is for networks you OWN or are explicitly authorised to administer "
    "(your own home network).\n"
    "Scanning, monitoring or blocking devices on someone else's network may be illegal and is "
    "not supported.\n"
    "netScan refuses to touch anything outside the subnet allow-list in your config, and never "
    "blocks the gateway or this host.\n"
    "Traffic capture records metadata only (addresses, ports, sizes), never payload contents."
)


class SafetyError(Exception):
    """Base for every refusal."""


class OutOfScopeError(SafetyError):
    pass


class ProtectedTargetError(SafetyError):
    pass


class NoticeNotAcceptedError(SafetyError):
    pass


@dataclass
class Scope:
    allowed: list[ipaddress.IPv4Network]
    gateway_ip: str = ""
    host_ips: set[str] = field(default_factory=set)
    protected_ips: set[str] = field(default_factory=set)
    protected_macs: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if not self.allowed:
            raise OutOfScopeError(
                "no allowed_subnets configured; run `netscan init` (or edit config.toml) so the scan scope is explicit"
            )
        self.protected_ips |= set(self.host_ips)
        if self.gateway_ip:
            self.protected_ips.add(self.gateway_ip)
        self.protected_macs = {m for m in (normalise_mac(x) for x in self.protected_macs) if m}

    def add_protected(self, value: str) -> None:
        mac = normalise_mac(value)
        if mac:
            self.protected_macs.add(mac)
            return
        try:
            self.protected_ips.add(str(ipaddress.ip_address(value)))
        except ValueError:
            raise SafetyError(f"cannot interpret protected entry {value!r} as an ip or mac") from None

    def contains(self, ip) -> bool:
        try:
            addr = ipaddress.ip_address(str(ip))
        except ValueError:
            return False
        return any(addr in net for net in self.allowed if addr.version == net.version)

    def check_ip(self, ip) -> str:
        """Allow only usable host addresses inside the allow-list."""
        if not self.contains(ip):
            raise OutOfScopeError(f"{ip} is outside the allowed subnets {[str(n) for n in self.allowed]}; refusing")
        addr = ipaddress.ip_address(str(ip))
        for net in self.allowed:
            if addr in net and net.prefixlen < 31 and addr in (net.network_address, net.broadcast_address):
                raise OutOfScopeError(f"{ip} is a network/broadcast address, not a device; refusing")
        return str(addr)

    def check_network(self, network) -> ipaddress.IPv4Network:
        """A scan range must be fully inside one allowed subnet."""
        try:
            net = ipaddress.ip_network(str(network), strict=False)
        except ValueError as exc:
            raise OutOfScopeError(f"invalid network {network!r}: {exc}") from exc
        if not any(net.version == a.version and net.subnet_of(a) for a in self.allowed):
            raise OutOfScopeError(
                f"{net} is not inside the allowed subnets {[str(n) for n in self.allowed]}; refusing to scan"
            )
        return net

    def is_protected(self, ip: str | None = None, mac: str | None = None) -> bool:
        if ip and str(ip) in self.protected_ips:
            return True
        norm = normalise_mac(mac) if mac else None
        return bool(norm and norm in self.protected_macs)

    def check_blockable(self, ip: str, mac: str | None = None) -> str:
        ip = self.check_ip(ip)
        if self.is_protected(ip, mac):
            raise ProtectedTargetError(f"{ip}{' / ' + mac if mac else ''} is the gateway, this host or protected; never blocked")
        return ip


def notice_accepted(path: Path) -> bool:
    return path.exists()


def record_acceptance(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"accepted_at": int(time.time())}), encoding="utf-8")


def ensure_notice(path: Path, *, accept: bool = False, input_fn=input, out=None, interactive: bool | None = None) -> None:
    """First-run gate. Raises NoticeNotAcceptedError unless acknowledged."""
    if notice_accepted(path):
        return
    out = out or sys.stderr
    print("\n=== netScan: first-run notice ===", file=out)
    print(NOTICE, file=out)
    if accept:
        record_acceptance(path)
        return
    if interactive is None:
        interactive = sys.stdin.isatty()
    if not interactive:
        raise NoticeNotAcceptedError(
            "first-run notice not acknowledged; run `netscan notice` interactively or pass --accept-terms"
        )
    answer = input_fn("Type 'yes' to confirm this is your own network: ").strip().lower()
    if answer != "yes":
        raise NoticeNotAcceptedError("notice not accepted; exiting")
    record_acceptance(path)
