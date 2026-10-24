"""Network I/O boundary. Everything that touches the wire lives behind `Transport`.

Production uses ScapyTransport; tests substitute a fake. GuardedTransport wraps any
transport and enforces the allow-list on every call, so no code path can probe or
send ARP to an address outside the user's own subnet.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Callable, Protocol

from netscan.parsing import Host, parse_neighbours
from netscan.safety import Scope

log = logging.getLogger("netscan.net")

@dataclass(frozen=True)
class LocalNet:
    interface: str
    ip: str
    mac: str
    network: ipaddress.IPv4Network
    gateway_ip: str


class Transport(Protocol):
    def local_net(self, interface: str = "") -> LocalNet: ...
    def arp_sweep(self, network: ipaddress.IPv4Network, interface: str, timeout: float) -> list[Host]: ...
    def send_arp_reply(self, interface: str, hwsrc: str, psrc: str, hwdst: str, pdst: str) -> None: ...
    def resolve_mac(self, ip: str, interface: str) -> str | None: ...
    def sniff(self, interface: str, bpf: str, callback: Callable, stop: threading.Event) -> None: ...
    def local_ips(self) -> set[str]: ...


def compute_local_network(routes, interface: str, ip_for_iface: Callable[[str], str]) -> tuple[str, str, ipaddress.IPv4Network, str]:
    """Pure helper over scapy-style route tuples (net, mask, gw, iface, addr, metric)."""
    default = None
    for net, msk, gw, iface, _addr, metric in routes:
        if net == 0 and msk == 0 and (not interface or str(getattr(iface, "name", iface)) == interface):
            if default is None or metric < default[5]:
                default = (net, msk, gw, iface, _addr, metric)
    if default is None and not interface:
        raise RuntimeError("no default route found; connect to your network or set network.interface/gateway in config")
    # an explicit interface (e.g. when a VPN owns the default route) may have no default route of its own
    iface = interface if default is None else str(getattr(default[3], "name", default[3]))
    gateway = "" if default is None else default[2]
    ip = ip_for_iface(iface)
    candidates = []
    for net, msk, gw, r_iface, _addr, _metric in routes:
        if str(getattr(r_iface, "name", r_iface)) != iface or msk in (0, 0xFFFFFFFF) or net == 0:
            continue
        network = ipaddress.ip_network((net, bin(msk).count("1")), strict=False)
        if network.network_address.is_link_local or network.is_multicast or ipaddress.ip_address(ip) not in network:
            continue
        candidates.append(network)
    if not candidates:
        raise RuntimeError(f"could not work out the subnet of {iface} ({ip})")
    network = max(candidates, key=lambda n: n.prefixlen)
    return iface, ip, network, gateway


def read_os_neighbours() -> list[Host]:
    if sys.platform.startswith("linux") and shutil.which("ip"):
        cmd = ["ip", "-4", "neigh", "show"]
    else:
        cmd = ["arp", "-an"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return parse_neighbours(out)


class ScapyTransport:
    """Real wire access. scapy is imported lazily so unit tests and --help stay fast."""

    def is_root(self) -> bool:
        """True when raw sockets are usable: euid 0, or CAP_NET_RAW (systemd unit runs unprivileged with it)."""
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return True
        try:
            with open("/proc/self/status", encoding="ascii") as fh:
                for line in fh:
                    if line.startswith("CapEff:"):
                        return bool(int(line.split()[1], 16) & (1 << 13))
        except OSError:
            pass
        return False

    def local_net(self, interface: str = "") -> LocalNet:
        from scapy.all import conf, get_if_addr, get_if_hwaddr

        iface, ip, network, gateway = compute_local_network(conf.route.routes, interface, get_if_addr)
        try:
            mac = get_if_hwaddr(iface)
        except Exception:  # noqa: BLE001 tunnel/odd interfaces
            mac = ""
        return LocalNet(iface, ip, mac, network, gateway)

    def local_ips(self) -> set[str]:
        ips = {"127.0.0.1"}
        try:
            from scapy.all import conf, get_if_addr

            for r in conf.route.routes:
                try:
                    ips.add(get_if_addr(str(getattr(r[3], "name", r[3]))))
                except Exception:  # noqa: BLE001
                    continue
        except Exception:  # noqa: BLE001
            pass
        ips.discard("0.0.0.0")
        return ips

    def arp_sweep(self, network: ipaddress.IPv4Network, interface: str, timeout: float) -> list[Host]:
        if self.is_root():
            from scapy.all import ARP, Ether, srp

            answered, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
                iface=interface, timeout=timeout, retry=1, verbose=False,
            )
            from netscan.macutil import normalise_mac

            hosts = {}
            for _sent, rcv in answered:
                mac = normalise_mac(rcv.hwsrc)
                if mac:
                    hosts[rcv.psrc] = Host(rcv.psrc, mac)
            return list(hosts.values())
        return self._nudge_sweep(network, timeout)

    def _nudge_sweep(self, network: ipaddress.IPv4Network, timeout: float) -> list[Host]:
        """Unprivileged fallback: a tiny UDP datagram per host makes the OS ARP for it, then read the table."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            for ip in network.hosts():
                try:
                    sock.sendto(b"", (str(ip), 9))
                except OSError:
                    continue
        finally:
            sock.close()
        time.sleep(min(max(timeout, 1.0), 4.0))
        return [h for h in read_os_neighbours() if ipaddress.ip_address(h.ip) in network]

    def send_arp_reply(self, interface: str, hwsrc: str, psrc: str, hwdst: str, pdst: str) -> None:
        from scapy.all import ARP, Ether, sendp

        sendp(
            Ether(dst=hwdst) / ARP(op=2, hwsrc=hwsrc, psrc=psrc, hwdst=hwdst, pdst=pdst),
            iface=interface, verbose=False,
        )

    def resolve_mac(self, ip: str, interface: str) -> str | None:
        from netscan.macutil import normalise_mac

        if not self.is_root():
            return next((h.mac for h in read_os_neighbours() if h.ip == ip), None)
        from scapy.all import getmacbyip

        return normalise_mac(getmacbyip(ip) or "")

    def sniff(self, interface: str, bpf: str, callback: Callable, stop: threading.Event) -> None:
        from scapy.all import sniff
        from scapy.error import Scapy_Exception

        use_filter = True
        while not stop.is_set():
            try:
                sniff(iface=interface, filter=bpf if use_filter else None, prn=callback, store=False, timeout=2)
            except Scapy_Exception as exc:
                if use_filter and "libpcap" in str(exc):
                    # no libpcap means no BPF; callbacks already ignore frames they do not care about
                    log.warning("libpcap not available, sniffing unfiltered (install libpcap/tcpdump for efficiency)")
                    use_filter = False
                    continue
                log.error("capture failed: %s", exc)
                stop.wait(5)
            except OSError as exc:
                log.error("capture failed on %s: %s (needs root/CAP_NET_RAW)", interface, exc)
                stop.wait(5)


class GuardedTransport:
    """Allow-list enforcement at the I/O boundary (defence in depth)."""

    def __init__(self, inner: Transport, scope: Scope):
        self._inner = inner
        self._scope = scope

    def local_net(self, interface: str = "") -> LocalNet:
        net = self._inner.local_net(interface)
        self._scope.check_network(net.network)
        return net

    def local_ips(self) -> set[str]:
        return self._inner.local_ips()

    def arp_sweep(self, network, interface, timeout):
        net = self._scope.check_network(network)
        return [h for h in self._inner.arp_sweep(net, interface, timeout) if self._scope.contains(h.ip)]

    def send_arp_reply(self, interface, hwsrc, psrc, hwdst, pdst):
        self._scope.check_ip(psrc)
        self._scope.check_ip(pdst)
        self._inner.send_arp_reply(interface, hwsrc, psrc, hwdst, pdst)

    def resolve_mac(self, ip, interface):
        self._scope.check_ip(ip)
        return self._inner.resolve_mac(ip, interface)

    def sniff(self, interface, bpf, callback, stop):
        self._inner.sniff(interface, bpf, callback, stop)
