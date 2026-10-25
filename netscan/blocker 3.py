"""Block/unblock devices. State lives in sqlite; enforcement is ARP cutoff or a Linux firewall.

ARP cutoff: the target is told the gateway lives at a dead MAC and the gateway is told the
target lives at a dead MAC, repeatedly, so traffic between them goes nowhere. It only lasts
while an enforcer (CLI `enforce` or the daemon) keeps sending, and restoring sends the true
MACs back. Firewall methods only work when this machine forwards the traffic (is the gateway).
"""

from __future__ import annotations

import logging
import subprocess
import threading
from typing import Callable

from netscan.macutil import normalise_mac
from netscan.monitor import BLOCKED, UNBLOCKED, Event
from netscan.safety import Scope
from netscan.store import Block, Store

log = logging.getLogger("netscan.blocker")

# locally administered address that no real device on the lan will own
DEAD_MAC = "02:de:ad:be:ef:01"
RESTORE_REPEATS = 5


class BlockError(Exception):
    pass


Runner = Callable[[list[str]], None]


def run_cmd(argv: list[str]) -> None:
    subprocess.run(argv, check=True, capture_output=True, text=True, timeout=15)


class IptablesBackend:
    CHAIN = "NETSCAN"

    def __init__(self, run: Runner = run_cmd):
        self.run = run

    def _has(self, argv: list[str]) -> bool:
        try:
            self.run(argv)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def _ensure(self) -> None:
        if not self._has(["iptables", "-nL", self.CHAIN]):
            self.run(["iptables", "-N", self.CHAIN])
        if not self._has(["iptables", "-C", "FORWARD", "-j", self.CHAIN]):
            self.run(["iptables", "-I", "FORWARD", "1", "-j", self.CHAIN])

    def block(self, mac: str, ip: str) -> None:
        self._ensure()
        for rule in (["-m", "mac", "--mac-source", mac], ["-s", ip], ["-d", ip]):
            if not self._has(["iptables", "-C", self.CHAIN, *rule, "-j", "DROP"]):
                self.run(["iptables", "-A", self.CHAIN, *rule, "-j", "DROP"])

    def unblock(self, mac: str, ip: str) -> None:
        for rule in (["-m", "mac", "--mac-source", mac], ["-s", ip], ["-d", ip]):
            while self._has(["iptables", "-C", self.CHAIN, *rule, "-j", "DROP"]):
                self.run(["iptables", "-D", self.CHAIN, *rule, "-j", "DROP"])


class NftablesBackend:
    """One set of blocked MACs and IPs plus a single drop rule, so unblock is just set removal."""

    def __init__(self, run: Runner = run_cmd):
        self.run = run

    def _ensure(self) -> None:
        r = self.run
        # `add` is meant to be idempotent, but tolerate older nft builds that report "File exists"
        for argv in (
            ["nft", "add", "table", "inet", "netscan"],
            ["nft", "add", "set", "inet", "netscan", "macs", "{ type ether_addr; }"],
            ["nft", "add", "set", "inet", "netscan", "ips", "{ type ipv4_addr; }"],
        ):
            try:
                r(argv)
            except subprocess.CalledProcessError as exc:
                if "exist" not in (exc.stderr or ""):
                    raise
        try:
            r(["nft", "list", "chain", "inet", "netscan", "forward"])
        except (subprocess.CalledProcessError, FileNotFoundError):
            r(["nft", "add", "chain", "inet", "netscan", "forward", "{ type filter hook forward priority -10; policy accept; }"])
            r(["nft", "add", "rule", "inet", "netscan", "forward", "ether", "saddr", "@macs", "drop"])
            r(["nft", "add", "rule", "inet", "netscan", "forward", "ip", "saddr", "@ips", "drop"])
            r(["nft", "add", "rule", "inet", "netscan", "forward", "ip", "daddr", "@ips", "drop"])

    def block(self, mac: str, ip: str) -> None:
        self._ensure()
        self.run(["nft", "add", "element", "inet", "netscan", "macs", f"{{ {mac} }}"])
        self.run(["nft", "add", "element", "inet", "netscan", "ips", f"{{ {ip} }}"])

    def unblock(self, mac: str, ip: str) -> None:
        for name, value in (("macs", mac), ("ips", ip)):
            try:
                self.run(["nft", "delete", "element", "inet", "netscan", name, f"{{ {value} }}"])
            except (subprocess.CalledProcessError, FileNotFoundError):
                log.debug("nft element %s already absent", value)


def make_firewall(method: str, run: Runner = run_cmd):
    return {"iptables": IptablesBackend, "nftables": NftablesBackend}.get(method, lambda run: None)(run=run)


class BlockManager:
    def __init__(self, store: Store, scope: Scope, method: str = "arp", firewall=None, now: Callable[[], float] | None = None):
        self.store = store
        self.scope = scope
        self.method = method
        self.firewall = firewall
        self._now = now

    def _resolve(self, ident: str):
        mac = normalise_mac(ident)
        dev = self.store.find_device(mac or ident)
        if dev is None:
            raise BlockError(f"unknown device {ident!r}; run `netscan scan` first so its MAC is known")
        return dev

    def block(self, ident: str, reason: str = "") -> tuple[Block, Event]:
        dev = self._resolve(ident)
        self.scope.check_blockable(dev.ip, dev.mac)  # raises OutOfScope / ProtectedTarget
        if self.firewall:
            self.firewall.block(dev.mac, dev.ip)
        self.store.add_block(dev.mac, dev.ip, self.method, reason, self._now() if self._now else None)
        ev = Event(BLOCKED, dev.mac, dev.ip, f"blocked ({self.method})", dev.vendor, dev.hostname)
        self.store.add_event(ev.kind, ev.mac, ev.ip, ev.message)
        return next(b for b in self.store.list_blocks() if b.mac == dev.mac), ev

    def unblock(self, ident: str, restore: Callable[[Block], None] | None = None) -> Event | None:
        mac = normalise_mac(ident)
        blk = next((b for b in self.store.list_blocks() if b.mac == mac or b.ip == ident), None)
        if blk is None:
            return None
        if self.firewall:
            self.firewall.unblock(blk.mac, blk.ip)
        self.store.remove_block(blk.mac)
        if restore:
            try:
                restore(blk)
            except Exception as exc:  # noqa: BLE001 best effort, the running enforcer also restores
                log.warning("could not send ARP restore now (%s); a running enforcer will do it", exc)
        dev = self.store.get_device(blk.mac)
        ev = Event(UNBLOCKED, blk.mac, blk.ip, "unblocked", dev.vendor if dev else "", dev.hostname if dev else "")
        self.store.add_event(ev.kind, ev.mac, ev.ip, ev.message)
        return ev

    def reapply(self) -> None:
        """After a reboot firewall rules are gone; replay persisted blocks."""
        if not self.firewall:
            return
        for blk in self.store.list_blocks():
            try:
                self.scope.check_blockable(blk.ip, blk.mac)
                self.firewall.block(blk.mac, blk.ip)
            except Exception as exc:  # noqa: BLE001
                log.error("could not re-apply block for %s: %s", blk.mac, exc)


class ArpEnforcer:
    """Keeps ARP cutoff alive for every persisted block; re-reads the db each tick."""

    def __init__(self, store: Store, scope: Scope, transport, interface: str, gateway_ip: str):
        self.store = store
        self.scope = scope
        self.transport = transport
        self.interface = interface
        self.gateway_ip = gateway_ip
        self._active: dict[str, str] = {}  # mac -> ip being poisoned
        self._gw_mac: str | None = None

    def _gateway_mac(self) -> str | None:
        if self._gw_mac is None:
            self._gw_mac = self.transport.resolve_mac(self.gateway_ip, self.interface)
        return self._gw_mac

    def _send_pair(self, ip: str, mac: str, gw_mac: str, gateway_at: str, target_at: str) -> None:
        """Tell the target where the gateway is, and the gateway where the target is."""
        # re-check at the point of sending, whatever the caller did
        self.scope.check_blockable(ip, mac)
        self.transport.send_arp_reply(self.interface, gateway_at, self.gateway_ip, mac, ip)
        self.transport.send_arp_reply(self.interface, target_at, ip, gw_mac, self.gateway_ip)

    def _current_ip(self, blk: Block) -> str:
        dev = self.store.get_device(blk.mac)
        return dev.ip if dev else blk.ip

    def tick(self) -> int:
        """One enforcement cycle; returns number of devices cut off."""
        wanted = {b.mac: self._current_ip(b) for b in self.store.list_blocks() if b.method == "arp"}
        for mac in [m for m in self._active if m not in wanted]:
            self._restore(mac, self._active.pop(mac))
        if not wanted:
            return 0
        gw_mac = self._gateway_mac()
        if not gw_mac:
            log.error("cannot resolve gateway MAC for %s; ARP cutoff paused", self.gateway_ip)
            return 0
        sent = 0
        for mac, ip in wanted.items():
            try:
                self._send_pair(ip, mac, gw_mac, DEAD_MAC, DEAD_MAC)
                self._active[mac] = ip
                sent += 1
            except Exception as exc:  # noqa: BLE001 one bad target must not stop the others
                log.error("ARP cutoff for %s (%s) refused/failed: %s", ip, mac, exc)
        return sent

    def _restore(self, mac: str, ip: str) -> None:
        gw_mac = self._gateway_mac()
        if not gw_mac:
            return
        for _ in range(RESTORE_REPEATS):
            self._send_pair(ip, mac, gw_mac, gw_mac, mac)

    def restore_block(self, blk: Block) -> None:
        """Used by `unblock` to heal caches immediately instead of waiting for ARP expiry."""
        self._restore(blk.mac, self._current_ip(blk))
        self._active.pop(blk.mac, None)

    def restore_all(self) -> None:
        for mac, ip in list(self._active.items()):
            try:
                self._restore(mac, ip)
            except Exception as exc:  # noqa: BLE001
                log.error("restore for %s failed: %s", mac, exc)
        self._active.clear()

    def run(self, stop: threading.Event, interval: float = 2.0) -> None:
        try:
            while not stop.is_set():
                self.tick()
                stop.wait(interval)
        finally:
            self.restore_all()
