"""Pi daemon: periodic sweeps, ARP watch for new devices, ARP cutoff enforcement, optional traffic capture."""

from __future__ import annotations

import logging
import signal
import threading

from netscan.blocker import DEAD_MAC, ArpEnforcer, BlockManager, make_firewall
from netscan.runtime import Runtime, sweep
from netscan.security import check_gateway_claim
from netscan.traffic import TrafficCollector, run_capture

log = logging.getLogger("netscan.daemon")


class Daemon:
    def __init__(self, rt: Runtime, stop: threading.Event | None = None):
        self.rt = rt
        self.stop = stop or threading.Event()
        self.enforcer = ArpEnforcer(rt.store, rt.scope, rt.transport, rt.local.interface, rt.scope.gateway_ip)
        self.blocks = BlockManager(rt.store, rt.scope, rt.cfg.block_method, make_firewall(rt.cfg.block_method))

    def sweep_once(self, now: float | None = None) -> int:
        """Sweep, mark stale devices offline, and dispatch alerts. Never raises."""
        try:
            _hosts, events = sweep(self.rt, now=now)
            events += self.rt.tracker.mark_offline(self.rt.cfg.daemon.offline_after, now)
        except Exception:  # noqa: BLE001 a failed sweep must not kill the daemon
            log.exception("sweep failed")
            return 0
        self.rt.alerter.dispatch(events)
        return len(events)

    def handle_arp(self, pkt) -> None:
        """ARP watch callback: any ARP frame names an ip/mac pair we can check against the inventory."""
        from scapy.layers.l2 import ARP

        if not pkt.haslayer(ARP):
            return
        arp = pkt[ARP]
        if arp.psrc in ("0.0.0.0", "") or not self.rt.scope.contains(arp.psrc):
            return
        from netscan.macutil import normalise_mac

        mac = normalise_mac(arp.hwsrc)
        # our own cutoff packets claim other hosts' ips at a dead mac; never record those as devices
        if not mac or mac == DEAD_MAC or (mac == self.rt.local.mac and arp.psrc != self.rt.local.ip):
            return
        try:
            spoof = check_gateway_claim(self.rt, arp.psrc, mac)
            if arp.psrc == self.rt.scope.gateway_ip and self.rt.gateway_mac and mac != self.rt.gateway_mac:
                # report it and do not record the gateway's address against the impostor
                if spoof:
                    self.rt.alerter.dispatch([spoof])
                return
            events = self.rt.tracker.observe_one(arp.psrc, mac)
        except Exception:  # noqa: BLE001
            log.exception("ARP watch failed to process a frame")
            return
        self.rt.alerter.dispatch(events)

    def handle_packet(self, pkt) -> None:
        """Watch callback: ARP frames check the inventory, DHCP requests teach us what the device calls itself."""
        from scapy.layers.dhcp import BOOTP
        from scapy.layers.l2 import ARP

        if pkt.haslayer(ARP):
            self.handle_arp(pkt)
        elif pkt.haslayer(BOOTP):
            self.handle_dhcp(pkt)

    def handle_dhcp(self, pkt) -> None:
        """A DHCP DISCOVER/REQUEST broadcast: keep the hostname, vendor class and option order the client announced."""
        from scapy.layers.dhcp import BOOTP, DHCP

        from netscan.discover.dhcpfp import parse_options
        from netscan.macutil import normalise_mac

        if not pkt.haslayer(DHCP) or pkt[BOOTP].op != 1:
            return
        mac = normalise_mac(":".join(f"{b:02x}" for b in bytes(pkt[BOOTP].chaddr)[:6]))
        if not mac or mac == self.rt.local.mac:
            return
        info = parse_options(pkt[DHCP].options)
        if not info:
            return
        try:
            store = self.rt.store
            if store.get_device(mac) is None and store.count_info("dhcp") >= store.MAX_DHCP_ROWS:
                return
            store.set_info(mac, "dhcp", info)
        except Exception:  # noqa: BLE001
            log.exception("DHCP watch failed to record a request")

    WATCH_FILTER = "arp or (udp and (port 67 or port 68))"

    def _loop_sweeps(self) -> None:
        while not self.stop.wait(self.rt.cfg.daemon.sweep_interval):
            self.sweep_once()

    def run(self) -> None:
        log.info(
            "netscan daemon starting on %s (%s), allowed %s, sweep every %ss",
            self.rt.local.interface, self.rt.local.network, [str(n) for n in self.rt.cfg.allowed_subnets], self.rt.cfg.daemon.sweep_interval,
        )
        self.blocks.reapply()
        # inventory first, so ARP watch and the baseline logic see the devices that already exist
        self.sweep_once()
        threads = [threading.Thread(target=self._loop_sweeps, name="netscan-sweep", daemon=True)]
        if self.rt.cfg.block_method == "arp":
            threads.append(threading.Thread(target=self.enforcer.run, args=(self.stop,), name="netscan-enforce", daemon=True))
        if self.rt.cfg.daemon.arp_watch:
            threads.append(
                threading.Thread(
                    target=self.rt.transport.sniff, args=(self.rt.local.interface, self.WATCH_FILTER, self.handle_packet, self.stop), name="netscan-arpwatch", daemon=True
                )
            )
        if self.rt.cfg.daemon.capture_traffic:
            collector = TrafficCollector(self.rt.store)
            threads.append(
                threading.Thread(target=run_capture, args=(self.rt.transport, self.rt.local.interface, collector, self.stop), name="netscan-capture", daemon=True)
            )
        for t in threads:
            t.start()
        self.stop.wait()
        log.info("netscan daemon stopping")
        for t in threads:
            t.join(timeout=10)


def install_signal_handlers(stop: threading.Event) -> None:
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
