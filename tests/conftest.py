"""Shared fixtures. No test touches the real network: all wire I/O goes through FakeTransport."""

from __future__ import annotations

import ipaddress

import pytest

from netscan.config import Config
from netscan.net import LocalNet
from netscan.parsing import Host
from netscan.runtime import build_runtime

HOST_IP, HOST_MAC = "192.168.1.10", "aa:aa:aa:00:00:10"
GW_IP, GW_MAC = "192.168.1.1", "aa:aa:aa:00:00:01"
PHONE = Host("192.168.1.20", "b8:27:eb:00:00:20")
TV = Host("192.168.1.30", "3c:5a:b4:00:00:30")


class FakeTransport:
    def __init__(self, hosts=None, network="192.168.1.0/24", local_ip=HOST_IP, gateway=GW_IP, mac=HOST_MAC):
        self.local = LocalNet("en0", local_ip, mac, ipaddress.ip_network(network), gateway)
        self.hosts = list(hosts if hosts is not None else [Host(GW_IP, GW_MAC), PHONE, TV])
        self.macs = {h.ip: h.mac for h in self.hosts}
        self.sent: list[tuple] = []
        self.sweeps: list = []
        self.sniffed: list = []
        self.dhcp_offers: list = []

    def local_net(self, interface=""):
        return self.local

    def local_ips(self):
        return {self.local.ip}

    def arp_sweep(self, network, interface, timeout):
        self.sweeps.append(network)
        return list(self.hosts)

    def send_arp_reply(self, interface, hwsrc, psrc, hwdst, pdst):
        self.sent.append((hwsrc, psrc, hwdst, pdst))

    def resolve_mac(self, ip, interface):
        return self.macs.get(ip)

    def dhcp_discover(self, interface, timeout):
        return list(self.dhcp_offers)

    def sniff(self, interface, bpf, callback, stop):
        for pkt in self.sniffed:
            callback(pkt)


@pytest.fixture
def fake():
    return FakeTransport()


@pytest.fixture
def cfg(tmp_path):
    return Config(allowed_subnets=[ipaddress.ip_network("192.168.1.0/24")], home=tmp_path)


@pytest.fixture
def rt(cfg, fake):
    runtime = build_runtime(cfg, fake, resolve_hostname=lambda ip: f"host-{ip.rsplit('.', 1)[1]}")
    yield runtime
    runtime.store.close()
