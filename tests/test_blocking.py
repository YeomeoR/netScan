import subprocess

import pytest

from conftest import GW_IP, GW_MAC, PHONE, TV
from netscan.blocker import DEAD_MAC, ArpEnforcer, BlockError, BlockManager, IptablesBackend, NftablesBackend, make_firewall
from netscan.parsing import Host
from netscan.runtime import build_runtime
from netscan.store import Store


def test_block_state_survives_restart(tmp_path, cfg, fake):
    rt1 = build_runtime(cfg, fake)
    rt1.tracker.observe([PHONE, TV], now=1)
    BlockManager(rt1.store, rt1.scope).block(PHONE.ip, "bedtime")
    rt1.store.close()

    reopened = Store(cfg.db_path)
    blocks = reopened.list_blocks()
    assert [(b.mac, b.ip, b.method, b.reason) for b in blocks] == [(PHONE.mac, PHONE.ip, "arp", "bedtime")], (
        "block must persist across processes"
    )
    assert reopened.is_blocked(PHONE.mac) and not reopened.is_blocked(TV.mac)
    reopened.close()


def test_unblock_removes_persisted_state_and_is_idempotent(rt):
    rt.tracker.observe([PHONE], now=1)
    mgr = BlockManager(rt.store, rt.scope)
    mgr.block(PHONE.mac)
    assert mgr.unblock(PHONE.ip).kind == "unblocked"
    assert rt.store.list_blocks() == [], "unblock must delete the stored block"
    assert mgr.unblock(PHONE.ip) is None, "unblocking an unblocked device is a no-op"


def test_block_unknown_device_is_an_error_not_a_guess(rt):
    with pytest.raises(BlockError):
        BlockManager(rt.store, rt.scope).block("192.168.1.200")


def test_block_by_mac_case_insensitive(rt):
    rt.tracker.observe([PHONE], now=1)
    BlockManager(rt.store, rt.scope).block(PHONE.mac.upper())
    assert rt.store.is_blocked(PHONE.mac)


def test_arp_enforcer_cuts_off_target_and_gateway_with_dead_mac(rt, fake):
    rt.tracker.observe([PHONE], now=1)
    BlockManager(rt.store, rt.scope).block(PHONE.ip)
    enforcer = ArpEnforcer(rt.store, rt.scope, rt.transport, "en0", GW_IP)
    assert enforcer.tick() == 1
    assert fake.sent == [
        (DEAD_MAC, GW_IP, PHONE.mac, PHONE.ip),  # target is told the gateway is at a dead mac
        (DEAD_MAC, PHONE.ip, GW_MAC, GW_IP),  # gateway is told the target is at a dead mac
    ]


def test_arp_enforcer_restores_true_macs_when_block_removed(rt, fake):
    rt.tracker.observe([PHONE], now=1)
    mgr = BlockManager(rt.store, rt.scope)
    mgr.block(PHONE.ip)
    enforcer = ArpEnforcer(rt.store, rt.scope, rt.transport, "en0", GW_IP)
    enforcer.tick()
    fake.sent.clear()
    mgr.unblock(PHONE.ip)  # another process (CLI) removes the block
    enforcer.tick()
    assert (GW_MAC, GW_IP, PHONE.mac, PHONE.ip) in fake.sent, "target must get the real gateway mac back"
    assert (PHONE.mac, PHONE.ip, GW_MAC, GW_IP) in fake.sent, "gateway must get the real target mac back"
    assert DEAD_MAC not in [s[0] for s in fake.sent]
    fake.sent.clear()
    enforcer.tick()
    assert fake.sent == [], "nothing is sent once restored and nothing is blocked"


def test_enforcer_never_poisons_protected_hosts_even_if_db_is_tampered(rt, fake):
    rt.store.add_block(GW_MAC, GW_IP, "arp", "tampered")
    rt.store.add_block("aa:bb:cc:dd:ee:ff", "8.8.8.8", "arp", "outside")
    enforcer = ArpEnforcer(rt.store, rt.scope, rt.transport, "en0", GW_IP)
    assert enforcer.tick() == 0
    assert fake.sent == [], "gateway and out-of-scope rows must never produce packets"


def test_enforcer_pauses_when_gateway_mac_unknown(rt, fake):
    rt.tracker.observe([PHONE], now=1)
    BlockManager(rt.store, rt.scope).block(PHONE.ip)
    fake.macs.clear()
    assert ArpEnforcer(rt.store, rt.scope, rt.transport, "en0", GW_IP).tick() == 0
    assert fake.sent == []


def test_enforcer_restore_all_on_shutdown(rt, fake):
    rt.tracker.observe([PHONE, TV], now=1)
    mgr = BlockManager(rt.store, rt.scope)
    mgr.block(PHONE.ip)
    mgr.block(TV.ip)
    enforcer = ArpEnforcer(rt.store, rt.scope, rt.transport, "en0", GW_IP)
    enforcer.tick()
    fake.sent.clear()
    enforcer.restore_all()
    assert {s[3] for s in fake.sent} >= {PHONE.ip, TV.ip}
    assert DEAD_MAC not in [s[0] for s in fake.sent]


def test_enforcer_follows_ip_change_of_blocked_mac(rt, fake):
    rt.tracker.observe([PHONE], now=1)
    BlockManager(rt.store, rt.scope).block(PHONE.mac)
    rt.tracker.observe([Host("192.168.1.55", PHONE.mac)], now=2)  # dhcp renewed
    ArpEnforcer(rt.store, rt.scope, rt.transport, "en0", GW_IP).tick()
    assert fake.sent[0][3] == "192.168.1.55", "block is by MAC, so the new ip must be targeted"


class Recorder:
    """Stateful stand-in for the iptables/nft binaries."""

    def __init__(self):
        self.calls = []
        self.rules = set()
        self.chains = set()
        self.nft_chain = False

    def __call__(self, argv):
        self.calls.append(list(argv))
        tool, op, rest = argv[0], argv[1], tuple(argv[2:])
        if tool == "iptables":
            if op == "-nL" and rest[0] not in self.chains:
                raise subprocess.CalledProcessError(1, argv)
            if op == "-C" and rest not in self.rules:
                raise subprocess.CalledProcessError(1, argv)
            if op == "-N":
                self.chains.add(rest[0])
            elif op == "-A":
                self.rules.add(rest)
            elif op == "-I":
                self.rules.add((rest[0],) + rest[2:])
            elif op == "-D":
                self.rules.discard(rest)
        elif tool == "nft":
            if op == "list" and not self.nft_chain:
                raise subprocess.CalledProcessError(1, argv)
            if op == "add" and rest[0] == "chain":
                self.nft_chain = True


def test_nftables_backend_uses_set_membership():
    rec = Recorder()
    fw = NftablesBackend(run=rec)
    fw.block("00:11:22:33:44:55", "192.168.1.20")
    assert ["nft", "add", "element", "inet", "netscan", "macs", "{ 00:11:22:33:44:55 }"] in rec.calls
    assert ["nft", "add", "element", "inet", "netscan", "ips", "{ 192.168.1.20 }"] in rec.calls
    assert any(c[:4] == ["nft", "add", "rule", "inet"] and "drop" in c for c in rec.calls), "drop rules created"
    fw.unblock("00:11:22:33:44:55", "192.168.1.20")
    assert ["nft", "delete", "element", "inet", "netscan", "macs", "{ 00:11:22:33:44:55 }"] in rec.calls


def test_iptables_backend_adds_and_removes_drop_rules():
    rec = Recorder()
    fw = IptablesBackend(run=rec)
    fw.block("00:11:22:33:44:55", "192.168.1.20")
    adds = [c for c in rec.calls if c[:2] == ["iptables", "-A"]]
    assert len(adds) == 3 and all(c[-1] == "DROP" for c in adds), "mac, source ip and dest ip rules"
    fw.block("00:11:22:33:44:55", "192.168.1.20")
    assert len([c for c in rec.calls if c[:2] == ["iptables", "-A"]]) == 3, "blocking twice must not duplicate rules"
    fw.unblock("00:11:22:33:44:55", "192.168.1.20")
    assert len([c for c in rec.calls if c[:2] == ["iptables", "-D"]]) == 3


def test_firewall_failure_does_not_persist_a_block(rt):
    def boom(argv):
        raise subprocess.CalledProcessError(1, argv)

    rt.tracker.observe([PHONE], now=1)
    mgr = BlockManager(rt.store, rt.scope, "nftables", NftablesBackend(run=boom))
    with pytest.raises(subprocess.CalledProcessError):
        mgr.block(PHONE.ip)
    assert rt.store.list_blocks() == [], "if enforcement fails, state must not claim the device is blocked"


def test_reapply_replays_persisted_firewall_blocks_after_reboot(rt):
    rt.tracker.observe([PHONE], now=1)
    rec = Recorder()
    mgr = BlockManager(rt.store, rt.scope, "nftables", NftablesBackend(run=rec))
    mgr.block(PHONE.ip)
    rec.calls.clear()
    mgr.reapply()
    assert ["nft", "add", "element", "inet", "netscan", "macs", f"{{ {PHONE.mac} }}"] in rec.calls


def test_make_firewall_selection():
    assert make_firewall("arp") is None
    assert isinstance(make_firewall("iptables"), IptablesBackend)
    assert isinstance(make_firewall("nftables"), NftablesBackend)


def test_nftables_tolerates_existing_objects_but_not_real_failures():
    class Exists(Recorder):
        def __call__(self, argv):
            super().__call__(argv)
            if argv[:3] == ["nft", "add", "table"] or argv[:3] == ["nft", "add", "set"]:
                raise subprocess.CalledProcessError(1, argv, stderr="Error: File exists")

    NftablesBackend(run=Exists()).block("00:11:22:33:44:55", "192.168.1.20")

    class Denied(Recorder):
        def __call__(self, argv):
            super().__call__(argv)
            if argv[:3] == ["nft", "add", "table"]:
                raise subprocess.CalledProcessError(1, argv, stderr="Operation not permitted")

    with pytest.raises(subprocess.CalledProcessError):
        NftablesBackend(run=Denied()).block("00:11:22:33:44:55", "192.168.1.20")


def test_two_nftables_blocks_both_persist(rt):
    rt.tracker.observe([PHONE, TV], now=1)
    mgr = BlockManager(rt.store, rt.scope, "nftables", NftablesBackend(run=Recorder()))
    mgr.block(PHONE.ip)
    mgr.block(TV.ip)
    assert {b.mac for b in rt.store.list_blocks()} == {PHONE.mac, TV.mac}
