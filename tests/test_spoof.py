"""Temporary MAC change: the commands that would run, the guards, restore and expiry. No real interface is touched."""

from __future__ import annotations

import time

import pytest

from conftest import GW_MAC, HOST_MAC, PHONE
from netscan.spoof import SpoofError, Spoofer
from netscan.web.controller import ApiError
from test_web import make_ctl, home, wait_store  # noqa: F401 fixtures

TARGET = "3c:5a:b4:aa:bb:cc"


class FakeNic:
    """Behaves like `ip link` / `ifconfig` for one interface, and records every command."""

    def __init__(self, platform="linux", mac=HOST_MAC, refuse=False, ignore_change=False):
        self.platform, self.mac, self.refuse, self.ignore_change = platform, mac, refuse, ignore_change
        self.cmds: list[list[str]] = []

    def __call__(self, cmd):
        self.cmds.append(cmd)
        if cmd[:3] == ["ip", "-o", "link"]:
            return 0, f"2: en0: <BROADCAST> mtu 1500 state UP\\    link/ether {self.mac} brd ff:ff:ff:ff:ff:ff"
        if cmd[:2] == ["ifconfig", "en0"] and len(cmd) == 2:
            return 0, f"en0: flags=8863<UP>\n\tether {self.mac}\n\tinet 192.168.1.10"
        if self.refuse and ("address" in cmd or "ether" in cmd):
            return 1, "Operation not permitted"
        if "address" in cmd and not self.ignore_change:
            self.mac = cmd[cmd.index("address") + 1]
        if "ether" in cmd and not self.ignore_change:
            self.mac = cmd[cmd.index("ether") + 1]
        return 0, ""


def spoofer(store, nic, **kw):
    return Spoofer(store, nic, platform=nic.platform, settle=0, **kw)


@pytest.fixture
def ctl(home):
    c = make_ctl(home)
    nic = FakeNic()
    c.spoofer = spoofer(c.store, nic)
    c.nic = nic
    c.start()
    yield c
    c.close()


def test_linux_change_and_restore_run_the_right_commands(home):
    c = make_ctl(home)
    nic = FakeNic()
    sp = spoofer(c.store, nic)
    state = sp.apply("en0", TARGET.upper(), 30)
    assert nic.mac == TARGET and state["original"] == HOST_MAC and state["spoofed"] == TARGET
    assert ["ip", "link", "set", "dev", "en0", "address", TARGET] in nic.cmds
    assert nic.cmds.index(["ip", "link", "set", "dev", "en0", "down"]) < nic.cmds.index(["ip", "link", "set", "dev", "en0", "address", TARGET])
    done = sp.restore()
    assert nic.mac == HOST_MAC and done["spoofed"] == TARGET and sp.state() is None
    with pytest.raises(SpoofError):
        sp.restore()
    c.close()


def test_changing_twice_keeps_the_real_original(home):
    c = make_ctl(home)
    nic = FakeNic()
    sp = spoofer(c.store, nic)
    sp.apply("en0", TARGET, 30)
    sp.apply("en0", "3c:5a:b4:00:00:99", 10)
    assert sp.state()["original"] == HOST_MAC
    sp.restore()
    assert nic.mac == HOST_MAC
    c.close()


def test_macos_uses_ifconfig(home):
    c = make_ctl(home)
    nic = FakeNic(platform="darwin")
    sp = spoofer(c.store, nic)
    sp.apply("en0", TARGET, 5)
    assert ["ifconfig", "en0", "ether", TARGET] in nic.cmds
    sp.restore()
    assert nic.mac == HOST_MAC
    c.close()


def test_refusals(home):
    c = make_ctl(home)
    nic = FakeNic()
    sp = spoofer(c.store, nic)
    for bad in ("nonsense", "01:00:5e:00:00:01", "ff:ff:ff:ff:ff:ff", ""):
        with pytest.raises(SpoofError):
            sp.apply("en0", bad, 5)
    with pytest.raises(SpoofError):
        sp.apply("en0", GW_MAC, 5, forbidden={GW_MAC})
    with pytest.raises(SpoofError):
        sp.apply("en0", TARGET, 0)
    with pytest.raises(SpoofError):
        sp.apply("en0", TARGET, 9999)
    with pytest.raises(SpoofError):
        sp.apply("en0", HOST_MAC, 5)
    with pytest.raises(SpoofError):
        sp.apply("en0;reboot", TARGET, 5)
    with pytest.raises(SpoofError):
        Spoofer(c.store, nic, platform="win32").apply("en0", TARGET, 5)
    assert sp.state() is None and nic.mac == HOST_MAC
    c.close()


def test_failed_change_leaves_nothing_saved_and_brings_the_link_up(home):
    c = make_ctl(home)
    nic = FakeNic(refuse=True)
    sp = spoofer(c.store, nic)
    with pytest.raises(SpoofError, match="CAP_NET_ADMIN|permitted"):
        sp.apply("en0", TARGET, 5)
    assert sp.state() is None
    assert ["ip", "link", "set", "dev", "en0", "up"] in nic.cmds
    quiet = FakeNic(ignore_change=True)
    with pytest.raises(SpoofError, match="did not accept"):
        spoofer(c.store, quiet).apply("en0", TARGET, 5)
    assert spoofer(c.store, quiet).state() is None
    c.close()


def test_reconcile_drops_a_change_that_a_reboot_undid(home):
    c = make_ctl(home)
    nic = FakeNic()
    sp = spoofer(c.store, nic)
    sp.apply("en0", TARGET, 30)
    sp.reconcile()
    assert sp.state() is not None
    nic.mac = HOST_MAC
    sp.reconcile()
    assert sp.state() is None
    c.close()


def test_api_change_then_restore(ctl):
    assert ctl.status()["spoof"]["active"] is False
    job = wait_store(ctl, ctl.submit_spoof({"mac": TARGET, "minutes": 15})["id"])
    assert job.state == "done", job.error
    st = ctl.status()["spoof"]
    assert st["active"] and st["spoofed"] == TARGET and st["original"] == HOST_MAC and 0 < st["seconds_left"] <= 900
    assert ctl.nic.mac == TARGET
    assert ctl._runtime().local.interface == "en0"
    kinds = [e["kind"] for e in ctl.events(10)]
    assert "mac_spoof" in kinds
    wait_store(ctl, ctl.submit_unspoof()["id"])
    assert ctl.nic.mac == HOST_MAC and ctl.status()["spoof"]["active"] is False
    assert "mac_restore" in [e["kind"] for e in ctl.events(10)]
    with pytest.raises(ApiError) as exc:
        ctl.submit_unspoof()
    assert exc.value.status == 409


def test_api_guards(ctl):
    ctl.store.upsert_device(PHONE.mac, PHONE.ip, "Apple", "iphone", time.time())
    with pytest.raises(ApiError) as exc:
        ctl.submit_spoof({"mac": PHONE.mac, "minutes": 5})
    assert exc.value.status == 409 and "online" in exc.value.message
    with pytest.raises(ApiError) as exc:
        ctl.submit_spoof({"mac": GW_MAC, "minutes": 5})
    assert exc.value.status == 400 and "router" in exc.value.message
    for body in ({"mac": TARGET, "minutes": 0}, {"mac": TARGET, "minutes": "5"}, {"mac": TARGET, "minutes": True}, {"mac": "zz"}, [1]):
        with pytest.raises(ApiError) as exc:
            ctl.submit_spoof(body)
        assert exc.value.status == 400
    ctl.store.add_block(PHONE.mac, PHONE.ip, "arp", "", time.time())
    with pytest.raises(ApiError) as exc:
        ctl.submit_spoof({"mac": PHONE.mac, "minutes": 5, "confirm": True})
    assert exc.value.status == 409 and "blocked" in exc.value.message
    ctl.store.remove_block(PHONE.mac)
    assert ctl.nic.mac == HOST_MAC
    out = wait_store(ctl, ctl.submit_spoof({"mac": PHONE.mac, "minutes": 5, "confirm": True})["id"])
    assert out.state == "done" and ctl.nic.mac == PHONE.mac


def test_expiry_restores_automatically(ctl):
    wait_store(ctl, ctl.submit_spoof({"mac": TARGET, "minutes": 1})["id"])
    ctl.spoof_tick()
    assert ctl.status()["spoof"]["active"]
    ctl.clock = lambda: time.time() + 3600
    ctl.spoofer.clock = ctl.clock
    ctl.spoof_tick()
    job = next(j for j in ctl.store.recent_jobs(5) if j.kind == "unspoof")
    assert job.source == "auto" and wait_store(ctl, job.id).state == "done"
    assert ctl.nic.mac == HOST_MAC and not ctl.status()["spoof"]["active"]


def test_unsupported_and_demo(home):
    c = make_ctl(home)
    c.spoofer.disabled_reason = "off in demo"
    assert c.status()["spoof"]["supported"] is False
    with pytest.raises(ApiError) as exc:
        c.submit_spoof({"mac": TARGET})
    assert exc.value.status == 409 and "demo" in exc.value.message
    c.close()
