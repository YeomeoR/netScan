"""End-to-end through the CLI entry point with a fake transport (no real network)."""

from __future__ import annotations

import pytest
from rich.console import Console

from conftest import GW_IP, GW_MAC, HOST_IP, PHONE, TV, FakeTransport
from netscan import cli
from netscan.blocker import DEAD_MAC
from netscan.config import render_config
from netscan.store import Store


@pytest.fixture(autouse=True)
def wide_console(monkeypatch):
    monkeypatch.setattr(cli, "console", Console(width=220, height=50))
    monkeypatch.setattr(cli, "err", Console(width=220, height=50, stderr=True))


@pytest.fixture
def home(tmp_path):
    (tmp_path / "config.toml").write_text(render_config(["192.168.1.0/24"]))
    return tmp_path


def run(home, *args, transport=None):
    transport = transport or FakeTransport()
    rc = cli.main(["--home", str(home), "--accept-terms", *args], transport=transport)
    return rc, transport


def test_init_writes_detected_subnet_and_validates_override(tmp_path, capsys):
    rc, _ = run(tmp_path, "init")
    assert rc == 0
    assert '"192.168.1.0/24"' in (tmp_path / "config.toml").read_text(), "init defaults to the detected local subnet"
    assert run(tmp_path, "init")[0] == 1, "refuses to overwrite without --force"
    assert run(tmp_path, "init", "--force", "--subnet", "8.8.8.0/24")[0] == 2, "public subnet can never enter the allow-list"
    assert '"192.168.1.0/24"' in (tmp_path / "config.toml").read_text(), "rejected init leaves the old config intact"


def test_scan_then_list_shows_devices_in_table(home, capsys):
    rc, fake = run(home, "scan", "--no-hostnames")
    assert rc == 0 and fake.sweeps, "scan performs a sweep"
    out = capsys.readouterr().out
    for needle in (PHONE.ip, PHONE.mac, "Raspberry", "online", HOST_IP):
        assert needle in out, f"scan table must show {needle}"
    assert run(home, "list")[0] == 0
    assert PHONE.mac in capsys.readouterr().out, "list reads persisted devices without scanning"


def test_second_scan_reports_new_device_and_offline(home, capsys):
    run(home, "scan", "--no-hostnames")
    capsys.readouterr()
    t = FakeTransport(hosts=[h for h in FakeTransport().hosts if h.mac != PHONE.mac] + [TV.__class__("192.168.1.31", "00:aa:bb:cc:dd:ee")])
    run(home, "scan", "--no-hostnames", transport=t)
    cap = capsys.readouterr()
    assert "new_device" in cap.err and "192.168.1.31" in cap.err, "new device must be announced on the terminal/log"
    assert "offline" in cap.out, "table shows the missing device as offline"
    store = Store(home / "netscan.db")
    assert store.get_device(PHONE.mac).online is False, "device missing from a scan is marked offline"
    store.close()


def test_block_unblock_roundtrip_via_cli_and_persistence(home, capsys):
    run(home, "scan", "--no-hostnames")
    rc, _ = run(home, "block", PHONE.ip, "--reason", "test")
    assert rc == 0
    out = capsys.readouterr().out
    assert "Blocked" in out and "enforce" in out
    assert run(home, "blocks")[0] == 0 and PHONE.mac in capsys.readouterr().out, "a new process sees the persisted block"
    run(home, "list")
    assert "BLOCKED" in capsys.readouterr().out

    rc, fake = run(home, "unblock", PHONE.ip)
    assert rc == 0
    assert (GW_MAC, GW_IP, PHONE.mac, PHONE.ip) in fake.sent, "unblock heals the target's ARP cache straight away"
    assert Store(home / "netscan.db").list_blocks() == []
    assert run(home, "unblock", PHONE.ip)[0] == 1, "unblocking something not blocked reports failure"


def test_cli_refuses_to_block_gateway_and_host(home, capsys):
    run(home, "scan", "--no-hostnames")
    for target in (GW_IP, GW_MAC, HOST_IP):
        rc, fake = run(home, "block", target)
        assert rc == 2, f"blocking {target} must be refused"
        assert fake.sent == []
    assert Store(home / "netscan.db").list_blocks() == []
    assert "never blocked" in capsys.readouterr().err


def test_block_unknown_target_fails_cleanly(home):
    run(home, "scan", "--no-hostnames")
    assert run(home, "block", "192.168.1.250")[0] == 1
    assert run(home, "block", "8.8.8.8")[0] == 1, "not in inventory"


def test_enforce_command_sends_cutoff_then_restores_on_stop(home, monkeypatch):
    run(home, "scan", "--no-hostnames")
    run(home, "block", PHONE.ip)
    fake = FakeTransport()
    import threading

    original = threading.Event.wait
    calls = {"n": 0}

    def wait_once(self, timeout=None):
        calls["n"] += 1
        if calls["n"] >= 2:
            self.set()
        return original(self, 0)

    monkeypatch.setattr(threading.Event, "wait", wait_once)
    assert cli.main(["--home", str(home), "--accept-terms", "enforce"], transport=fake) == 0
    macs = [s[0] for s in fake.sent]
    assert DEAD_MAC in macs and GW_MAC in macs, "cut off while running and restored on exit"
    assert macs.index(DEAD_MAC) < macs.index(GW_MAC)


def test_events_and_show_commands(home, capsys):
    run(home, "scan", "--no-hostnames")
    capsys.readouterr()
    assert run(home, "events")[0] == 0
    assert "baseline" in capsys.readouterr().out
    assert run(home, "show", PHONE.mac)[0] == 0
    assert "No traffic recorded" in capsys.readouterr().out
    assert run(home, "show", "192.168.1.201")[0] == 1


def test_format_helpers():
    assert cli.fmt_bytes(0) == "0 B" and cli.fmt_bytes(2048) == "2.0 KB" and cli.fmt_bytes(5 * 1024**3) == "5.0 GB"
