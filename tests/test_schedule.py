import time

import pytest

from netscan.store import Store
from netscan.web.demo import DemoTransport, demo_setup
from netscan.web.schedule import MIN_INTERVAL, next_daily, normalise_sweep_params, parse_hhmm


def test_parse_hhmm():
    assert parse_hhmm("03:05") == (3, 5) and parse_hhmm(" 23:59 ") == (23, 59)
    for bad in ("24:00", "3", "ab:cd", "12:60", ""):
        with pytest.raises(ValueError):
            parse_hhmm(bad)


def test_next_daily_is_strictly_future_and_rolls_over_days():
    now = time.mktime((2026, 3, 31, 23, 30, 0, 0, 0, -1))
    nxt = next_daily(now, "00:15")
    assert time.localtime(nxt)[:5] == (2026, 4, 1, 0, 15), "rolls into the next month"
    same_day = next_daily(now, "23:45")
    assert time.localtime(same_day)[:5] == (2026, 3, 31, 23, 45)
    at_exact = time.mktime((2026, 3, 31, 12, 0, 0, 0, 0, -1))
    assert next_daily(at_exact, "12:00") > at_exact + 3600 * 23, "exactly now means tomorrow, not an immediate re-fire"


def test_sweep_param_defaults_and_bounds():
    p = normalise_sweep_params(None, 900)
    assert p == {"timeout": 3.0, "hostnames": True, "offline_after": 900, "capture_seconds": 0, "flush": 5.0}
    assert normalise_sweep_params({"timeout": 10, "offline_after": 0}, 900)["offline_after"] == 0
    for bad in ({"timeout": 0.5}, {"timeout": True}, {"hostnames": 1}, {"capture_seconds": -1}, {"flush": 100}, "nope"):
        with pytest.raises(ValueError):
            normalise_sweep_params(bad)
    assert MIN_INTERVAL == 30


def test_store_schedule_and_job_roundtrip(tmp_path):
    s = Store(tmp_path / "x.db")
    sc = s.add_schedule("A", "interval", 60, "", None, {"timeout": 2}, 100.0, now=1.0)
    assert s.due_schedules(99) == [] and [x.id for x in s.due_schedules(100)] == [sc.id]
    s.update_schedule(sc.id, enabled=False)
    assert s.due_schedules(1000) == [], "disabled schedules never fire"
    with pytest.raises(ValueError):
        s.update_schedule(sc.id, id=5)
    j1 = s.add_job("sweep", {}, "manual")
    j2 = s.add_job("sweep", {}, "schedule:1")
    s.update_job(j1.id, state="running")
    assert [j.id for j in s.active_jobs()] == [j1.id, j2.id] and [j.id for j in s.active_jobs("schedule:1")] == [j2.id]
    assert s.interrupt_stale_jobs() == 2 and s.active_jobs() == []
    for _ in range(5):
        s.add_job("sweep", {})
    s.prune_jobs(keep=3)
    assert len(s.recent_jobs(50)) == 3
    s.close()


def test_demo_transport_is_self_contained():
    cfg, transport, resolver = demo_setup()
    assert str(cfg.allowed_subnets[0]) == "192.168.77.0/24" and cfg.home.name.startswith("netscan-demo-")
    first = transport.arp_sweep(transport.local.network, "demo0", 0.0)
    for _ in range(3):
        later = transport.arp_sweep(transport.local.network, "demo0", 0.0)
    assert "192.168.77.99" not in {h.ip for h in first} and "192.168.77.99" in {h.ip for h in later}, "a new device shows up after a few sweeps"
    assert resolver("192.168.77.1") == "router.lan"
