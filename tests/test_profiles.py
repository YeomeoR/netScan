import time

import pytest

from conftest import GW_MAC, PHONE, FakeTransport
from netscan.config import load_config, render_config
from netscan.parsing import Host
from netscan.profiles import ID_PATTERN, legacy_home, network_db_path, network_id, open_store
from netscan.runtime import build_runtime, sweep
from netscan.store import Store
from test_web import FakeWifi, make_ctl

HOME_GW = GW_MAC
FRIEND_GW = "bb:bb:bb:00:50:01"
FRIEND_HOST = Host("192.168.50.20", "cc:cc:cc:00:50:20")


def friend_transport():
    return FakeTransport(hosts=[Host("192.168.50.1", FRIEND_GW), FRIEND_HOST], network="192.168.50.0/24", local_ip="192.168.50.7", gateway="192.168.50.1")


@pytest.fixture
def follow_cfg(tmp_path):
    (tmp_path / "config.toml").write_text(render_config(["192.168.1.0/24"], HOME_GW, follow=True))
    return load_config(None, tmp_path)


def macs(store):
    return {d.mac for d in store.list_devices()}


def test_network_id_prefers_the_router_mac_and_falls_back_to_the_subnet():
    assert network_id("AA:BB:CC:00:11:22", "192.168.1.0/24") == "gw-aabbcc001122", "the router's MAC must name the network"
    assert network_id("", "192.168.1.0/24") == "net-192-168-1-0-24", "without a router MAC the subnet names it"
    assert network_id("not a mac", "10.0.0.0/24") == "net-10-0-0-0-24"
    assert ID_PATTERN.fullmatch(network_id("", "192.168.1.0/24")), "ids must be safe to use as file names"


def test_network_db_path_refuses_ids_that_could_leave_the_folder(follow_cfg):
    for bad in ("../x", "a/b", "", "Gw-1", "x" * 80):
        with pytest.raises(ValueError):
            network_db_path(follow_cfg, bad)
    assert network_db_path(follow_cfg, "gw-1").parent.name == "networks"


def test_attached_networks_keep_their_own_devices_but_share_jobs_and_settings(tmp_path):
    store = Store(tmp_path / "netscan.db")
    store.attach_network("home", tmp_path / "networks" / "home.db")
    store.upsert_device("aa:aa:aa:00:00:01", "192.168.1.1", "", "", 1.0)
    store.set_setting("ntfy", {"topic": "t"})
    store.add_job("sweep", {}, "manual", 1.0)
    store.attach_network("friend", tmp_path / "networks" / "friend.db")
    assert macs(store) == set(), "a new network must start with an empty device list"
    assert store.get_setting("ntfy") == {"topic": "t"}, "settings are shared between networks"
    assert len(store.recent_jobs(10)) == 1, "jobs are shared between networks"
    store.upsert_device("cc:cc:cc:00:50:20", "192.168.50.20", "", "", 2.0)
    store.add_event("new_device", "cc:cc:cc:00:50:20", "192.168.50.20", "x")
    store.attach_network("home", tmp_path / "networks" / "home.db")
    assert macs(store) == {"aa:aa:aa:00:00:01"}, "going back must show the first network's devices only"
    assert store.recent_events(10) == [], "events are per network too"
    assert Store.count_devices_in(tmp_path / "networks" / "friend.db") == 1, "other networks can be counted without attaching"
    assert Store.count_devices_in(tmp_path / "networks" / "missing.db") == 0


def test_data_from_before_per_network_files_moves_to_the_pinned_home_network(tmp_path):
    store = Store(tmp_path / "netscan.db")
    store.upsert_device("aa:aa:aa:00:00:01", "192.168.1.1", "", "", 1.0)
    store.add_block("aa:aa:aa:00:00:01", "192.168.1.1", "arp", "r", 1.0)
    store.set_setting("keep", 1)
    home_db = tmp_path / "networks" / "gw-home.db"
    store.attach_network("friend", tmp_path / "networks" / "friend.db", ("gw-home", home_db))
    assert macs(store) == set(), "the first network we land on must not inherit the home devices"
    assert Store.count_devices_in(home_db) == 1, "old data belongs to the home network, wherever we first land"
    store.attach_network("gw-home", home_db)
    assert macs(store) == {"aa:aa:aa:00:00:01"} and len(store.list_blocks()) == 1, "devices and blocks must follow the move"
    assert store.get_setting("keep") == 1
    assert {n["id"] for n in store.list_networks()} == {"gw-home"}, "the home network is noted as the original one"
    store.close()
    again = Store(tmp_path / "netscan.db")
    again.attach_network("gw-home", home_db)
    assert macs(again) == {"aa:aa:aa:00:00:01"}, "reopening must not bring bare tables back that shadow the network's"
    again.close()


def test_legacy_data_lands_on_the_current_network_when_no_router_is_pinned(tmp_path):
    store = Store(tmp_path / "netscan.db")
    store.upsert_device("aa:aa:aa:00:00:01", "192.168.1.1", "", "", 1.0)
    store.attach_network("here", tmp_path / "networks" / "here.db")
    assert macs(store) == {"aa:aa:aa:00:00:01"}, "without a pinned home, existing data goes to the network we are on"


def test_open_store_returns_to_the_network_the_last_run_was_on(follow_cfg):
    first = open_store(follow_cfg)
    assert first.network_path is None, "a fresh install stays in single-file mode"
    first.attach_network("gw-aabbcc", network_db_path(follow_cfg, "gw-aabbcc"))
    first.upsert_device("aa:aa:aa:00:00:09", "192.168.1.9", "", "", 1.0)
    first.close()
    again = open_store(follow_cfg)
    assert again.network_path == network_db_path(follow_cfg, "gw-aabbcc") and macs(again) == {"aa:aa:aa:00:00:09"}, "list and show must see the same network as the dashboard"
    again.close()


def test_runtime_gives_each_network_its_own_device_list(follow_cfg):
    home_rt = build_runtime(follow_cfg, FakeTransport(), None)
    sweep(home_rt, now=100.0, resolve_names=False)
    assert home_rt.network_id == "gw-aaaaaa000001" and macs(home_rt.store) >= {PHONE.mac}, "the home network is named after its router"
    home_rt.store.close()
    friend_rt = build_runtime(follow_cfg, friend_transport(), None)
    sweep(friend_rt, now=200.0, resolve_names=False)
    assert friend_rt.network_id == "gw-bbbbbb005001"
    assert FRIEND_HOST.mac in macs(friend_rt.store) and PHONE.mac not in macs(friend_rt.store), "the friend's list must not mix with home"
    friend_rt.store.close()
    back = build_runtime(follow_cfg, FakeTransport(), None)
    assert PHONE.mac in macs(back.store) and FRIEND_HOST.mac not in macs(back.store), "coming home must bring the home list back"
    assert {n["id"] for n in back.store.list_networks()} == {"gw-aaaaaa000001", "gw-bbbbbb005001"}, "every network visited is remembered"
    back.store.close()


def test_without_follow_the_single_file_layout_is_untouched(tmp_path):
    (tmp_path / "config.toml").write_text(render_config(["192.168.1.0/24"]))
    cfg = load_config(None, tmp_path)
    rt = build_runtime(cfg, FakeTransport(), None)
    assert rt.network_id == "" and rt.store.network_path is None, "per-network files are only used when following networks"
    sweep(rt, now=1.0, resolve_names=False)
    rt.store.close()
    assert not (tmp_path / "networks").exists(), "no extra files for the usual home install"
    assert Store.count_devices_in(cfg.db_path) >= 1


def test_join_and_scan_follows_the_network_labels_it_and_queues_a_scan(tmp_path):
    (tmp_path / "config.toml").write_text(render_config(["192.168.1.0/24"], HOME_GW))
    wifi = FakeWifi()
    ctl = make_ctl(tmp_path, friend_transport(), wifi=wifi)
    ctl.start()
    try:
        assert ctl.status()["follow_network"] is False
        out = ctl.wifi_connect({"ssid": "Gran", "password": "hunter2hunter2", "scan": True})
        assert out["ready"] is True and out["job"], out
        assert ctl.status()["follow_network"] is True, "join and scan must switch following on"
        listed = ctl.status()["networks"]
        assert [(n["label"], n["current"]) for n in listed if n["id"] == "gw-bbbbbb005001"] == [("Gran", True)], "the network is named after the Wi-Fi joined"
        assert "hunter2" not in repr(ctl.status()) and "hunter2" not in repr(out), "the password must not come back"
    finally:
        ctl.close()


def test_failed_join_and_scan_puts_following_back(tmp_path):
    (tmp_path / "config.toml").write_text(render_config(["192.168.1.0/24"], HOME_GW))
    ctl = make_ctl(tmp_path, friend_transport(), wifi=FakeWifi())
    ctl.start()
    try:
        from netscan.web.errors import ApiError

        with pytest.raises(ApiError):
            ctl.wifi_connect({"ssid": "Gran", "password": "wrong", "scan": True})
        assert ctl.status()["follow_network"] is False, "a join that failed must not leave the config changed"
        with pytest.raises(ApiError) as bad:
            ctl.wifi_connect({"ssid": "Gran", "scan": "yes"})
        assert bad.value.status == 400
    finally:
        ctl.close()


def test_controller_status_lists_networks_with_device_counts(tmp_path):
    (tmp_path / "config.toml").write_text(render_config(["192.168.1.0/24"], HOME_GW, follow=True))
    ctl = make_ctl(tmp_path, FakeTransport())
    ctl.start()
    try:
        job = ctl.submit_scan({"hostnames": False})
        deadline = time.time() + 10
        while time.time() < deadline and ctl.store.get_job(job["id"]).state in ("queued", "running"):
            time.sleep(0.05)
        networks = ctl.status()["networks"]
        assert len(networks) == 1 and networks[0]["current"] and networks[0]["devices"] >= 2, networks
        assert networks[0]["id"] == "gw-aaaaaa000001" and GW_MAC == HOME_GW
    finally:
        ctl.close()
