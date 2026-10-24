"""Labels/trust, alert settings, block rules, presence and security checks. No real network."""

from __future__ import annotations

import datetime as dt
import json
import time

import pytest
from scapy.layers.l2 import ARP, Ether

from conftest import GW_IP, GW_MAC, HOST_IP, HOST_MAC, PHONE, TV, FakeTransport
from netscan.alerts import Alerter
from netscan.blocker import DEAD_MAC
from netscan.config import AlertConfig
from netscan.daemon import Daemon
from netscan.monitor import Event
from netscan.net import DhcpOffer
from netscan.parsing import Host
from netscan.portscan import MAX_TARGETS, port_info, record_scans, scan_ports
from netscan.runtime import sweep
from netscan.safety import OutOfScopeError
from netscan.security import analyse_dhcp
from netscan.store import Store
from netscan.web.controller import ApiError
from netscan.web.features import presence_segments
from netscan.web.rules import next_transition, parse_hhmm, validate_rule, window_active
from test_web import TOKEN, Client, api, ctl, home, make_ctl, scan  # noqa: F401 fixtures


class Poster:
    def __init__(self, fail: bool = False):
        self.calls, self.fail = [], fail

    def __call__(self, url, body, headers, timeout):
        if self.fail:
            raise OSError("connection refused")
        self.calls.append((url, body, headers))


def local(year, month, day, hour, minute=0) -> dt.datetime:
    return dt.datetime(year, month, day, hour, minute)


# 2026-10-26 is a Monday
MON = (2026, 10, 26)


# ---- store ----

def test_store_meta_settings_rules_and_scans_roundtrip(tmp_path):
    s = Store(tmp_path / "x.db")
    assert s.get_meta("aa").trust == "unknown" and s.get_meta("aa").label == ""
    s.set_meta("aa", 1.0, label="Dad's laptop", track=True, trust="known")
    m = s.get_meta("aa")
    assert (m.label, m.track, m.trust, m.alert) == ("Dad's laptop", True, "known", "default")
    with pytest.raises(ValueError):
        s.set_meta("aa", bogus=1)
    assert s.get_setting("missing", 5) == 5
    s.set_setting("k", {"a": [1]})
    assert s.get_setting("k") == {"a": [1]}
    r = s.add_rule("night", "window", ["aa"], [0, 1], "22:00", "07:00", None, now=1.0)
    s.update_rule(r.id, active=True, held=["aa"])
    got = s.get_rule(r.id)
    assert got.active and got.held == ["aa"] and got.days == [0, 1]
    assert s.delete_rule(r.id) and s.get_rule(r.id) is None
    s.set_port_scan("aa", "1.2.3.4", [22, 80], 5.0)
    assert s.get_port_scan("aa")["open"] == [22, 80]
    s.close()


# ---- alerts ----

def test_alert_settings_in_db_override_config_and_per_device_mode(tmp_path):
    s = Store(tmp_path / "x.db")
    post = Poster()
    a = Alerter(AlertConfig(webhook_url="https://cfg.invalid", notify_on=("new_device",)), post, s)
    a.dispatch([Event("device_offline", mac="aa", message="x")])
    assert post.calls == [], "config default does not notify on offline"
    s.set_setting("alerts", {"notify_on": ["device_offline"], "webhook_url": "https://db.invalid"})
    a.dispatch([Event("device_offline", mac="aa", message="x")])
    assert [c[0] for c in post.calls] == ["https://db.invalid"], "dashboard settings win over config.toml"
    s.set_meta("aa", alert="mute")
    a.dispatch([Event("device_offline", mac="aa", message="x")])
    assert len(post.calls) == 1, "muted device never notifies"
    s.set_meta("aa", alert="always")
    a.dispatch([Event("ip_changed", mac="aa", message="x")])
    assert len(post.calls) == 2, "an 'always' device notifies for every kind"
    a.dispatch([Event("baseline", mac="aa", message="seed")])
    assert len(post.calls) == 2, "baseline is never sent"
    s.close()


def test_alert_test_reports_per_channel_errors():
    ok = Alerter(AlertConfig(webhook_url="https://a.invalid", ntfy_url="https://n.invalid/t"), Poster()).test()
    assert ok["webhook"] == {"configured": True, "ok": True, "error": ""} and ok["ntfy"]["ok"]
    bad = Alerter(AlertConfig(webhook_url="https://a.invalid"), Poster(fail=True)).test()
    assert bad["webhook"]["ok"] is False and "refused" in bad["webhook"]["error"] and bad["ntfy"]["configured"] is False


def test_alerts_api_never_returns_secrets_and_validates(api, ctl):
    code, v = api.call("PUT", "/api/alerts", {"webhook_url": "https://hooks.example.com/secret/abc", "ntfy_url": "https://ntfy.sh/mytopic", "ntfy_token": "tk_secret"})
    assert code == 200
    text = json.dumps(v)
    assert "secret" not in text and "mytopic" not in text and "tk_secret" not in text
    assert v["webhook"] == {"configured": True, "host": "https://hooks.example.com/…"} and v["ntfy"]["token"] is True
    assert api.call("PUT", "/api/alerts", {"webhook_url": "ftp://x"})[0] == 400
    assert api.call("PUT", "/api/alerts", {"webhook_url": "javascript:alert(1)"})[0] == 400
    assert api.call("PUT", "/api/alerts", {"notify_on": ["nope"]})[0] == 400
    code, v = api.call("PUT", "/api/alerts", {"notify_on": ["new_device", "ip_conflict"], "ntfy_token": None})
    assert v["notify_on"] == ["new_device", "ip_conflict"] and v["ntfy"]["token"] is True, "null keeps the stored secret"
    _, v = api.call("PUT", "/api/alerts", {"webhook_url": ""})
    assert v["webhook"]["configured"] is False, "empty string clears"
    _, v = api.call("PUT", "/api/alerts", {"reset": True})
    assert v["overridden"] == []


def test_alerts_test_endpoint_needs_a_channel(api, ctl):
    assert api.post("/api/alerts/test")[0] == 409
    api.call("PUT", "/api/alerts", {"webhook_url": "http://127.0.0.1:1/hook"})
    code, res = api.post("/api/alerts/test")
    assert code == 200 and res["webhook"]["configured"] and res["webhook"]["ok"] is False and res["webhook"]["error"]


# ---- device labels and trust ----

def test_meta_and_review_flow(api):
    scan(api)
    _, devices = api.get("/api/devices")
    assert all(d["trust"] == "unknown" and d["name"] for d in devices)
    code, d = api.call("PUT", f"/api/devices/{PHONE.mac}/meta", {"label": "Mum's phone", "owner": "Mum", "category": "phone", "track": True})
    assert code == 200 and d["name"] == "Mum's phone" and d["owner"] == "Mum" and d["track"] is True
    assert api.call("PUT", f"/api/devices/{PHONE.mac}/meta", {"trust": "wizard"})[0] == 400
    assert api.call("PUT", f"/api/devices/{PHONE.mac}/meta", {"label": "x" * 41})[0] == 400
    assert api.call("PUT", f"/api/devices/{PHONE.mac}/meta", {})[0] == 400
    assert api.call("PUT", "/api/devices/aa:bb:cc:dd:ee:ff/meta", {"label": "x"})[0] == 404
    assert api.post("/api/devices/review", {"macs": [PHONE.mac], "trust": "known"})[1]["updated"] == 1
    _, st = api.get("/api/status")
    assert st["counts"]["unreviewed"] == 3
    assert api.post("/api/devices/review", {"all_unreviewed": True})[1]["updated"] == 3
    assert api.get("/api/status")[1]["counts"]["unreviewed"] == 0
    assert api.post("/api/devices/review", {"macs": ["zz"]})[0] == 404
    assert api.post("/api/devices/review", {})[0] == 400
    _, detail = api.get(f"/api/devices/{PHONE.mac}")
    assert detail["device"]["label"] == "Mum's phone" and "presence" in detail and detail["ports"] is None


# ---- rule time maths ----

def test_parse_and_validate_rules():
    assert parse_hhmm("07:05") == 425 and parse_hhmm("24:00", allow_24=True) == 1440
    for bad in ("7", "25:00", "12:60", "24:00", "ab"):
        with pytest.raises(ValueError):
            parse_hhmm(bad)
    ok = validate_rule({"name": " Bedtime ", "macs": ["a", "a", "b"], "days": [4, 0], "start": "22:00", "end": "7:00"}, 0)
    assert ok["name"] == "Bedtime" and ok["macs"] == ["a", "b"] and ok["days"] == [0, 4] and ok["end"] == "07:00"
    for body in ({"macs": ["a"], "days": [0], "start": "1:00", "end": "2:00"}, {"name": "x", "days": [0], "start": "1:00", "end": "2:00"},
                 {"name": "x", "macs": ["a"], "days": [], "start": "1:00", "end": "2:00"}, {"name": "x", "macs": ["a"], "days": [7], "start": "1:00", "end": "2:00"},
                 {"name": "x", "macs": ["a"], "days": [0], "start": "1:00", "end": "1:00"}, {"name": "x", "kind": "timer", "macs": ["a"]},
                 {"name": "x", "kind": "timer", "macs": ["a"], "minutes": 0}, {"name": "x", "kind": "timer", "macs": ["a"], "minutes": True}):
        with pytest.raises(ValueError):
            validate_rule(body, 0)
    assert validate_rule({"name": "x", "kind": "timer", "macs": ["a"], "minutes": 30}, 100)["until"] == 1900


def test_window_handles_overnight_and_weekdays():
    days = [0, 1, 2, 3, 4]  # Mon-Fri nights
    assert window_active(days, "22:00", "07:00", local(*MON, 23))
    assert window_active(days, "22:00", "07:00", local(2026, 10, 27, 6, 59)), "Tuesday 06:59 belongs to Monday night"
    assert not window_active(days, "22:00", "07:00", local(2026, 10, 27, 7, 0)), "end is exclusive"
    assert not window_active(days, "22:00", "07:00", local(*MON, 12))
    assert not window_active(days, "22:00", "07:00", local(2026, 10, 31, 23)), "Saturday night is not in the list"
    assert window_active(days, "22:00", "07:00", local(2026, 10, 31, 3)), "but early Saturday is still Friday night"
    assert not window_active(days, "22:00", "07:00", local(2026, 11, 1, 3)), "Sunday 03:00 follows an unlisted Saturday"
    assert window_active([0], "00:00", "24:00", local(*MON, 23, 59)) and not window_active([0], "00:00", "24:00", local(2026, 10, 27, 0, 0))
    assert window_active([0], "09:00", "17:00", local(*MON, 9, 0)) and not window_active([0], "09:00", "17:00", local(*MON, 17, 0))


def test_next_transition():
    from netscan.store import BlockRule

    rule = BlockRule(1, "n", "window", True, ["a"], [0], "22:00", "07:00", None, [], False, "", 0.0)
    now = local(*MON, 12).timestamp()
    assert dt.datetime.fromtimestamp(next_transition(rule, now)) == local(*MON, 22)
    now = local(*MON, 23).timestamp()
    assert dt.datetime.fromtimestamp(next_transition(rule, now)) == local(2026, 10, 27, 7)
    rule.enabled = False
    assert next_transition(rule, now) is None
    timer = BlockRule(2, "t", "timer", True, ["a"], [], "", "", 500.0, [], False, "", 0.0)
    assert next_transition(timer, 1.0) == 500.0


# ---- rule engine ----

def clocked_ctl(home, start):
    box = [start]
    c = make_ctl(home, clock=lambda: box[0])
    c.start()
    return c, box


def test_timer_rule_blocks_then_expires_and_releases(home):
    c, box = clocked_ctl(home, time.time())
    try:
        scan_job = c.submit_scan({"hostnames": False})
        deadline = time.time() + 10
        while c.store.get_job(scan_job["id"]).state in ("queued", "running") and time.time() < deadline:
            time.sleep(0.05)
        rule = c.quick_block({"macs": [PHONE.mac, TV.mac], "minutes": 30})
        assert rule["active"] and sorted(rule["held"]) == sorted([PHONE.mac, TV.mac]) and rule["kind"] == "timer"
        blocks = {b.mac: b for b in c.store.list_blocks()}
        assert blocks[PHONE.mac].reason.startswith("rule: ")
        with pytest.raises(ApiError) as exc:
            c.unblock({"target": PHONE.mac})
        assert exc.value.status == 409 and "rule" in exc.value.message
        assert c.status()["counts"]["rules_active"] == 1
        box[0] += 29 * 60
        c.rule_engine.tick(box[0])
        assert len(c.store.list_blocks()) == 2, "still inside the timer"
        box[0] += 2 * 60
        c.rule_engine.tick(box[0])
        assert c.store.list_blocks() == [] and c.store.list_rules() == [], "timer expiry unblocks and deletes the rule"
    finally:
        c.close()


def test_window_rule_applies_only_inside_window_and_leaves_manual_blocks(home):
    now = local(*MON, 12).timestamp()
    c, box = clocked_ctl(home, now)
    try:
        job = c.submit_scan({"hostnames": False})
        while c.store.get_job(job["id"]).state in ("queued", "running"):
            time.sleep(0.05)
        c.block({"target": TV.mac, "reason": "manual"})
        rule = c.create_rule({"name": "Bedtime", "macs": [PHONE.mac, TV.mac], "days": [0], "start": "22:00", "end": "07:00"})
        assert not rule["active"] and rule["next_transition"] == local(*MON, 22).timestamp()
        box[0] = local(*MON, 22, 30).timestamp()
        c.rule_engine.tick(box[0])
        active = c.rules()[0]
        assert active["active"] and active["held"] == [PHONE.mac], "the manually blocked TV is not taken over"
        c.store.remove_block(PHONE.mac)  # something removed the block behind the rule's back
        c.rule_engine.tick(box[0])
        assert c.store.is_blocked(PHONE.mac), "an active rule re-asserts its block"
        box[0] = local(2026, 10, 27, 7, 1).timestamp()
        c.rule_engine.tick(box[0])
        assert not c.store.is_blocked(PHONE.mac) and c.store.is_blocked(TV.mac), "only the rule's own block is released"
        assert c.rules()[0]["active"] is False
        # pausing an active rule releases it immediately
        box[0] = local(2026, 11, 2, 23).timestamp()
        c.rule_engine.tick(box[0])
        c.update_rule(rule["id"], {"enabled": False})
        assert not c.store.is_blocked(PHONE.mac)
        c.update_rule(rule["id"], {"enabled": True})
        assert c.store.is_blocked(PHONE.mac)
        c.delete_rule(rule["id"])
        assert not c.store.is_blocked(PHONE.mac) and c.store.is_blocked(TV.mac)
    finally:
        c.close()


def test_rules_refuse_protected_and_unknown_devices(api):
    scan(api)
    assert api.post("/api/rules/quick", {"macs": [GW_MAC], "minutes": 10})[0] == 403, "gateway is protected"
    assert api.post("/api/rules/quick", {"macs": [HOST_MAC], "minutes": 10})[0] == 403, "so is this machine"
    assert api.post("/api/rules/quick", {"macs": ["aa:bb:cc:dd:ee:ff"], "minutes": 10})[0] == 404
    assert api.post("/api/rules/quick", {"macs": [PHONE.mac], "minutes": 0})[0] == 400
    assert api.post("/api/rules/quick", {"macs": [], "minutes": 5})[0] == 400
    assert api.post("/api/rules", {"name": "x", "macs": [PHONE.mac], "days": [1], "start": "08:00", "end": "08:00"})[0] == 400
    code, r = api.post("/api/rules/quick", {"macs": [PHONE.mac], "minutes": 15})
    assert code == 200 and r["active"]
    assert api.post("/api/unblock", {"target": PHONE.mac})[0] == 409
    assert api.call("DELETE", f"/api/rules/{r['id']}")[0] == 200
    assert api.post("/api/unblock", {"target": PHONE.mac})[0] == 404, "deleting the rule released the block"
    assert api.call("DELETE", "/api/rules/999")[0] == 404


# ---- presence ----

def test_presence_segments_from_events():
    evs = [(1000, "device_offline"), (2000, "device_online"), (3000, "device_offline")]
    segs = presence_segments(evs, first_seen=0, since=0, until=4000, offline_after=100)
    assert [(s["start"], s["end"], s["online"]) for s in segs] == [(0, 900, True), (900, 2000, False), (2000, 2900, True), (2900, 4000, False)]
    clipped = presence_segments(evs, 0, 1500, 2500, 100)
    assert [(s["start"], s["end"], s["online"]) for s in clipped] == [(1500, 2000, False), (2000, 2500, True)]
    assert presence_segments([], 5000, 0, 4000, 100) == [], "nothing before the device was first seen"


def test_presence_api_lists_tracked_devices(api, ctl):
    scan(api)
    assert api.get("/api/presence")[1]["devices"] == []
    api.call("PUT", f"/api/devices/{PHONE.mac}/meta", {"track": True, "owner": "Mum"})
    _, p = api.get("/api/presence?hours=6")
    assert p["tracked"] == 1 and p["home"] == 1 and p["devices"][0]["owner"] == "Mum" and p["devices"][0]["segments"]
    assert len(api.get("/api/presence?all=1")[1]["devices"]) == 4
    assert api.get("/api/presence?hours=abc")[0] == 400


# ---- security: conflicts, spoofing, dhcp, ports ----

def test_duplicate_ip_in_one_sweep_raises_a_conflict_once(rt, fake):
    fake.hosts = [Host(GW_IP, GW_MAC), PHONE, Host(PHONE.ip, "de:ad:be:ef:00:99")]
    _hosts, events = sweep(rt, now=1000)
    conflicts = [e for e in events if e.kind == "ip_conflict"]
    assert len(conflicts) == 1 and PHONE.ip in conflicts[0].message and "de:ad:be:ef:00:99" in conflicts[0].message
    _hosts, events = sweep(rt, now=1100)
    assert not [e for e in events if e.kind == "ip_conflict"], "the same finding is not repeated within hours"
    _hosts, events = sweep(rt, now=1000 + 7 * 3600)
    assert [e for e in events if e.kind == "ip_conflict"], "but it is raised again later if it persists"


def arp_frame(ip, mac):
    return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=mac, psrc=ip, pdst=HOST_IP)


def test_arp_watch_flags_someone_claiming_the_gateway(rt):
    post = Poster()
    rt.alerter = Alerter(AlertConfig(webhook_url="https://h.invalid"), post)
    d = Daemon(rt)
    d.sweep_once(now=1)
    assert rt.gateway_mac == GW_MAC
    d.handle_arp(arp_frame(GW_IP, GW_MAC))
    assert post.calls == [], "the real router is fine"
    d.handle_arp(arp_frame(GW_IP, "de:ad:be:ef:00:42"))
    assert len(post.calls) == 1 and json.loads(post.calls[0][1])["kind"] == "arp_spoof"
    d.handle_arp(arp_frame(GW_IP, "de:ad:be:ef:00:42"))
    assert len(post.calls) == 1, "deduplicated"
    assert rt.store.get_device("de:ad:be:ef:00:42") is None, "the impostor is not recorded as owning the gateway address"
    d.handle_arp(arp_frame(GW_IP, DEAD_MAC))
    assert len(post.calls) == 1, "our own cutoff packets never count"


def test_dhcp_analysis():
    gw = DhcpOffer(GW_IP, GW_MAC, "192.168.1.50", GW_IP)
    assert analyse_dhcp([gw], GW_IP, GW_MAC) == []
    assert analyse_dhcp([], GW_IP, GW_MAC) == []
    rogue = DhcpOffer("192.168.1.66", "02:aa:bb:cc:dd:66", "192.168.1.51", "192.168.1.66")
    problems = analyse_dhcp([gw, rogue], GW_IP, GW_MAC)
    assert any("2 DHCP servers" in p for p in problems) and any("default gateway" in p for p in problems)
    assert analyse_dhcp([DhcpOffer("192.168.1.2", "02:aa:bb:cc:dd:02", "192.168.1.9", "192.168.1.2")], GW_IP, GW_MAC), "a lone server that hands out another router is flagged"


def test_dhcp_probe_job_records_result_and_alerts(api, ctl):
    ctl.raw.dhcp_offers = [DhcpOffer(GW_IP, GW_MAC, "192.168.1.50", GW_IP)]
    code, job = api.post("/api/security/dhcp-probe")
    done = api.wait_job(job["id"])
    assert code == 200 and done["state"] == "done" and done["summary"] == {"offers": 1, "problems": 0}
    ctl.raw.dhcp_offers.append(DhcpOffer("192.168.1.66", "02:aa:bb:cc:dd:66", "192.168.1.51", "192.168.1.66"))
    done = api.wait_job(api.post("/api/security/dhcp-probe")[1]["id"])
    assert done["summary"]["problems"] == 2
    sec = api.get("/api/security")[1]
    assert sec["last_dhcp"]["problems"] and len(sec["last_dhcp"]["offers"]) == 2
    assert {f["kind"] for f in sec["findings"]} == {"rogue_dhcp"}


def test_port_scan_scope_limits_and_diffs(rt):
    open_ports = {PHONE.ip: {22, 3389}, TV.ip: {8080}}
    seen = []

    def connect(ip, port, timeout):
        seen.append(ip)
        return port in open_ports.get(ip, ())

    targets = [(PHONE.mac, PHONE.ip), (TV.mac, TV.ip)]
    res = scan_ports(targets, rt.scope, ports=[22, 80, 3389, 8080], connect=connect)
    assert res == {PHONE.mac: [22, 3389], TV.mac: [8080]} and set(seen) == {PHONE.ip, TV.ip}
    with pytest.raises(OutOfScopeError):
        scan_ports([("aa", "8.8.8.8")], rt.scope, connect=connect)
    assert "8.8.8.8" not in seen
    with pytest.raises(ValueError):
        scan_ports([(f"m{i}", "192.168.1.20") for i in range(MAX_TARGETS + 1)], rt.scope, connect=connect)
    rt.tracker.observe([PHONE, TV], 1)
    first = record_scans(rt, targets, res, now=10)
    assert [e.kind for e in first] == ["port_opened"] and "3389" in first[0].message, "only the first-seen risky port is raised"
    res[TV.mac].append(80)
    second = record_scans(rt, targets, res, now=20)
    assert [("80" in e.message) for e in second] == [True], "a newly opened port is raised"
    assert record_scans(rt, targets, res, now=30) == []
    assert port_info(3389)["risk"] == "high" and port_info(65000)["service"] == "unknown"


def test_port_scan_api_flow(api, ctl):
    scan(api)
    ctl.raw.port_connect = lambda ip, port, timeout: (ip, port) in {(PHONE.ip, 23), (PHONE.ip, 80)}
    assert api.post("/api/security/ports", {"macs": ["aa:aa:aa:aa:aa:aa"]})[0] == 404
    assert api.post("/api/security/ports", {"macs": "x"})[0] == 400
    code, job = api.post("/api/security/ports", {"macs": [PHONE.mac]})
    done = api.wait_job(job["id"])
    assert code == 200 and done["state"] == "done" and done["summary"]["open"] == 2 and done["summary"]["findings"] == 1
    sec = api.get("/api/security")[1]
    row = next(s for s in sec["port_scans"] if s["mac"] == PHONE.mac)
    assert {p["port"] for p in row["open"]} == {23, 80} and any(p["risk"] == "high" for p in row["open"])
    assert api.get(f"/api/devices/{PHONE.mac}")[1]["ports"]["open"][0]["service"]
    online = api.post("/api/security/ports", {})[1]
    assert api.wait_job(online["id"])["state"] == "done", "no macs means every online device"


def test_new_security_kinds_are_in_default_notifications_and_config_template():
    from netscan.config import DEFAULT_NOTIFY_ON, render_config

    assert {"ip_conflict", "arp_spoof", "rogue_dhcp", "port_opened"} <= set(DEFAULT_NOTIFY_ON)
    assert '"arp_spoof"' in render_config(["192.168.1.0/24"])
