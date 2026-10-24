import json

from scapy.layers.l2 import ARP, Ether

from conftest import GW_IP, GW_MAC, HOST_IP, HOST_MAC, PHONE, TV
from netscan.alerts import Alerter
from netscan.blocker import DEAD_MAC
from netscan.config import AlertConfig
from netscan.daemon import Daemon
from netscan.monitor import Event
from netscan.parsing import Host
from netscan.runtime import sweep


def kinds(events):
    return [e.kind for e in events]


def test_new_device_detected_on_second_sweep_after_baseline(rt):
    first = rt.tracker.observe([Host(GW_IP, GW_MAC), PHONE], now=100, allow_baseline=True)
    assert kinds(first) == ["baseline"], "first sweep seeds silently (one summary, no per-device alert)"
    assert rt.store.count_devices() == 2
    second = rt.tracker.observe([Host(GW_IP, GW_MAC), PHONE, TV], now=200)
    assert kinds(second) == ["new_device"], "a device never seen before must raise exactly one new_device event"
    assert second[0].mac == TV.mac and second[0].ip == TV.ip
    assert rt.tracker.observe([Host(GW_IP, GW_MAC), PHONE, TV], now=300) == [], "known devices raise nothing"


def test_every_device_alerts_when_baseline_disabled(rt):
    rt.tracker.silent_baseline = False
    assert kinds(rt.tracker.observe([PHONE, TV], now=1, allow_baseline=True)) == ["new_device", "new_device"]


def test_device_record_has_vendor_hostname_and_first_last_seen(rt):
    rt.tracker.observe([PHONE], now=100)
    rt.tracker.observe([PHONE], now=250)
    dev = rt.store.get_device(PHONE.mac)
    assert "raspberry" in dev.vendor.lower()
    assert dev.hostname == "host-20", "hostname comes from the resolver"
    assert (dev.first_seen, dev.last_seen, dev.online) == (100, 250, True), "first_seen is kept, last_seen advances"


def test_offline_then_online_and_ip_change(rt):
    rt.tracker.observe([PHONE], now=100)
    assert kinds(rt.tracker.mark_offline(900, now=500)) == [], "within the window stays online"
    off = rt.tracker.mark_offline(900, now=1100)
    assert kinds(off) == ["device_offline"] and not rt.store.get_device(PHONE.mac).online
    assert rt.tracker.mark_offline(900, now=2000) == [], "already offline: no repeat event"
    back = rt.tracker.observe([Host("192.168.1.77", PHONE.mac)], now=2100)
    assert kinds(back) == ["device_online", "ip_changed"]
    assert rt.store.get_device(PHONE.mac).ip == "192.168.1.77"


def test_hostname_not_requeried_for_known_device(cfg, fake):
    from netscan.runtime import build_runtime

    calls = []
    rt2 = build_runtime(cfg, fake, resolve_hostname=lambda ip: calls.append(ip) or "name")
    rt2.tracker.observe([PHONE], now=1)
    rt2.tracker.observe([PHONE], now=2)
    assert calls == [PHONE.ip], "reverse DNS only for new/moved/nameless devices"
    rt2.store.close()


def test_out_of_scope_hosts_are_never_recorded(rt):
    rt.tracker.observe([Host("8.8.8.8", "00:11:22:33:44:55"), Host("192.168.2.9", "00:11:22:33:44:66")], now=1)
    assert rt.store.count_devices() == 0


def test_sweep_includes_this_host_and_alerts_flow(rt, fake):
    hosts, events = sweep(rt, now=10)
    assert {h.ip for h in hosts} == {GW_IP, PHONE.ip, TV.ip, HOST_IP}
    assert HOST_MAC in {d.mac for d in rt.store.list_devices()}
    assert kinds(events) == ["baseline"]


# alerts

class Poster:
    def __init__(self, fail=False):
        self.calls, self.fail = [], fail

    def __call__(self, url, body, headers, timeout):
        self.calls.append((url, body, headers))
        if self.fail:
            raise OSError("boom")


def new_event():
    return Event("new_device", TV.mac, TV.ip, "new device on network", "Samsung", "tv")


def test_webhook_and_ntfy_payloads():
    post = Poster()
    cfg = AlertConfig(webhook_url="https://hook.invalid/x", ntfy_url="https://ntfy.invalid/topic", ntfy_token="tk")
    Alerter(cfg, post).dispatch([new_event()])
    hook = next(c for c in post.calls if c[0].startswith("https://hook"))
    body = json.loads(hook[1])
    assert body["kind"] == "new_device" and body["ip"] == TV.ip and body["mac"] == TV.mac, "webhook carries device identity as json"
    ntfy = next(c for c in post.calls if "ntfy" in c[0])
    assert ntfy[2]["Authorization"] == "Bearer tk" and ntfy[2]["Priority"] == "high"
    assert TV.ip.encode() in ntfy[1]


def test_alert_filtering_and_failure_isolation(caplog):
    post = Poster()
    Alerter(AlertConfig(webhook_url="https://h.invalid"), post).dispatch([Event("device_offline", PHONE.mac, PHONE.ip, "x")])
    assert post.calls == [], "kinds not in notify_on are not sent"
    failing = Poster(fail=True)
    Alerter(AlertConfig(webhook_url="https://h.invalid", ntfy_url="https://n.invalid/t"), failing).dispatch([new_event(), new_event()])
    assert len(failing.calls) == 4, "a failing sink must not stop the others or later events"


def test_alert_rejects_non_http_urls():
    from netscan.alerts import http_post

    for url in ("file:///etc/passwd", "ftp://x/y"):
        try:
            http_post(url, b"", {}, 1)
        except ValueError:
            continue
        raise AssertionError(f"{url} must be refused")


# daemon: sweep + ARP watch

def make_daemon(rt):
    post = Poster()
    rt.alerter = Alerter(AlertConfig(webhook_url="https://h.invalid"), post)
    return Daemon(rt), post


def arp_frame(ip, mac, op=2):
    return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=op, hwsrc=mac, psrc=ip, pdst="192.168.1.1")


def test_arp_watch_alerts_on_new_device(rt):
    d, post = make_daemon(rt)
    d.sweep_once(now=1)  # baseline
    assert post.calls == [], "baseline sweep stays quiet"
    d.handle_arp(arp_frame("192.168.1.90", "00:11:22:aa:bb:cc", op=1))
    assert len(post.calls) == 1 and json.loads(post.calls[0][1])["ip"] == "192.168.1.90", "ARP from an unknown mac alerts"
    d.handle_arp(arp_frame("192.168.1.90", "00:11:22:aa:bb:cc"))
    assert len(post.calls) == 1, "same device again does not alert twice"


def test_arp_watch_ignores_probes_out_of_scope_and_our_own_cutoff_packets(rt):
    d, post = make_daemon(rt)
    d.sweep_once(now=1)
    d.handle_arp(arp_frame("0.0.0.0", "00:11:22:aa:bb:cc", op=1))
    d.handle_arp(arp_frame("8.8.8.8", "00:11:22:aa:bb:cc"))
    d.handle_arp(arp_frame(GW_IP, DEAD_MAC))
    d.handle_arp(arp_frame(PHONE.ip, HOST_MAC))
    d.handle_arp(Ether() / ARP(hwsrc="not-a-mac", psrc="192.168.1.60"))
    assert post.calls == [] and rt.store.count_devices() == 4, "no phantom devices from probes, spoofs or our own packets"


def test_sweep_once_survives_transport_failure(rt, fake):
    d, post = make_daemon(rt)

    def boom(*a, **k):
        raise OSError("interface down")

    fake.arp_sweep = boom
    assert d.sweep_once() == 0, "a failed sweep is logged, not raised"


def test_sweep_once_marks_offline_and_alerts_when_configured(rt, fake):
    d, post = make_daemon(rt)
    rt.alerter.cfg.notify_on = ("new_device", "device_offline")
    d.sweep_once(now=1000)
    fake.hosts = [h for h in fake.hosts if h.mac != TV.mac]
    d.sweep_once(now=1000 + rt.cfg.daemon.offline_after + 60)
    assert [json.loads(c[1])["kind"] for c in post.calls] == ["device_offline"]
    assert json.loads(post.calls[0][1])["mac"] == TV.mac


def test_daemon_run_baselines_before_arp_watch_and_alerts_only_for_unknown_mac(rt, fake):
    import threading

    d, post = make_daemon(rt)
    fake.sniffed = [arp_frame(PHONE.ip, PHONE.mac), arp_frame("192.168.1.91", "00:11:22:aa:bb:dd", op=1)]
    threading.Timer(0.5, d.stop.set).start()
    d.run()
    sent = [json.loads(c[1]) for c in post.calls]
    assert [s["mac"] for s in sent] == ["00:11:22:aa:bb:dd"], "devices known from the baseline sweep must not alert; the unknown mac must, once"
    assert rt.store.count_devices() == 5


def test_reverse_dns_is_bounded(monkeypatch):
    import time

    from netscan import runtime

    monkeypatch.setattr(runtime.socket, "gethostbyaddr", lambda ip: time.sleep(5) or ("slow", [], []))
    start = time.time()
    assert runtime.reverse_dns("192.168.1.5", timeout=0.2) == ""
    assert time.time() - start < 2, "a stalled resolver must not stall the sweep"


def test_store_upsert_keeps_first_seen_and_never_blanks_known_fields(rt):
    rt.store.upsert_device("00:11:22:33:44:55", "192.168.1.5", "Acme", "tv", 10)
    dev = rt.store.upsert_device("00:11:22:33:44:55", "192.168.1.6", "", "", 20)
    assert (dev.first_seen, dev.last_seen, dev.vendor, dev.hostname, dev.ip) == (10, 20, "Acme", "tv", "192.168.1.6")


def test_concurrent_observers_announce_a_new_device_once(rt):
    import threading

    results = []
    barrier = threading.Barrier(8)

    def go():
        barrier.wait()
        results.append(rt.tracker.observe([TV], now=5))

    threads = [threading.Thread(target=go) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sum(len([e for e in r if e.kind == "new_device"]) for r in results) == 1, "sweep + ARP watch racing must not double alert"


def test_ntfy_headline_identifies_the_device_not_its_hostname(tmp_path):
    from netscan.store import Store

    s = Store(tmp_path / "n.db")
    s.upsert_device(TV.mac, TV.ip, "Samsung", "router-made-name", 100)
    post = Poster()
    a = Alerter(AlertConfig(ntfy_url="https://ntfy.invalid/t"), post, s)
    a.dispatch([new_event()])
    headers, body = post.calls[-1][2], post.calls[-1][1].decode()
    assert headers["Title"].startswith("Samsung ") and "router-made-name" not in headers["Title"]
    assert headers["Title"].endswith(": new device") and TV.mac[-5:] in headers["Title"]
    assert "Hostname: router-made-name" in body and f"MAC: {TV.mac}" in body and "Vendor: Samsung" in body

    s.set_meta(TV.mac, 200, label="Lounge TV \u2019s", owner="Sam")
    a.dispatch([new_event()])
    headers, body = post.calls[-1][2], post.calls[-1][1].decode()
    assert headers["Title"].startswith("=?UTF-8?B?"), "non-ascii titles are sent as an encoded word, not rejected"
    assert "Owner: Sam" in body and "Name: Lounge TV" in body
    s.close()


def test_back_online_alert_respects_notify_on_and_reports_the_gap(rt):
    rt.tracker.observe([PHONE], now=1000)
    rt.tracker.mark_offline(offline_after=60, now=2000)
    events = rt.tracker.observe([PHONE], now=1000 + 2 * 3600)
    online = next(e for e in events if e.kind == "device_online")
    assert "last seen" in online.message and "ago" in online.message
    post = Poster()
    Alerter(AlertConfig(ntfy_url="https://n.invalid/t", webhook_url="https://h.invalid"), post, rt.store).dispatch([online])
    assert post.calls == [], "device_online is not in the default notify_on"


def test_alert_says_why_when_a_device_override_forces_it(tmp_path):
    from netscan.store import Store

    s = Store(tmp_path / "w.db")
    s.set_meta(PHONE.mac, 1, alert="always")
    post = Poster()
    Alerter(AlertConfig(ntfy_url="https://n.invalid/t"), post, s).dispatch([Event("device_online", PHONE.mac, PHONE.ip, "device back online")])
    assert "Sent because: this device is set to 'Always alert'" in post.calls[0][1].decode()
    s.close()
