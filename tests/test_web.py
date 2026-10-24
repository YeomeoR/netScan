"""Dashboard backend: HTTP API, auth, jobs, schedules, services. No real network: FakeTransport only."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from conftest import GW_IP, GW_MAC, HOST_IP, PHONE, TV, FakeTransport
from netscan.blocker import DEAD_MAC
from netscan.config import Config, render_config
from netscan.store import Store
from netscan.web.controller import ApiError, Controller
from netscan.web.server import hostname_of, load_or_create_token, make_server

TOKEN = "test-token-123"


class Client:
    def __init__(self, port: int, token: str = TOKEN):
        self.base = f"http://127.0.0.1:{port}"
        self.token = token

    def call(self, method: str, path: str, body=None, token: str | None = ..., headers=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        tok = self.token if token is ... else token
        if tok:
            req.add_header("Authorization", f"Bearer {tok}")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if resp.headers.get_content_type() == "application/json" else raw)
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, json.loads(raw)
            except json.JSONDecodeError:
                return exc.code, raw

    def get(self, path, **kw):
        return self.call("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self.call("POST", path, {} if body is None else body, **kw)

    def wait_job(self, jid: int, timeout: float = 10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            _, jobs = self.get("/api/jobs")
            job = next(j for j in jobs if j["id"] == jid)
            if job["state"] not in ("queued", "running"):
                return job
            time.sleep(0.05)
        raise AssertionError(f"job {jid} did not finish")


@pytest.fixture
def home(tmp_path):
    (tmp_path / "config.toml").write_text(render_config(["192.168.1.0/24"]))
    return tmp_path


def make_ctl(home, transport=None, **kw):
    from netscan.config import load_config

    cfg = load_config(None, home)
    return Controller(cfg, transport or FakeTransport(), resolver=lambda ip: f"host-{ip.rsplit('.', 1)[1]}", scheduler_tick=3600, **kw)


@pytest.fixture
def ctl(home):
    c = make_ctl(home)
    c.start()
    yield c
    c.close()


@pytest.fixture
def api(ctl):
    server = make_server(ctl, "127.0.0.1", 0, TOKEN)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    yield Client(server.server_address[1])
    server.shutdown()
    server.server_close()


def scan(api, **body):
    status, job = api.post("/api/scan", {"hostnames": False, **body})
    assert status == 200, job
    return api.wait_job(job["id"])


# ---- auth and transport-level safety ----

def test_api_requires_the_token_but_static_files_do_not(api):
    assert api.get("/api/status", token=None)[0] == 401
    assert api.get("/api/status", token="wrong")[0] == 401
    assert api.get("/api/status")[0] == 200
    status, body = api.get("/", token=None)
    assert status == 200 and b"<title>netScan</title>" in body
    assert api.get("/app.js", token=None)[0] == 200 and api.get("/style.css", token=None)[0] == 200


def test_static_server_serves_only_whitelisted_files(api):
    for path in ("/../../etc/passwd", "/%2e%2e/%2e%2e/etc/passwd", "/netscan/config.py", "/static/app.js", "/app.js/../config.toml"):
        assert api.get(path, token=None)[0] == 404, path


def test_dns_rebinding_and_cors(api):
    status, body = api.get("/api/status", headers={"Host": "evil.example:8787"})
    assert status == 403, "loopback-bound server rejects foreign Host headers"
    assert api.call("OPTIONS", "/api/status")[0] == 405, "no CORS preflight is ever granted"
    assert hostname_of("[::1]:80") == "[::1]" and hostname_of("localhost:8787") == "localhost" and hostname_of("localhost") == "localhost"


def test_security_headers_and_json_errors(api):
    req = urllib.request.Request(api.base + "/", headers={})
    with urllib.request.urlopen(req) as resp:
        assert "default-src 'self'" in resp.headers["Content-Security-Policy"]
        assert resp.headers["X-Frame-Options"] == "DENY" and resp.headers["Cache-Control"] == "no-store"
    assert api.get("/api/nope")[0] == 404
    assert api.call("DELETE", "/api/status")[0] == 405
    status, body = api.call("POST", "/api/scan", None)
    assert status == 200
    req = urllib.request.Request(api.base + "/api/scan", data=b"{not json", method="POST", headers={"Authorization": f"Bearer {TOKEN}"})
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req)
    assert exc.value.code == 400


def test_token_file_is_private_and_stable(tmp_path):
    t1 = load_or_create_token(tmp_path)
    assert t1 and load_or_create_token(tmp_path) == t1
    assert ((tmp_path / "web_token").stat().st_mode & 0o777) == 0o600
    assert load_or_create_token(tmp_path, "given") == "given"


# ---- scan / devices / blocking ----

def test_scan_job_populates_devices_and_summary(api):
    job = scan(api)
    assert job["state"] == "done" and job["summary"]["seen"] == 4 and job["summary"]["baseline"] is True
    _, devices = api.get("/api/devices")
    assert {d["ip"] for d in devices} == {GW_IP, PHONE.ip, TV.ip, HOST_IP}
    phone = next(d for d in devices if d["ip"] == PHONE.ip)
    assert phone["vendor"] == "Raspberry Pi Foundation" and phone["online"] and not phone["blocked"]
    _, status = api.get("/api/status")
    assert status["counts"] == {"devices": 4, "online": 4, "offline": 0, "blocked": 0}
    assert status["ready"] and status["network"]["network"] == "192.168.1.0/24" and status["privileged"]


def test_hostname_lookup_is_optional(home):
    calls = []
    ctl = make_ctl(home)
    ctl.resolver = lambda ip: calls.append(ip) or "x"
    ctl.start()
    try:
        ctl._runtime().tracker.resolve_hostname = ctl.resolver
        job = ctl.submit_scan({"hostnames": False})
        wait_store(ctl, job["id"])
        assert calls == [], "hostnames=false must not trigger reverse DNS"
        job = ctl.submit_scan({"hostnames": True})
        wait_store(ctl, job["id"])
    finally:
        ctl.close()


def wait_store(ctl, jid, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        row = ctl.store.get_job(jid)
        if row.state not in ("queued", "running"):
            return row
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def test_offline_after_controls_missing_device_handling(home):
    fake = FakeTransport()
    ctl = make_ctl(home, fake)
    ctl.start()
    try:
        wait_store(ctl, ctl.submit_scan({"hostnames": False})["id"])
        fake.hosts = [h for h in fake.hosts if h.mac != PHONE.mac]
        job = wait_store(ctl, ctl.submit_scan({"hostnames": False, "offline_after": 3600})["id"])
        assert job.summary["offline"] == 0 and ctl.store.get_device(PHONE.mac).online, "grace period keeps it online"
        job = wait_store(ctl, ctl.submit_scan({"hostnames": False, "offline_after": 0})["id"])
        assert job.summary["offline"] == 1 and not ctl.store.get_device(PHONE.mac).online
    finally:
        ctl.close()


@pytest.mark.parametrize("body", [{"timeout": 999}, {"timeout": "x"}, {"hostnames": "yes"}, {"offline_after": -1}, {"capture_seconds": 99999}, {"offline_after": 1.5}])
def test_scan_parameters_are_validated(api, body):
    status, err = api.post("/api/scan", body)
    assert status == 400 and err["error"]


def test_device_detail_and_unknown_device(api):
    scan(api)
    status, detail = api.get(f"/api/devices/{PHONE.mac}")
    assert status == 200 and detail["device"]["ip"] == PHONE.ip and detail["traffic"] == []
    assert api.get(f"/api/devices/{PHONE.ip}")[0] == 200, "lookup by ip works too"
    assert api.get("/api/devices/192.168.1.250")[0] == 404
    assert api.get(f"/api/devices/{PHONE.mac.replace(':', '%3A')}")[0] == 200, "browsers send percent-encoded MACs"


def test_block_unblock_and_protected_targets(api, ctl):
    scan(api)
    for target in (GW_IP, GW_MAC, HOST_IP):
        status, err = api.post("/api/block", {"target": target})
        assert status == 403 and "never blocked" in err["error"], f"{target} must be refused"
    assert api.post("/api/block", {"target": "192.168.1.250"})[0] == 404
    assert api.post("/api/block", {"target": ""})[0] == 400
    status, blk = api.post("/api/block", {"target": PHONE.ip, "reason": "bedtime"})
    assert status == 200 and blk["mac"] == PHONE.mac and blk["enforcer_running"] is False and "enforcer" in blk["note"]
    _, blocks = api.get("/api/blocks")
    assert [b["reason"] for b in blocks] == ["bedtime"]
    assert next(d for d in api.get("/api/devices")[1] if d["mac"] == PHONE.mac)["blocked"]
    _, events = api.get("/api/events")
    assert any(e["kind"] == "blocked" for e in events)
    assert api.post("/api/unblock", {"target": PHONE.mac})[0] == 200
    assert (GW_MAC, GW_IP, PHONE.mac, PHONE.ip) in ctl.raw.sent, "unblock heals the ARP cache immediately"
    assert api.post("/api/unblock", {"target": PHONE.mac})[0] == 404
    assert api.get("/api/blocks")[1] == []


# ---- jobs ----

def test_queued_job_can_be_cancelled_and_running_job_finishes(home, monkeypatch):
    ctl = make_ctl(home)
    gate = threading.Event()
    started = threading.Event()

    def slow(self, params, cancel):
        started.set()
        gate.wait(5)
        return {"seen": 0}

    monkeypatch.setattr(Controller, "_do_sweep", slow)
    ctl.start()
    try:
        first = ctl.submit_scan({})
        assert started.wait(5)
        second = ctl.submit_scan({})
        assert ctl.store.get_job(second["id"]).state == "queued", "jobs run one at a time"
        assert ctl.cancel_job(second["id"])["state"] == "cancelled"
        with pytest.raises(ApiError) as exc:
            ctl.cancel_job(second["id"])
        assert exc.value.status == 409
        gate.set()
        assert wait_store(ctl, first["id"]).state == "done"
        assert ctl.store.get_job(second["id"]).state == "cancelled", "a cancelled job never runs"
        with pytest.raises(ApiError):
            ctl.cancel_job(999)
    finally:
        gate.set()
        ctl.close()


def test_failed_job_reports_error_and_worker_survives(home):
    fake = FakeTransport()
    ctl = make_ctl(home, fake)
    ctl.start()
    try:
        def boom(*a, **k):
            raise RuntimeError("interface went away")

        fake.arp_sweep = boom
        job = wait_store(ctl, ctl.submit_scan({})["id"])
        assert job.state == "error" and "interface went away" in job.error
        fake.arp_sweep = lambda *a, **k: list(fake.hosts)
        assert wait_store(ctl, ctl.submit_scan({})["id"]).state == "done"
    finally:
        ctl.close()


def test_stale_jobs_are_closed_out_on_restart(home):
    store = Store(home / "netscan.db")
    jid = store.add_job("sweep", {}).id
    store.close()
    ctl = make_ctl(home)
    ctl.start()
    try:
        row = ctl.store.get_job(jid)
        assert row.state == "interrupted" and "restart" in row.error
    finally:
        ctl.close()


def test_traffic_capture_job_records_metadata_only(home):
    fake = FakeTransport()
    pkt = Ether(src=PHONE.mac, dst="02:00:00:00:00:99") / IP(src=PHONE.ip, dst="93.184.216.34") / TCP(sport=5000, dport=443)
    fake.sniffed = [pkt, pkt]
    ctl = make_ctl(home, fake)
    ctl.start()
    try:
        wait_store(ctl, ctl.submit_scan({"hostnames": False})["id"])
        job = wait_store(ctl, ctl.submit_traffic({"duration": 1})["id"], timeout=15)
        assert job.state == "done" and job.summary["packets"] == 2 and job.summary["devices"] == 1
        detail = ctl.device_detail(PHONE.mac)
        assert detail["traffic"][0]["service"] == "HTTPS" and detail["traffic"][0]["peer_ip"] == "93.184.216.34"
        assert all(not isinstance(v, (bytes, bytearray)) for row in detail["traffic"] for v in row.values())
        with pytest.raises(ApiError):
            ctl.submit_traffic({"duration": 0})
        with pytest.raises(ApiError):
            ctl.submit_traffic({"duration": 99999})
    finally:
        ctl.close()


def test_capture_refused_without_privileges(home):
    fake = FakeTransport()
    fake.is_root = lambda: False
    ctl = make_ctl(home, fake)
    ctl.start()
    try:
        assert ctl.status()["privileged"] is False
        job = wait_store(ctl, ctl.submit_traffic({"duration": 1})["id"])
        assert job.state == "error" and "root" in job.error
        for name in ("enforce", "watch", "capture"):
            with pytest.raises(ApiError) as exc:
                ctl.start_service(name)
            assert exc.value.status == 409 and "root" in exc.value.message
    finally:
        ctl.close()


# ---- schedules ----

def test_schedule_crud_and_validation(api):
    status, s = api.post("/api/schedules", {"name": "Often", "kind": "interval", "every_seconds": 120, "params": {"timeout": 2, "hostnames": False, "offline_after": 600, "capture_seconds": 10}})
    assert status == 200 and s["every_seconds"] == 120 and s["params"]["capture_seconds"] == 10 and s["enabled"]
    assert s["next_run"] == pytest.approx(time.time() + 120, abs=5)
    assert api.get("/api/schedules")[1][0]["id"] == s["id"]

    status, paused = api.call("PUT", f"/api/schedules/{s['id']}", {"enabled": False})
    assert status == 200 and paused["next_run"] is None and paused["params"] == s["params"], "pausing keeps the params"
    _, resumed = api.call("PUT", f"/api/schedules/{s['id']}", {"enabled": True})
    assert resumed["next_run"] == pytest.approx(time.time() + 120, abs=5)
    _, edited = api.call("PUT", f"/api/schedules/{s['id']}", {"every_seconds": 600, "name": "Slower"})
    assert edited["next_run"] == pytest.approx(time.time() + 600, abs=5) and edited["name"] == "Slower"
    assert api.call("DELETE", f"/api/schedules/{s['id']}")[0] == 200
    assert api.call("DELETE", f"/api/schedules/{s['id']}")[0] == 404
    assert api.call("PUT", "/api/schedules/99", {"enabled": False})[0] == 404

    for bad in (
        {"kind": "interval", "every_seconds": 5},
        {"kind": "interval", "every_seconds": 10**9},
        {"kind": "daily", "at_time": "25:00"},
        {"kind": "daily", "at_time": "noon"},
        {"kind": "once", "run_at": time.time() - 60},
        {"kind": "once"},
        {"kind": "weekly"},
        {"name": ""},
        {"name": "x" * 61},
        {"params": {"timeout": 0}},
        {"enabled": "yes"},
    ):
        status, err = api.post("/api/schedules", bad)
        assert status == 400 and err["error"], f"{bad} should be rejected"


def test_daily_schedule_next_run_is_in_the_future_at_that_time(api):
    _, s = api.post("/api/schedules", {"kind": "daily", "at_time": "03:30"})
    lt = time.localtime(s["next_run"])
    assert (lt.tm_hour, lt.tm_min) == (3, 30) and 0 < s["next_run"] - time.time() <= 86400 + 3600


def test_scheduler_tick_runs_due_sweeps_with_the_chosen_params(home):
    ctl = make_ctl(home)
    ctl.start()
    try:
        s = ctl.create_schedule({"name": "Nightly", "kind": "interval", "every_seconds": 60, "params": {"hostnames": False, "offline_after": 0, "timeout": 2}})
        assert ctl.scheduler.tick(time.time()) == [], "not due yet"
        due = time.time() + 61
        assert ctl.scheduler.tick(due) == [s["id"]]
        job = next(j for j in ctl.store.recent_jobs() if j.source == f"schedule:{s['id']}")
        assert job.params["timeout"] == 2.0 and job.params["hostnames"] is False
        wait_store(ctl, job.id)
        after = ctl.store.get_schedule(s["id"])
        assert after.last_status == "done" and "devices seen" in after.last_message
        assert after.next_run == pytest.approx(due + 60), "interval re-arms from when it fired"
        assert ctl.scheduler.tick(due + 1) == []
    finally:
        ctl.close()


def test_once_schedule_fires_once_then_disables(home):
    ctl = make_ctl(home)
    ctl.start()
    try:
        s = ctl.create_schedule({"kind": "once", "run_at": time.time() + 30, "params": {"hostnames": False}})
        assert ctl.scheduler.tick(time.time() + 31) == [s["id"]]
        row = ctl.store.get_schedule(s["id"])
        assert row.enabled is False and row.next_run is None
        assert ctl.scheduler.tick(time.time() + 9999) == []
    finally:
        ctl.close()


def test_scheduler_does_not_pile_up_runs(home, monkeypatch):
    gate = threading.Event()
    started = threading.Event()

    def slow(self, params, cancel):
        started.set()
        gate.wait(5)
        return {"seen": 1}

    monkeypatch.setattr(Controller, "_do_sweep", slow)
    ctl = make_ctl(home)
    ctl.start()
    try:
        s = ctl.create_schedule({"kind": "interval", "every_seconds": 30, "params": {}})
        t = time.time() + 31
        assert ctl.scheduler.tick(t) == [s["id"]]
        assert started.wait(5)
        assert ctl.scheduler.tick(t + 31) == [], "previous run still active, so skipped"
        assert ctl.store.get_schedule(s["id"]).last_status == "skipped"
        with pytest.raises(ApiError) as exc:
            ctl.run_schedule_now(s["id"])
        assert exc.value.status == 409
        gate.set()
    finally:
        gate.set()
        ctl.close()


def test_run_now_and_create_with_run_now(api):
    _, s = api.post("/api/schedules", {"name": "Now", "kind": "interval", "every_seconds": 3600, "params": {"hostnames": False}, "run_now": True})
    deadline = time.time() + 10
    while time.time() < deadline and api.get("/api/schedules")[1][0]["last_status"] != "done":
        time.sleep(0.05)
    assert api.get("/api/schedules")[1][0]["last_status"] == "done"
    status, job = api.post(f"/api/schedules/{s['id']}/run")
    assert status == 200 and job["source"] == f"schedule:{s['id']}"
    assert api.post("/api/schedules/99/run")[0] == 404


# ---- services ----

def test_enforcer_service_cuts_off_then_restores_on_stop(api, ctl):
    scan(api)
    api.post("/api/block", {"target": PHONE.ip})
    status, svc = api.post("/api/services/enforce/start")
    assert status == 200 and svc["running"]
    assert api.post("/api/services/enforce/start")[0] == 409
    deadline = time.time() + 5
    while time.time() < deadline and not any(s[0] == DEAD_MAC for s in ctl.raw.sent):
        time.sleep(0.05)
    assert any(s[0] == DEAD_MAC for s in ctl.raw.sent)
    assert api.get("/api/status")[1]["services"]["enforce"]["running"]
    status, svc = api.post("/api/services/enforce/stop")
    assert status == 200 and not svc["running"]
    assert any(s[0] == GW_MAC and s[3] == PHONE.ip for s in ctl.raw.sent), "stopping restores the true MACs"
    assert api.post("/api/services/bogus/start")[0] == 404


def test_arp_watch_service_records_new_devices(home):
    from scapy.layers.l2 import ARP

    fake = FakeTransport()
    fake.sniffed = [Ether(src="3c:5a:b4:00:00:99", dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc="3c:5a:b4:00:00:99", psrc="192.168.1.99", pdst=GW_IP)]
    ctl = make_ctl(home, fake)
    ctl.start()
    try:
        wait_store(ctl, ctl.submit_scan({"hostnames": False})["id"])
        ctl.start_service("watch")
        deadline = time.time() + 5
        while time.time() < deadline and ctl.store.get_device("3c:5a:b4:00:00:99") is None:
            time.sleep(0.05)
        assert ctl.store.get_device("3c:5a:b4:00:00:99") is not None
        assert any(e["kind"] == "new_device" for e in ctl.events())
    finally:
        ctl.close()


def test_enforcer_not_offered_for_firewall_methods(home):
    (home / "config.toml").write_text(render_config(["192.168.1.0/24"]).replace('method = "arp"', 'method = "nftables"'))
    ctl = make_ctl(home)
    ctl.start()
    try:
        svc = ctl.status()["services"]["enforce"]
        assert svc["available"] is False and "nftables" in svc["unavailable_reason"]
        with pytest.raises(ApiError) as exc:
            ctl.start_service("enforce")
        assert exc.value.status == 409
    finally:
        ctl.close()


def test_daemon_mode_bootstraps_baseline_schedule_and_services(home):
    fake = FakeTransport()
    ctl = make_ctl(home, fake, daemon=True)
    ctl.start()
    try:
        deadline = time.time() + 10
        while time.time() < deadline and not (ctl._services["watch"].running and ctl._services["enforce"].running):
            time.sleep(0.05)
        assert ctl._services["watch"].thread is not None and ctl._services["enforce"].running
        startup = [j for j in ctl.store.recent_jobs() if j.source == "startup"]
        assert startup and startup[0].state == "done" and startup[0].summary["baseline"] is True
        sched = ctl.store.list_schedules()
        assert len(sched) == 1 and sched[0].every_seconds == ctl.cfg.daemon.sweep_interval and sched[0].params["offline_after"] == ctl.cfg.daemon.offline_after
        assert ctl.status()["daemon"] is True
    finally:
        ctl.close()


# ---- setup / config ----

def test_unconfigured_dashboard_offers_init_and_stays_scoped(tmp_path):
    fake = FakeTransport()
    ctl = Controller(Config(home=tmp_path), fake, resolver=lambda ip: "", scheduler_tick=3600)
    ctl.start()
    try:
        st = ctl.status()
        assert st["configured"] is False and st["ready"] is False and "allowed_subnets" in st["error"]
        with pytest.raises(ApiError) as exc:
            ctl.submit_scan({})
            job = ctl.store.recent_jobs()[0]
            wait_store(ctl, job.id)
            raise ApiError(0, job.error)
        job = ctl.store.recent_jobs()[0]
        assert job.state == "error" and fake.sweeps == [], "nothing is scanned before an allow-list exists"
        with pytest.raises(ApiError) as exc:
            ctl.block({"target": PHONE.ip})
        assert exc.value.status == 403
        out = ctl.init_config({})
        assert out["subnets"] == ["192.168.1.0/24"] and out["gateway_mac"] == GW_MAC
        assert (tmp_path / "config.toml").exists()
        assert ctl.status()["ready"] is True and ctl.cfg.gateway_mac == GW_MAC
        with pytest.raises(ApiError) as exc:
            ctl.init_config({})
        assert exc.value.status == 409
        with pytest.raises(ApiError) as exc:
            ctl.init_config({"force": True, "subnets": ["8.8.8.0/24"]})
        assert exc.value.status == 400, "a public subnet can never enter the allow-list"
    finally:
        ctl.close()


def test_wrong_network_is_refused_by_the_gateway_pin(home):
    (home / "config.toml").write_text(render_config(["192.168.1.0/24"], "de:ad:be:ef:00:01"))
    fake = FakeTransport()
    ctl = make_ctl(home, fake)
    ctl.start()
    try:
        st = ctl.status()
        assert st["ready"] is False and "does not match" in st["error"]
        job = wait_store(ctl, ctl.submit_scan({})["id"])
        assert job.state == "error" and fake.sweeps == []
    finally:
        ctl.close()


def test_config_view_never_leaks_secret_urls(home):
    text = render_config(["192.168.1.0/24"]).replace(
        '# ntfy_url = "https://ntfy.sh/your-private-topic"', 'ntfy_url = "https://ntfy.sh/secret-topic"'
    ).replace('# ntfy_token = ""', 'ntfy_token = "tk_secret"')
    (home / "config.toml").write_text(text)
    ctl = make_ctl(home)
    try:
        dumped = json.dumps(ctl.config_view())
        assert "secret" not in dumped and "ntfy" in dumped
    finally:
        ctl.close()
