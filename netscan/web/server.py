"""HTTP layer: a small JSON API plus the static dashboard, on the standard library only.

Security model: the dashboard can block devices, so every /api call needs the bearer token
(stored 0600 in the data dir, printed at start-up). Browsers cannot add that header
cross-origin without a CORS preflight, which we never grant, so other websites cannot drive
it. Bound to loopback the Host header is also checked to blunt DNS rebinding. Traffic is
plain HTTP: on a LAN bind, treat the token like a Wi-Fi password and keep it on that LAN.
"""

from __future__ import annotations

import hmac
import json
import logging
import mimetypes
import os
import re
import secrets
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, unquote, urlparse

from netscan.safety import SafetyError
from netscan.web.controller import Controller
from netscan.web.errors import ApiError

log = logging.getLogger("netscan.web.http")

MAX_BODY = 64 * 1024
STATIC_FILES = {"/": "index.html", "/index.html": "index.html", "/app.js": "app.js", "/help.js": "help.js", "/extra.js": "extra.js", "/updates.js": "updates.js", "/spoof.js": "spoof.js", "/style.css": "style.css", "/favicon.svg": "favicon.svg"}
LOOPBACK_HOSTS = {"127.0.0.1", "localhost"}


def load_or_create_token(home: Path, override: str = "") -> str:
    """The dashboard token: explicit override, else <home>/web_token (created 0600 on first use)."""
    if override:
        return override
    path = Path(home) / "web_token"
    try:
        token = path.read_text(encoding="utf-8").strip()
        if token:
            return token
    except FileNotFoundError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(24)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(token + "\n")
    return token


def hostname_of(host_header: str) -> str:
    host = host_header.strip()
    if host.startswith("["):
        return host.split("]")[0] + "]"
    return host.rsplit(":", 1)[0] if ":" in host else host


def _read_static(name: str) -> bytes:
    return resources.files("netscan.web").joinpath("static", name).read_bytes()


Route = tuple[str, "re.Pattern[str]", Callable]


def build_routes(c: Controller) -> list[Route]:
    def r(method: str, pattern: str, fn: Callable) -> Route:
        return method, re.compile(f"^{pattern}$"), fn

    return [
        r("GET", "/api/status", lambda m, q, b: c.status()),
        r("POST", "/api/refresh", lambda m, q, b: c.refresh_runtime()),
        r("GET", "/api/config", lambda m, q, b: c.config_view()),
        r("POST", "/api/init", lambda m, q, b: c.init_config(b)),
        r("GET", "/api/devices", lambda m, q, b: c.devices()),
        r("GET", r"/api/devices/(?P<ident>[^/]+)", lambda m, q, b: c.device_detail(unquote(m["ident"]))),
        r("PUT", r"/api/devices/(?P<ident>[^/]+)/meta", lambda m, q, b: c.set_meta(unquote(m["ident"]), b)),
        r("POST", "/api/devices/review", lambda m, q, b: c.review(b)),
        r("GET", "/api/alerts", lambda m, q, b: c.alerts_view()),
        r("PUT", "/api/alerts", lambda m, q, b: c.update_alerts(b)),
        r("POST", "/api/alerts/test", lambda m, q, b: c.test_alerts()),
        r("GET", "/api/rules", lambda m, q, b: c.rules()),
        r("POST", "/api/rules", lambda m, q, b: c.create_rule(b)),
        r("POST", "/api/rules/quick", lambda m, q, b: c.quick_block(b)),
        r("PUT", r"/api/rules/(?P<id>\d+)", lambda m, q, b: c.update_rule(int(m["id"]), b)),
        r("DELETE", r"/api/rules/(?P<id>\d+)", lambda m, q, b: c.delete_rule(int(m["id"]))),
        r("GET", "/api/presence", lambda m, q, b: c.presence(_float_query(q, "hours", 24), q.get("all", ["0"])[0] == "1")),
        r("GET", "/api/security", lambda m, q, b: c.security()),
        r("POST", "/api/security/dhcp-probe", lambda m, q, b: c.submit_dhcp_probe()),
        r("POST", "/api/security/ports", lambda m, q, b: c.submit_ports(b)),
        r("POST", "/api/scan", lambda m, q, b: c.submit_scan(b)),
        r("POST", "/api/traffic", lambda m, q, b: c.submit_traffic(b)),
        r("POST", "/api/update-oui", lambda m, q, b: c.submit_update_oui()),
        r("GET", "/api/update", lambda m, q, b: c.update_status(q.get("force", ["0"])[0] == "1")),
        r("PUT", "/api/update", lambda m, q, b: c.set_update_auto(b)),
        r("POST", "/api/update/apply", lambda m, q, b: c.submit_update()),
        r("GET", "/api/spoof", lambda m, q, b: c.spoof_status()),
        r("POST", "/api/spoof", lambda m, q, b: c.submit_spoof(b)),
        r("POST", "/api/spoof/restore", lambda m, q, b: c.submit_unspoof()),
        r("GET", "/api/blocks", lambda m, q, b: c.blocks()),
        r("POST", "/api/block", lambda m, q, b: c.block(b)),
        r("POST", "/api/unblock", lambda m, q, b: c.unblock(b)),
        r("GET", "/api/events", lambda m, q, b: c.events(_int_query(q, "limit", 50))),
        r("GET", "/api/jobs", lambda m, q, b: c.jobs(_int_query(q, "limit", 30))),
        r("POST", r"/api/jobs/(?P<id>\d+)/cancel", lambda m, q, b: c.cancel_job(int(m["id"]))),
        r("POST", r"/api/services/(?P<name>[a-z]+)/start", lambda m, q, b: c.start_service(m["name"])),
        r("POST", r"/api/services/(?P<name>[a-z]+)/stop", lambda m, q, b: c.stop_service(m["name"])),
        r("GET", "/api/schedules", lambda m, q, b: c.schedules()),
        r("POST", "/api/schedules", lambda m, q, b: c.create_schedule(b)),
        r("PUT", r"/api/schedules/(?P<id>\d+)", lambda m, q, b: c.update_schedule(int(m["id"]), b)),
        r("DELETE", r"/api/schedules/(?P<id>\d+)", lambda m, q, b: c.delete_schedule(int(m["id"]))),
        r("POST", r"/api/schedules/(?P<id>\d+)/run", lambda m, q, b: c.run_schedule_now(int(m["id"]))),
    ]


def _int_query(q: dict, key: str, default: int) -> int:
    try:
        return int(q.get(key, [default])[0])
    except (TypeError, ValueError):
        raise ApiError(400, f"{key} must be a whole number") from None


def _float_query(q: dict, key: str, default: float) -> float:
    try:
        return float(q.get(key, [default])[0])
    except (TypeError, ValueError):
        raise ApiError(400, f"{key} must be a number") from None


def make_handler(controller: Controller, token: str, loopback_only: bool):
    routes = build_routes(controller)

    class Handler(BaseHTTPRequestHandler):
        server_version = "netscan"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # noqa: A003
            log.debug("%s %s", self.address_string(), fmt % args)

        # plumbing
        def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            )
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status: int, payload) -> None:
            self._send(status, json.dumps(payload).encode(), "application/json; charset=utf-8")

        def _error(self, status: int, message: str) -> None:
            self._json(status, {"error": message})

        def _host_ok(self) -> bool:
            return not loopback_only or hostname_of(self.headers.get("Host") or "") in LOOPBACK_HOSTS

        def _authorised(self) -> bool:
            header = self.headers.get("Authorization", "")
            supplied = header[7:] if header.lower().startswith("bearer ") else ""
            return hmac.compare_digest(supplied.encode(), token.encode())

        def _body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                raise ApiError(413, "request body too large")
            if length == 0:
                return {}
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise ApiError(400, "body must be valid JSON") from None
            if not isinstance(data, dict):
                raise ApiError(400, "body must be a JSON object")
            return data

        # dispatch
        def _handle(self) -> None:
            if not self._host_ok():
                return self._error(HTTPStatus.FORBIDDEN, "unexpected Host header")
            url = urlparse(self.path)
            path = url.path
            if not path.startswith("/api/"):
                return self._static(path)
            if not self._authorised():
                time.sleep(0.4)  # slows token guessing without a lockout that could shut the owner out
                return self._error(HTTPStatus.UNAUTHORIZED, "missing or wrong access token")
            matched_path = False
            for method, pattern, fn in routes:
                m = pattern.match(path)
                if not m:
                    continue
                matched_path = True
                if method != self.command:
                    continue
                try:
                    body = self._body() if self.command in ("POST", "PUT") else {}
                    result = fn(m.groupdict(), parse_qs(url.query), body)
                except ApiError as exc:
                    return self._error(exc.status, exc.message)
                except SafetyError as exc:
                    return self._error(HTTPStatus.FORBIDDEN, str(exc))
                except Exception:  # noqa: BLE001
                    log.exception("unhandled error for %s %s", self.command, path)
                    return self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal error; see the netscan log")
                return self._json(HTTPStatus.OK, result)
            self._error(HTTPStatus.METHOD_NOT_ALLOWED if matched_path else HTTPStatus.NOT_FOUND, "no such endpoint")

        def _static(self, path: str) -> None:
            name = STATIC_FILES.get(path)
            if name is None or self.command not in ("GET", "HEAD"):
                return self._error(HTTPStatus.NOT_FOUND, "not found")
            try:
                body = _read_static(name)
            except FileNotFoundError:
                return self._error(HTTPStatus.NOT_FOUND, "not found")
            ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
            self._send(HTTPStatus.OK, body, f"{ctype}; charset=utf-8" if ctype.startswith("text/") or ctype.endswith("javascript") else ctype)

        do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _handle

        def do_OPTIONS(self):  # noqa: N802 no CORS: cross-origin pages get nothing
            self._error(HTTPStatus.METHOD_NOT_ALLOWED, "cross-origin requests are not allowed")

    return Handler


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(controller: Controller, host: str, port: int, token: str) -> DashboardServer:
    loopback = host in LOOPBACK_HOSTS
    return DashboardServer((host, port), make_handler(controller, token, loopback))


def serve_forever(server: DashboardServer, stop: threading.Event | None = None) -> None:
    stop = stop or threading.Event()
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.3}, name="netscan-http", daemon=True)
    thread.start()
    try:
        while thread.is_alive() and not stop.wait(0.5):
            pass
    finally:
        server.shutdown()
        server.server_close()
