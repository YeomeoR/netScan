"""Alert sinks: terminal/log always, plus optional webhook and ntfy. Failures never crash the daemon."""

from __future__ import annotations

import json
import logging
import urllib.request
from typing import Callable

from netscan.config import AlertConfig
from netscan.monitor import Event

log = logging.getLogger("netscan.alerts")

PostFn = Callable[[str, bytes, dict, float], None]


def http_post(url: str, body: bytes, headers: dict, timeout: float) -> None:
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError(f"refusing non-http alert url {url!r}")
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout):  # noqa: S310 scheme checked above
        pass


class Alerter:
    def __init__(self, cfg: AlertConfig, post: PostFn = http_post):
        self.cfg = cfg
        self._post = post

    def dispatch(self, events: list[Event]) -> None:
        for ev in events:
            log.warning("ALERT %s | %s", ev.kind, ev.describe()) if ev.kind == "new_device" else log.info("%s | %s", ev.kind, ev.describe())
            if ev.kind not in self.cfg.notify_on:
                continue
            self._send_webhook(ev)
            self._send_ntfy(ev)

    def _send_webhook(self, ev: Event) -> None:
        if not self.cfg.webhook_url:
            return
        payload = {
            "kind": ev.kind, "message": ev.message, "ip": ev.ip, "mac": ev.mac,
            "vendor": ev.vendor, "hostname": ev.hostname, "text": ev.describe(),
        }
        self._safe(self.cfg.webhook_url, json.dumps(payload).encode(), {"Content-Type": "application/json"}, "webhook")

    def _send_ntfy(self, ev: Event) -> None:
        if not self.cfg.ntfy_url:
            return
        headers = {
            "Title": f"netScan: {ev.kind.replace('_', ' ')}",
            "Priority": "high" if ev.kind == "new_device" else "default",
            "Tags": "warning" if ev.kind == "new_device" else "information_source",
        }
        if self.cfg.ntfy_token:
            headers["Authorization"] = f"Bearer {self.cfg.ntfy_token}"
        self._safe(self.cfg.ntfy_url, ev.describe().encode(), headers, "ntfy")

    def _safe(self, url: str, body: bytes, headers: dict, name: str) -> None:
        try:
            self._post(url, body, headers, self.cfg.timeout)
        except Exception as exc:  # noqa: BLE001 alert delivery must never take the daemon down
            log.error("%s alert failed: %s", name, exc)
