"""Alert sinks: terminal/log always, plus optional webhook and ntfy. Failures never crash the daemon."""

from __future__ import annotations

import json
import logging
import urllib.request
from dataclasses import replace
from typing import Callable

from netscan.config import AlertConfig
from netscan.monitor import SECURITY_KINDS, Event

log = logging.getLogger("netscan.alerts")

PostFn = Callable[[str, bytes, dict, float], None]


def http_post(url: str, body: bytes, headers: dict, timeout: float) -> None:
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError(f"refusing non-http alert url {url!r}")
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout):  # noqa: S310 scheme checked above
        pass


def alert_overrides(store) -> dict:
    """Dashboard-edited alert settings stored in the db; they win over config.toml."""
    if store is None:
        return {}
    try:
        data = store.get_setting("alerts", {})
    except Exception:  # noqa: BLE001 a broken settings row must not stop alerting
        return {}
    return data if isinstance(data, dict) else {}


def effective_alert_config(base: AlertConfig, store) -> AlertConfig:
    over = alert_overrides(store)
    cfg = replace(base)
    for key in ("webhook_url", "ntfy_url", "ntfy_token"):
        if isinstance(over.get(key), str):
            setattr(cfg, key, over[key])
    if isinstance(over.get("notify_on"), list):
        cfg.notify_on = tuple(str(k) for k in over["notify_on"])
    return cfg


class Alerter:
    def __init__(self, cfg: AlertConfig, post: PostFn = http_post, store=None):
        self.cfg = cfg
        self._post = post
        self.store = store

    def effective(self) -> AlertConfig:
        return effective_alert_config(self.cfg, self.store)

    def _device_mode(self, mac: str) -> str:
        if not mac or self.store is None:
            return "default"
        try:
            meta = self.store.get_meta(mac)
        except Exception:  # noqa: BLE001
            return "default"
        return meta.alert if meta else "default"

    def dispatch(self, events: list[Event]) -> None:
        cfg = self.effective()
        for ev in events:
            loud = ev.kind == "new_device" or ev.kind in SECURITY_KINDS
            log.warning("ALERT %s | %s", ev.kind, ev.describe()) if loud else log.info("%s | %s", ev.kind, ev.describe())
            mode = self._device_mode(ev.mac)
            if mode == "mute" or ev.kind == "baseline":
                continue
            if mode != "always" and ev.kind not in cfg.notify_on:
                continue
            self._send_webhook(ev, cfg)
            self._send_ntfy(ev, cfg)

    def test(self) -> dict:
        """Send a test message to every configured channel; returns {channel: {configured, ok, error}}."""
        cfg = self.effective()
        probe = Event("test", message="netScan test alert: your notifications are working")
        out = {}
        for name, url, sender in (("webhook", cfg.webhook_url, self._send_webhook), ("ntfy", cfg.ntfy_url, self._send_ntfy)):
            if not url:
                out[name] = {"configured": False, "ok": False, "error": ""}
                continue
            err = sender(probe, cfg)
            out[name] = {"configured": True, "ok": err is None, "error": err or ""}
        return out

    def _send_webhook(self, ev: Event, cfg: AlertConfig) -> str | None:
        if not cfg.webhook_url:
            return None
        payload = {
            "kind": ev.kind, "message": ev.message, "ip": ev.ip, "mac": ev.mac,
            "vendor": ev.vendor, "hostname": ev.hostname, "text": ev.describe(),
        }
        return self._safe(cfg, cfg.webhook_url, json.dumps(payload).encode(), {"Content-Type": "application/json"}, "webhook")

    def _send_ntfy(self, ev: Event, cfg: AlertConfig) -> str | None:
        if not cfg.ntfy_url:
            return None
        urgent = ev.kind == "new_device" or ev.kind in SECURITY_KINDS
        headers = {
            "Title": f"netScan: {ev.kind.replace('_', ' ')}",
            "Priority": "high" if urgent else "default",
            "Tags": "warning" if urgent else "information_source",
        }
        if cfg.ntfy_token:
            headers["Authorization"] = f"Bearer {cfg.ntfy_token}"
        return self._safe(cfg, cfg.ntfy_url, ev.describe().encode(), headers, "ntfy")

    def _safe(self, cfg: AlertConfig, url: str, body: bytes, headers: dict, name: str) -> str | None:
        try:
            self._post(url, body, headers, cfg.timeout)
        except Exception as exc:  # noqa: BLE001 alert delivery must never take the daemon down
            log.error("%s alert failed: %s", name, exc)
            return str(exc) or exc.__class__.__name__
        return None
