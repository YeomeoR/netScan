"""Alert sinks: terminal/log always, plus optional webhook and ntfy. Failures never crash the daemon."""

from __future__ import annotations

import base64
import json
import logging
import socket
import time
import urllib.request
from dataclasses import replace
from typing import Callable

from netscan.config import AlertConfig
from netscan.macutil import is_locally_administered
from netscan.monitor import SECURITY_KINDS, Event, ago

log = logging.getLogger("netscan.alerts")

PostFn = Callable[[str, bytes, dict, float], None]

KIND_SHORT = {
    "new_device": "new device", "device_online": "back online", "device_offline": "went offline",
    "ip_changed": "IP changed", "blocked": "blocked", "unblocked": "unblocked", "ip_conflict": "IP conflict",
    "arp_spoof": "ARP spoof", "rogue_dhcp": "rogue DHCP", "port_opened": "port opened", "test": "test",
}


def header_text(value: str) -> str:
    """HTTP headers are latin-1; ntfy accepts anything else as an RFC 2047 encoded word."""
    try:
        value.encode("ascii")
        return value
    except UnicodeEncodeError:
        return "=?UTF-8?B?" + base64.b64encode(value.encode("utf-8")).decode("ascii") + "?="


def machine_name() -> str:
    try:
        return socket.gethostname().split(".")[0]
    except OSError:
        return ""


def describe_device(ev: Event, store, now: float | None = None) -> dict:
    """Everything useful for telling devices apart: your own label first, then vendor and the tail of the MAC.
    The reverse-DNS hostname is kept as a detail, not a headline; it is often a router-made name or missing."""
    now = time.time() if now is None else now
    dev = meta = None
    if store is not None and ev.mac:
        try:
            dev, meta = store.get_device(ev.mac), store.get_meta(ev.mac)
        except Exception:  # noqa: BLE001 alert text must not depend on the database being healthy
            dev = meta = None
    vendor = (dev.vendor if dev else "") or ev.vendor
    private = bool(ev.mac) and is_locally_administered(ev.mac)
    tail = ev.mac[-5:] if ev.mac else ""
    if meta and meta.label:
        name = meta.label
    elif vendor and not private:
        name = f"{vendor} {tail}".strip()
    elif private:
        name = f"Private MAC {tail}".strip()
    else:
        name = ev.ip or ev.mac or ""
    return {
        "name": name, "label": meta.label if meta else "", "owner": meta.owner if meta else "",
        "category": meta.category if meta else "", "trust": meta.trust if meta else "",
        "vendor": vendor, "private_mac": private, "hostname": (dev.hostname if dev else "") or ev.hostname,
        "ip": (dev.ip if dev else "") or ev.ip, "first_seen": dev.first_seen if dev else None,
        "known_for": ago(now - dev.first_seen) if dev else "",
    }


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


def ntfy_body(ev: Event, info: dict, why: str = "") -> str:
    lines = [ev.message]
    pairs = [
        ("Name", info["label"]), ("Owner", info["owner"]), ("Type", info["category"]),
        ("IP", info["ip"]), ("MAC", ev.mac + (" (private/randomised)" if info["private_mac"] else "")),
        ("Vendor", info["vendor"] if not info["private_mac"] else ""), ("Hostname", info["hostname"]),
        ("Status", {"known": "known", "guest": "guest", "unknown": "not reviewed"}.get(info["trust"], "") if ev.mac else ""),
        ("First seen", f"{info['known_for']} ago" if info["known_for"] else ""),
        ("Sent by", machine_name()),
        ("Sent because", why),
    ]
    lines += [f"{k}: {v}" for k, v in pairs if v]
    return "\n".join(lines)


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
            why = "this device is set to 'Always alert'" if mode == "always" and ev.kind not in cfg.notify_on else ""
            self._send_webhook(ev, cfg, why)
            self._send_ntfy(ev, cfg, why)

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

    def _send_webhook(self, ev: Event, cfg: AlertConfig, why: str = "") -> str | None:
        if not cfg.webhook_url:
            return None
        info = describe_device(ev, self.store)
        payload = {
            "kind": ev.kind, "message": ev.message, "ip": ev.ip, "mac": ev.mac,
            "vendor": ev.vendor, "hostname": ev.hostname, "text": ev.describe(),
            "name": info["name"], "owner": info["owner"], "category": info["category"], "trust": info["trust"],
            "private_mac": info["private_mac"], "first_seen": info["first_seen"], "sent_by": machine_name(), "why": why,
        }
        return self._safe(cfg, cfg.webhook_url, json.dumps(payload).encode(), {"Content-Type": "application/json"}, "webhook")

    def _send_ntfy(self, ev: Event, cfg: AlertConfig, why: str = "") -> str | None:
        if not cfg.ntfy_url:
            return None
        urgent = ev.kind == "new_device" or ev.kind in SECURITY_KINDS
        info = describe_device(ev, self.store)
        short = KIND_SHORT.get(ev.kind, ev.kind.replace("_", " "))
        title = f"{info['name']}: {short}" if info["name"] else f"netScan: {short}"
        headers = {
            "Title": header_text(title),
            "Priority": "high" if urgent else "default",
            "Tags": "warning" if urgent else "information_source",
        }
        if cfg.ntfy_token:
            headers["Authorization"] = f"Bearer {cfg.ntfy_token}"
        return self._safe(cfg, cfg.ntfy_url, ntfy_body(ev, info, why).encode("utf-8"), headers, "ntfy")

    def _safe(self, cfg: AlertConfig, url: str, body: bytes, headers: dict, name: str) -> str | None:
        try:
            self._post(url, body, headers, cfg.timeout)
        except Exception as exc:  # noqa: BLE001 alert delivery must never take the daemon down
            log.error("%s alert failed: %s", name, exc)
            return str(exc) or exc.__class__.__name__
        return None
