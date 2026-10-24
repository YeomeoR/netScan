"""Dashboard features layered on the controller: device labels and trust, alert settings, block rules, presence and security checks.

Kept as a mixin so `Controller` stays readable; every method goes through the same core and guards as the rest of the API.
"""

from __future__ import annotations

import logging
import threading
import time
from urllib.parse import urlsplit

from netscan.macutil import normalise_mac
from netscan.monitor import ALERTABLE_KINDS, DEVICE_OFFLINE, DEVICE_ONLINE, NEW_DEVICE, SECURITY_KINDS
from netscan.portscan import COMMON_PORTS, MAX_TARGETS, port_info, record_scans, scan_ports, tcp_connect
from netscan.safety import SafetyError
from netscan.security import run_dhcp_probe
from netscan.store import BlockRule, Device, DeviceMeta
from netscan.web.errors import ApiError
from netscan.web.rules import DAY_NAMES, next_transition, validate_rule

log = logging.getLogger("netscan.web")

CATEGORIES = ("", "phone", "computer", "tv", "media", "console", "speaker", "camera", "iot", "printer", "network", "server", "other")
TRUST_LEVELS = ("unknown", "known", "guest")
ALERT_MODES = ("default", "always", "mute")
MAX_PRESENCE_HOURS = 24 * 30
SECRET_KEYS = ("webhook_url", "ntfy_url", "ntfy_token")


def display_name(dev: Device | None, meta: DeviceMeta | None, mac: str = "") -> str:
    if meta and meta.label:
        return meta.label
    if dev:
        return dev.hostname or dev.vendor or dev.mac
    return mac


def meta_dict(m: DeviceMeta | None) -> dict:
    m = m or DeviceMeta("")
    return {"label": m.label, "owner": m.owner, "category": m.category, "trust": m.trust, "notes": m.notes, "track": m.track, "alert": m.alert}


def presence_segments(events: list[tuple[float, str]], first_seen: float, since: float, until: float, offline_after: float) -> list[dict]:
    """Online/offline intervals clipped to [since, until], rebuilt from the event log.

    Approximate: an offline event is raised `offline_after` seconds after the last sighting, so it is back-dated by that much.
    """
    points: list[tuple[float, bool]] = [(first_seen, True)]
    prev_ts = first_seen
    for ts, kind in events:
        if kind in (NEW_DEVICE, DEVICE_ONLINE):
            points.append((ts, True))
        elif kind == DEVICE_OFFLINE:
            points.append((max(prev_ts, ts - offline_after), False))
        prev_ts = max(prev_ts, ts)
    points.sort(key=lambda p: p[0])
    merged: list[dict] = []
    for i, (t, state) in enumerate(points):
        end = points[i + 1][0] if i + 1 < len(points) else until
        a, b = max(t, since), min(end, until)
        if b <= a:
            continue
        if merged and merged[-1]["online"] == state and merged[-1]["end"] == a:
            merged[-1]["end"] = b
        else:
            merged.append({"start": a, "end": b, "online": state})
    return merged


class FeatureMixin:
    # expects Controller attributes: store, cfg, clock, _services, _runtime, _manager, _submit, start_service

    # --- device labels, owners, trust
    def _meta_map(self) -> dict[str, DeviceMeta]:
        return self.store.list_meta()

    def _require_device(self, ident: str) -> Device:
        dev = self.store.find_device(normalise_mac(ident) or ident)
        if dev is None:
            raise ApiError(404, f"unknown device {ident!r}; run a scan first")
        return dev

    def set_meta(self, ident: str, body: dict) -> dict:
        dev = self._require_device(ident)
        if not isinstance(body, dict):
            raise ApiError(400, "body must be an object")
        fields: dict = {}
        for key, limit in (("label", 40), ("owner", 40), ("notes", 500)):
            if key in body:
                v = body[key]
                if not isinstance(v, str) or len(v.strip()) > limit:
                    raise ApiError(400, f"{key} must be text up to {limit} characters")
                fields[key] = v.strip()
        for key, allowed in (("category", CATEGORIES), ("trust", TRUST_LEVELS), ("alert", ALERT_MODES)):
            if key in body:
                if body[key] not in allowed:
                    raise ApiError(400, f"{key} must be one of: {', '.join(a or 'none' for a in allowed)}")
                fields[key] = body[key]
        if "track" in body:
            if not isinstance(body["track"], bool):
                raise ApiError(400, "track must be true or false")
            fields["track"] = body["track"]
        if not fields:
            raise ApiError(400, "nothing to change")
        self.store.set_meta(dev.mac, self.clock(), **fields)
        return self.device_by_mac(dev.mac)

    def device_by_mac(self, mac: str) -> dict:
        blocked = {b.mac: b for b in self.store.list_blocks()}
        dev = self.store.get_device(mac)
        return self._device_dict(dev, blocked, self.store.traffic_totals(), self._meta_map())  # type: ignore[arg-type]

    def review(self, body: dict) -> dict:
        """Bulk trust change: mark devices known / guest / unknown in one go."""
        if not isinstance(body, dict):
            raise ApiError(400, "body must be an object")
        trust = body.get("trust", "known")
        if trust not in TRUST_LEVELS:
            raise ApiError(400, f"trust must be one of: {', '.join(TRUST_LEVELS)}")
        metas = self._meta_map()
        if body.get("all_unreviewed") is True:
            macs = [d.mac for d in self.store.list_devices() if metas.get(d.mac, DeviceMeta(d.mac)).trust == "unknown"]
        else:
            raw = body.get("macs")
            if not isinstance(raw, list) or not raw or not all(isinstance(m, str) for m in raw) or len(raw) > 500:
                raise ApiError(400, "macs must be a list of 1 to 500 device MAC addresses")
            macs = []
            for ident in raw:
                macs.append(self._require_device(ident).mac)
        now = self.clock()
        for mac in dict.fromkeys(macs):
            self.store.set_meta(mac, now, trust=trust)
        return {"updated": len(set(macs)), "trust": trust}

    # --- alert settings
    @staticmethod
    def _host_of(url: str) -> str:
        if not url:
            return ""
        parts = urlsplit(url)
        return f"{parts.scheme}://{parts.netloc}/…" if parts.netloc else "configured"

    def alerts_view(self) -> dict:
        from netscan.alerts import alert_overrides, effective_alert_config

        eff = effective_alert_config(self.cfg.alerts, self.store)
        over = alert_overrides(self.store)
        return {
            "webhook": {"configured": bool(eff.webhook_url), "host": self._host_of(eff.webhook_url)},
            "ntfy": {"configured": bool(eff.ntfy_url), "host": self._host_of(eff.ntfy_url), "token": bool(eff.ntfy_token)},
            "notify_on": list(eff.notify_on),
            "kinds": list(ALERTABLE_KINDS),
            "security_kinds": list(SECURITY_KINDS),
            "overridden": sorted(over),
        }

    def update_alerts(self, body: dict) -> dict:
        """Omitted or null keeps a value, "" clears it, anything else replaces it. Secrets are never echoed back."""
        if not isinstance(body, dict):
            raise ApiError(400, "body must be an object")
        over = dict(self.store.get_setting("alerts", {}) or {})
        if body.get("reset") is True:
            over = {}
        for key in SECRET_KEYS:
            if body.get(key) is None:
                continue
            v = body[key]
            if not isinstance(v, str) or len(v) > 500:
                raise ApiError(400, f"{key} must be text up to 500 characters")
            v = v.strip()
            if v and key.endswith("_url") and not (v.lower().startswith(("http://", "https://")) and urlsplit(v).netloc):
                raise ApiError(400, f"{key} must be a full http(s) URL")
            over[key] = v
        if body.get("notify_on") is not None:
            kinds = body["notify_on"]
            if not isinstance(kinds, list) or not all(isinstance(k, str) for k in kinds):
                raise ApiError(400, "notify_on must be a list of event kinds")
            bad = [k for k in kinds if k not in ALERTABLE_KINDS]
            if bad:
                raise ApiError(400, f"unknown event kinds: {', '.join(bad)}")
            over["notify_on"] = list(dict.fromkeys(kinds))
        self.store.set_setting("alerts", over)
        return self.alerts_view()

    def test_alerts(self) -> dict:
        from netscan.alerts import Alerter

        results = Alerter(self.cfg.alerts, store=self.store).test()
        if not any(r["configured"] for r in results.values()):
            raise ApiError(409, "no alert channel is configured; add a webhook or ntfy URL first")
        return results

    # --- block rules
    def _rule_dict(self, r: BlockRule, names: dict[str, str], now: float) -> dict:
        warning = ""
        if r.active and self.cfg.block_method == "arp" and not self._services["enforce"].running:
            warning = "The ARP enforcer is not running, so the block is recorded but not applied. Start it under System > Services."
        return {
            "id": r.id, "name": r.name, "kind": r.kind, "enabled": r.enabled, "macs": r.macs,
            "devices": [{"mac": m, "name": names.get(m, m)} for m in r.macs],
            "days": r.days, "day_names": [DAY_NAMES[d] for d in r.days], "start": r.start, "end": r.end, "until": r.until,
            "active": r.active, "held": r.held, "next_transition": next_transition(r, now), "warning": warning,
        }

    def _name_map(self) -> dict[str, str]:
        metas = self._meta_map()
        return {d.mac: display_name(d, metas.get(d.mac)) for d in self.store.list_devices()}

    def rules(self) -> list[dict]:
        names, now = self._name_map(), self.clock()
        return [self._rule_dict(r, names, now) for r in self.store.list_rules()]

    def _check_rule_devices(self, macs: list[str]) -> list[str]:
        rt = self._runtime()
        out = []
        for ident in macs:
            dev = self._require_device(ident)
            if rt.scope.is_protected(dev.ip, dev.mac):
                raise ApiError(403, f"{dev.ip} is protected (gateway, this machine or on your never-block list) and cannot be in a block rule")
            out.append(dev.mac)
        return out

    def _validated_rule(self, body: dict, existing: BlockRule | None) -> dict:
        try:
            v = validate_rule(body, self.clock(), existing)
        except ValueError as exc:
            raise ApiError(400, str(exc)) from exc
        v["macs"] = self._check_rule_devices(v["macs"])
        return v

    def create_rule(self, body: dict) -> dict:
        v = self._validated_rule(body, None)
        rule = self.store.add_rule(v["name"], v["kind"], v["macs"], v["days"], v["start"], v["end"], v["until"], v["enabled"], self.clock())
        self.rule_engine.tick(self.clock())
        return self._rule_dict(self.store.get_rule(rule.id), self._name_map(), self.clock())  # type: ignore[arg-type]

    def quick_block(self, body: dict) -> dict:
        """'Block these devices for N minutes' as a self-expiring timer rule."""
        if not isinstance(body, dict):
            raise ApiError(400, "body must be an object")
        macs, minutes = body.get("macs"), body.get("minutes")
        label = body.get("name")
        if not isinstance(macs, list) or not macs:
            raise ApiError(400, "choose at least one device")
        if not isinstance(minutes, int) or isinstance(minutes, bool):
            raise ApiError(400, "minutes must be a whole number")
        names = self._name_map()
        shown = names.get(normalise_mac(str(macs[0])) or "", str(macs[0]))
        default_name = f"Block {shown}" + (f" +{len(macs) - 1}" if len(macs) > 1 else "") + f" for {minutes} min"
        return self.create_rule({"kind": "timer", "name": label if isinstance(label, str) and label.strip() else default_name, "macs": macs, "minutes": minutes})

    def update_rule(self, rid: int, body: dict) -> dict:
        existing = self.store.get_rule(rid)
        if existing is None:
            raise ApiError(404, f"no such rule {rid}")
        v = self._validated_rule(body, existing)
        if existing.active and not self.rule_engine.release(existing):
            raise ApiError(409, "the network is not ready, so the rule's blocks cannot be released yet")
        self.store.update_rule(rid, **v)
        self.rule_engine.tick(self.clock())
        return self._rule_dict(self.store.get_rule(rid), self._name_map(), self.clock())  # type: ignore[arg-type]

    def delete_rule(self, rid: int) -> dict:
        existing = self.store.get_rule(rid)
        if existing is None:
            raise ApiError(404, f"no such rule {rid}")
        if existing.active and not self.rule_engine.release(existing):
            raise ApiError(409, "the network is not ready, so the rule's blocks cannot be released yet")
        self.store.delete_rule(rid)
        return {"deleted": rid}

    def rule_holding(self, mac: str) -> BlockRule | None:
        return next((r for r in self.store.list_rules() if r.active and r.enabled and mac in r.held), None)

    def ensure_enforcer(self) -> None:
        if self.cfg.block_method != "arp" or self._services["enforce"].running:
            return
        try:
            self.start_service("enforce")
        except Exception as exc:  # noqa: BLE001 the rule is still recorded; the UI warns that nothing enforces it
            log.warning("could not start the enforcer for a rule: %s", getattr(exc, "message", exc))

    # --- presence
    def presence(self, hours: float = 24, include_all: bool = False) -> dict:
        hours = max(1.0, min(float(hours), MAX_PRESENCE_HOURS))
        now = self.clock()
        since = now - hours * 3600
        metas = self._meta_map()
        offline_after = self.cfg.daemon.offline_after
        devices = []
        for dev in self.store.list_devices():
            meta = metas.get(dev.mac)
            if not include_all and not (meta and meta.track):
                continue
            evs = [(r["ts"], r["kind"]) for r in self.store.events_for_mac(dev.mac)]
            segs = presence_segments(evs, dev.first_seen, since, now, offline_after)
            devices.append({
                "mac": dev.mac, "name": display_name(dev, meta), "owner": meta.owner if meta else "", "category": meta.category if meta else "",
                "tracked": bool(meta and meta.track), "online": dev.online, "last_seen": dev.last_seen, "first_seen": dev.first_seen,
                "segments": segs, "online_seconds": round(sum(s["end"] - s["start"] for s in segs if s["online"])),
            })
        devices.sort(key=lambda d: (not d["online"], d["name"].lower()))
        tracked = sum(1 for d in devices if d["tracked"])
        return {
            "since": since, "until": now, "hours": hours, "devices": devices, "tracked": tracked,
            "home": sum(1 for d in devices if d["tracked"] and d["online"]),
            "approximate": f"Presence follows sweeps: a device counts as away only after {offline_after // 60} min unseen.",
        }

    # --- security
    def security(self) -> dict:
        metas = self._meta_map()
        devs = {d.mac: d for d in self.store.list_devices()}
        findings = []
        for r in self.store.events_of_kinds(SECURITY_KINDS, 100):
            row = dict(r)
            row["name"] = display_name(devs.get(row["mac"]), metas.get(row["mac"]), row["mac"]) if row["mac"] else ""
            findings.append(row)
        scans = []
        for s in self.store.list_port_scans():
            dev = devs.get(s["mac"])
            scans.append({
                "mac": s["mac"], "ip": dev.ip if dev else s["ip"], "name": display_name(dev, metas.get(s["mac"]), s["mac"]),
                "ts": s["ts"], "open": [port_info(p) for p in s["open"]],
            })
        scans.sort(key=lambda s: (-sum(1 for p in s["open"] if p["risk"] == "high"), -len(s["open"]), s["ip"]))
        unreviewed = sum(1 for d in devs.values() if metas.get(d.mac, DeviceMeta(d.mac)).trust == "unknown")
        return {
            "findings": findings, "last_dhcp": self.store.get_setting("last_dhcp"), "port_scans": scans,
            "ports_checked": sorted(COMMON_PORTS), "max_targets": MAX_TARGETS, "unreviewed": unreviewed,
            "gateway": (self._rt.scope.gateway_ip if self._rt else ""), "gateway_mac": (self._rt.gateway_mac if self._rt else ""),
            "arp_watch": self._services["watch"].running,
        }

    def submit_dhcp_probe(self) -> dict:
        return self._submit("dhcp", {})

    def submit_ports(self, body: dict) -> dict:
        if not isinstance(body, dict):
            raise ApiError(400, "body must be an object")
        raw = body.get("macs")
        if raw is None:
            macs = [d.mac for d in self.store.list_devices() if d.online]
        elif isinstance(raw, list) and raw and all(isinstance(m, str) for m in raw):
            macs = [self._require_device(m).mac for m in raw]
        else:
            raise ApiError(400, "macs must be a list of device MAC addresses")
        macs = list(dict.fromkeys(macs))
        if not macs:
            raise ApiError(400, "no online devices to scan; run a scan first or pick devices")
        if len(macs) > MAX_TARGETS:
            raise ApiError(400, f"select at most {MAX_TARGETS} devices per port scan")
        return self._submit("ports", {"macs": macs})

    def _do_dhcp(self) -> dict:
        rt = self._runtime()
        if not rt.transport.can_raw():
            raise ApiError(409, "the DHCP check needs root (sudo) or CAP_NET_RAW")
        try:
            result = run_dhcp_probe(rt, now=self.clock())
        except PermissionError as exc:
            raise ApiError(409, str(exc)) from exc
        return {"offers": len(result["offers"]), "problems": len(result["problems"])}

    def _do_ports(self, params: dict, cancel: threading.Event) -> dict:
        rt = self._runtime()
        targets = []
        for mac in params.get("macs", []):
            dev = self.store.get_device(mac)
            if dev:
                targets.append((dev.mac, dev.ip))
        t0 = time.time()
        try:
            results = scan_ports(targets, rt.scope, connect=getattr(self.raw, "port_connect", tcp_connect), cancel=cancel)
        except SafetyError as exc:
            raise ApiError(403, str(exc)) from exc
        if cancel.is_set():
            return {"devices": 0, "open": 0, "findings": 0, "partial": True}
        events = record_scans(rt, targets, results, self.clock())
        rt.alerter.dispatch(events)
        return {
            "devices": len(targets), "open": sum(len(v) for v in results.values()), "findings": len(events),
            "duration": round(time.time() - t0, 1),
        }

