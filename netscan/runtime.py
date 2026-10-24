"""Wires config, scope, transport, storage and tracker together for the CLI and the daemon."""

from __future__ import annotations

import socket
import threading
from dataclasses import dataclass
from typing import Callable

from netscan.alerts import Alerter
from netscan.config import Config
from netscan.net import GuardedTransport, LocalNet, ScapyTransport, Transport
from netscan.monitor import DeviceTracker
from netscan.oui import OuiDb
from netscan.parsing import Host
from netscan.macutil import normalise_mac
from netscan.safety import OutOfScopeError, Scope
from netscan.store import Store


@dataclass
class Runtime:
    cfg: Config
    scope: Scope
    transport: GuardedTransport
    local: LocalNet
    store: Store
    oui: OuiDb
    tracker: DeviceTracker
    alerter: Alerter
    gateway_mac: str = ""


def reverse_dns(ip: str, timeout: float = 2.0) -> str:
    """gethostbyaddr has no timeout of its own and can stall a sweep, so bound it with a helper thread."""
    result: list[str] = []

    def work() -> None:
        try:
            result.append(socket.gethostbyaddr(ip)[0])
        except (OSError, UnicodeError):
            pass

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    return result[0] if result else ""


def build_runtime(cfg: Config, transport: Transport | None = None, resolve_hostname: Callable[[str], str] | None = reverse_dns) -> Runtime:
    """Detect the local network and refuse to continue unless it sits inside the allow-list."""
    raw = transport or ScapyTransport()
    local = raw.local_net(cfg.interface)
    gateway = cfg.gateway or local.gateway_ip
    protected_macs = {local.mac} if local.mac else set()
    scope = Scope(cfg.allowed_subnets, gateway_ip=gateway, host_ips=set(raw.local_ips()) | {local.ip}, protected_macs=protected_macs)
    scope.check_network(local.network)
    for entry in cfg.extra_protected:
        scope.add_protected(entry)
    guarded = GuardedTransport(raw, scope)
    try:
        gw_mac = guarded.resolve_mac(gateway, local.interface) if gateway else None
    except Exception:  # noqa: BLE001 best effort; the gateway ip is protected regardless
        gw_mac = None
    if cfg.gateway_mac and normalise_mac(cfg.gateway_mac) != gw_mac:
        # the allow-list is just a CIDR, and 192.168.1.0/24 is also someone else's wifi; pinning the router's MAC tells them apart
        raise OutOfScopeError(
            f"gateway MAC {gw_mac or 'unknown'} does not match network.gateway_mac {cfg.gateway_mac}; this does not look like your network, refusing"
        )
    if gw_mac:
        scope.add_protected(gw_mac)
    store = Store(cfg.db_path)
    oui = OuiDb.load(cfg.oui_path)
    tracker = DeviceTracker(store, oui, scope, resolve_hostname, cfg.daemon.silent_baseline)
    return Runtime(cfg, scope, guarded, local, store, oui, tracker, Alerter(cfg.alerts, store=store), gateway_mac=gw_mac or normalise_mac(cfg.gateway_mac) or "")


def sweep(rt: Runtime, timeout: float = 3.0, now: float | None = None, resolve_names: bool = True):
    """One ARP sweep of the local subnet; returns (hosts, events)."""
    hosts = rt.transport.arp_sweep(rt.local.network, rt.local.interface, timeout)
    hosts = [h for h in hosts if h.ip != rt.local.ip]
    if rt.local.mac:
        hosts.append(Host(rt.local.ip, rt.local.mac))
    events = rt.tracker.observe(hosts, now, allow_baseline=True, resolve_names=resolve_names)
    events += rt.tracker.check_conflicts([(h.ip, h.mac) for h in hosts], now)
    return hosts, events


def write_initial_config(cfg: Config, transport: Transport, subnets: list[str] | None = None, force: bool = False) -> tuple[list[str], str, LocalNet]:
    """Detect the local network, pin the gateway MAC when resolvable and write config.toml.

    Shared by `netscan init` and the dashboard. Returns (subnets, gateway_mac, local).
    """
    from netscan.config import ConfigError, parse_subnets, render_config

    if cfg.config_path.exists() and not force:
        raise ConfigError(f"{cfg.config_path} already exists (use force to overwrite)")
    local = transport.local_net(cfg.interface)
    chosen = list(subnets) if subnets else [str(local.network)]
    parse_subnets(chosen)
    try:
        gw_mac = transport.resolve_mac(local.gateway_ip, local.interface) if local.gateway_ip else None
    except Exception:  # noqa: BLE001 pinning is optional
        gw_mac = None
    cfg.config_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.config_path.write_text(render_config(chosen, gw_mac or ""), encoding="utf-8")
    return chosen, gw_mac or "", local
