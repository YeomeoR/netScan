"""Per-network data: each network this machine joins gets its own sqlite file for devices, events, blocks and traffic."""

from __future__ import annotations

import re
from pathlib import Path

from netscan.config import Config
from netscan.macutil import normalise_mac
from netscan.store import Store


ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")


def network_id(gateway_mac: str, subnet: str) -> str:
    """The router's MAC tells two homes that both use 192.168.1.0/24 apart; the subnet is the fallback."""
    mac = normalise_mac(gateway_mac)
    if mac:
        return "gw-" + mac.replace(":", "")
    return "net-" + re.sub(r"[^0-9a-z]+", "-", subnet.lower()).strip("-")


def network_db_path(cfg: Config, net_id: str) -> Path:
    if not ID_PATTERN.fullmatch(net_id):
        raise ValueError(f"unusable network id {net_id!r}")
    return cfg.db_path.parent / "networks" / f"{net_id}.db"  # type: ignore[union-attr]


def legacy_home(cfg: Config) -> tuple[str, Path] | None:
    """Where data recorded before per-network files belongs: the router pinned in the config, if there is one."""
    mac = normalise_mac(cfg.gateway_mac)
    if not mac:
        return None
    net_id = network_id(mac, "")
    return net_id, network_db_path(cfg, net_id)


def open_store(cfg: Config) -> Store:
    """Open the database the way the last run left it, so commands that never detect the network see the same data."""
    store = Store(cfg.db_path)  # type: ignore[arg-type]
    net_id = store.get_setting("active_network")
    if isinstance(net_id, str) and ID_PATTERN.fullmatch(net_id):
        store.attach_network(net_id, network_db_path(cfg, net_id), legacy_home(cfg))
    return store
