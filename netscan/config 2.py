"""Configuration: TOML file plus a per-user home dir holding the db and the notice acknowledgement."""

from __future__ import annotations

import ipaddress
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from netscan.macutil import normalise_mac

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

# an allow-list wider than /16 is almost certainly a mistake, and never a home network
MAX_ALLOWED_SPAN_PREFIX = 16


class ConfigError(ValueError):
    pass


def default_home() -> Path:
    return Path(os.environ.get("NETSCAN_HOME", "~/.netscan")).expanduser()


DEFAULT_NOTIFY_ON = ("new_device", "ip_conflict", "arp_spoof", "rogue_dhcp", "port_opened")


@dataclass
class AlertConfig:
    webhook_url: str = ""
    ntfy_url: str = ""  # full topic url, e.g. https://ntfy.sh/my-private-topic
    ntfy_token: str = ""
    notify_on: tuple[str, ...] = DEFAULT_NOTIFY_ON
    timeout: float = 5.0


@dataclass
class DaemonConfig:
    sweep_interval: int = 300
    offline_after: int = 900
    arp_watch: bool = True
    capture_traffic: bool = False
    # first ever sweep seeds the inventory without raising an alert per existing device
    silent_baseline: bool = True


@dataclass
class Config:
    allowed_subnets: list[ipaddress.IPv4Network] = field(default_factory=list)
    interface: str = ""
    gateway: str = ""
    gateway_mac: str = ""  # optional: pin your router's MAC so the same CIDR on another network is refused
    follow_network: bool = False  # also allow whatever private network this machine is connected to right now
    extra_protected: list[str] = field(default_factory=list)  # ips or macs never blocked
    block_method: str = "arp"  # arp | iptables | nftables
    home: Path = field(default_factory=default_home)
    db_path: Path | None = None
    oui_path: Path | None = None
    alerts: AlertConfig = field(default_factory=AlertConfig)
    daemon: DaemonConfig = field(default_factory=DaemonConfig)

    def __post_init__(self) -> None:
        self.home = Path(self.home)
        if self.db_path is None:
            self.db_path = self.home / "netscan.db"
        if self.oui_path is None:
            self.oui_path = self.home / "oui.tsv"

    @property
    def config_path(self) -> Path:
        return self.home / "config.toml"

    @property
    def notice_path(self) -> Path:
        return self.home / "notice_accepted"


def parse_subnets(values) -> list[ipaddress.IPv4Network]:
    """Validate the allow-list: private IPv4 only, no huge ranges. Raises ConfigError."""
    if isinstance(values, str):
        values = [values]
    nets: list[ipaddress.IPv4Network] = []
    for raw in values or []:
        try:
            net = ipaddress.ip_network(str(raw).strip(), strict=False)
        except ValueError as exc:
            raise ConfigError(f"invalid subnet {raw!r}: {exc}") from exc
        if net.version != 4:
            raise ConfigError(f"{raw!r}: only IPv4 subnets are supported")
        if not (net.is_private and not net.is_loopback and not net.is_multicast):
            raise ConfigError(f"{raw!r} is not a private network; netScan only scans home networks")
        if net.prefixlen < MAX_ALLOWED_SPAN_PREFIX:
            raise ConfigError(f"{raw!r} is too large (smallest allowed prefix is /{MAX_ALLOWED_SPAN_PREFIX})")
        nets.append(net)
    return nets


def load_config(path: Path | None = None, home: Path | None = None) -> Config:
    home = Path(home).expanduser() if home else default_home()
    path = Path(path).expanduser() if path else home / "config.toml"
    if not path.exists():
        return Config(home=home)
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"cannot parse {path}: {exc}") from exc

    net = data.get("network", {})
    safety = data.get("safety", {})
    block = data.get("block", {})
    storage = data.get("storage", {})
    alerts = data.get("alerts", {})
    daemon = data.get("daemon", {})

    method = block.get("method", "arp")
    if method not in ("arp", "iptables", "nftables"):
        raise ConfigError(f"block.method must be arp, iptables or nftables (got {method!r})")

    cfg = Config(
        allowed_subnets=parse_subnets(net.get("allowed_subnets", [])),
        interface=net.get("interface", ""),
        gateway=net.get("gateway", ""),
        gateway_mac=net.get("gateway_mac", ""),
        follow_network=bool(net.get("follow_network", False)),
        extra_protected=[str(x) for x in safety.get("extra_protected", [])],
        block_method=method,
        home=home,
        db_path=Path(storage["db_path"]).expanduser() if storage.get("db_path") else None,
        oui_path=Path(storage["oui_path"]).expanduser() if storage.get("oui_path") else None,
        alerts=AlertConfig(
            webhook_url=alerts.get("webhook_url", ""),
            ntfy_url=alerts.get("ntfy_url", ""),
            ntfy_token=alerts.get("ntfy_token", ""),
            notify_on=tuple(alerts.get("notify_on", list(DEFAULT_NOTIFY_ON))),
            timeout=float(alerts.get("timeout", 5.0)),
        ),
        daemon=DaemonConfig(
            sweep_interval=int(daemon.get("sweep_interval", 300)),
            offline_after=int(daemon.get("offline_after", 900)),
            arp_watch=bool(daemon.get("arp_watch", True)),
            capture_traffic=bool(daemon.get("capture_traffic", False)),
            silent_baseline=bool(daemon.get("silent_baseline", True)),
        ),
    )
    if cfg.daemon.sweep_interval < 10:
        raise ConfigError("daemon.sweep_interval must be at least 10 seconds")
    if cfg.daemon.offline_after <= cfg.daemon.sweep_interval:
        raise ConfigError("daemon.offline_after must be larger than daemon.sweep_interval or devices flap offline")
    if cfg.gateway_mac and not normalise_mac(cfg.gateway_mac):
        raise ConfigError(f"network.gateway_mac {cfg.gateway_mac!r} is not a valid MAC")
    return cfg


def write_follow_network(path: Path, value: bool) -> None:
    """Set network.follow_network in place, keeping the rest of the file (comments included) as the user wrote it."""
    text = Path(path).read_text(encoding="utf-8")
    lines = [ln for ln in text.splitlines(keepends=True) if not re.match(r"^\s*#?\s*follow_network\s*=", ln)]
    new = f"follow_network = {'true' if value else 'false'}\n"
    for i, ln in enumerate(lines):
        if ln.strip() == "[network]":
            lines.insert(i + 1, new)
            break
    else:
        lines += ["" if not lines or lines[-1].endswith("\n") else "\n", "\n[network]\n", new]
    tmp = Path(str(path) + ".tmp")
    tmp.write_text("".join(lines), encoding="utf-8")
    try:
        load_config(tmp, Path(path).parent)  # never leave a file that will not load
    except ConfigError:
        tmp.unlink(missing_ok=True)
        raise
    tmp.replace(path)


CONFIG_TEMPLATE = """\
# netScan configuration. Only use netScan on a network you own.

[network]
# allow-list: netScan refuses to scan or block anything outside these subnets
allowed_subnets = [{subnets}]
{follow_line}# interface = "en0"      # auto-detected when empty
# gateway = "192.168.1.1" # auto-detected when empty
{gateway_mac_line}
[safety]
# extra ips or macs that must never be blocked (gateway and this host are always protected)
extra_protected = []

[block]
# arp = ARP cutoff (works from any host on the lan, needs root and `netscan enforce`/daemon running)
# iptables / nftables = Linux only, effective when this machine is the gateway/router
method = "arp"

[alerts]
# webhook_url = "https://example.invalid/hook"
# ntfy_url = "https://ntfy.sh/your-private-topic"
# ntfy_token = ""
notify_on = ["new_device", "ip_conflict", "arp_spoof", "rogue_dhcp", "port_opened"]
# also: "device_online", "device_offline", "ip_changed", "blocked", "unblocked"
# the dashboard (System > Alerts) can override these settings; dashboard values win

[daemon]
sweep_interval = 300   # seconds between automated sweeps
offline_after = 900    # seconds without sighting before a device is marked offline
arp_watch = true       # listen for ARP to spot new devices between sweeps
capture_traffic = false # record per-device traffic metadata (see README for capture limits)
silent_baseline = true # first sweep seeds the inventory without alerting per device
"""


def render_config(subnets: list[str], gateway_mac: str = "", follow: bool = False) -> str:
    follow_line = (
        "follow_network = true  # scan whichever private network this machine is on (laptop use); the same size and privacy limits apply\n"
        if follow
        else "# follow_network = true # laptop use: also allow whichever private network you are connected to\n"
    )
    line = (
        f'gateway_mac = "{gateway_mac}"  # refuse to run on any other router with the same subnet\n'
        if gateway_mac
        else '# gateway_mac = "aa:bb:cc:dd:ee:ff" # pin your router\'s MAC: refuse a different network with the same subnet\n'
    )
    return CONFIG_TEMPLATE.format(subnets=", ".join(f'"{s}"' for s in subnets), gateway_mac_line=line, follow_line=follow_line)
