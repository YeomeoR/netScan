"""Command line interface (Mac local mode and the entry point for the Pi daemon)."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import socket
import sys
import threading
import time
from pathlib import Path

from rich.console import Console
from rich.table import Table

from netscan import __version__
from netscan.blocker import ArpEnforcer, BlockError, BlockManager, make_firewall
from netscan.config import ConfigError, load_config
from netscan.macutil import normalise_mac
from netscan.net import ScapyTransport
from netscan.oui import update_oui
from netscan.runtime import Runtime, build_runtime, reverse_dns, sweep, write_initial_config
from netscan.safety import NoticeNotAcceptedError, SafetyError, ensure_notice
from netscan.store import Block, Device, Store

console = Console()
err = Console(stderr=True)

CAPTURE_LIMITS = (
    "Capture limit: on a switched network this host only sees its own and broadcast/multicast traffic. "
    "Other devices' traffic is visible only if this machine is in the path (gateway/ARP-mediated) or a switch mirrors ports."
)


def fmt_ts(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def fmt_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def devices_table(devices: list[Device], blocks: list[Block], totals: dict[str, tuple[int, int]] | None = None, title: str = "Devices") -> Table:
    blocked = {b.mac for b in blocks}
    totals = totals or {}
    table = Table(title=title, header_style="bold")
    for col in ("IP", "MAC", "Vendor", "Hostname", "First seen", "Last seen", "Status"):
        table.add_column(col, no_wrap=col in ("IP", "MAC"))
    if totals:
        table.add_column("Traffic", justify="right")
    for d in devices:
        if d.mac in blocked:
            status = "[bold red]BLOCKED[/]"
        else:
            status = "[green]online[/]" if d.online else "[dim]offline[/]"
        row = [d.ip, d.mac, d.vendor or "-", d.hostname or "-", fmt_ts(d.first_seen), fmt_ts(d.last_seen), status]
        if totals:
            b, p = totals.get(d.mac, (0, 0))
            row.append(f"{fmt_bytes(b)} / {p} pkts" if p else "-")
        table.add_row(*row)
    return table


def blocks_table(blocks: list[Block]) -> Table:
    table = Table(title="Blocked devices", header_style="bold")
    for col in ("IP", "MAC", "Method", "Since", "Reason"):
        table.add_column(col, no_wrap=col in ("IP", "MAC"))
    for b in blocks:
        table.add_row(b.ip, b.mac, b.method, fmt_ts(b.blocked_at), b.reason or "-")
    return table


def traffic_table(store: Store, mac: str, limit: int = 25) -> Table:
    table = Table(title="Traffic metadata (no payloads)", header_style="bold")
    for col in ("Dir", "Proto", "Service", "Peer IP", "Peer host", "Port"):
        table.add_column(col)
    for col in ("Bytes", "Packets"):
        table.add_column(col, justify="right")
    table.add_column("Last seen")
    from netscan.traffic import service_name

    for r in store.traffic_for(mac)[:limit]:
        table.add_row(r.direction, r.proto, service_name(r.proto, r.peer_port) or "-", r.peer_ip, r.peer_host or "-", str(r.peer_port or "-"), fmt_bytes(r.bytes), str(r.packets), fmt_ts(r.last_seen))
    return table


def setup_logging(verbose: bool, plain: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    if plain:
        logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stdout, force=True)
    else:
        from rich.logging import RichHandler

        logging.basicConfig(level=level, format="%(message)s", handlers=[RichHandler(console=err, show_path=False, markup=False)], force=True)


def need_root(what: str) -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        err.print(f"[yellow]Note:[/] {what} needs root; re-run with sudo for full functionality.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netscan", description="Home network scanner and controller. Only for networks you own.")
    p.add_argument("--version", action="version", version=f"netscan {__version__}")
    p.add_argument("--config", type=Path, help="path to config.toml (default: <home>/config.toml)")
    p.add_argument("--home", type=Path, help="data dir (default: $NETSCAN_HOME or ~/.netscan)")
    p.add_argument("--accept-terms", action="store_true", help="acknowledge the own-network-only notice non-interactively")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="write a config with the detected local subnet as the allow-list")
    s.add_argument("--subnet", action="append", help="allowed subnet (repeatable); default: detected local subnet")
    s.add_argument("--force", action="store_true")
    sub.add_parser("notice", help="show and acknowledge the own-network-only notice")
    s = sub.add_parser("scan", help="ARP sweep the local subnet and show devices")
    s.add_argument("--timeout", type=float, default=3.0)
    s.add_argument("--no-hostnames", action="store_true", help="skip reverse DNS lookups")
    sub.add_parser("list", help="show known devices from the database")
    s = sub.add_parser("show", help="device detail plus traffic metadata")
    s.add_argument("target", help="ip or mac")
    s = sub.add_parser("traffic", help="capture traffic metadata for a while, then summarise")
    s.add_argument("--duration", type=int, default=30, help="seconds to capture")
    s.add_argument("--flush", type=float, default=5.0)
    s = sub.add_parser("block", help="block a device's network access")
    s.add_argument("target", help="ip or mac of a known device")
    s.add_argument("--reason", default="")
    s = sub.add_parser("unblock", help="restore a device's network access")
    s.add_argument("target")
    sub.add_parser("blocks", help="list persisted blocks")
    s = sub.add_parser("enforce", help="foreground ARP cutoff enforcer for persisted blocks (needs root)")
    s.add_argument("--interval", type=float, default=2.0)
    sub.add_parser("watch", help="foreground ARP watch: alert when new devices appear (needs root)")
    sub.add_parser("daemon", help="run the Pi daemon (periodic sweeps, ARP watch, enforcement)")
    sub.add_parser("events", help="recent events")
    sub.add_parser("update-oui", help="download the latest IEEE vendor registry")
    s = sub.add_parser("update", help="pull the latest netScan from GitHub into the checkout it was installed from and reinstall")
    s.add_argument("--check", action="store_true", help="only report whether a newer version exists")
    s.add_argument("--auto", choices=["on", "off"], help="switch automatic updates (applied by the running dashboard) on or off, then exit")
    s = sub.add_parser("spoof", help="temporarily use another MAC address on this machine's network interface, then put the real one back")
    s.add_argument("action", choices=["status", "set", "restore"])
    s.add_argument("mac", nargs="?", help="address to use (for set)")
    s.add_argument("--minutes", type=int, default=30, help="how long to keep it (default 30); netScan waits and restores it, Ctrl-C restores early")
    s.add_argument("--yes", action="store_true", help="skip the confirmation question")
    s = sub.add_parser("web", help="browser dashboard with the full feature set plus timed sweeps (the terminal commands keep working too)")
    s.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1; use 0.0.0.0 on the Pi to reach it from your LAN)")
    s.add_argument("--port", type=int, default=8787)
    s.add_argument("--token", default="", help="access token (default: $NETSCAN_WEB_TOKEN or <home>/web_token, created on first run)")
    s.add_argument("--daemon", action="store_true", help="also run the daemon duties: baseline sweep, periodic sweep schedule, ARP watch, enforcer, optional capture")
    s.add_argument("--open", action="store_true", help="open the dashboard in a browser")
    s.add_argument("--demo", action="store_true", help="simulated network and throwaway data dir (no root, nothing real is touched)")
    return p


def cmd_init(args, cfg, transport) -> int:
    if cfg.config_path.exists() and not args.force:
        err.print(f"{cfg.config_path} already exists (use --force to overwrite)")
        return 1
    subnets, gw_mac, local = write_initial_config(cfg, transport, args.subnet, args.force)
    if not args.subnet:
        console.print(f"Detected local network [bold]{local.network}[/] on {local.interface}")
    if gw_mac:
        console.print(f"Pinning gateway {local.gateway_ip} ({gw_mac}) so this config only works on this network")
    console.print(f"Wrote {cfg.config_path} with allow-list {subnets}")
    return 0


def cmd_scan(args, cfg, transport) -> int:
    rt = build_runtime(cfg, transport, None if args.no_hostnames else reverse_dns)
    need_root("ARP scanning (falling back to an unprivileged ping-nudge + ARP table read)")
    with console.status(f"Sweeping {rt.local.network} on {rt.local.interface}..."):
        stamp = time.time()
        _hosts, events = sweep(rt, args.timeout, now=stamp)
        events += rt.tracker.mark_offline(0, now=stamp)
    rt.alerter.dispatch(events)
    console.print(devices_table(rt.store.list_devices(), rt.store.list_blocks(), rt.store.traffic_totals()))
    return 0


def cmd_list(args, cfg, transport) -> int:
    store = Store(cfg.db_path)
    devices = store.list_devices()
    if not devices:
        console.print("No devices recorded yet. Run `netscan scan` first.")
        return 0
    console.print(devices_table(devices, store.list_blocks(), store.traffic_totals()))
    return 0


def cmd_show(args, cfg, transport) -> int:
    store = Store(cfg.db_path)
    from netscan.macutil import normalise_mac

    dev = store.find_device(normalise_mac(args.target) or args.target)
    if dev is None:
        err.print(f"unknown device {args.target!r}; run `netscan scan` first")
        return 1
    console.print(devices_table([dev], store.list_blocks(), title=f"Device {dev.mac}"))
    if store.traffic_for(dev.mac):
        console.print(traffic_table(store, dev.mac))
    else:
        console.print("[dim]No traffic recorded for this device. See `netscan traffic` and the README capture limits.[/]")
    return 0


def cmd_traffic(args, cfg, transport) -> int:
    from netscan.traffic import TrafficCollector, run_capture

    rt = build_runtime(cfg, transport, None)
    need_root("packet capture")
    console.print(f"[yellow]{CAPTURE_LIMITS}[/]")
    collector = TrafficCollector(rt.store, resolver=reverse_dns)
    stop = threading.Event()
    timer = threading.Timer(args.duration, stop.set)
    timer.start()
    try:
        with console.status(f"Capturing metadata on {rt.local.interface} for {args.duration}s (Ctrl-C to stop)..."):
            run_capture(rt.transport, rt.local.interface, collector, stop, args.flush)
    except KeyboardInterrupt:
        stop.set()
        collector.flush()
    finally:
        timer.cancel()
    console.print(devices_table(rt.store.list_devices(), rt.store.list_blocks(), rt.store.traffic_totals(), title="Per-device traffic totals"))
    return 0


def _manager(rt: Runtime) -> BlockManager:
    return BlockManager(rt.store, rt.scope, rt.cfg.block_method, make_firewall(rt.cfg.block_method))


def cmd_block(args, cfg, transport) -> int:
    rt = build_runtime(cfg, transport, None)
    try:
        blk, ev = _manager(rt).block(args.target, args.reason)
    except BlockError as exc:
        err.print(f"[red]{exc}[/]")
        return 1
    rt.alerter.dispatch([ev])
    console.print(f"[bold red]Blocked[/] {blk.ip} ({blk.mac}) via {blk.method}; state saved.")
    if blk.method == "arp":
        console.print("ARP cutoff only holds while an enforcer runs: `sudo netscan enforce` (Mac) or the Pi daemon.")
    return 0


def cmd_unblock(args, cfg, transport) -> int:
    rt = build_runtime(cfg, transport, None)
    enforcer = ArpEnforcer(rt.store, rt.scope, rt.transport, rt.local.interface, rt.scope.gateway_ip)
    ev = _manager(rt).unblock(args.target, restore=enforcer.restore_block if rt.cfg.block_method == "arp" else None)
    if ev is None:
        err.print(f"{args.target} is not blocked")
        return 1
    rt.alerter.dispatch([ev])
    console.print(f"[green]Unblocked[/] {ev.ip} ({ev.mac}).")
    return 0


def cmd_blocks(args, cfg, transport) -> int:
    blocks = Store(cfg.db_path).list_blocks()
    console.print(blocks_table(blocks) if blocks else "No blocked devices.")
    return 0


def cmd_enforce(args, cfg, transport) -> int:
    from netscan.daemon import install_signal_handlers

    rt = build_runtime(cfg, transport, None)
    need_root("ARP cutoff")
    enforcer = ArpEnforcer(rt.store, rt.scope, rt.transport, rt.local.interface, rt.scope.gateway_ip)
    stop = threading.Event()
    install_signal_handlers(stop)
    console.print("Enforcing persisted blocks; Ctrl-C restores ARP tables and exits.")
    enforcer.run(stop, max(args.interval, 0.5))
    return 0


def cmd_watch(args, cfg, transport) -> int:
    from netscan.daemon import Daemon, install_signal_handlers

    rt = build_runtime(cfg, transport, reverse_dns)
    need_root("ARP watching")
    stop = threading.Event()
    install_signal_handlers(stop)
    daemon = Daemon(rt, stop)
    daemon.sweep_once()
    console.print(f"Watching ARP on {rt.local.interface} ({rt.local.network}); Ctrl-C to stop.")
    rt.transport.sniff(rt.local.interface, "arp", daemon.handle_arp, stop)
    return 0


def cmd_daemon(args, cfg, transport) -> int:
    from netscan.daemon import Daemon, install_signal_handlers

    setup_logging(args.verbose, plain=True)
    rt = build_runtime(cfg, transport, reverse_dns)
    stop = threading.Event()
    install_signal_handlers(stop)
    Daemon(rt, stop).run()
    return 0


def cmd_events(args, cfg, transport) -> int:
    rows = Store(cfg.db_path).recent_events(30)
    table = Table(title="Recent events", header_style="bold")
    for col in ("Time", "Kind", "IP", "MAC", "Message"):
        table.add_column(col)
    for r in rows:
        table.add_row(fmt_ts(r["ts"]), r["kind"], r["ip"], r["mac"], r["message"])
    console.print(table)
    return 0


def cmd_update_oui(args, cfg, transport) -> int:
    try:
        n = update_oui(cfg.oui_path)
    except RuntimeError as exc:
        console.print(f"[red]update-oui failed:[/red] {exc}")
        return 1
    console.print(f"Saved {n} vendor prefixes to {cfg.oui_path}")
    return 0


def cmd_web(args, cfg, transport) -> int:
    from netscan.web.controller import Controller
    from netscan.web.server import load_or_create_token, make_server, serve_forever

    setup_logging(args.verbose, plain=args.daemon)
    resolver = reverse_dns
    if args.demo:
        from netscan.web.demo import demo_setup

        cfg, transport, resolver = demo_setup()
        console.print("[yellow]Demo mode:[/] simulated network, throwaway data in " + str(cfg.home))
    elif not args.daemon:
        need_root("ARP scanning, capture and blocking")
    token = load_or_create_token(cfg.home, args.token or os.environ.get("NETSCAN_WEB_TOKEN", ""))
    try:
        from netscan.update import Updater

        updater = Updater(disabled_reason="Updates are switched off in demo mode.") if args.demo else None
        controller = Controller(cfg, transport, daemon=args.daemon, resolver=resolver, updater=updater)
        if args.demo:
            controller.spoofer.disabled_reason = "Changing the MAC address is switched off in demo mode."
        server = make_server(controller, args.host, args.port, token)
    except OSError as exc:
        err.print(f"[bold red]Cannot listen on {args.host}:{args.port}:[/] {exc}")
        return 1
    stop = threading.Event()
    restart = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    controller.on_restart = lambda: (restart.set(), stop.set())
    controller.start()
    shown = args.host if args.host not in ("0.0.0.0", "") else socket.gethostname()
    base = f"http://{shown}:{args.port}/"
    if args.daemon:
        logging.getLogger("netscan.web").info("dashboard on %s (access token in %s)", base, cfg.home / "web_token")
    else:
        console.print(f"Dashboard: [bold]{base}#token={token}[/]  (Ctrl-C to stop)")
    if args.host not in ("127.0.0.1", "localhost"):
        err.print("[yellow]Listening beyond this machine over plain HTTP: anyone on the network who learns the token can block devices. Keep it on your LAN.[/]")
    if args.open:
        import webbrowser

        webbrowser.open(f"http://127.0.0.1:{args.port}/#token={token}" if args.host in ("0.0.0.0", "") else f"{base}#token={token}")
    try:
        serve_forever(server, stop)
    finally:
        controller.close()
    if restart.is_set():
        logging.getLogger("netscan.web").info("restarting to run the updated code")
        sys.stdout.flush()
        os.execv(sys.executable, [sys.executable, *sys.argv])
    return 0


def cmd_update(args, cfg, transport) -> int:
    from netscan.update import UpdateError, Updater

    if args.auto:
        store = Store(cfg.db_path)
        try:
            store.set_setting("update", {"auto": args.auto == "on"})
        finally:
            store.close()
        console.print(f"Automatic updates are {args.auto}. The running dashboard follows GitHub every few minutes while this is on.")
        return 0
    up = Updater()
    info = up.check(force=True)
    if not info["supported"]:
        err.print(f"[red]Cannot update:[/red] {info['reason']}")
        return 1
    if info["error"]:
        err.print(f"[red]{info['error']}[/red]")
        return 1
    console.print(f"On [bold]{info['branch']}[/bold] at {info['commit']} ({info['subject']}); {info['behind']} new commit(s) on GitHub.")
    for c in info["new_commits"]:
        console.print(f"  {c['sha']}  {c['subject']}")
    if args.check or not info["behind"]:
        return 0
    try:
        done = up.apply()
    except UpdateError as exc:
        err.print(f"[red]Update failed:[/red] {exc}")
        return 1
    console.print(f"[green]Updated {done['from']} to {done['to']}.[/green] Restart the dashboard (or the netscan-web service) to use it.")
    return 0


def cmd_spoof(args, cfg, transport) -> int:
    from netscan.spoof import SpoofError, Spoofer

    store = Store(cfg.db_path)
    spoofer = Spoofer(store)
    try:
        if args.action == "status":
            saved = spoofer.state()
            if not saved:
                console.print("This machine is using its own MAC address (netScan has not changed it).")
            else:
                left = max(0, int(saved["expires"] - time.time()))
                console.print(f"{saved['interface']} uses [bold]{saved['spoofed']}[/]; the real address {saved['original']} returns in {left // 60}m (run `netscan spoof restore` to do it now).")
            return 0
        if args.action == "restore":
            done = spoofer.restore()
            console.print(f"[green]Restored[/] {done['interface']} to {done['original']}.")
            return 0
        if not args.mac:
            err.print("give the MAC address to use: netscan spoof set aa:bb:cc:dd:ee:ff")
            return 2
        need_root("changing the MAC address")
        local = transport.local_net(cfg.interface)
        gateway = transport.resolve_mac(local.gateway_ip, local.interface) if local.gateway_ip else None
        mac = spoofer.validate(args.mac, {m for m in (gateway, normalise_mac(cfg.gateway_mac)) if m})
        dev = store.find_device(mac)
        if dev and dev.online:
            err.print(f"[yellow]{dev.hostname or dev.vendor or mac} is online. Two devices with one address knock each other off the network.[/]")
        if not args.yes:
            console.print(f"{local.interface} will use {mac} for {args.minutes} minutes and may drop off the network for a few seconds (the IP address can change).")
            if input("Continue? [y/N] ").strip().lower() not in ("y", "yes"):
                return 1
        saved = spoofer.apply(local.interface, mac, args.minutes)
        console.print(f"[bold]{local.interface} now uses {mac}.[/] The real address {saved['original']} comes back in {args.minutes} minutes. Press Ctrl-C to restore it now.")
        try:
            time.sleep(args.minutes * 60)
        except KeyboardInterrupt:
            pass
        finally:
            if spoofer.state():
                done = spoofer.restore()
                console.print(f"[green]Restored[/] {done['interface']} to {done['original']}.")
        return 0
    except SpoofError as exc:
        err.print(f"[bold red]MAC change failed:[/] {exc}")
        return 1
    finally:
        store.close()


COMMANDS = {
    "init": cmd_init, "scan": cmd_scan, "list": cmd_list, "show": cmd_show, "traffic": cmd_traffic,
    "block": cmd_block, "unblock": cmd_unblock, "blocks": cmd_blocks, "enforce": cmd_enforce,
    "watch": cmd_watch, "daemon": cmd_daemon, "events": cmd_events, "update-oui": cmd_update_oui, "web": cmd_web, "update": cmd_update, "spoof": cmd_spoof,
}


def main(argv: list[str] | None = None, transport=None, input_fn=input) -> int:
    args = build_parser().parse_args(argv)
    transport = transport or ScapyTransport()
    if args.cmd not in ("daemon", "web"):
        setup_logging(args.verbose)
    try:
        cfg = load_config(args.config, args.home)
        if args.cmd == "notice":
            ensure_notice(cfg.notice_path, accept=args.accept_terms, input_fn=input_fn, out=sys.stdout)
            console.print("Notice acknowledged.")
            return 0
        if not (args.cmd == "web" and args.demo):
            ensure_notice(cfg.notice_path, accept=args.accept_terms, input_fn=input_fn)
        return COMMANDS[args.cmd](args, cfg, transport)
    except (SafetyError, NoticeNotAcceptedError) as exc:
        err.print(f"[bold red]Refused:[/] {exc}")
        return 2
    except ConfigError as exc:
        err.print(f"[bold red]Config error:[/] {exc}")
        return 2
    except RuntimeError as exc:
        err.print(f"[bold red]Error:[/] {exc}")
        return 1
    except PermissionError as exc:
        err.print(f"[bold red]Permission denied:[/] {exc}. Try with sudo.")
        return 3
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
