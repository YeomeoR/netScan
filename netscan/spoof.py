"""Temporarily change this machine's own MAC address on one interface, and put it back.

Only the interface netScan itself runs on is ever touched. The original address is stored in the
database before anything changes, so a restore still works after netScan restarts, and every change
carries an expiry so it never outlives a few hours. Linux resets the address on reboot; macOS does too.
"""

from __future__ import annotations

import re
import subprocess
import sys
import time
from typing import Callable

from netscan.macutil import is_multicast, normalise_mac
from netscan.store import Store

MAX_MINUTES = 8 * 60
DEFAULT_MINUTES = 30
SETTING = "spoof"
_IFACE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
_LINK_MAC = re.compile(r"link/ether\s+([0-9a-f:]{17})", re.I)
_IFCONFIG_MAC = re.compile(r"\bether\s+([0-9a-f:]{11,17})", re.I)

Runner = Callable[[list[str]], tuple[int, str]]


class SpoofError(Exception):
    pass


def default_runner(cmd: list[str]) -> tuple[int, str]:
    try:
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, str(exc)
    return done.returncode, (done.stdout + done.stderr).strip()


class Spoofer:
    def __init__(self, store: Store, runner: Runner = default_runner, platform: str | None = None,
                 clock: Callable[[], float] = time.time, disabled_reason: str = "", settle: float = 2.0):
        self.store = store
        self.run = runner
        self.platform = platform or sys.platform
        self.clock = clock
        self.disabled_reason = disabled_reason
        self.settle = settle

    @property
    def unsupported(self) -> str:
        if self.disabled_reason:
            return self.disabled_reason
        if not (self.platform.startswith("linux") or self.platform == "darwin"):
            return "Changing the MAC address is only supported on Linux and macOS."
        return ""

    def state(self) -> dict | None:
        saved = self.store.get_setting(SETTING)
        return saved if isinstance(saved, dict) and saved.get("original") else None

    def current_mac(self, interface: str) -> str:
        if not _IFACE.match(interface or ""):
            raise SpoofError(f"unusable interface name {interface!r}")
        if self.platform.startswith("linux"):
            rc, out = self.run(["ip", "-o", "link", "show", "dev", interface])
            found = _LINK_MAC.search(out) if rc == 0 else None
        else:
            rc, out = self.run(["ifconfig", interface])
            found = _IFCONFIG_MAC.search(out) if rc == 0 else None
        mac = normalise_mac(found.group(1)) if found else None
        if not mac:
            raise SpoofError(f"could not read the MAC address of {interface}: {out or 'no output'}")
        return mac

    def validate(self, value: str, forbidden: set[str] | None = None) -> str:
        mac = normalise_mac(value)
        if not mac:
            raise SpoofError("that is not a valid MAC address (use aa:bb:cc:dd:ee:ff)")
        if is_multicast(mac):
            raise SpoofError("a multicast address (first byte odd) cannot be used as a device address")
        if mac in (forbidden or set()):
            raise SpoofError("that is the router's address; copying it would take the whole network down")
        return mac

    def _set(self, interface: str, mac: str) -> None:
        if self.platform.startswith("linux"):
            steps = [["ip", "link", "set", "dev", interface, "down"], ["ip", "link", "set", "dev", interface, "address", mac]]
            for cmd in steps:
                rc, out = self.run(cmd)
                if rc != 0:
                    self.run(["ip", "link", "set", "dev", interface, "up"])
                    raise SpoofError(f"{' '.join(cmd)} failed: {out or 'no permission? netScan needs CAP_NET_ADMIN or root'}")
            rc, out = self.run(["ip", "link", "set", "dev", interface, "up"])
            if rc != 0:
                raise SpoofError(f"could not bring {interface} back up: {out}")
        else:
            rc, out = self.run(["ifconfig", interface, "ether", mac])
            if rc != 0:
                raise SpoofError(
                    f"ifconfig refused: {out or 'no output'}. Run netScan with sudo. On Wi-Fi, macOS often only accepts this "
                    "while Wi-Fi is on but not joined to a network; some newer Macs refuse it entirely."
                )
            self.run(["networksetup", "-setairportpower", interface, "off"])
            self.run(["networksetup", "-setairportpower", interface, "on"])
        time.sleep(self.settle)
        now = self.current_mac(interface)
        if now != mac:
            raise SpoofError(f"{interface} still reports {now} instead of {mac}; the driver did not accept the change")

    def apply(self, interface: str, mac: str, minutes: int, forbidden: set[str] | None = None) -> dict:
        if self.unsupported:
            raise SpoofError(self.unsupported)
        mac = self.validate(mac, forbidden)
        if not 1 <= minutes <= MAX_MINUTES:
            raise SpoofError(f"minutes must be between 1 and {MAX_MINUTES}")
        saved = self.state()
        if saved and saved["interface"] != interface:
            raise SpoofError(f"{saved['interface']} is already changed; put it back first")
        current = self.current_mac(interface)
        original = saved["original"] if saved else current
        if mac == current:
            raise SpoofError(f"{interface} already has that address")
        now = self.clock()
        started = saved["started"] if saved else now
        self.store.set_setting(SETTING, {"interface": interface, "original": original, "spoofed": mac, "started": started, "expires": now + minutes * 60})
        try:
            self._set(interface, mac)
        except SpoofError:
            try:
                if self.current_mac(interface) == original:
                    self.store.set_setting(SETTING, {})
            except SpoofError:
                pass
            raise
        return self.state() or {}

    def restore(self) -> dict:
        saved = self.state()
        if not saved:
            raise SpoofError("the MAC address has not been changed by netScan")
        interface, original = saved["interface"], saved["original"]
        if self.current_mac(interface) != original:
            self._set(interface, original)
        self.store.set_setting(SETTING, {})
        return saved

    def reconcile(self) -> None:
        """After a reboot the hardware address is back, so a stored change that no longer matches is stale."""
        saved = self.state()
        if not saved:
            return
        try:
            current = self.current_mac(saved["interface"])
        except SpoofError:
            return
        if current != saved["spoofed"]:
            self.store.set_setting(SETTING, {})

    def expired(self) -> bool:
        saved = self.state()
        return bool(saved and self.clock() >= saved.get("expires", 0))
