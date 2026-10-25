"""Look for nearby Wi-Fi networks and join one, so a laptop can be pointed at a friend's network from the dashboard.

macOS uses system_profiler (scan) and networksetup (join); Linux uses nmcli. Everything that touches the system goes
through an injectable `run`, so the parsers and the flow are tested without a radio. The password is only ever passed to
the join command: it is never stored, logged or echoed back in an error.
"""
from __future__ import annotations

import json
import platform
import re
import shutil
import subprocess
import time
from collections.abc import Callable

SCAN_TIMEOUT = 40
JOIN_TIMEOUT = 45
JOIN_SETTLE = 20  # seconds to wait for the address to come up after joining
MAX_NETWORKS = 60
REDACTED = "<redacted>"

Run = Callable[[list[str], float], "tuple[int, str]"]


class WifiError(Exception):
    pass


def system_run(cmd: list[str], timeout: float) -> tuple[int, str]:
    try:
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise WifiError(f"{cmd[0]} is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise WifiError(f"{cmd[0]} took too long") from exc
    return done.returncode, (done.stdout or "") + (done.stderr or "")


def _first_int(text) -> int | None:
    m = re.search(r"-?\d+", str(text or ""))
    return int(m.group()) if m else None


def _security_label(raw: str) -> str:
    text = str(raw or "").lower().replace("spairport_security_mode_", "")
    if not text or text in ("none", "open"):
        return "Open"
    for key, label in (("wpa3", "WPA3"), ("wpa2", "WPA2"), ("wpa", "WPA"), ("wep", "WEP"), ("enterprise", "Enterprise")):
        if key in text:
            return label + (" Enterprise" if "enterprise" in text and key != "enterprise" else "")
    return text.replace("_", " ")


def _quality(dbm: int | None) -> int | None:
    """Rough 0-100 bar from dBm: -50 or better is full, -90 or worse is empty."""
    return None if dbm is None else max(0, min(100, int((dbm + 90) * 100 / 40)))


def parse_system_profiler(text: str) -> dict:
    """Networks from `system_profiler SPAirPortDataType -json`. Newer macOS hides names without Location access."""
    try:
        data = json.loads(text)
        cards = data["SPAirPortDataType"][0].get("spairport_airport_interfaces", [])
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        return {"networks": [], "current": "", "redacted": False}
    found: dict[str, dict] = {}
    current, redacted = "", False

    def add(entry: dict, is_current: bool) -> None:
        nonlocal current, redacted
        ssid = str(entry.get("_name") or "").strip()
        if not ssid or ssid == REDACTED:
            redacted = redacted or ssid == REDACTED
            return
        dbm = _first_int(entry.get("spairport_signal_noise"))
        item = {"ssid": ssid, "signal": dbm, "quality": _quality(dbm), "security": _security_label(entry.get("spairport_security_mode", "")),
                "channel": _first_int(entry.get("spairport_network_channel")), "current": is_current}
        if is_current:
            current = ssid
        if ssid not in found or (item["quality"] or 0) > (found[ssid]["quality"] or 0) or is_current:
            found[ssid] = item

    for card in cards:
        if not isinstance(card, dict):
            continue
        if isinstance(card.get("spairport_current_network_information"), dict):
            add(card["spairport_current_network_information"], True)
        for key in ("spairport_airport_other_local_wireless_networks", "spairport_airport_local_wireless_networks"):
            for entry in card.get(key) or []:
                if isinstance(entry, dict):
                    add(entry, False)
    return {"networks": list(found.values()), "current": current, "redacted": redacted}


def parse_hardware_ports(text: str) -> str:
    """The Wi-Fi device name (en0) from `networksetup -listallhardwareports`."""
    port = ""
    for line in text.splitlines():
        if line.startswith("Hardware Port:"):
            port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and port.lower() in ("wi-fi", "airport"):
            return line.split(":", 1)[1].strip()
    return ""


def parse_preferred(text: str) -> list[str]:
    """Saved networks from `networksetup -listpreferredwirelessnetworks en0`."""
    lines = [ln.strip() for ln in text.splitlines()]
    return [ln for ln in lines[1:] if ln and not ln.startswith("Error")] if lines and lines[0].startswith("Preferred networks") else []


def split_nmcli(line: str) -> list[str]:
    """nmcli's terse output separates fields with ':' and escapes literal ones as '\\:'."""
    return [part.replace("\\:", ":").replace("\\\\", "\\") for part in re.split(r"(?<!\\):", line)]


def parse_nmcli(text: str) -> dict:
    """Networks from `nmcli -t -f IN-USE,SSID,SIGNAL,SECURITY,CHAN dev wifi list`."""
    found: dict[str, dict] = {}
    current = ""
    for line in text.splitlines():
        parts = split_nmcli(line)
        if len(parts) < 5 or not parts[1].strip():
            continue
        in_use, ssid, signal, security, channel = parts[0].strip() == "*", parts[1].strip(), _first_int(parts[2]), parts[3].strip(), _first_int(parts[4])
        item = {"ssid": ssid, "signal": None, "quality": signal if signal is None else max(0, min(100, signal)),
                "security": _security_label(security.replace("--", "")), "channel": channel, "current": in_use}
        if in_use:
            current = ssid
        if ssid not in found or (item["quality"] or 0) > (found[ssid]["quality"] or 0) or in_use:
            found[ssid] = item
    return {"networks": list(found.values()), "current": current, "redacted": False}


class WifiManager:
    def __init__(self, run: Run = system_run, system: str | None = None, sleep: Callable[[float], None] = time.sleep, which=shutil.which, settle: float = JOIN_SETTLE):
        self._run = run
        self.system = system or platform.system()
        self._sleep = sleep
        self._which = which
        self._settle = settle

    @property
    def unsupported(self) -> str:
        if self.system == "Darwin":
            return ""
        if self.system == "Linux":
            return "" if self._which("nmcli") else "NetworkManager (nmcli) is not installed on this machine, so it cannot manage Wi-Fi."
        return f"Joining Wi-Fi from here is not supported on {self.system or 'this system'}."

    def interface(self) -> str:
        if self.system == "Darwin":
            code, out = self._run(["networksetup", "-listallhardwareports"], 10)
            name = parse_hardware_ports(out) if code == 0 else ""
            if not name:
                raise WifiError("this machine has no Wi-Fi adapter")
            return name
        code, out = self._run(["nmcli", "-t", "-f", "DEVICE,TYPE", "dev"], 10)
        for line in out.splitlines():
            parts = split_nmcli(line)
            if code == 0 and len(parts) >= 2 and parts[1] == "wifi":
                return parts[0]
        raise WifiError("this machine has no Wi-Fi adapter")

    def saved(self, iface: str) -> list[str]:
        if self.system != "Darwin":
            code, out = self._run(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"], 10)
            return [split_nmcli(ln)[0] for ln in out.splitlines() if code == 0 and "wireless" in ln]
        code, out = self._run(["networksetup", "-listpreferredwirelessnetworks", iface], 10)
        return parse_preferred(out) if code == 0 else []

    def scan(self) -> dict:
        """Nearby networks plus the saved ones, so a name can still be picked when the system hides the scan."""
        if self.unsupported:
            raise WifiError(self.unsupported)
        iface = self.interface()
        if self.system == "Darwin":
            code, out = self._run(["system_profiler", "SPAirPortDataType", "-json"], SCAN_TIMEOUT)
            result = parse_system_profiler(out) if code == 0 else {"networks": [], "current": "", "redacted": False}
        else:
            code, out = self._run(["nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL,SECURITY,CHAN", "dev", "wifi", "list", "--rescan", "yes"], SCAN_TIMEOUT)
            if code != 0:
                raise WifiError("the Wi-Fi scan failed")
            result = parse_nmcli(out)
        nearby = sorted(result["networks"], key=lambda n: (not n["current"], -(n["quality"] or 0), n["ssid"].lower()))[:MAX_NETWORKS]
        known = {n["ssid"] for n in nearby}
        saved = [s for s in self.saved(iface) if s]
        return {"interface": iface, "networks": nearby, "current": result["current"], "redacted": result["redacted"],
                "saved": [s for s in saved if s not in known][:MAX_NETWORKS]}

    def current(self, iface: str) -> str:
        if self.system == "Darwin":
            code, out = self._run(["networksetup", "-getairportnetwork", iface], 10)
            m = re.match(r"Current Wi-Fi Network:\s*(.+)", out.strip())
            return m.group(1).strip() if code == 0 and m else ""
        code, out = self._run(["nmcli", "-t", "-f", "ACTIVE,SSID", "dev", "wifi"], 10)
        for line in out.splitlines():
            parts = split_nmcli(line)
            if code == 0 and len(parts) >= 2 and parts[0] == "yes":
                return parts[1]
        return ""

    def connect(self, ssid: str, password: str = "") -> str:
        """Join `ssid` and wait until the system reports it as the current network. Returns the interface name."""
        if self.unsupported:
            raise WifiError(self.unsupported)
        iface = self.interface()
        if self.system == "Darwin":
            cmd = ["networksetup", "-setairportnetwork", iface, ssid] + ([password] if password else [])
        else:
            cmd = ["nmcli", "dev", "wifi", "connect", ssid, "ifname", iface] + (["password", password] if password else [])
        code, out = self._run(cmd, JOIN_TIMEOUT)
        # networksetup exits 0 even when it fails and only says so in its output; never repeat the command line (it holds the password)
        problem = out.strip().replace(password, "***") if password else out.strip()
        if code != 0 or (self.system == "Darwin" and problem):
            if "could not find" in problem.lower() or "no network with ssid" in problem.lower():
                raise WifiError(f"{ssid} was not found. Is it in range, and is the name spelled exactly?")
            raise WifiError("could not join that network. Check the password." if not problem else f"could not join that network: {problem[:160]}")
        deadline = time.monotonic() + self._settle
        while self.current(iface) != ssid:
            if time.monotonic() >= deadline:
                raise WifiError("the network accepted the request but this machine did not connect to it; check the password")
            self._sleep(1.0)
        return iface
