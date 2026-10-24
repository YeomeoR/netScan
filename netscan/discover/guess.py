"""Turn the raw things a device told us into a name and a best guess at what it is.

Every guess carries the reasons behind it, so the dashboard can show why netScan thinks so.
Nothing here writes to the network or the database.
"""

from __future__ import annotations

import re

from netscan.discover.util import clean

GENERIC_NAMES = {"", "unknown", "localhost", "android", "linux", "device", "generic", "upnp", "internetgatewaydevice", "media renderer", "mediarenderer"}
HEXISH = re.compile(r"^[0-9a-f:\-_]{10,}$", re.I)

# hostname fragment -> (category, os/brand note)
HOSTNAME_HINTS = (
    (r"iphone", "phone", "iOS"), (r"ipad", "phone", "iPadOS"), (r"galaxy|pixel|android|oneplus|redmi|xiaomi", "phone", "Android"),
    (r"macbook|imac|mac-?mini|mac-?studio", "computer", "macOS"), (r"desktop-|laptop-|-pc$|^pc-", "computer", "Windows"),
    (r"appletv|apple-tv", "tv", "tvOS"), (r"homepod", "speaker", "HomePod"), (r"chromecast|google-?home|nest-?(mini|hub|audio)", "media", "Google Cast"),
    (r"echo|alexa|fire-?tv|firetv|kindle", "media", "Amazon"), (r"roku", "tv", "Roku"), (r"sonos", "speaker", "Sonos"),
    (r"playstation|^ps[345]\b", "console", "PlayStation"), (r"xbox", "console", "Xbox"), (r"nintendo|switch", "console", "Nintendo"),
    (r"printer|laserjet|officejet|deskjet|envy|epson|brother|canon", "printer", ""), (r"cam|ring|nest-?cam|doorbell|reolink", "camera", ""),
    (r"esp[-_]?\d|esp32|esp8266|tasmota|shelly|sonoff|tuya|wled", "iot", "ESP microcontroller"), (r"pihole|pi-hole|raspberry|raspi|^pi$|nas|synology|unraid", "server", ""),
    (r"router|gateway|access-?point|\bap-|unifi|ubnt|mesh|extender|repeater", "network", ""), (r"tv|bravia|webos|tizen|vizio", "tv", ""),
)

# advertised service -> (category, reason)
SERVICE_HINTS = (
    ("_googlecast", "media", "advertises Google Cast"), ("_airplay", "media", "advertises AirPlay"), ("_raop", "speaker", "advertises AirPlay audio"),
    ("_ipp", "printer", "advertises IPP printing"), ("_printer", "printer", "advertises a print queue"), ("_pdl-datastream", "printer", "advertises raw printing"),
    ("_hap", "iot", "advertises HomeKit"), ("_homekit", "iot", "advertises HomeKit"), ("_spotify-connect", "speaker", "advertises Spotify Connect"),
    ("_smb", "computer", "shares files over SMB"), ("_afpovertcp", "computer", "shares files (AFP)"), ("_workstation", "computer", "advertises a workstation"),
    ("_companion-link", "phone", "advertises Apple companion link"), ("_ssh", "server", "advertises SSH"), ("_http", "iot", "advertises a web page"),
)

UPNP_TYPES = {
    "internetgatewaydevice": ("network", "is an internet gateway"), "wanconnectiondevice": ("network", "is a WAN connection"),
    "mediarenderer": ("media", "is a UPnP media renderer"), "mediaserver": ("server", "is a UPnP media server"),
    "printer": ("printer", "is a UPnP printer"), "wlanaccesspoint": ("network", "is a Wi-Fi access point"),
    "basic": ("iot", "is a basic UPnP device"), "digitalsecuritycamera": ("camera", "is a camera"),
}


def usable_name(name: str) -> bool:
    low = clean(name, 80).lower()
    return low not in GENERIC_NAMES and not HEXISH.match(low) and not re.fullmatch(r"[\d.]+", low)


def best_name(info: dict[str, dict]) -> tuple[str, str]:
    """(name, where it came from). Friendly names a person typed beat machine names."""
    ssdp, mdns, dhcp, nb = info.get("ssdp", {}), info.get("mdns", {}), info.get("dhcp", {}), info.get("netbios", {})
    banners = info.get("banners", {})
    candidates = [
        (mdns.get("friendly", ""), "Bonjour"), (ssdp.get("friendly", ""), "UPnP"), (mdns.get("hostname", ""), "Bonjour hostname"),
        (dhcp.get("hostname", ""), "DHCP hostname"), (nb.get("name", ""), "NetBIOS"),
    ]
    for page in banners.values():
        if isinstance(page, dict) and page.get("title") and len(page["title"]) <= 40 and not re.search(r"\b(login|index|home|welcome|404|error|router)\b", page["title"], re.I):
            candidates.append((page["title"], "web page title"))
    for name, source in candidates:
        if name and usable_name(name):
            return clean(name, 60), source
    return "", ""


def guess_type(info: dict[str, dict], vendor: str = "", private_mac: bool = False) -> dict:
    """Best guess at what the device is. Returns category, os, model and the reasons, each possibly empty."""
    ssdp, mdns, dhcp, ttl, banners = info.get("ssdp", {}), info.get("mdns", {}), info.get("dhcp", {}), info.get("ttl", {}), info.get("banners", {})
    votes: dict[str, int] = {}
    reasons: list[str] = []
    os_name = model = ""

    def vote(category: str, reason: str, weight: int = 1) -> None:
        if category:
            votes[category] = votes.get(category, 0) + weight
        if reason and reason not in reasons:
            reasons.append(reason)

    services = [s.lower() for s in mdns.get("services", [])]
    txt = mdns.get("txt", {})
    for prefix, category, why in SERVICE_HINTS:
        if any(s.startswith(prefix) for s in services):
            vote(category, why, 2)
    model = clean(txt.get("md") or txt.get("model") or txt.get("am") or "", 60)
    if model:
        reasons.append(f"model reported as {model}")
        low = model.lower()
        if low.startswith(("appletv",)):
            vote("tv", "", 3)
        elif low.startswith(("macbook", "imac", "macmini", "macpro", "mac1")):
            vote("computer", "", 3)
        elif low.startswith(("audioaccessory", "homepod")):
            vote("speaker", "", 3)
        elif low.startswith(("iphone", "ipad")):
            vote("phone", "", 3)
        elif "chromecast" in low or "google tv" in low:
            vote("media", "", 3)
        elif "nest" in low or "home" in low:
            vote("speaker", "", 2)

    dev_type = ssdp.get("device_type", "").lower()
    if dev_type in UPNP_TYPES:
        vote(*UPNP_TYPES[dev_type], 2)
    if ssdp.get("model") and not model:
        model = ssdp["model"]
        reasons.append(f"UPnP model {model}")
    if ssdp.get("manufacturer") and not vendor:
        vendor = ssdp["manufacturer"]

    dhcp_os = dhcp.get("os", "")
    if dhcp_os:
        os_name = dhcp_os
        reasons.append(f"DHCP client looks like {dhcp_os}")
        if dhcp_os in ("Android",):
            vote("phone", "", 1)
        elif dhcp_os in ("Windows", "macOS"):
            vote("computer", "", 1)
        elif dhcp_os in ("Xbox", "PlayStation", "Nintendo"):
            vote("console", "", 3)
        elif dhcp_os == "Roku":
            vote("tv", "", 3)

    nb = info.get("netbios", {})
    if nb:
        os_name = os_name or "Windows"
        vote("computer", "answers to NetBIOS (Windows or Samba)", 1)

    for port, page in banners.items():
        if not isinstance(page, dict):
            continue
        text = " ".join(str(page.get(k, "")) for k in ("banner", "server", "title", "realm")).lower()
        if "openssh" in text and not os_name:
            for tag, label in (("ubuntu", "Ubuntu Linux"), ("raspbian", "Raspberry Pi OS"), ("debian", "Debian Linux"), ("freebsd", "FreeBSD")):
                if tag in text:
                    os_name = label
                    reasons.append(f"SSH banner says {label}")
                    break
            else:
                reasons.append("runs an SSH server")
            vote("server", "", 1)
        if "dropbear" in text:
            vote("iot", "SSH server is Dropbear (embedded devices)", 1)
        if re.search(r"printer|laserjet|officejet|epson|brother|canon|cups", text):
            vote("printer", "web page looks like a printer", 3)
        if re.search(r"camera|hikvision|dahua|reolink|axis|ipcam|dvr|nvr", text):
            vote("camera", "web page looks like a camera", 3)
        if re.search(r"router|gateway|access point|openwrt|dd-wrt|mikrotik|ubiquiti|unifi|tp-link|netgear|fritz", text):
            vote("network", "web page looks like network gear", 3)
        if re.search(r"synology|qnap|nas|plex|home ?assistant|pi-?hole", text):
            vote("server", "web page looks like a server or NAS", 2)

    seen = ttl.get("initial")
    if seen == 128 and not os_name:
        os_name = "Windows"
        reasons.append("ping reply TTL points to Windows")
    elif seen == 255:
        vote("network", "ping reply TTL 255 (network gear)", 1)
    elif seen == 64 and not os_name:
        reasons.append("ping reply TTL points to Linux, macOS, iOS or Android")

    name, _src = best_name(info)
    for text in (name, mdns.get("hostname", ""), dhcp.get("hostname", "")):
        low = (text or "").lower()
        if not low:
            continue
        for pattern, category, note in HOSTNAME_HINTS:
            if re.search(pattern, low):
                vote(category, f"name \"{clean(text, 40)}\" suggests {category}", 1)
                if note and not os_name and note[0].isupper() and category in ("phone", "computer"):
                    os_name = note
                break

    if private_mac and not votes:
        reasons.append("private (randomised) MAC, usually a phone, tablet or laptop")
    category = max(votes, key=lambda c: votes[c]) if votes and max(votes.values()) > 0 else ""
    return {"category": category, "os": os_name, "model": model, "vendor": clean(vendor, 60), "reasons": reasons[:8]}


def identity(info: dict[str, dict], vendor: str = "", private_mac: bool = False) -> dict:
    """Name, source of the name and the type guess in one dict; `info` is {source: data}."""
    name, source = best_name(info)
    return {"name": name, "name_source": source, **guess_type(info, vendor, private_mac)}


def flat(rows: dict[str, dict]) -> dict[str, dict]:
    """{source: {"data":..., "ts":...}} as stored -> {source: data}."""
    return {k: (v.get("data") or {}) for k, v in rows.items() if k != "checked"}
