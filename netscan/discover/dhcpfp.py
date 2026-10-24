"""What a device says when it asks for an address: its name, its vendor class and the order it lists DHCP options.

Only broadcast client messages (DISCOVER/REQUEST) are read, and only by listening; nothing is sent.
"""

from __future__ import annotations

from netscan.discover.util import clean

DISCOVER, REQUEST = 1, 3

# vendor class prefix -> operating system. These are written by the OS's own DHCP client, so they are reliable.
VENDOR_CLASS_OS = (
    ("MSFT 5.0", "Windows"), ("android-dhcp", "Android"), ("dhcpcd", "Linux"), ("udhcp", "Linux (embedded)"),
    ("Xbox", "Xbox"), ("PLAYSTATION", "PlayStation"), ("Nintendo", "Nintendo"), ("Roku", "Roku"),
)

# the parameter request list is a habit of the DHCP client; these are the common ones. A match is a hint, not proof.
PARAM_LIST_OS = (
    ("1,3,6,15,31,33,43,44,46,47,119,121,249,252", "Windows"),
    ("1,121,3,6,15,119,252,95,44,46", "macOS"),
    ("1,121,3,6,15,119,252", "iOS / iPadOS / macOS"),
    ("1,3,6,15,26,28,51,58,59,43", "Android"),
    ("1,28,2,3,15,6,119,12,44,47,26,121,42", "Linux"),
)


def _text(value) -> str:
    if isinstance(value, (bytes, bytearray)):
        return clean(bytes(value).decode("utf-8", "replace").strip("\x00"), 80)
    return clean(str(value), 80)


def _params(value) -> list[int]:
    if isinstance(value, (bytes, bytearray)):
        return list(value)[:60]
    try:
        return [int(v) for v in value][:60]
    except (TypeError, ValueError):
        return []


def parse_options(options) -> dict:
    """Fold a scapy-style option list into what is worth keeping. Returns {} for anything that is not a client request."""
    kind = None
    out: dict = {}
    for opt in options or []:
        if not isinstance(opt, tuple) or len(opt) < 2:
            continue
        name, value = opt[0], opt[1]
        if name == "message-type":
            kind = value
        elif name == "hostname":
            out["hostname"] = _text(value)
        elif name == "vendor_class_id":
            out["vendor_class"] = _text(value)
        elif name == "param_req_list":
            out["params"] = ",".join(str(p) for p in _params(value))
        elif name == "requested_addr":
            out["requested"] = _text(value)
    if kind not in (DISCOVER, REQUEST):
        return {}
    out = {k: v for k, v in out.items() if v}
    if out:
        out["os"] = os_hint(out)
    return {k: v for k, v in out.items() if v}


def os_hint(info: dict) -> str:
    vendor = info.get("vendor_class", "")
    for prefix, name in VENDOR_CLASS_OS:
        if vendor.lower().startswith(prefix.lower()):
            return name
    params = info.get("params", "")
    for known, name in PARAM_LIST_OS:
        if params == known:
            return name
    return ""
