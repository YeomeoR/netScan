"""MAC address helpers shared by parsing, storage and safety checks."""

from __future__ import annotations

import re

_HEX12 = re.compile(r"^[0-9a-f]{12}$")


def normalise_mac(value: str) -> str | None:
    """Return aa:bb:cc:dd:ee:ff or None if value is not a usable unicast-style MAC.

    Handles the macOS `arp -an` habit of dropping leading zeros (1:2:3:4:5:6).
    """
    if not value or not isinstance(value, str):
        return None
    value = value.strip().lower()
    if ":" in value or "-" in value:
        parts = re.split(r"[:-]", value)
        if len(parts) != 6 or any(not 1 <= len(p) <= 2 for p in parts):
            return None
        value = "".join(p.zfill(2) for p in parts)
    else:
        value = value.replace(".", "")
    if not _HEX12.match(value):
        return None
    mac = ":".join(value[i : i + 2] for i in range(0, 12, 2))
    if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return None
    return mac


def is_locally_administered(mac: str) -> bool:
    """True for randomised/private MACs (bit 1 of the first octet), which have no OUI vendor."""
    return bool(int(mac[:2], 16) & 0x02)


def is_multicast(mac: str) -> bool:
    return bool(int(mac[:2], 16) & 0x01)
