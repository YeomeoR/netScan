"""A minimal DNS wire-format reader/writer, enough for mDNS. Never trusts lengths or pointers in a packet."""

from __future__ import annotations

import socket
import struct

A, PTR, TXT, AAAA, SRV = 1, 12, 16, 28, 33
MAX_NAME_JUMPS = 20


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        raw = label.encode("utf-8")
        if not raw or len(raw) > 63:
            raise ValueError(f"bad DNS label in {name!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(name: str, qtype: int, unicast_response: bool = False, txid: int = 0) -> bytes:
    """One-question query. The mDNS 'QU' bit asks the responder to answer us directly instead of by multicast."""
    qclass = 0x8001 if unicast_response else 1
    return struct.pack(">HHHHHH", txid, 0, 1, 0, 0, 0) + encode_name(name) + struct.pack(">HH", qtype, qclass)


def read_name(data: bytes, pos: int) -> tuple[str, int]:
    labels: list[str] = []
    end = -1
    jumps = 0
    while True:
        if pos >= len(data):
            raise ValueError("name runs past the packet")
        n = data[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise ValueError("truncated pointer")
            if end < 0:
                end = pos + 2
            pos = ((n & 0x3F) << 8) | data[pos + 1]
            jumps += 1
            if jumps > MAX_NAME_JUMPS:
                raise ValueError("pointer loop")
            continue
        if n & 0xC0:
            raise ValueError("unsupported label type")
        if pos + 1 + n > len(data):
            raise ValueError("label runs past the packet")
        labels.append(data[pos + 1 : pos + 1 + n].decode("utf-8", "replace"))
        pos += 1 + n
    return ".".join(labels), (end if end >= 0 else pos)


def _txt(rdata: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    i = 0
    while i < len(rdata):
        n = rdata[i]
        item = rdata[i + 1 : i + 1 + n]
        i += 1 + n
        if not item:
            continue
        key, _, val = item.decode("utf-8", "replace").partition("=")
        out.setdefault(key.lower(), val)
    return out


def parse_message(data: bytes) -> list[dict]:
    """All resource records (answers, authority, additional) as dicts: name, type, rdata. Malformed packets give []."""
    try:
        _id, _flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
        pos = 12
        for _ in range(qd):
            _name, pos = read_name(data, pos)
            pos += 4
        records = []
        for _ in range(min(an + ns + ar, 200)):
            name, pos = read_name(data, pos)
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[pos : pos + 10])
            pos += 10
            rdata = data[pos : pos + rdlen]
            if len(rdata) != rdlen:
                break
            start = pos
            pos += rdlen
            if rtype == A and rdlen == 4:
                value: object = socket.inet_ntoa(rdata)
            elif rtype == AAAA and rdlen == 16:
                value = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype == PTR:
                value = read_name(data, start)[0]
            elif rtype == TXT:
                value = _txt(rdata)
            elif rtype == SRV and rdlen >= 7:
                port = struct.unpack(">H", rdata[4:6])[0]
                value = {"port": port, "target": read_name(data, start + 6)[0]}
            else:
                continue
            records.append({"name": name, "type": rtype, "rdata": value})
        return records
    except (ValueError, struct.error):
        return []
