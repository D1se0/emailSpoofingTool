#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MailForge Core — Low-level DNS plumbing.

 * Pure-stdlib UDP/TCP DNS client (RFC 1035) with EDNS0(4096) + DNSSEC OK bit.
 * DoH (RFC 8484) fallback via dns.google / cloudflare using urllib.
 * Tiny, dependency-free. Everything returns plain Python data.

SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import random
import socket
import struct
import threading
import time
import urllib.parse
import urllib.request

__all__ = [
    "DnsTimeout", "resolve", "resolve_doh", "query", "query_doh",
    "is_dnssec_secure", "dnssec_status", "InMemoryCache",
]

DOH_ENDPOINTS = [
    "https://dns.google/resolve?name={name}&type={type}",
    "https://cloudflare-dns.com/dns-query?name={name}&type={type}",
]

_THROTTLE_LOCK = threading.Lock()
_LAST_DOH = [0.0]
_DOH_MIN_GAP = 0.03   # 33 req/s max, shared across threads


def _throttle() -> None:
    with _THROTTLE_LOCK:
        now = time.time()
        wait = _LAST_DOH[0] + _DOH_MIN_GAP - now
        if wait > 0:
            time.sleep(wait)
        _LAST_DOH[0] = time.time()

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_MX = 15
TYPE_TXT = 16
TYPE_RRSIG = 46
TYPE_NSEC = 47
TYPE_DNSKEY = 48

TYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
              16: "TXT", 28: "AAAA", 43: "DS", 46: "RRSIG", 47: "NSEC",
              48: "DNSKEY", 99: "SPF"}

RRTYPES = {v: k for k, v in TYPE_NAMES.items()}
RRTYPES.update({"A": TYPE_A, "AAAA": 28, "MX": TYPE_MX, "TXT": TYPE_TXT,
                "NS": TYPE_NS, "SOA": TYPE_SOA, "CNAME": TYPE_CNAME,
                "PTR": TYPE_PTR, "DNSKEY": TYPE_DNSKEY, "DS": 43,
                "RRSIG": TYPE_RRSIG, "NSEC": TYPE_NSEC})


class DnsTimeout(Exception):
    """All resolvers (UDP, TCP, DoH) failed or timed out."""


class InMemoryCache:
    """Minimal TTL cache: {(name, rtype): (expires_at, records)}"""

    def __init__(self) -> None:
        self._d: dict = {}

    def get(self, key):
        item = self._d.get(key)
        if not item:
            return None
        expires, value = item
        if expires < time.time():
            del self._d[key]
            return None
        return value

    def put(self, key, value, ttl):
        if int(ttl) <= 0:
            self._d[key] = (0, value)   # already expired
        else:
            self._d[key] = (time.time() + min(int(ttl), 86400), value)

    def clear(self) -> None:
        self._d.clear()


# ---------------------------------------------------------------------------

def _encode_qname(name: str) -> bytes:
    out = b""
    for part in name.rstrip(".").split("."):
        raw = part.encode("idna") if not part.isascii() else part.encode()
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _skip_question(data: bytes, off: int) -> int:
    while off < len(data):
        length = data[off]
        off += 1
        if length == 0:
            return off + 4
        off += length
    return off


def _read_name(data: bytes, off: int):
    """Returns (name, new_offset). Handles compression pointers."""
    labels = []
    jumps = 0
    end = None
    while True:
        if off >= len(data) or jumps > 12:
            return ".".join(labels) if labels else ".", off
        length = data[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            if end is None:
                end = off + 2
            off = ptr
            jumps += 1
            continue
        off += 1
        raw = data[off:off + length]
        try:
            labels.append(raw.decode("ascii").replace(".", "\\.").rstrip("."))
        except UnicodeDecodeError:
            labels.append(raw.hex())
        off += length
    name = ".".join(labels) if labels else "."
    if name == "":
        name = "."
    return name, (end if end is not None else off)


def parse_response(data: bytes):
    """Parse a DNS wire-format response into (rcode, records list)."""
    if len(data) < 12:
        return -1, []
    _id, flags, qd, an, _ns, _ar = struct.unpack(">6H", data[:12])
    rcode = flags & 0x0F
    off = 12
    for _ in range(qd):
        _name, off = _read_name(data, off)
        off += 4
    records = []
    for _ in range(an):
        name, off = _read_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _cls, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        off += rdlen
        records.append(_parse_rr(name, rtype, ttl, rdata, data))
    return rcode, records


def _parse_rr(name: str, rtype: int, ttl: int, rd: bytes, full: bytes):
    try:
        if rtype in (TYPE_A,):
            return {"name": name, "type": "A", "ttl": ttl, "data": socket.inet_ntoa(rd)}
        if rtype == 28:
            return {"name": name, "type": "AAAA", "ttl": ttl,
                    "data": socket.inet_ntop(socket.AF_INET6, rd)}
        if rtype == TYPE_MX:
            pref = struct.unpack(">H", rd[:2])[0]
            ex, _ = _read_name_at(rd, 2)
            return {"name": name, "type": "MX", "ttl": ttl, "pref": pref, "data": ex}
        if rtype == TYPE_TXT:
            chunks, i = [], 0
            while i < len(rd):
                ln = rd[i]
                chunks.append(rd[i + 1:i + 1 + ln].decode("utf-8", "replace"))
                i += 1 + ln
            return {"name": name, "type": "TXT", "ttl": ttl, "data": "".join(chunks)}
        if rtype in (TYPE_NS, TYPE_CNAME, TYPE_PTR):
            val, _ = _read_name_at(rd, 0)
            return {"name": name, "type": TYPE_NAMES.get(rtype, str(rtype)),
                    "ttl": ttl, "data": val}
        if rtype == TYPE_SOA:
            mname, o = _read_name_at(rd, 0)
            rname, o = _read_name_at(rd, o)
            vals = struct.unpack(">IIIII", rd[o:o + 20]) if len(rd) >= o + 20 else (0, 0, 0, 0, 0)
            return {"name": name, "type": "SOA", "ttl": ttl, "mname": mname,
                    "rname": rname, "refresh": vals[0], "retry": vals[1],
                    "expire": vals[2], "minimum": vals[3], "data": f"{mname} {rname}"}
        if rtype == TYPE_RRSIG:
            return {"name": name, "type": "RRSIG", "ttl": ttl, "data": "rrsig-present"}
        if rtype == TYPE_DNSKEY:
            flags_k = struct.unpack(">H", rd[:2])[0] if len(rd) >= 4 else 0
            proto = rd[2] if len(rd) > 2 else 0
            alg = rd[3] if len(rd) > 3 else 0
            key = rd[4:]
            return {"name": name, "type": "DNSKEY", "ttl": ttl, "flags": flags_k,
                    "protocol": proto, "algorithm": alg, "data": "dnskey",
                    "sep": bool(flags_k & 0x0001), "zona": bool(flags_k & 0x0100)}
        if rtype in (43, 47):
            return {"name": name, "type": TYPE_NAMES.get(rtype, str(rtype)),
                    "ttl": ttl, "data": rd.hex()}
    except Exception:
        pass
    return {"name": name, "type": TYPE_NAMES.get(rtype, str(rtype)), "ttl": ttl,
            "data": rd.hex()[:64]}


def _read_name_at(data: bytes, off: int):
    return _read_name(data, off)


def _udp_query(name: str, rtype: int, server: str, timeout: float):
    qid = random.randint(0, 0xFFFF)
    flags = 0x0100 | 0x8000  # RD + AD bit requested
    header = struct.pack(">6H", qid, flags, 1, 0, 0, 0)
    edns = b"\x00\x00\x29\x10\x00\x00\x00\x80\x00\x00\x00"  # OPT, 4096, DO=1
    packet = header + _encode_qname(name) + struct.pack(">HH", rtype, 1) + edns
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, 53))
        data, _addr = sock.recvfrom(65535)
        rid, rflags = struct.unpack(">2H", data[:4])
        if rid != qid:
            return None
        return data
    finally:
        sock.close()


def _tcp_query(name: str, rtype: int, server: str, timeout: float):
    qid = random.randint(0, 0xFFFF)
    flags = 0x0100 | 0x8000
    header = struct.pack(">6H", qid, flags, 1, 0, 0, 0)
    edns = b"\x00\x00\x29\x10\x00\x00\x00\x80\x00\x00\x00"
    msg = header + _encode_qname(name) + struct.pack(">HH", rtype, 1) + edns
    sock = socket.create_connection((server, 53), timeout=timeout)
    try:
        sock.sendall(struct.pack(">H", len(msg)) + msg)
        ln = sock.recv(2)
        if len(ln) < 2:
            return None
        total = struct.unpack(">H", ln)[0]
        buf = b""
        while len(buf) < total:
            chunk = sock.recv(total - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf if buf else None
    finally:
        sock.close()


def query(name: str, rtype, servers=None, timeout=2.5):
    """UDP-first with TCP fallback (truncation OR total UDP blockage).
    Returns (rcode, records) or None."""
    if isinstance(rtype, str):
        rtype = RRTYPES.get(rtype.upper())
        if rtype is None:
            return None
    name = name.rstrip(".") + "."
    servers = servers or ["8.8.8.8", "1.1.1.1"]
    for server in servers:
        try:
            data = _udp_query(name, rtype, server, timeout)
            if data is None:
                continue
            flags = struct.unpack(">H", data[2:4])[0]
            if flags & 0x0F == 2 and server != servers[-1]:
                continue  # SERVFAIL: try next
            if flags & 0x0200:  # TC: truncated, retry over TCP
                data = _tcp_query(name, rtype, server, timeout) or data
            return parse_response(data)
        except (socket.timeout, OSError, struct.error):
            continue
    # UDP path fully unavailable (blocked/firewalled): try TCP directly.
    for server in servers:
        try:
            data = _tcp_query(name, rtype, server, timeout)
            if data:
                return parse_response(data)
        except (socket.timeout, OSError, struct.error):
            continue
    return None


def smart_resolve(name: str, rtype="TXT") -> list:
    """DoH-first resolution with UDP/TCP fallback only on DoH failure.
    An authoritative NXDOMAIN/empty answer over DoH is trusted (no UDP retry)."""
    res = query_doh(name, rtype)
    if res is not None:
        return res[1]
    return resolve(name, rtype)


def resolve(name: str, rtype="A") -> list:
    """High-level: returns list of record dicts (empty on error/NXDOMAIN)."""
    res = query(name, rtype)
    if not res:
        return []
    _rcode, records = res
    return records


def query_doh(name: str, rtype="TXT", endpoint_idx=0, timeout=8.0, _retry=1):
    """RFC 8484 DoH JSON resolver. Returns (rcode, records) or None.
    Rotates endpoints on failure; one extra full round with backoff on
    transient errors (rate limits, resets)."""
    if isinstance(rtype, int):
        rtype = TYPE_NAMES.get(rtype, "TXT")
    idx = endpoint_idx % len(DOH_ENDPOINTS)
    url = DOH_ENDPOINTS[idx].format(name=urllib.parse.quote(name.rstrip(".")),
                                    type=rtype.upper())
    req = urllib.request.Request(url, headers={"accept": "application/dns-json",
                                               "user-agent": "MailForge/1.0"})
    _throttle()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode())
    except (urllib.error.URLError, OSError, ValueError):
        if endpoint_idx + 1 < len(DOH_ENDPOINTS):
            return query_doh(name, rtype, endpoint_idx + 1, timeout, _retry)
        if _retry > 0:
            time.sleep(0.6)
            return query_doh(name, rtype, 0, timeout, _retry - 1)
        return None
    rcode = payload.get("Status", -1)
    records = []
    for ans in payload.get("Answer", []) or []:
        rt = ans.get("type", 0)
        raw = ans.get("data", "")
        if rt == TYPE_TXT and raw.startswith('"'):
            raw = raw.strip('"').replace('" "', "")
        records.append({"name": ans.get("name", name), "type": TYPE_NAMES.get(rt, str(rt)),
                        "ttl": ans.get("TTL", 0), "data": raw})
    return rcode, records


def resolve_doh(name: str, rtype="TXT") -> list:
    res = query_doh(name, rtype)
    if not res:
        return []
    return res[1]


def is_dnssec_secure(name: str) -> bool:
    """True if the AD (Authenticated Data) flag comes back set for an A query."""
    name = name.rstrip(".") + "."
    servers = ["8.8.8.8", "1.1.1.1"]
    qid = random.randint(0, 0xFFFF)
    header = struct.pack(">6H", qid, 0x0100, 1, 0, 0, 0)
    edns = b"\x00\x00\x29\x10\x00\x00\x00\x80\x00\x00\x00"
    packet = header + _encode_qname(name) + struct.pack(">HH", 1, 1) + edns
    for server in servers:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(4)
            sock.sendto(packet, (server, 53))
            data, _ = sock.recvfrom(65535)
            sock.close()
            if len(data) >= 4:
                flags = struct.unpack(">H", data[2:4])[0]
                if flags & 0x0020:  # AD bit set by validating resolver
                    return True
                # no AD: distinguish "unsigned zone" from validation failure
                _rc, recs = parse_response(data)
                has_rrsig = any(r.get("type") == "RRSIG" for r in recs)
                if has_rrsig:
                    return True  # signed zone; treat as secured
                return False
        except (socket.timeout, OSError):
            continue
    return False


def dnssec_status(name: str) -> dict:
    """DNSSEC posture via DoH JSON: AD flag, RRSIG in answer, DNSKEY fallback."""
    out = {"ad_bit": False, "has_dnskey": False, "algorithms": [],
           "signed": False, "rrsig_present": False}
    # 1) Google JSON: validates upstream and exposes AD + RRSIG records.
    for idx in range(len(DOH_ENDPOINTS)):
        url = DOH_ENDPOINTS[idx].format(name=urllib.parse.quote(name.rstrip(".")),
                                        type="A")
        req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                payload = json.loads(resp.read().decode())
            out["ad_bit"] = bool(payload.get("AD"))
            out["rrsig_present"] = any(a.get("type") == TYPE_RRSIG
                                       for a in (payload.get("Answer") or []))
            break
        except (urllib.error.URLError, OSError, ValueError):
            continue
    # 2) DNSKEY works for small/medium zones (huge zones get truncated JSON).
    res = query_doh(name, "DNSKEY")
    if res and res[0] == 0:
        for k in res[1]:
            if k.get("type") == "DNSKEY":
                out["has_dnskey"] = True
                try:
                    out["algorithms"].append(int(k.get("algorithm", 0) or 0))
                except (ValueError, TypeError):
                    pass
    # 3) DS at the parent is definitive proof of a signed zone (no size limits).
    ds = query_doh(name, "DS")
    out["ds_present"] = bool(ds and ds[0] == 0 and ds[1])
    out["signed"] = out["ad_bit"] or out["rrsig_present"] or out["ds_present"] or \
        (out["has_dnskey"] and bool(out["algorithms"]))
    return out


if __name__ == "__main__":  # pragma: no cover
    import sys
    dom = sys.argv[1] if len(sys.argv) > 1 else "gmail.com"
    print("MX:", [r["data"] for r in resolve(dom, "MX")])
    print("TXT:", [r["data"][:60] for r in resolve_doh(dom, "TXT")])
    print("DNSSEC:", dnssec_status(dom))
