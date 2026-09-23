#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MailForge Core — DKIM (RFC 6376) discovery + crypto verification.

Pure-stdlib verification: DNS TXT selector._domainkey lookup, RSA/Ed25519
signature check of a raw RFC 5322 message, body canonicalization
(simple/relaxed) and header hash chain reconstruction.

SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import base64
import hashlib
import re

__all__ = ["DkimKey", "DkimSig", "fetch_dkim_key", "guess_selectors",
           "verify_dkim", "parse_dkim_header"]


class DkimKeyError(Exception):
    pass


class DkimKey:
    def __init__(self, selector: str, domain: str, txt: str) -> None:
        self.selector = selector
        self.domain = domain
        self.raw = txt
        self.version = "DKIM1"
        self.key_type = "rsa"
        self.hash_algs = ["sha256"]
        self.service = "*"
        self.flags: list = []
        self.notes = ""
        self.pub_key_b64 = ""
        self._parse(txt)

    def _parse(self, txt: str) -> None:
        for tag in txt.split(";"):
            tag = tag.strip()
            if not tag or "=" not in tag:
                continue
            k, _, v = tag.partition("=")
            k, v = k.strip().lower(), v.strip()
            if k == "v":
                self.version = v
            elif k == "k":
                self.key_type = v.lower()
            elif k == "h":
                self.hash_algs = [x.strip().lower() for x in v.split(":") if x.strip()]
            elif k == "s":
                self.service = v
            elif k == "t":
                self.flags = [x.strip().lower() for x in v.split(":") if x.strip()]
            elif k == "n":
                self.notes = v
            elif k == "p":
                self.pub_key_b64 = v.replace(" ", "")

    @property
    def revoked(self) -> bool:
        return self.pub_key_b64 == ""

    @property
    def weak_bits(self) -> int:
        """RSA modulus size if parseable, 0 otherwise."""
        try:
            from . import _rsalite
            der = base64.b64decode(self.pub_key_b64)
            bits = _rsalite.rsa_modulus_bits(der)
            return bits or 0
        except Exception:
            return 0

    def to_dict(self) -> dict:
        return {"selector": self.selector, "domain": self.domain,
                "key_type": self.key_type, "hash_algs": self.hash_algs,
                "flags": self.flags, "notes": self.notes,
                "revoked": self.revoked, "weak_bits": self.weak_bits,
                "service": self.service, "raw": self.raw}


class DkimSig:
    """One DKIM-Signature header field, parsed into tags."""

    def __init__(self, header_value: str) -> None:
        self.raw = header_value
        self.tags = {}
        for part in header_value.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            k, _, v = part.partition("=")
            self.tags[k.strip().lower()] = v.strip()

    def get(self, key, default=None):
        return self.tags.get(key, default)

    @property
    def domain(self):
        return (self.get("d") or "").strip().lower()

    @property
    def selector(self):
        return (self.get("s") or "").strip()

    @property
    def algorithm(self):
        return (self.get("a") or "").lower()

    @property
    def covers(self):
        """List of headers covered by the signature (from the h= tag)."""
        return [h.strip().lower() for h in (self.get("h") or "").split(":") if h.strip()]


def parse_dkim_header(value: str) -> DkimSig:
    return DkimSig(value)


def fetch_dkim_key(selector: str, domain: str):
    """Returns (DkimKey|None, raw_txt, error|None). Follows CNAME chains
    (very common: selector1._domainkey.acme → provider-hosted key zone)."""
    from . import dnsx
    fqdn = f"{selector}._domainkey.{domain}"
    records = dnsx.smart_resolve(fqdn, "TXT")
    hops = 0
    while records and any(r.get("type") == "CNAME" for r in records) and hops < 4:
        target = next(r["data"] for r in records if r.get("type") == "CNAME")
        records = dnsx.smart_resolve(target.rstrip("."), "TXT")
        hops += 1
    txts = [r for r in (records or []) if r.get("type") == "TXT" and r.get("data")]
    if not txts:
        return None, None, f"no TXT at {fqdn}"
    raw = txts[0]["data"]
    if not raw:
        return None, None, "empty TXT record"
    try:
        return DkimKey(selector, domain, raw), raw, None
    except Exception as exc:
        return None, raw, f"unparsable key: {exc}"


COMMON_SELECTORS = [
    "google", "selector1", "selector2", "s1", "s2", "dkim", "default",
    "k1", "mail", "smtp", "email", "zoho", "protonmail", "pm", "mta",
    "smtpout", "mailgun", "mandrill", "sendgrid", "amazonses", "feb2024",
    "analytics", "hs1", "hs2", "hubspot", "salesforce", "sf1", "sf2",
    "2023", "2024", "2025", "2026", "x", "mx", "sv1", "sv2", "tk1", "tk2",
    "kr1", "kr2", "api", "auth", "spf", "domainkey", "dk", "message",
    # date-style selectors used by Gmail/Google Workspace and others
    "20161025", "20230601", "20221201", "20210101",
    *[f"{y}0101" for y in range(2016, 2027)],
    *[f"{y}0601" for y in range(2016, 2027)],
]


def guess_selectors(domain: str, extra=(), max_workers=16, timeout=6.0) -> list:
    """Probe a list of common selectors; returns list of DkimKey."""
    import concurrent.futures as cf
    from . import dnsx

    tried = list(dict.fromkeys(list(extra) + COMMON_SELECTORS))
    found = []

    def probe(sel):
        try:
            key, _raw, err = fetch_dkim_key(sel, domain)
            if key and not err:
                return key
        except Exception:
            pass
        return None

    with cf.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for res in pool.map(probe, tried):
            if res:
                found.append(res)
    return found


# --------------------------------------------------------------------------
# Crypto: RFC 3447 PKCS#1 v1.5 RSA verify + Ed25519 (RFC 8032), stdlib-only.
# --------------------------------------------------------------------------

def _b64decode_pkcs1(b64: str):
    """Decode SubjectPublicKeyInfo or PKCS#1 DER -> (n, e) or ('ed25519', raw32)."""
    from . import _rsalite
    der = base64.b64decode(b64)
    return _rsalite.parse_public_key(der)


def _canonical_headers(msg: bytes, sig: DkimSig):
    """Rebuild the signed header list (bottom-up, canonicalized)."""
    canon = (sig.get("c") or "simple/simple").split("/")
    hcanon = canon[0]
    bcanon = canon[1] if len(canon) > 1 else "simple"
    header_names = sig.covers

    # Collect all header fields in raw form (RFC 5322 unfolding preserved).
    raw_headers = []
    pos = 0
    while True:
        eol = msg.find(b"\r\n", pos)
        if eol < 0:
            break
        line = msg[pos:eol]
        if line == b"":
            break
        # continuation lines
        while True:
            nxt = msg.find(b"\r\n", eol + 2)
            nxt = nxt if nxt >= 0 else len(msg)
            if nxt < len(msg) and msg[nxt:nxt + 2] == b"\r\n" and nxt + 2 < len(msg) \
                    and msg[nxt + 2:nxt + 3] in (b" ", b"\t"):
                eol = msg.find(b"\r\n", nxt + 2)
                if eol < 0:
                    break
                continue
            break
        raw_headers.append(line)
        pos = eol + 2

    # For each name in h= pick an unused header, bottom-up.
    used = set()
    signed_lines = []
    for name in header_names:
        for idx in range(len(raw_headers) - 1, -1, -1):
            if idx in used:
                continue
            lname = raw_headers[idx].split(b":", 1)[0].strip().lower()
            if lname == name:
                used.add(idx)
                signed_lines.append(raw_headers[idx])
                break

    def canon_h(line: bytes) -> bytes:
        if hcanon == "simple":
            return line
        name, _, value = line.partition(b":")
        name = name.strip() + b":"
        # unfold
        value = value.replace(b"\r\n", b"")
        value = re.sub(rb"[ \t]+", b" ", value).strip()
        return name + b" " + value

    # DKIM-Signature itself (b= emptied, canonicalized with h= canon rules).
    dsig_raw = raw_headers and None
    b_tag = sig.get("b") or ""
    dsig_value = sig.raw
    # The sig header we sign is the one WITHOUT b= value.
    dsig_stripped = re.sub(rb"b=[^;]*", b"b=", dsig_value.encode("utf-8", "replace"))
    # Note: only up to and including the terminating CRLF of that header.
    if b_tag:
        idx = dsig_stripped.find(b"b=" + b_tag.encode())
        if idx >= 0:
            dsig_stripped = dsig_stripped[:idx] + b"b=" + dsig_stripped[idx + 2 + len(b_tag):]

    dsig_stripped = canon_h_bytes(dsig_stripped, hcanon)

    to_hash = b"".join(canon_h(l) + b"\r\n" for l in signed_lines)
    to_hash += dsig_stripped
    return to_hash, bcanon, hcanon


def canon_h_bytes(line: bytes, hcanon: str) -> bytes:
    if hcanon == "simple":
        return line
    # relaxed: lowercase name, unfold, collapse WSP, strip trailing WSP
    name, sep, value = line.partition(b":")
    name = name.strip().lower() + b":" + sep
    value = value.replace(b"\r\n", b"")
    value = re.sub(rb"[ \t]+", b" ", value).strip()
    value = value.rstrip()
    return name + b" " + value


def _canonical_body(msg: bytes, bcanon: str) -> bytes:
    # Split headers/body at first empty CRLF line.
    parts = msg.split(b"\r\n\r\n", 1)
    body = parts[1] if len(parts) > 1 else b""
    if bcanon == "simple":
        body = body.rstrip(b"\r\n") + b"\r\n" if body.strip() else b"\r\n"
        return body
    # relaxed
    lines = body.split(b"\r\n")
    out = []
    for ln in lines:
        ln = ln.replace(b"\r\n", b"")
        ln = re.sub(rb"[ \t]+", b" ", ln).rstrip()
        out.append(ln)
    body = b"\r\n".join(out)
    body = body.rstrip(b"\r\n")
    return body + b"\r\n" if body else b"\r\n"


def verify_dkim(msg: bytes, sig: DkimSig, key: DkimKey) -> dict:
    """Full crypto verification. Returns {valid, reason, details}."""
    from . import _rsalite

    result = {"valid": False, "reason": "", "algorithm": sig.algorithm,
              "domain": sig.domain, "selector": sig.selector, "details": {}}
    try:
        n, e = _b64decode_pkcs1(key.pub_key_b64)
    except Exception as exc:
        result["reason"] = f"key decode failed: {exc}"
        return result

    if sig.algorithm.startswith("rsa") and not isinstance(n, int):
        result["reason"] = "algorithm mismatch: rsa-* but key is not RSA"
        return result
    if sig.algorithm.startswith("ed25519") and isinstance(n, int):
        result["reason"] = "algorithm mismatch: ed25519-* but key is RSA"
        return result

    to_hash, bcanon, _h = _canonical_headers(msg, sig)
    body_hash_input = _canonical_body(msg, bcanon)
    l_tag = sig.get("l")
    if l_tag:
        try:
            body_hash_input = body_hash_input[:int(l_tag)]
        except ValueError:
            pass

    alg_hash = {"rsa-sha1": hashlib.sha1, "rsa-sha256": hashlib.sha256,
                "ed25519-sha256": hashlib.sha256}.get(sig.algorithm)
    if alg_hash is None:
        result["reason"] = f"unsupported algorithm '{sig.algorithm}'"
        return result

    computed_body = alg_hash(body_hash_input).digest()
    bh = sig.get("bh", "")
    try:
        if base64.b64decode(bh + "==", validate=False) != computed_body:
            result["reason"] = "body hash mismatch (bh)"
            result["details"]["computed_bh"] = base64.b64encode(computed_body).decode()
            return result
    except Exception:
        result["reason"] = "malformed bh tag"
        return result

    header_hash = alg_hash(to_hash).digest()
    b_val = (sig.get("b") or "").replace(" ", "")
    try:
        sig_bytes = base64.b64decode(b_val + "==", validate=False)
    except Exception:
        result["reason"] = "malformed b= signature"
        return result

    ok = False
    if isinstance(n, int):
        ok = _rsalite.rsa_verify(n, e, sig_bytes, header_hash,
                                 "sha1" if "sha1" in sig.algorithm else "sha256")
    else:
        ok = _rsalite.ed25519_verify(n, sig_bytes, header_hash)

    if not ok:
        result["reason"] = "signature does not verify (b= mismatch)"
        return result
    result["valid"] = True
    result["reason"] = "signature verifies"
    return result
