#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MailForge Core — minimal crypto verifier (stdlib-only).

 * DER/ASN.1 walking for SubjectPublicKeyInfo + PKCS#1 RSAPublicKey.
 * RSA PKCS#1 v1.5 signature verification (RFC 3447 §8.2.2, verify-only).
 * Ed25519 verification (RFC 8032) in pure Python (extended coordinates).

Only *verification* is implemented on purpose — this module cannot sign,
encrypt or generate keys.

SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import hashlib

__all__ = ["parse_public_key", "rsa_modulus_bits", "rsa_verify", "ed25519_verify"]

_OID_RSA = bytes.fromhex("2a864886f70d010101")   # 1.2.840.113549.1.1.1
_OID_ED25519 = bytes.fromhex("2b6570")            # 1.3.101.112

_DIGESTINFO = {
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


# --------------------------------------------------------------------------
# Minimal DER
# --------------------------------------------------------------------------

def _tlv(data: bytes, off: int):
    """Read one TLV. Returns (tag, content, next_offset) or (None, None, off)."""
    if off + 2 > len(data):
        return None, None, off
    tag = data[off]
    off += 1
    ln = data[off]
    off += 1
    if ln & 0x80:
        nbytes = ln & 0x7F
        if nbytes == 0 or off + nbytes > len(data):
            return None, None, off
        ln = int.from_bytes(data[off:off + nbytes], "big")
        off += nbytes
    if off + ln > len(data):
        return None, None, off
    return tag, data[off:off + ln], off + ln


def _find_oid(seq: bytes, oid: bytes) -> bool:
    off = 0
    while off < len(seq):
        tag, val, noff = _tlv(seq, off)
        if tag is None:
            break
        if tag == 0x06 and val == oid:
            return True
        off = noff
    return False


def parse_public_key(der: bytes):
    """Return (n:int, e:int) for RSA or ('ed25519', 32-byte-pub) for Ed25519.

    Accepts SubjectPublicKeyInfo, bare PKCS#1 RSAPublicKey and raw 32-byte
    Ed25519 keys.
    """
    if len(der) == 32:                      # raw ed25519
        return ("ed25519", der)

    tag, content, _ = _tlv(der, 0)
    if tag != 0x30:
        raise ValueError("not a DER SEQUENCE")

    # Try SubjectPublicKeyInfo: SEQ { SEQ{OID,...}, BIT STRING }
    t1, algid, o1 = _tlv(content, 0)
    if t1 == 0x30:
        t2, bits, o2 = _tlv(content, o1)
        if t1 == 0x30 and t2 == 0x03 and len(algid) >= 2:
            inner_tag, inner, _o3 = _tlv(bits, 0)  # skip unused-bits byte? _tlv handles
            if _find_oid(algid, _OID_ED25519):
                # BIT STRING content: 1 unused-bits byte + 32 bytes
                return ("ed25519", bits[1:])
            if _find_oid(algid, _OID_RSA):
                return _parse_pkcs1(bits[1:])

    # Bare PKCS#1
    return _parse_pkcs1(content)


def _parse_pkcs1(body: bytes):
    tag, seq_content, _ = _tlv(body, 0)
    if tag != 0x30:
        raise ValueError("RSA key: expected SEQUENCE")
    ints = []
    off = 0
    while len(ints) < 2:
        t, val, off = _tlv(seq_content, off)
        if t != 0x02:
            raise ValueError("RSA key: expected INTEGER")
        ints.append(int.from_bytes(val, "big"))
    n, e = ints
    if n <= 0 or e <= 0:
        raise ValueError("RSA key: non-positive integer")
    return n, e


def rsa_modulus_bits(der: bytes) -> int:
    try:
        parsed = parse_public_key(der)
    except Exception:
        return 0
    if isinstance(parsed[0], int):
        return parsed[0].bit_length()
    return 256


# --------------------------------------------------------------------------
# RSA PKCS#1 v1.5 verify
# --------------------------------------------------------------------------

def rsa_verify(n: int, e: int, signature: bytes, digest: bytes, hashname: str) -> bool:
    prefix = _DIGESTINFO.get(hashname)
    if prefix is None or not isinstance(n, int):
        return False
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    m = pow(s, e, n)
    em = m.to_bytes(k, "big")
    t = prefix + digest
    if k < len(t) + 11:
        return False
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return _consteq(em, expected)


def _consteq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    acc = 0
    for x, y in zip(a, b):
        acc |= x ^ y
    return acc == 0


# --------------------------------------------------------------------------
# Ed25519 (RFC 8032) — pure Python, extended coordinates
# --------------------------------------------------------------------------

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _inv(x):
    return pow(x, _P - 2, _P)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if (x * x - xx) % _P != 0:
        raise ValueError("point decompression failed")
    if x % 2 != 0:
        x = _P - x
    return x


_BY = (4 * _inv(5)) % _P
_BX = _xrecover(_BY)
_B = (_BX, _BY, 1, (_BX * _BY) % _P)   # extended coords (X, Y, Z, T)
_IDENT = (0, 1, 1, 0)


def _edwards_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (t1 * 2 * _D * t2) % _P
    d = (z1 * 2 * z2) % _P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return ((e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P)


def _scalarmult(p, e):
    q = _IDENT
    while e > 0:
        if e & 1:
            q = _edwards_add(q, p)
        p = _edwards_add(p, p)
        e >>= 1
    return q


def _point_compress(p):
    x, y, z, _t = p
    zi = _inv(z)
    x = (x * zi) % _P
    y = (y * zi) % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _point_decompress(s: bytes):
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    try:
        x = _xrecover(y)
    except ValueError:
        return None
    if x & 1 != sign:
        x = _P - x
    return (x, y, 1, (x * y) % _P)


def ed25519_verify(pub32: bytes, signature: bytes, msg: bytes) -> bool:
    if len(pub32) != 32 or len(signature) != 64:
        return False
    a = _point_decompress(pub32)
    if a is None:
        return False
    r_bytes = signature[:32]
    s_val = int.from_bytes(signature[32:], "little")
    if s_val >= _L:
        return False
    r = _point_decompress(r_bytes)
    if r is None:
        return False
    k = int.from_bytes(hashlib.sha512(r_bytes + pub32 + msg).digest(), "little") % _L
    lhs = _scalarmult(_B, s_val)
    rhs = _edwards_add(r, _scalarmult(a, k))
    return _consteq(_point_compress(lhs), _point_compress(rhs))


if __name__ == "__main__":  # pragma: no cover - RFC 8032 test vector 1
    sk = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    import hashlib as _h
    pub = _h.sha512(sk).digest()[32:]
    pub_bytes = bytes(bytearray([pub[i] & 0xFF for i in range(32)]))
    msg = b""
    sig = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    print("ed25519 self-test:", ed25519_verify(pub_bytes, sig, msg))
