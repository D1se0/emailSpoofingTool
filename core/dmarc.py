#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MailForge Core — DMARC (RFC 7489) parser + policy evaluation.

Includes organizational-domain discovery (§3.2) using an embedded snapshot
of common multi-label public suffixes, _dmarc.<domain> lookup with the
standard fall-back to the org domain, and full tag validation.

SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import dnsx

__all__ = ["DmarcRecord", "parse_dmarc", "fetch_dmarc", "org_domain",
           "policy_strength", "DmarcError"]

MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.ar", "com.br", "com.au", "co.jp", "co.kr", "com.mx", "com.tr",
    "com.cn", "com.tw", "com.hk", "com.sg", "com.co", "com.pe", "com.uy",
    "com.ve", "com.do", "com.gt", "com.sv", "com.ni", "com.pa", "com.ec",
    "com.py", "com.bo", "co.in", "co.nz", "co.za", "co.il", "co.id",
    "co.th", "co.ma", "com.ng", "com.eg", "com.pk", "com.bd", "com.vn",
    "com.ph", "com.my", "com.ua", "com.pl", "com.pt", "com.gr", "com.cy",
    "com.mt", "com.tr", "org.au", "net.au", "org.nz", "net.nz", "gov.au",
    "edu.au", "ac.nz", "govt.nz", "com.ru", "org.ru", "net.ru", "co.uk.",
}

POLICIES = ("none", "quarantine", "reject")
REPORT_FORMATS = ("afrf", "iodef")

_TAG_RE = re.compile(r"^\s*([a-zA-Z]{1,6})\s*=\s*(.*?)\s*$")


class DmarcError(Exception):
    pass


@dataclass
class DmarcRecord:
    raw: str = ""
    domain: str = ""
    org_domain: str = ""
    is_org_policy: bool = False
    version: str = ""
    p: str = ""
    sp: str = ""
    adkim: str = "r"
    aspf: str = "r"
    pct: int = 100
    rua: list = field(default_factory=list)
    ruf: list = field(default_factory=list)
    fo: str = "0"
    rf: str = "afrf"
    ri: int = 86400
    np: str = ""
    psd: str = ""
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    def effective_policy(self, from_domain: str = "") -> str:
        """Policy that applies to a given RFC5322.From domain (handles sp=)."""
        target = (from_domain or self.domain).lower().rstrip(".")
        if self.sp and target != self.org_domain and target.endswith("." + self.org_domain):
            return self.sp
        return self.p

    def to_dict(self) -> dict:
        return {
            "raw": self.raw, "domain": self.domain, "org_domain": self.org_domain,
            "is_org_policy": self.is_org_policy, "p": self.p, "sp": self.sp,
            "adkim": self.adkim, "aspf": self.aspf, "pct": self.pct,
            "rua": self.rua, "ruf": self.ruf, "fo": self.fo, "rf": self.rf,
            "ri": self.ri, "np": self.np, "psd": self.psd,
            "errors": self.errors, "warnings": self.warnings,
        }


def org_domain(domain: str) -> str:
    """Best-effort organizational domain (§3.2) without a full PSL."""
    d = domain.lower().rstrip(".")
    labels = d.split(".")
    if len(labels) <= 2:
        return d
    last2 = ".".join(labels[-2:])
    if last2 in MULTI_SUFFIXES:
        return ".".join(labels[-3:]) if len(labels) >= 3 else d
    return last2


def _parse_uri_list(value: str) -> list:
    return [u.strip() for u in value.split(",") if u.strip()]


def parse_dmarc(raw: str, domain: str, org_dom: str = "",
                is_org_policy: bool = False) -> DmarcRecord:
    if not raw.lower().startswith("v=dmarc1"):
        raise DmarcError("not a DMARC record (missing 'v=DMARC1')")
    rec = DmarcRecord(raw=raw, domain=domain,
                      org_domain=org_dom or org_domain(domain),
                      is_org_policy=is_org_policy)
    seen = set()
    for part in raw.split(";"):
        part = part.strip()
        if not part:
            continue
        m = _TAG_RE.match(part)
        if not m:
            rec.errors.append(f"malformed tag: '{part}'")
            continue
        k, v = m.group(1).lower(), m.group(2)
        if k in seen:
            rec.errors.append(f"duplicate tag '{k}'")
            continue
        seen.add(k)
        if k == "v":
            rec.version = v
        elif k == "p":
            rec.p = v.lower()
        elif k == "sp":
            rec.sp = v.lower()
        elif k == "np":
            rec.np = v.lower()
        elif k == "psd":
            rec.psd = v.lower()
        elif k == "adkim":
            rec.adkim = v.lower() if v.lower() in ("r", "s") else rec.adkim
            if v.lower() not in ("r", "s"):
                rec.errors.append(f"bad adkim value '{v}'")
        elif k == "aspf":
            rec.aspf = v.lower() if v.lower() in ("r", "s") else rec.aspf
            if v.lower() not in ("r", "s"):
                rec.errors.append(f"bad aspf value '{v}'")
        elif k == "pct":
            try:
                rec.pct = int(v)
                if not 0 <= rec.pct <= 100:
                    rec.errors.append(f"pct out of range: {v}")
            except ValueError:
                rec.errors.append(f"pct not an integer: '{v}'")
        elif k == "rua":
            rec.rua = _parse_uri_list(v)
        elif k == "ruf":
            rec.ruf = _parse_uri_list(v)
        elif k == "fo":
            rec.fo = v
        elif k == "rf":
            rec.rf = v
        elif k == "ri":
            try:
                rec.ri = int(v)
            except ValueError:
                rec.errors.append(f"ri not an integer: '{v}'")
        else:
            rec.warnings.append(f"unknown tag '{k}' (ignored per RFC 7489 §6.6.3)")

    if rec.version.lower() != "dmarc1":
        rec.errors.append(f"bad v= value: '{rec.version}'")
    if not rec.p:
        rec.errors.append("required tag 'p' is missing")
    elif rec.p not in POLICIES:
        rec.errors.append(f"invalid p= value: '{rec.p}'")
    if rec.sp and rec.sp not in POLICIES:
        rec.errors.append(f"invalid sp= value: '{rec.sp}'")
    if rec.np and rec.np not in POLICIES:
        rec.errors.append(f"invalid np= value: '{rec.np}'")
    if rec.rua:
        for uri in rec.rua:
            if not uri.lower().startswith(("mailto:", "https://")):
                rec.warnings.append(f"rua URI without mailto:/https:// scheme: '{uri}'")
    if rec.pct != 100 and rec.p in ("none",):
        rec.warnings.append("pct<100 with p=none has no effect")
    return rec


def _lookup(domain: str, org_dom: str):
    fqdn = f"_dmarc.{domain.rstrip('.')}"
    records = dnsx.smart_resolve(fqdn, "TXT")
    cands = [r.get("data", "") for r in (records or [])
             if r.get("data", "").lower().startswith("v=dmarc1")]
    if not records:
        return None, "no _dmarc record"
    if len(cands) > 1:
        return None, "multiple _dmarc TXT records (RFC 7489 §6.6.3 violation)"
    if not cands:
        return None, "_dmarc exists but is not a DMARC record"
    return cands[0], None


def fetch_dmarc(domain: str):
    """Returns (DmarcRecord|None, error|None). Implements §6.6.3 discovery:
    exact _dmarc.<domain> first, then _dmarc.<org-domain> on failure."""
    d = domain.lower().rstrip(".")
    org = org_domain(d)
    raw, err = _lookup(d, org)
    if raw:
        try:
            return parse_dmarc(raw, d, org, is_org_policy=False), None
        except DmarcError as exc:
            return None, str(exc)
    if org != d:
        raw2, _err2 = _lookup(org, org)
        if raw2:
            try:
                rec = parse_dmarc(raw2, org, org, is_org_policy=True)
                return rec, None
            except DmarcError as exc:
                return None, str(exc)
        return None, f"no DMARC at {d} nor at org domain {org}"
    return None, err or "no DMARC record"


def policy_strength(rec: DmarcRecord, from_domain: str = "") -> int:
    """0..100 score of how much the effective policy blocks spoofing."""
    pol = rec.effective_policy(from_domain)
    score = {"none": 15, "quarantine": 55, "reject": 85}.get(pol, 0)
    if rec.pct >= 100:
        score += 10
    elif rec.pct > 0:
        score += int(10 * rec.pct / 100)
    if rec.adkim == "s":
        score += 2
    if rec.aspf == "s":
        score += 2
    if rec.rua:
        score += 1
    return min(score, 100)
