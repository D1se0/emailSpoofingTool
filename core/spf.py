#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MailForge Core — SPF (RFC 7208) parser + evaluator.

Parses an SPF record into a typed model and evaluates which mechanisms
would authorize an arbitrary (ip4/ip6) sender or the 'all'-catch behaviour.

SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from . import dnsx

__all__ = ["SpfMech", "SpfRecord", "parse_spf", "SpfError", "fetch_spf"]

SPF_PREFIX = "v=spf1"
_MECH_RE = re.compile(
    r"^(?P<q>[-~+?])?(?P<m>ip4|ip6|include|redirect|exists|ptr|exp|mx|all|a)"
    r"(?P<sep>[:=])?(?P<val>[^\s]*)$", re.IGNORECASE)


class SpfError(Exception):
    """The TXT record is not a valid SPF record."""


@dataclass
class SpfMech:
    qualifier: str            # '', '+', '-', '~', '?'
    kind: str                 # ip4, ip6, a, mx, ptr, exists, include, redirect, exp, all
    value: str = ""
    count_lookups: int = 0    # RFC 7208 §4.6.4 (10-lookup budget)


@dataclass
class SpfRecord:
    raw: str = ""
    domain: str = ""
    mechanisms: list = field(default_factory=list)
    modifiers: dict = field(default_factory=dict)
    lookup_count: int = 0
    all_policy: str = ""      # -all, ~all, ?all, +all or '' when absent
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    dns_lookups: int = 0      # consumed budget

    def has_mechanism(self, kind: str) -> bool:
        return any(m.kind.lower() == kind for m in self.mechanisms)


def parse_spf(raw: str, domain: str = "", follow_redirect: bool = False,
              _depth: int = 0) -> SpfRecord:
    if not raw or not raw.lower().startswith(SPF_PREFIX):
        raise SpfError("not an SPF record (missing 'v=spf1')")
    rec = SpfRecord(raw=raw, domain=domain)
    tokens = raw.split()[1:]
    if not tokens:
        rec.errors.append("SPF record contains no mechanisms")
        return rec

    seen_redirect = False
    for tok in tokens:
        m = _MECH_RE.match(tok)
        if not m:
            rec.errors.append(f"unparsable token: '{tok}'")
            continue
        q = m.group("q") or "+"
        kind = m.group("m").lower()
        sep = m.group("sep") or ""
        val = m.group("val") or ""

        if kind in ("redirect", "exp"):
            if sep != "=":
                rec.errors.append(f"modifier '{kind}' must use '=' (got '{tok}')")
                continue
            if kind == "redirect":
                if seen_redirect:
                    rec.errors.append("duplicate 'redirect' modifier")
                seen_redirect = True
                rec.lookup_count += 1
            rec.modifiers[kind] = val
            continue

        if sep == "=":
            rec.errors.append(f"unknown modifier '{kind}' treated as mechanism")
            continue

        mech = SpfMech(qualifier=q, kind=kind, value=val)
        if kind == "ip4":
            if not val or "/" not in val and not _is_ipv4(val):
                rec.errors.append(f"bad ip4 mechanism: '{tok}'")
        elif kind == "ip6":
            if not val:
                rec.errors.append(f"bad ip6 mechanism: '{tok}'")
        elif kind in ("a", "mx"):
            rec.lookup_count += 1
        elif kind == "ptr":
            rec.lookup_count += 1
            rec.warnings.append("'ptr' mechanism is slow and discouraged by RFC 7208 §5.5")
        elif kind == "exists":
            rec.lookup_count += 1
        elif kind == "include":
            if not val:
                rec.errors.append("'include' without domain")
            rec.lookup_count += 1
        elif kind == "all":
            if val:
                rec.errors.append("'all' takes no value")
            rec.all_policy = q + "all"
        rec.mechanisms.append(mech)

    if not rec.all_policy and "redirect" not in rec.modifiers:
        rec.warnings.append("no 'all' mechanism and no redirect: implicit '+all' "
                            "(ANY server on the Internet may spoof this domain!)")

    # ip4/ip6 duplicated entries (informational only)
    ips = [m.value for m in rec.mechanisms if m.kind == "ip4"]
    if len(ips) != len(set(ips)):
        rec.warnings.append("duplicated ip4 entries")

    # RFC 7208 §6.1: redirect to the referenced SPF record when 'all' absent.
    if (follow_redirect and _depth < 5 and not rec.all_policy
            and rec.modifiers.get("redirect")):
        target = rec.modifiers["redirect"]
        try:
            sub, _c, err = fetch_spf(target)
            if sub is not None:
                sub.lookup_count += rec.lookup_count
                sub.domain = domain
                sub.raw = f"{raw} (redirect→{target}) " \
                          f"+ {sub.raw[:120]}"
                return sub
        except Exception:
            pass
    return rec


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def fetch_spf(domain: str) -> tuple:
    """Returns (spf_record_or_None, all_txt_candidates, error_string_or_None)."""
    candidates, err = [], None
    try:
        txts = dnsx.smart_resolve(domain, "TXT")
    except Exception as exc:            # network level failure
        return None, [], str(exc)
    if not txts:
        err = f"no TXT records for '{domain}' (SPF absent)"
        return None, [], err
    for r in txts:
        data = r.get("data", "")
        if data.lower().startswith(SPF_PREFIX):
            candidates.append(data)
    if len(candidates) > 1:
        return None, candidates, "multiple SPF records (RFC 7208 §3.2 → PERMERROR)"
    if not candidates:
        return None, [], "no v=spf1 record found"
    try:
        return parse_spf(candidates[0], domain, follow_redirect=True), [], None
    except SpfError as exc:
        return None, candidates, str(exc)


def evaluate_authorization(rec: SpfRecord, ip: str = "") -> dict:
    """Static evaluation: would this IP (or 'any' when empty) pass SPF?"""
    result = {"ip": ip or "ANY", "verdict": "fail", "matched_by": None}
    for mech in rec.mechanisms:
        hit = False
        if mech.kind == "all":
            hit = True
        elif mech.kind == "ip4" and ip and "." in ip:
            hit = _ip_in(mech.value, ip)
        elif mech.kind == "ip6" and ip and ":" in ip:
            hit = _ip_in(mech.value, ip)
        elif mech.kind in ("a", "mx") and ip:
            hit = None   # requires live resolution; reported as 'dynamic'
        if hit is True:
            result["verdict"] = {"+": "pass", "-": "fail",
                                 "~": "softfail", "?": "neutral"}[mech.qualifier]
            result["matched_by"] = f"{mech.qualifier}{mech.kind}:{mech.value}".rstrip(":")
            return result
    if "redirect" in rec.modifiers:
        result["verdict"] = "redirect"
        result["matched_by"] = f"redirect={rec.modifiers['redirect']}"
    return result


def _ip_in(net: str, ip: str) -> bool:
    try:
        if "." in ip:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(
                net if "/" in net else net + "/32", strict=False)
        return ipaddress.ip_address(ip) in ipaddress.ip_network(
            net if "/" in net else net + "/128", strict=False)
    except ValueError:
        return False
