#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MailForge Core — Vulnerability scoring engine + attack-vector simulation.

Computes a 0-100 risk score (0 = bullet-proof, 100 = trivially spoofable)
by combining DNS posture (SPF/DKIM/DMARC/DNSSEC/MTA-STS/STARTTLS) with a
per-vector feasibility simulation. No email is sent in this phase.

SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import dnsx, dkim, dmarc, spf

__all__ = ["Vector", "AnalysisResult", "analyze_domain", "WEIGHTS"]

WEIGHTS = {"spf": 0.20, "dkim": 0.10, "dmarc": 0.40, "dnssec": 0.10,
           "tls": 0.10, "misc": 0.10}


@dataclass
class Vector:
    name: str
    description: str
    feasible: bool = False
    likelihood: int = 0      # 0-100
    notes: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "description": self.description,
                "feasible": self.feasible, "likelihood": self.likelihood,
                "notes": self.notes}


@dataclass
class AnalysisResult:
    domain: str = ""
    scanned_at: str = ""
    score: int = 0
    grade: str = "?"
    summary: str = ""
    spf: dict = field(default_factory=dict)
    dkim: dict = field(default_factory=dict)
    dmarc: dict = field(default_factory=dict)
    dnssec: dict = field(default_factory=dict)
    mx: list = field(default_factory=list)
    starttls: dict = field(default_factory=dict)
    mta_sts: dict = field(default_factory=dict)
    tls_rpt: dict = field(default_factory=dict)
    bimi: dict = field(default_factory=dict)
    vectors: list = field(default_factory=list)
    findings: list = field(default_factory=list)   # {severity, title, detail}
    recommendations: list = field(default_factory=list)

    def to_dict(self) -> dict:
        spf_out = {k: v for k, v in self.spf.items() if k != "record"}
        if self.spf.get("record") is not None:
            r = self.spf["record"]
            spf_out["record"] = {"raw": r.raw, "all_policy": r.all_policy,
                                 "lookup_count": r.lookup_count,
                                 "errors": r.errors, "warnings": r.warnings,
                                 "mechanisms": [
                                     {"qualifier": m.qualifier, "kind": m.kind,
                                      "value": m.value} for m in r.mechanisms]}
        dmarc_out = {k: v for k, v in self.dmarc.items() if k != "record"}
        if self.dmarc.get("record") is not None:
            dmarc_out["record"] = self.dmarc["record"].to_dict()
        return {
            "domain": self.domain, "scanned_at": self.scanned_at,
            "score": self.score, "grade": self.grade, "summary": self.summary,
            "spf": spf_out, "dkim": self.dkim, "dmarc": dmarc_out,
            "dnssec": self.dnssec, "mx": self.mx, "starttls": self.starttls,
            "mta_sts": self.mta_sts, "tls_rpt": self.tls_rpt,
            "bimi": self.bimi,
            "vectors": [v.to_dict() for v in self.vectors],
            "findings": self.findings,
            "recommendations": self.recommendations,
        }


def _add_finding(findings: list, severity: str, title: str, detail: str) -> None:
    findings.append({"severity": severity, "title": title, "detail": detail})


def _sim_vectors(res: AnalysisResult) -> None:
    """Fill res.vectors with per-attack feasibility estimates."""
    spf_rec = res.spf.get("record")
    dmarc_rec = res.dmarc.get("record")
    spf_none = res.spf.get("status") == "missing"
    spf_weak_all = bool(spf_rec) and spf_rec.all_policy in ("+all", "?all")
    spf_soft = bool(spf_rec) and spf_rec.all_policy == "~all"
    spf_hard = bool(spf_rec) and spf_rec.all_policy == "-all"
    dm_missing = res.dmarc.get("status") == "missing"
    dm_none = bool(dmarc_rec) and dmarc_rec.effective_policy() == "none"
    dm_quar = bool(dmarc_rec) and dmarc_rec.effective_policy() == "quarantine"
    dm_reject = bool(dmarc_rec) and dmarc_rec.effective_policy() == "reject"
    dkim_ok = res.dkim.get("status") == "found" and res.dkim.get("keys_found", 0) > 0

    # Direct alignment spoof: attacker owns unrelated domain, passes its own SPF.
    direct = dm_missing or dm_none
    res.vectors.append(Vector(
        "Direct spoof (unaligned From)",
        "Attacker sends from their own domain with correct SPF/DKIM but a "
        "display name or From that mimics yours. DMARC p=none/missing lets "
        "it land in the inbox.",
        feasible=direct,
        likelihood=95 if dm_missing else 80 if dm_none else 15,
        notes="blocked by DMARC alignment" if not direct else ""))

    # Exact-domain spoof with no envelope alignment (fail SPF on your domain).
    exact = spf_none or spf_weak_all
    if dm_reject:
        exact = False
    elif dm_quar:
        exact = spf_none or spf_weak_all   # still delivers, quarantined
    res.vectors.append(Vector(
        "Exact-domain spoof (SPF fail path)",
        "Envelope sender @yourdomain from attacker IP; relies on weak/absent "
        "SPF. DMARC p=reject stops it only when alignment fails AND policy is hard.",
        feasible=exact,
        likelihood=90 if spf_none and dm_missing else
                   75 if spf_weak_all and (dm_missing or dm_none) else
                   40 if spf_soft and (dm_missing or dm_none) else
                   15 if dm_quar else 0,
        notes=f"spf all={spf_rec.all_policy if spf_rec else '∅'}"))

    # Lookalike domain registration.
    lookalike = True   # always possible; only mitigations differ
    res.vectors.append(Vector(
        "Lookalike domain (typosquat/homoglyph)",
        "Attacker registers yourdomain.co / yourcomany.com / IDN homoglyph "
        "and sends with perfect SPF+DKIM+DMARC from that domain. Technical "
        "controls cannot block it; only brand monitoring and user training do.",
        feasible=lookalike, likelihood=45,
        notes="mitigate: register key lookalikes, BIMI/VMC, user awareness"))

    # DKIM replay / l= abuse.
    replay = dkim_ok and (dm_missing or dm_none)
    res.vectors.append(Vector(
        "DKIM replay attack",
        "A legitimately signed message (e.g. newsletter) is re-sent to "
        "thousands of other recipients, staying DKIM-valid. Signatures "
        "covering few headers and long expiry (x=) enable this.",
        feasible=replay, likelihood=35 if replay else 5,
        notes="mitigate: DMARC reject, ARC, short x=, full h= coverage"))

    # Null reverse-path (bounce) spoofing.
    bouncer = spf_hard is False or (dm_missing or dm_none)
    res.vectors.append(Vector(
        "Null reverse-path spoofing (bounces)",
        "MAIL FROM:<> cannot be SPF-'included'; attackers abuse DSN messages "
        "to inject content. p=reject on aligned From still applies to the "
        "display headers.",
        feasible=bouncer, likelihood=25 if bouncer else 5,
        notes="mitigate: reject@ alignment + p=reject"))

    # Subdomain abuse when only sp=none.
    subd = bool(dmarc_rec) and bool(dmarc_rec.sp) and dmarc_rec.sp == "none"
    subd_missing = dm_missing
    res.vectors.append(Vector(
        "Subdomain escape",
        "spoof.yourdomain.com inherits nothing if DMARC uses sp=none or no "
        "org-level policy exists. Attacker mails from unguarded subdomains.",
        feasible=subd or subd_missing,
        likelihood=80 if subd_missing else 60 if subd else 10,
        notes=f"sp={dmarc_rec.sp if dmarc_rec else '∅'}"))

    # Display-name impersonation (always feasible technically).
    res.vectors.append(Vector(
        "Display-name impersonation",
        '"CE0 of Company <attacker@evil.test>" renders as the CEO in many '
        "clients. No protocol prevents it; detection is heuristic.",
        feasible=True, likelihood=30,
        notes="mitigate: mark verified senders with BIMI, train users"))

    # Server-side transport downgrade.
    sts = res.mta_sts.get("present", False)
    tls_status = res.starttls.get("status", "unknown")
    tls_weak = (tls_status == "no-starttls") or (tls_status != "verified" and not sts)
    res.vectors.append(Vector(
        "STARTTLS downgrade / MITM",
        "Without MTA-STS or DANE, an active attacker can strip STARTTLS on "
        "the wire and read/reset the SMTP session.",
        feasible=tls_weak,
        likelihood=65 if tls_status == "no-starttls" else
                   35 if not sts else 0,
        notes=f"MTA-STS={'on' if sts else 'off'} · probe={tls_status}"))

    return


def _spf_sub_status(res: AnalysisResult, domain: str) -> dict:
    rec, cands, err = spf.fetch_spf(domain)
    status = "found" if rec else ("multiple" if cands and not rec else "missing")
    lookups = rec.dns_lookups if rec else 0
    include_depth = 0
    if rec:
        include_depth = sum(1 for m in rec.mechanisms if m.kind == "include")
        rec.dns_lookups = rec.lookup_count
    out = {"status": status, "raw": rec.raw if rec else (cands[0] if cands else ""),
           "record": rec, "candidates": cands, "error": err,
           "lookup_count": rec.lookup_count if rec else 0,
           "all_policy": rec.all_policy if rec else "",
           "uses_ptr": rec.has_mechanism("ptr") if rec else False,
           "uses_include": include_depth}
    return out


def _mx_starttls(res: AnalysisResult, domain: str) -> None:
    mxs = dnsx.smart_resolve(domain, "MX")
    entries = []
    for r in (mxs or []):
        data = (r.get("data") or "").strip().rstrip(".")
        if not data:
            continue
        # DoH JSON gives MX as "<pref> <host>"; wire parser adds "pref" key.
        if "pref" in r:
            pref, host = r.get("pref", 0), data
        else:
            parts = data.split(None, 1)
            try:
                pref, host = int(parts[0]), (parts[1] if len(parts) > 1 else "")
            except (ValueError, IndexError):
                pref, host = 0, data
        if host:
            entries.append({"pref": pref, "host": host.rstrip(".")})
    seen = set()
    res.mx = [e for e in sorted(entries, key=lambda x: (x["pref"], x["host"]))
              if not (e["host"] in seen or seen.add(e["host"]))]

    supported, checked, errors = 0, 0, 0
    certs = []
    import socket as _s
    import ssl as _ssl
    for entry in res.mx[:3]:
        host = entry["host"]
        if not host:
            continue
        checked += 1
        try:
            ctx = _ssl.create_default_context()
            with _s.create_connection((host, 25), timeout=4) as sock:
                banner = sock.recv(256).decode("utf-8", "replace")[:80]
                sock.sendall(b"EHLO probe.mailforge.local\r\n")
                _ehlo = sock.recv(4096).decode("utf-8", "replace").lower()
                if "starttls" in _ehlo:
                    sock.sendall(b"STARTTLS\r\n")
                    _ans = sock.recv(256).decode("utf-8", "replace")
                    if _ans.startswith("220"):
                        with ctx.wrap_socket(sock, server_hostname=host) as tls:
                            cert = tls.getpeercert()
                            certs.append({"host": host, "subject": dict(
                                x[0] for x in cert.get("subject", [])),
                                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                                "notAfter": cert.get("notAfter")})
                            supported += 1
                            break
                sock.sendall(b"QUIT\r\n")
        except (OSError, _ssl.SSLError, ValueError):
            errors += 1
            entry["probe_error"] = "unreachable or filtered (port 25)"
    if checked == 0:
        status = "no-mx"
    elif supported:
        status = "verified"
    elif errors == checked:
        status = "unknown"      # could not reach any MX (egress filtering)
    else:
        status = "no-starttls"
    res.starttls = {"status": status, "supported": supported > 0,
                    "hosts_checked": checked, "hosts_supported": supported,
                    "certs": certs}


def _misc_checks(res: AnalysisResult, domain: str) -> None:
    # MTA-STS
    sts_txt = dnsx.resolve_doh(f"_mta-sts.{domain}", "TXT") or \
        dnsx.resolve(f"_mta-sts.{domain}", "TXT")
    sts_pol = (dnsx.resolve_doh(f"mta-sts.{domain}", "TXT") or [])
    policy_text = ""
    try:
        import urllib.request
        with urllib.request.urlopen(
                f"https://mta-sts.{domain}/.well-known/mta-sts.txt", timeout=6) as r:
            policy_text = r.read().decode("utf-8", "replace")[:2048]
    except Exception:
        policy_text = ""
    rec = next((r["data"] for r in (sts_txt or []) if "v=STSv1" in r["data"]), "")
    res.mta_sts = {"present": bool(rec), "raw": rec, "policy_https": bool(policy_text),
                   "policy": policy_text}

    # TLS-RPT
    rpt = dnsx.resolve_doh(f"_smtp._tls.{domain}", "TXT") or \
        dnsx.resolve(f"_smtp._tls.{domain}", "TXT")
    raw = next((r["data"] for r in (rpt or []) if "v=TLSRPTv1" in r["data"]), "")
    res.tls_rpt = {"present": bool(raw), "raw": raw}

    # BIMI
    bimi = dnsx.resolve_doh(f"default._bimi.{domain}", "TXT") or \
        dnsx.resolve(f"default._bimi.{domain}", "TXT")
    raw = next((r["data"] for r in (bimi or []) if "v=BIMI1" in r["data"]), "")
    res.bimi = {"present": bool(raw), "raw": raw}

    # DNSSEC
    ds = dnsx.dnssec_status(domain)
    res.dnssec = ds


def _score(res: AnalysisResult) -> None:
    s_spf, s_dkim, s_dm, s_dns, s_tls, s_misc = 0, 0, 0, 0, 0, 0
    rec = res.spf.get("record")
    if res.spf.get("status") == "found" and rec:
        s_spf = 100
        if rec.all_policy == "-all":
            s_spf = 100
        elif rec.all_policy == "~all":
            s_spf = 70
        elif rec.all_policy in ("+all", "?all"):
            s_spf = 5
        if rec.errors:
            s_spf -= 15 * len(rec.errors)
        if rec.lookup_count > 10:
            s_spf -= 10
        if res.spf.get("uses_ptr"):
            s_spf -= 5
        s_spf = max(s_spf, 0)

    s_dkim = min(100, 45 * res.dkim.get("keys_found", 0))
    if res.dkim.get("weak_keys"):
        s_dkim -= 10 * res.dkim["weak_keys"]
    if res.dkim.get("revoked_keys"):
        s_dkim += 5
    s_dkim = max(0, min(s_dkim, 100))

    drec = res.dmarc.get("record")
    if drec:
        s_dm = dmarc.policy_strength(drec)
        if drec.errors:
            s_dm -= 10 * len(drec.errors)
        s_dm = max(s_dm, 0)
    elif res.dmarc.get("status") == "missing":
        s_dm = 0

    s_dns = 100 if res.dnssec.get("signed") else 0
    tls_status = res.starttls.get("status", "unknown")
    if tls_status == "verified":
        s_tls = 70 if not res.mta_sts.get("present") else 95
        if res.tls_rpt.get("present"):
            s_tls = min(100, s_tls + 5)
    elif tls_status in ("unknown", "no-mx"):
        s_tls = 50 if res.mta_sts.get("present") else 30
    else:
        s_tls = 0
    s_misc = (55 if res.mta_sts.get("present") else 0) + \
             (25 if res.tls_rpt.get("present") else 0) + \
             (20 if res.bimi.get("present") else 0)
    s_misc = min(s_misc, 100)

    total = (s_spf * WEIGHTS["spf"] + s_dkim * WEIGHTS["dkim"] +
             s_dm * WEIGHTS["dmarc"] + s_dns * WEIGHTS["dnssec"] +
             s_tls * WEIGHTS["tls"] + s_misc * WEIGHTS["misc"])
    res.score = int(round(total))


GRADES = [(85, "A", "Muy protegido"), (70, "B", "Protegido con huecos"),
          (50, "C", "Vulnerable parcial"), (25, "D", "Vulnerable"),
          (0, "F", "Críticamente vulnerable")]


def _grade(score: int):
    for floor, letter, label in GRADES:
        if score >= floor:
            return letter, label
    return "F", "Críticamente vulnerable"


def _recommend(res: AnalysisResult) -> None:
    rec = res.spf.get("record")
    if res.spf.get("status") != "found":
        res.recommendations.append("Publica un registro SPF con '-all' final.")
    elif rec and rec.all_policy != "-all":
        res.recommendations.append("Endurece SPF: migra a '-all' (usa 'v=spf1 ... -all').")
    if rec and rec.lookup_count > 8:
        res.recommendations.append(f"SPF usa {rec.lookup_count} lookups (límite 10): aplanar includes.")
    if not res.dkim.get("keys_found"):
        res.recommendations.append("Publica claves DKIM (2 selectores: rotación) y firma salientes.")
    drec = res.dmarc.get("record")
    if not drec:
        res.recommendations.append("Publica DMARC: 'v=DMARC1; p=quarantine; rua=mailto:...'")
    elif drec.effective_policy() == "none":
        res.recommendations.append("Sube DMARC de p=none a p=quarantine (pct=25 → 100) y luego p=reject.")
    elif drec.effective_policy() == "quarantine" and drec.pct < 100:
        res.recommendations.append(f"Aumenta pct={drec.pct} → 100 antes de pasar a p=reject.")
    if not res.dnssec.get("signed"):
        res.recommendations.append("Habilita DNSSEC en tu zona DNS (registrar + KSK DS).")
    if not res.mta_sts.get("present"):
        res.recommendations.append("Publica MTA-STS (TXT _mta-sts + https policy) para forzar TLS.")
    if not res.tls_rpt.get("present"):
        res.recommendations.append("Publica TLS-RPT para recibir informes de fallos TLS.")
    if not res.bimi.get("present"):
        res.recommendations.append("Considera BIMI+VMC para mostrar tu logo verificado.")
    if not res.recommendations:
        res.recommendations.append("Postura excelente: mantén rotación DKIM y monitoriza informes DMARC.")


def analyze_domain(domain: str, deep_dkim: bool = True) -> AnalysisResult:
    """Full passive analysis. Never sends email."""
    import datetime
    res = AnalysisResult(domain=domain.lower().rstrip("."),
                         scanned_at=datetime.datetime.now(
                             datetime.timezone.utc).isoformat())

    res.spf = _spf_sub_status(res, domain)
    if res.spf.get("record"):
        _r = res.spf["record"]
        _add_finding(res.findings, "ok" if _r.all_policy == "-all" else
                     ("low" if _r.all_policy == "~all" else "high"),
                     f"SPF: {_r.all_policy or 'sin all'}",
                     _r.raw[:160])

    # DKIM discovery (collapse wildcard answers: same TXT for every selector)
    keys = dkim.guess_selectors(domain) if deep_dkim else []
    unique = {}
    for k in keys:
        unique.setdefault(k.raw, k)
    if len(unique) == 1 and next(iter(unique.values())).revoked and len(keys) > 2:
        wild = next(iter(unique.values()))
        res.dkim = {"status": "wildcard-empty", "keys_found": 0,
                    "keys": [wild.to_dict()], "weak_keys": 0,
                    "revoked_keys": len(keys),
                    "note": ("wildcard DNS: cualquier selector devuelve 'p=' vacío; "
                             "no hay firma DKIM real")}
        _add_finding(res.findings, "medium", "DKIM wildcard con clave vacía",
                     "Cualquier selector responde 'v=DKIM1; p=' — no hay claves "
                     "reales; publica selectores firmantes y elimina el wildcard.")
    else:
        keys = list(unique.values())
        weak = [k for k in keys if k.weak_bits and k.weak_bits < 2048]
        revoked = [k for k in keys if k.revoked]
        res.dkim = {"status": "found" if any(not k.revoked for k in keys)
                    else ("only-revoked" if keys else "not-found"),
                    "keys_found": len([k for k in keys if not k.revoked]),
                    "keys": [k.to_dict() for k in keys],
                    "weak_keys": len(weak), "revoked_keys": len(revoked)}

    drec, derr = dmarc.fetch_dmarc(domain)
    res.dmarc = {"status": "found" if drec else "missing", "record": drec,
                 "error": derr, "raw": drec.raw if drec else "",
                 "score": dmarc.policy_strength(drec) if drec else 0}
    if drec:
        _add_finding(res.findings, "ok" if drec.effective_policy() == "reject"
                     else ("medium" if drec.effective_policy() == "quarantine" else "high"),
                     f"DMARC: p={drec.effective_policy()} pct={drec.pct}",
                     drec.raw[:160])
    else:
        _add_finding(res.findings, "critical", "DMARC ausente",
                     "Cualquier tercero puede suplantar este dominio con alineación fallida.")

    _misc_checks(res, domain)
    _mx_starttls(res, domain)
    _sim_vectors(res)
    _score(res)
    res.grade, res.summary = _grade(res.score)
    _recommend(res)
    return res
