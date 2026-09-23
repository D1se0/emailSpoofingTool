#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MailForge api.py — JSON bridge between the Node server and the Python core.

Protocol: `python3 api.py <action> [json-payload]` → prints exactly one line
starting with `##JSON##` followed by compact JSON. Any other stdout line is
considered diagnostics; stderr is for errors.

SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import dkim, dmarc, spf, scorer, hardening  # noqa: E402

JSON_PREFIX = "##JSON##"


def emit(obj) -> None:
    print(JSON_PREFIX + json.dumps(obj, ensure_ascii=False, default=str))


def _valid_domain(d: str) -> bool:
    import re
    return bool(re.match(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})*\.[a-z]{2,63}$",
                         d.lower().strip()))


def _out_of_domain_guard(domain: str, to: str) -> bool:
    return to.lower().rstrip(".") != domain.lower().rstrip(".") \
        and not to.lower().endswith("@" + domain.lower().rstrip("."))


def main() -> None:
    if len(sys.argv) < 2:
        emit({"error": "usage: api.py <action> [payload-json]"})
        return
    action = sys.argv[1]
    payload = {}
    if len(sys.argv) > 2:
        try:
            payload = json.loads(sys.argv[2])
        except json.JSONDecodeError:
            emit({"error": "payload is not valid JSON"})
            return

    try:
        if action == "analyze":
            domain = (payload.get("domain") or "").lower().strip()
            if not _valid_domain(domain):
                return emit({"error": "invalid domain"})
            emit(scorer.analyze_domain(domain).to_dict())

        elif action == "dkim":
            domain = (payload.get("domain") or "").lower().strip()
            if not _valid_domain(domain):
                return emit({"error": "invalid domain"})
            keys = dkim.guess_selectors(domain)
            emit({"domain": domain, "keys": [k.to_dict() for k in keys]})

        elif action == "harden":
            domain = (payload.get("domain") or "").lower().strip()
            if not _valid_domain(domain):
                return emit({"error": "invalid domain"})
            recs = hardening.generate_records(
                domain,
                spf_ips=[str(i) for i in (payload.get("ips") or [])][:20],
                dkim_selector=(payload.get("selector") or "s1").strip(),
                dmarc_policy=(payload.get("policy") or "reject"),
                rua=(payload.get("rua") or ""))
            emit({"domain": domain, "records": recs,
                  "postfix": hardening.generate_postfix_config(
                      domain, payload.get("selector") or "s1"),
                  "dkim_guide": hardening.generate_dkim_guide(
                      domain, payload.get("selector") or "s1")})

        elif action == "rollout":
            domain = (payload.get("domain") or "").lower().strip()
            if not _valid_domain(domain):
                return emit({"error": "invalid domain"})
            emit({"domain": domain,
                  "plan": hardening.generate_rollout_plan(
                      domain, payload.get("rua") or "")})

        elif action == "selftest":
            domain = (payload.get("domain") or "").lower().strip()
            to = (payload.get("to") or "").lower().strip()
            if not _valid_domain(domain):
                return emit({"error": "invalid domain"})
            if _out_of_domain_guard(domain, to):
                return emit({"error": "recipient outside analyzed domain",
                             "detail": "self-test is restricted to in-domain mailboxes"})
            emit(hardening.send_selftest(
                domain, to,
                smtp_host=(payload.get("smtp_host") or ""),
                dry_run=bool(payload.get("dry_run"))))

        elif action == "spooftest":
            domain = (payload.get("domain") or "").lower().strip()
            if not _valid_domain(domain):
                return emit({"error": "invalid domain"})
            to = (payload.get("to") or f"tu-buzon@{domain}").lower().strip()
            if _out_of_domain_guard(domain, to):
                return emit({"error": "recipient outside analyzed domain",
                             "detail": "el Spoof Lab solo apunta a buzones del dominio analizado"})
            preview = hardening.build_spoof_preview(
                domain,
                exec_name=(payload.get("exec_name") or "CEO").strip()[:60],
                motif=(payload.get("motif") or "invoice").strip()[:20])
            # Verdict prediction from LIVE posture (best-effort, offline-safe).
            verdict, basis = "desconocido", []
            try:
                drec, _e = dmarc.fetch_dmarc(domain)
                srec, _c, _e2 = spf.fetch_spf(domain)
                pol = drec.effective_policy() if drec else "missing"
                basis.append(f"DMARC p={pol}")
                basis.append(f"SPF all={srec.all_policy if srec else 'ausente'}")
                verdict = {"reject": "RECHAZADO (550) — p=reject activo",
                           "quarantine": "CUARENTENA/SPAM — p=quarantine activo",
                           "none": "BANDEJA DE ENTRADA — dominio suplantable ❗",
                           "missing": "BANDEJA DE ENTRADA — sin DMARC ❗"}.get(pol,
                           "indeterminado")
            except Exception as exc:
                basis.append(f"postura no disponible: {exc}")
            emit({"domain": domain, "to": to,
                  "message": preview["message"],
                  "profile": preview["profile"],
                  "predicted_verdict": verdict,
                  "posture_basis": basis,
                  "commands": hardening.generate_injection_commands(domain, to)})

        elif action == "compose":
            """Free-form spoof composer: any From/To/Subject/Text/attachments."""
            out = hardening.compose_spoof_email(
                from_name=(payload.get("from_name") or "").strip()[:120],
                from_email=(payload.get("from_email") or "").strip()[:254],
                to=(payload.get("to") or "").strip()[:254],
                subject=(payload.get("subject") or "").strip()[:998],
                text=str(payload.get("text") or "")[:100000],
                reply_to=(payload.get("reply_to") or "").strip()[:254],
                attachments=(payload.get("attachments") or [])[:10],
                priority=(payload.get("priority") or "normal").strip()[:8])
            out["commands"] = hardening.generate_freeform_commands(
                from_email=(payload.get("from_email") or "").strip()[:254],
                to=(payload.get("to") or "").strip()[:254],
                from_name=(payload.get("from_name") or "").strip()[:120],
                subject=(payload.get("subject") or "").strip()[:998],
                text=str(payload.get("text") or "")[:100000],
                reply_to=(payload.get("reply_to") or "").strip()[:254],
                attachments=(payload.get("attachments") or [])[:10],
                priority=(payload.get("priority") or "normal").strip()[:8],
                smtp_host=(payload.get("smtp_host") or "").strip()[:253])
            out["notice"] = ("⚠ USO EN ENTORNO CONTROLADO: dirige este mensaje "
                             "solo a buzones propios o con consentimiento "
                             "(simulacros de phishing autorizados).")
            emit(out)

        elif action == "swaks_send":
            """REAL send through installed swaks: user params → swaks argv."""
            from core import swaks_bridge
            atts = (payload.get("attachments") or [])[:10]
            out = swaks_bridge.swaks_send(
                from_name=(payload.get("from_name") or "").strip()[:120],
                from_email=(payload.get("from_email") or "").strip()[:254],
                to=(payload.get("to") or "").strip()[:254],
                subject=(payload.get("subject") or "").strip()[:998],
                text=str(payload.get("text") or "")[:100000],
                reply_to=(payload.get("reply_to") or "").strip()[:254],
                attachments=atts,
                priority=(payload.get("priority") or "normal").strip()[:8],
                smtp_host=(payload.get("smtp_host") or "").strip()[:253],
                smtp_port=int(payload.get("smtp_port") or 25) or 25,
                smtp_user=(payload.get("smtp_user") or "").strip()[:128],
                smtp_pass=str(payload.get("smtp_pass") or "")[:128],
                tls_mode=(payload.get("tls_mode") or "tls").strip()[:14],
                timeout=int(payload.get("timeout") or 45))
            emit(out)

        elif action == "drill_send":
            domain = (payload.get("domain") or "").lower().strip()
            to = (payload.get("to") or "").lower().strip()
            if not _valid_domain(domain):
                return emit({"error": "invalid domain"})
            if _out_of_domain_guard(domain, to):
                return emit({"error": "recipient outside analyzed domain",
                             "detail": "el envío real solo apunta a buzones del dominio analizado"})
            emit(hardening.send_spoof_drill(
                domain, to,
                exec_name=(payload.get("exec_name") or "CEO").strip()[:60],
                motif=(payload.get("motif") or "invoice").strip()[:20],
                smtp_host=(payload.get("smtp_host") or "").strip()[:253],
                smtp_port=int(payload.get("smtp_port") or 0) or 25,
                smtp_user=(payload.get("smtp_user") or "").strip()[:128],
                smtp_pass=str(payload.get("smtp_pass") or "")[:128],
                helo_name=(payload.get("helo") or "drill.mailforge.local").strip()[:253]))

        elif action == "drill_check":
            emit(hardening.check_drill_arrival(
                (payload.get("imap_host") or "").strip()[:253],
                (payload.get("imap_user") or "").strip()[:254],
                str(payload.get("imap_pass") or "")[:128],
                wait_seconds=int(payload.get("wait_seconds") or 0),
                port=int(payload.get("imap_port") or 993)))

        elif action == "verify":
            raw = payload.get("raw") or ""
            if not raw or len(raw) > 1024 * 1024:
                return emit({"error": "raw email required (max 1MB)"})
            raw_bytes = raw.encode("utf-8", "replace") if "\r\n" not in raw \
                else raw.encode("utf-8", "replace")
            results = []
            import re as _re
            sig_values = _re.findall(
                r"DKIM-Signature:\s*([^\r\n]*(?:\r\n[ \t][^\r\n]*)*)",
                raw, flags=_re.IGNORECASE)
            for sv in sig_values[:5]:
                sig = dkim.parse_dkim_header(" ".join(
                    ln.strip() for ln in sv.splitlines()))
                if not sig.domain or not sig.selector:
                    results.append({"domain": sig.domain, "selector": sig.selector,
                                    "valid": False, "reason": "missing d=/s="})
                    continue
                key, _raw, err = dkim.fetch_dkim_key(sig.selector, sig.domain)
                if key is None:
                    results.append({"domain": sig.domain, "selector": sig.selector,
                                    "valid": False, "reason": f"key lookup failed: {err}"})
                    continue
                results.append(dkim.verify_dkim(raw_bytes, sig, key))
            emit({"signatures_checked": len(results), "results": results})

        else:
            emit({"error": f"unknown action '{action}'"})
    except Exception as exc:  # noqa: BLE001
        emit({"error": f"{type(exc).__name__}: {exc}"})


if __name__ == "__main__":
    main()
