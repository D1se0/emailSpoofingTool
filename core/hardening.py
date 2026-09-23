#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MailForge Core — Defensive hardening generator.

Given a domain's analysis, produces copy-paste-ready DNS records, Postfix
config, OpenDKIM setup, DKIM key generation guidance and a phased DMARC
rollout plan. Also generates an *authorized* self-test email to a single
in-domain mailbox so the owner can observe DMARC reporting live.

SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import base64
import os
import secrets
import smtplib
import socket
import textwrap
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

__all__ = ["generate_records", "generate_postfix_config", "generate_dkim_guide",
           "generate_rollout_plan", "build_selftest_message", "send_selftest"]


def generate_records(domain: str, spf_ips: list = None, dkim_selector: str = "s1",
                     dmarc_policy: str = "reject", pct: int = 100,
                     rua: str = "", mta_sts_id: str = None,
                     tls_rpt_mail: str = "") -> list:
    """Return list of {type, name, value, ttl, note} DNS records to publish."""
    spf_ips = spf_ips or []
    recs = []
    spf_mechs = " ".join(f"ip4:{ip}" for ip in spf_ips if ":" not in ip)
    spf_mechs += " " + " ".join(f"ip6:{ip}" for ip in spf_ips if ":" in ip)
    spf_val = f"v=spf1 {spf_mechs} mx a -all".replace("  ", " ").strip()
    recs.append({"type": "TXT", "name": domain, "ttl": 3600, "value": spf_val,
                 "note": "SPF: autoriza TU infraestructura; '-all' rechaza el resto."})

    recs.append({"type": "TXT", "name": f"{dkim_selector}._domainkey.{domain}",
                 "ttl": 3600,
                 "value": "v=DKIM1; k=rsa; p=<CLAVE_PUBLICA_DEL_PASO_DKIM>",
                 "note": "Sustituye por la p= real tras generar el par (ver guía DKIM)."})

    rua_tag = f"rua=mailto:{rua}" if rua else "rua=mailto:dmarc-reports@" + domain
    pct_tag = f"; pct={pct}" if pct < 100 else ""
    recs.append({"type": "TXT", "name": f"_dmarc.{domain}", "ttl": 3600,
                 "value": f"v=DMARC1; p={dmarc_policy}; sp=reject; adkim=s; aspf=s; "
                          f"{rua_tag}; ruf=mailto:{rua or 'dmarc-forensic@' + domain}; "
                          f"fo=1{pct_tag}",
                 "note": "DMARC estricto (alineación) con informes agregados+forenses."})

    sts_id = mta_sts_id or ("sts" + secrets.token_hex(4))
    recs.append({"type": "TXT", "name": f"_mta-sts.{domain}", "ttl": 3600,
                 "value": f"v=STSv1; id={sts_id}",
                 "note": "MTA-STS: cambia el id en cada actualización de la policy."})
    recs.append({"type": "TXT", "name": f"_smtp._tls.{domain}", "ttl": 3600,
                 "value": (f"v=TLSRPTv1; rua=mailto:{tls_rpt_mail}"
                           if tls_rpt_mail else
                           f"v=TLSRPTv1; rua=mailto:tls-reports@{domain}"),
                 "note": "TLS-RPT: informes diarios de fallos TLS de otros MTA."})
    recs.append({"type": "A", "name": f"mta-sts.{domain}", "ttl": 86400,
                 "value": "<IP_DEL_HOST_QUE_SIRVE_LA_POLICY_HTTPS>",
                 "note": "Debe servir https://mta-sts.DOMINIO/.well-known/mta-sts.txt"})
    return recs


MTA_STS_POLICY = """version: STSv1
mode: enforce
mx: {mx}
max_age: 86400
"""


def generate_postfix_config(domain: str, dkim_selector: str = "s1") -> str:
    return textwrap.dedent(f"""\
    # ── /etc/postfix/main.d/main.cf (fragmento anti-spoofing saliente) ──
    # DKIM firmado por OpenDKIM en el puerto 8891
    milter_default_action   = accept
    milter_protocol         = 6
    smtpd_milters           = inet:localhost:8891
    non_smtpd_milters       = $smtpd_milters

    # Rechazar correo entrante que falla SPF/DKIM/DMARC (policyd-spf + opendmarc)
    smtpd_recipient_restrictions =
        permit_mynetworks,
        permit_sasl_authenticated,
        reject_unauth_destination,
        check_policy_service unix:private/policyd-spf,
        reject_unauth_pipelining

    smtpd_milter_maps       = unix:/etc/postfix/dmarc-milter.map
    # /etc/postfix/dmarc-milter.map:
    #   {domain}    inet:localhost:8893   # OpenDMARC en modo reject
    #   *           inet:localhost:8893

    # Evitar que NUESTRO servidor reenvíe spoofing (open-relay = desenfrenado)
    smtpd_sender_restrictions =
        permit_mynetworks,
        reject_sender_login_mismatch,
        reject_unauthenticated

    # TLS obligatorio hacia fuera (complementa MTA-STS)
    smtp_tls_security_level = may
    smtp_tls_note_starttls_offer = yes
    smtp_dns_support_level  = dnssec
    smtp_host_lookup        = dns

    # Registro de cabeceras Received firmadas (ARC si usas OpenARC)
    # header_checks para marcar suplantación interna:
    smtpd_forbid_unauth_pipe destinations = $mydestination

    # ── /etc/opendkim.conf ──
    # Syslog          yes
    # Domain          {domain}
    # Selector        {dkim_selector}
    # KeyFile         /etc/opendkim/keys/{domain}/{dkim_selector}.private
    # Socket          inet:8891@localhost
    # InternalHosts   refile:/etc/opendkim/TrustedHosts
    # Mode            sv        # firmar y verificar
    # SubDomains      no
    # Canonicalization relaxed/relaxed
    # OversignHeaders From,Subject,Date,Message-ID,To,MIME-Version,List-Id
    """)


def generate_dkim_guide(domain: str, selector: str = "s1") -> str:
    return textwrap.dedent(f"""\
    ══ Rotación / generación de claves DKIM — {domain} ══

    1) Genera un par RSA-2048 (o Ed25519) nuevo — NUNCA reutilices claves >1 año:

       # RSA 2048 (compatibilidad máxima)
       opendkim-genkey -b 2048 -d {domain} -s {selector} -v
       mv {selector}.private /etc/opendkim/keys/{domain}/{selector}.private
       chmod 600 /etc/opendkim/keys/{domain}/{selector}.private

       # Alternativa OpenSSL manual:
       openssl genrsa -out {selector}.private 2048
       openssl rsa -in {selector}.private -pubout -outform DER | \\
         tail -c +13 | base64 -w0   # <- esto es tu p= (SubjectPublicKeyInfo DER)

    2) Publica el TXT ({selector}._domainkey.{domain}):
       v=DKIM1; k=rsa; p=<CONTENIDO_DE_ARRIBA>

    3) Configura el firmante (OpenDKIM/Rspamd) y reinicia:
       systemctl restart opendkim && postfix reload

    4) Verifica con esta misma herramienta: analyze --dkim-selectors {selector}

    5) Tras 48 h sin errores → publica el segundo selector 's2' y alternalo;
       así puedes revocar una clave cada mes sin downtime (t= flag en TXT).

    6) Revoca la antigua quitando 'p=' (vacío = clave revocada, RFC 6376 §3.6.1).
    """)


def generate_rollout_plan(domain: str, rua: str = "") -> str:
    rua = rua or f"dmarc-reports@{domain}"
    return textwrap.dedent(f"""\
    ══ Plan de despliegue DMARC en fases — {domain} ══

    FASE 0 (hoy)      v=DMARC1; p=none; rua=mailto:{rua}; fo=1;
                      → Recopila informes 2-4 semanas; identifica TODOS los remitentes legítimos.

    FASE 1            v=DMARC1; p=quarantine; pct=25; rua=mailto:{rua}; fo=1;
                      → 25% de los fallos a spam. Monitoriza falsos positivos.

    FASE 2            p=quarantine; pct=100;
                      → Si 2 semanas limpias, sube el porcentaje.

    FASE 3            v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100;
                      → Estado final. Alineación ESTRICTA. Subdominios heredan.

    FASE 4            Añade MTA-STS enforce + TLS-RPT + BIMI si aplica.
                      Revisa el informe semanal (los XML rua llegan como adjuntos).

    ⚠  Nunca saltes de p=none a p=reject directo: los remitentes legítimos
       olvidados (CRM, facturación, marketing) quedarían bloqueados.
    """)


# --------------------------------------------------------------------------
# Authorized self-test: send ONE marked email to an in-domain mailbox.
# --------------------------------------------------------------------------

SELFTEST_SUBJECT = "[MailForge SELF-TEST] Verificación anti-spoofing de {domain}"


def build_selftest_message(domain: str, to_addr: str, spf_domain: str = "",
                           display_name: str = "MailForge Self-Test") -> EmailMessage:
    """Compose the authorized test message.

    The envelope sender and From are forced INSIDE the analyzed domain, and
    the body is unambiguously a security test. Never use third-party domains.
    """
    msg = EmailMessage()
    msg["Subject"] = SELFTEST_SUBJECT.format(domain=domain)
    msg["From"] = f"{display_name} <mailforge-selftest@{(spf_domain or domain).lower()}>"
    msg["To"] = to_addr
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=domain)
    msg["X-MailForge-Test"] = "authorized-security-selftest"
    msg["Auto-Submitted"] = "auto-generated"
    msg["X-Priority"] = "3"
    msg.set_content(textwrap.dedent(f"""\
        ============================================================
         AUTORIZADO: prueba de seguridad anti-spoofing (MailForge)
        ============================================================

        Dominio analizado : {domain}
        Fecha (UTC)       : {formatdate(localtime=False)}
        Remitente simulado: mailforge-selftest@{(spf_domain or domain).lower()}

        QUÉ COMPROBAR EN TU BANDEJA:
          1. ¿Entró en INBOX o en spam/cuarentena?
             · inbox    → tu DMARC/SPF NO bloquea self-mail fallido
             · spam     → filtros lo marcaron (parcial)
          2. Cabecera 'Authentication-Results' de tu proveedor:
             · spf=fail  (esperado: IP no está en tu SPF)
             · dkim=none (esperado: no firmamos)
             · dmarc=fail (esperado: sin alineación)
          3. Revisa el informe rua de hoy: verás este fallo reflejado.

        Si este mensaje llegó a INBOX con dmarc=fail visible en
        Authentication-Results, TU DOMINIO ES SUPLANTABLE por terceros.

        Generado por MailForge — herramienta defensiva.
        """))
    return msg


def send_selftest(domain: str, to_addr: str, smtp_host: str = "",
                  smtp_port: int = 25, smtp_user: str = "",
                  smtp_pass: str = "", dry_run: bool = False) -> dict:
    """Send the single authorized self-test message via the domain's MX.

    Confirmation of ownership is enforced by the caller (interactive prompt);
    here we double-check that the recipient belongs to the analyzed domain.
    """
    recipient_domain = to_addr.rsplit("@", 1)[-1].lower().rstrip(".")
    if recipient_domain != domain.lower().rstrip("."):
        return {"sent": False,
                "error": ("destinatario fuera de dominio: el self-test solo "
                          "puede enviarse a un buzón del dominio analizado")}

    mxs = []
    from . import dnsx
    for r in (dnsx.resolve(domain, "MX") or dnsx.resolve_doh(domain, "MX") or []):
        mxs.append((r.get("pref", 0), r.get("data", "").rstrip(".")))
    mxs.sort()
    host = smtp_host or (mxs[0][1] if mxs else domain)

    msg = build_selftest_message(domain, to_addr)

    if dry_run:
        return {"sent": False, "dry_run": True, "mx": host,
                "message": msg.as_string()}

    try:
        with smtplib.SMTP(host, smtp_port, timeout=20) as srv:
            srv.ehlo("mailforge-selftest.local")
            if smtp_user:
                srv.starttls()
                srv.login(smtp_user, smtp_pass)
            srv.send_message(msg)
        return {"sent": True, "mx": host, "to": to_addr,
                "message_id": msg["Message-ID"]}
    except (smtplib.SMTPException, OSError, socket.timeout) as exc:
        return {"sent": False, "mx": host, "error": f"{type(exc).__name__}: {exc}"}
