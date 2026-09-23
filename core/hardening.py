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
import imaplib
import os
import re
import secrets
import smtplib
import socket
import textwrap
import time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

__all__ = ["generate_records", "generate_postfix_config", "generate_dkim_guide",
           "generate_rollout_plan", "build_selftest_message", "send_selftest",
           "build_spoof_preview", "generate_injection_commands", "send_spoof_drill",
           "check_drill_arrival"]


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
# Spoof Lab — RED-TEAM PREVIEW for the analyzed (owned) domain.
#
# This does NOT send anything. It renders a realistic spoofed message that a
# real attacker would craft against YOUR domain, plus the exact commands for
# the operator to inject it from THEIR OWN relay (swaks/sendmail) to a mailbox
# THEY control. Purpose: observe with your own eyes whether your SPF/DKIM/DMARC
# posture stops the attack (inbox vs quarantine vs reject).
# --------------------------------------------------------------------------

def _ascii_localpart(name: str) -> str:
    """'CE0 Carlos Pérez' → 'ce0.carlos.perez' (SMTP-safe local part)."""
    import unicodedata
    norm = unicodedata.normalize("NFKD", name)
    ascii_only = "".join(c for c in norm if not unicodedata.combining(c))
    cleaned = "".join(c if (c.isalnum() or c in ".-") else "."
                      for c in ascii_only.lower().replace(" ", "."))
    return re.sub(r"\.+", ".", cleaned).strip(".") or "ceo"


# --------------------------------------------------------------------------
# Spoof Lab — free-form composer (attacker-view drill).
#
# The operator fills the same fields a spoofing web-tool would expose (From
# name, From email, To, Subject, Text, attachments...). MailForge adds the
# disclosure banner and ONE pre-flight notice: "controlled environment / your
# own domain". The automated send path keeps the in-domain guard; the manual
# injection generator does not restrict recipients (the operator runs it).
# --------------------------------------------------------------------------

def compose_spoof_email(from_name: str = "", from_email: str = "",
                        to: str = "", subject: str = "", text: str = "",
                        reply_to: str = "", attachments: list = None,
                        priority: str = "normal") -> dict:
    """Build a fully configurable RFC 5322 message (MIME when attachments).

    attachments: list of {filename, content_b64, mime?} — content is base64.
    Returns {message, headers, has_attachments, warnings[]}.
    """
    warnings = []
    from_name = (from_name or "").strip()
    from_email = (from_email or "").strip()
    to = (to or "").strip()
    subject = (subject or "").strip() or "(sin asunto)"
    text = text or ""
    if not from_email:
        warnings.append("sin From E-mail no se puede construir el mensaje")
        return {"message": "", "headers": {}, "has_attachments": False,
                "warnings": warnings}
    if "@" not in to:
        warnings.append("destinatario sin @ — comprueba el campo To")

    # Encode ONLY the display name (RFC 2047) and keep the addr-spec raw;
    # encoding the whole header (default) breaks address parsing in clients.
    if from_name:
        from email.header import Header
        from email.utils import formataddr as _fa
        disp_from = _fa((Header(from_name, "utf-8").encode(), from_email))
    else:
        disp_from = from_email

    if attachments:
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.mime.application import MIMEApplication

        mixed = MIMEMultipart()
        mixed["From"] = disp_from
        mixed["To"] = to
        mixed["Subject"] = subject
        mixed["Date"] = formatdate(localtime=False)
        mixed["Message-ID"] = make_msgid(domain=(from_email.rsplit("@", 1)[-1]
                                                 or "mailforge.local"))
        mixed["X-Mailer"] = "MailForge-SpoofLab/1.3 (authorized drill)"
        if reply_to:
            mixed["Reply-To"] = reply_to
        if priority in ("high", "low"):
            mixed["X-Priority"] = "1" if priority == "high" else "5"
            mixed["Importance"] = "High" if priority == "high" else "Low"
        mixed.attach(MIMEText(text, "plain", "utf-8"))
        for att in attachments[:10]:
            try:
                raw = base64.b64decode(att.get("content_b64", ""), validate=True)
                part = MIMEApplication(raw)
                part.add_header("Content-Disposition", "attachment",
                                filename=(att.get("filename") or "attachment.bin")
                                .replace("\r", "").replace("\n", ""))
                if att.get("mime"):
                    part.set_type(att["mime"])
                mixed.attach(part)
            except Exception as exc:
                warnings.append(f"adjunto '{att.get('filename')}' omitido: {exc}")
        return {"message": mixed.as_string(), "headers": dict(mixed.items()),
                "has_attachments": True, "warnings": warnings}

    # plain message (no MIME multiparts)
    from email.mime.text import MIMEText as _MT
    msg = _MT(text, "plain", "utf-8")
    msg["From"] = disp_from
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=(from_email.rsplit("@", 1)[-1]
                                            or "mailforge.local"))
    msg["X-Mailer"] = "MailForge-SpoofLab/1.3 (authorized drill)"
    if reply_to:
        msg["Reply-To"] = reply_to
    if priority in ("high", "low"):
        msg["X-Priority"] = "1" if priority == "high" else "5"
        msg["Importance"] = "High" if priority == "high" else "Low"
    return {"message": msg.as_string(), "headers": dict(msg.items()),
            "has_attachments": False, "warnings": warnings}


def _shq(s: str) -> str:
    """Shell single-quote escape: 'CE0 don't' → 'CE0 don'\''t'."""
    return "'" + str(s).replace("'", "'\\''") + "'"


def generate_freeform_commands(from_email: str, to: str, from_name: str = "",
                               subject: str = "", text: str = "",
                               reply_to: str = "", attachments: list = None,
                               priority: str = "normal",
                               smtp_host: str = "") -> str:
    """Ready-to-run swaks/sendmail commands implementing exactly the composed
    message, for the operator to run from their own machine.

    Option 1 uses per-header flags (--h-From:, --h-Subject:, …). Option 2
    ships the exact .eml (adjuntos incluidos) via `swaks --data @file`, so
    no local MTA is needed.
    """
    composed = compose_spoof_email(from_name=from_name, from_email=from_email,
                                   to=to, subject=subject, text=text,
                                   reply_to=reply_to,
                                   attachments=attachments, priority=priority)
    b64 = base64.b64encode(composed["message"].encode()).decode()
    from_domain = from_email.rsplit("@", 1)[-1]
    recip_domain = to.rsplit("@", 1)[-1] if "@" in to else ""

    # Target server: operator relay if given; else the recipient's first MX
    # (best-effort DNS; if unresolvable, swaks falls back to MX lookup itself).
    server = smtp_host
    if not server and recip_domain:
        try:
            mx = _resolve_target_mx(recip_domain)
            server = mx[0][1] if mx else ""
        except Exception:
            server = ""
    server_line = f" \\\n      --server {_shq(server)}" if server else ""

    name = from_name or from_email
    reply_line = (f" \\\n      --h-Reply-To: {_shq(reply_to)}" if reply_to else "")
    prio_lines = ""
    if priority == "high":
        prio_lines = " \\\n      --h-X-Priority: '1 (Highest)' \\\n      --h-Importance: 'High'"
    elif priority == "low":
        prio_lines = " \\\n      --h-X-Priority: '5 (Lowest)' \\\n      --h-Importance: 'Low'"
    att_note = (f"\n    · El mensaje lleva {len(attachments)} adjunto(s): usa la "
                f"Opción 2 (--data con el .eml completo). En la Opción 1 añade "
                f"--attach @ruta-del-fichero por cada uno.") if attachments else ""

    common = f"--ehlo {_shq(from_domain)}{server_line} -tls"
    return textwrap.dedent(f"""\
    ══ Spoof Lab — inyección manual (ejecútalo TÚ desde tu equipo) ══

    From visible : {name} <{from_email}>
    Envelope     : {from_email}
    To           : {to}
    Subject      : {subject}
    Adjuntos     : {len(attachments or [])}
    Ruta         : {('relay propio ' + server) if smtp_host else ('MX del destinatario: ' + (server or recip_domain))}{att_note}

    ▸ Opción 1 — swaks directo (cabeceras controladas):
        swaks \\
          --to {_shq(to)} \\
          --from {_shq(from_email)} \\
          {common} \\
          --h-From: {_shq(f"{name} <{from_email}>")}{reply_line}{prio_lines} \\
          --h-Subject: {_shq(subject)} \\
          --h-X-Mailer: 'MailForge-SpoofLab/1.3 (authorized drill)' \\
          --body {_shq(text[:1800])}

    ▸ Opción 2 — mensaje .eml EXACTO (byte a byte, adjuntos incluidos) vía swaks:
        echo '{b64}' | base64 -d > /tmp/spoof-drill.eml
        swaks --to {_shq(to)} --from {_shq(from_email)} {common} --data @/tmp/spoof-drill.eml

      (alternativa con MTA local — requiere sendmail/postfix instalado:)
        sendmail -t -f {from_email} < /tmp/spoof-drill.eml

    ▸ Notas:
        · -tls usa STARTTLS oportunista (como un emisor real) y --ehlo presenta
          tu dominio en el saludo SMTP.
        · Si el puerto 25 saliente está bloqueado en tu red → VPS o relay
          autorizado (--server smtp.turelay.com --port 587).
        · Marca 'X-Mailer: … (authorized drill)' identifica el drill — quítala
          solo si sabes lo que haces.

    ⚠ USO EN ENTORNO CONTROLADO: dirígete únicamente a buzones propios o de
      personas que te hayan dado consentimiento (simulacros de phishing).
    """)


def build_spoof_preview(domain: str, exec_name: str = "CEO",
                        exec_email: str = "", motif: str = "invoice",
                        to_addr: str = "") -> dict:
    """Craft a would-be spoofing email against `domain` (red-team drill).
    Returns the RFC5322 message (plus its parts), the attack profile and the
    verdict prediction from the last known posture."""
    exec_email = exec_email or f"{_ascii_localpart(exec_name)}@{domain}"
    motifs = {
        "invoice": ("URGENTE: Factura vencida #INV-8841 — pago hoy",
                    "Adjunto la factura correspondiente. Por favor liquidar antes "
                    "de las 18:00 para evitar recargo. Cualquier duda, respóndeme "
                    "a este correo directamente.\n\n--\nDirección de Finanzas"),
        "password": ("Alerta de seguridad: contraseña expirada",
                     "Su contraseña corporativa expira hoy. Cambiéela desde el "
                     "portal interno para evitar la suspensión de la cuenta."),
        "giftcard": ("¡Felicidades! Has sido seleccionado para el bonus trimestral",
                     "Enhorabuena: has sido elegido entre el personal para recibir "
                     "el bonus de este trimestre. Confirma tus datos respondiendo "
                     "a este mensaje antes de las 17:00."),
    }
    subject, body = motifs.get(motif, motifs["invoice"])
    from_header = f"\"{exec_name} (aviso urgente)\" <{exec_email}>"
    to_header = to_addr or f"tu-buzon@{domain}"

    # Deliberately forged headers: external MTA, no DKIM, From inside domain.
    spoofed = (
        f"Received: from attacker-relay.example.net (unknown [203.0.113.66])\r\n"
        f"\tby mx.{domain} with ESMTPS id DRILL-MESSAGE;\r\n"
        f"\t{formatdate(localtime=False)}\r\n"
        f"From: {from_header}\r\n"
        f"Reply-To: drill-collector@mailforge.example.net\r\n"
        f"To: <{to_header}>\r\n"
        f"Subject: {subject}\r\n"
        f"Date: {formatdate(localtime=False)}\r\n"
        f"Message-ID: <drill-{secrets.token_hex(6)}@attacker-relay.example.net>\r\n"
        f"X-Mailer: MailForge-SpoofLab/1.0 (authorized drill)\r\n"
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"\r\n"
        f"{body}\r\n"
    )

    attack_profile = {
        "envelope_from": f"spoof-drill@{domain}",
        "header_from": exec_email,
        "spf_will_be": "fail (relay externo no está en tu SPF)",
        "dkim_will_be": "none (sin firma)",
        "dmarc_will_be": "fail (sin alineación)",
        "technique": "display-name impersonation + Reply-To hijack",
    }
    return {"message": spoofed, "profile": attack_profile,
            "domain": domain, "motif": motif,
            "from_header": from_header, "to_header": to_header,
            "subject": subject, "body": body,
            "env_from": f"spoof-drill@{domain}"}


def generate_injection_commands(domain: str, to_addr: str,
                                smtp_host: str = "", exec_name: str = "CEO",
                                motif: str = "invoice") -> str:
    """Exact commands for the operator to inject the drill message from
    their own machine/relay. MailForge never sends out-of-domain: these
    commands are executed BY THE OPERATOR against a mailbox THEY control."""
    pv = build_spoof_preview(domain, exec_name=exec_name, motif=motif,
                             to_addr=to_addr)
    hdr_from = pv["from_header"]
    env_from = pv["env_from"]
    subject = pv["subject"]
    body_line = pv["body"].splitlines()[0]
    b64 = base64.b64encode(pv["message"].encode()).decode()
    server_arg = (f"--server {smtp_host} " if smtp_host else "")  # sin --server → MX del destinatario
    return textwrap.dedent(f"""\
    ══ Spoof Lab — inyección manual del drill (TODO corre de TU cuenta) ══

    Objetivo   : {to_addr}
    Suplantado : {hdr_from}
    Envelope   : {env_from}
    Ruta       : swaks entrega al MX del DESTINATARIO ({to_addr.rsplit('@',1)[-1]})
                 — no necesitas ser relay de {domain}.

    ▸ Opción 1 — swaks (impersonación explícita con cabeceras -h-):
        swaks \\
          --to '{to_addr}' \\
          --from '{env_from}' \\
          {server_arg}\\
          --h-From: '{hdr_from}' \\
          --h-Reply-To: 'drill-collector@mailforge.example.net' \\
          --h-Subject: '{subject}' \\
          --h-X-Mailer: 'MailForge-SpoofLab/1.0 (authorized drill)' \\
          --body '{body_line}'

    ▸ Opción 2 — mensaje .eml completo + sendmail -t (usa SUS cabeceras):
        echo '{b64}' | base64 -d > /tmp/spoof-drill.eml
        cat /tmp/spoof-drill.eml | sendmail -t -f {env_from}

    ▸ Notas de red:
        · El puerto 25 saliente suele estar bloqueado en ADSL/fibra doméstica
          → ejecuta desde un VPS, o usa tu relay autorizado:
          añade --server smtp.turelay.com --port 587
        · NO envíes al MX de {domain} como 'relay de otros': el RCPT va al
          dominio del DESTINATARIO.

    ▸ Qué observar después:
        1. ¿Llegó al buzón, spam o rechazado? → eficacia de TU protección
        2. Authentication-Results del receptor: spf=fail dkim=none dmarc=fail
        3. Informe rua del día: el drill aparecerá como fallo DMARC

    ▸ Interpretación:
        · Rechazado (550)      → p=reject funciona  ✅
        · Cuarentena/spam      → p=quarantine o filtros parciales ⚠
        · En INBOX             → TU DOMINIO ES SUPLANTABLE — aplica hardening ❌

    ⚠ El envío AUTOMATIZADO de la herramienta (drill) solo admite buzones del
      dominio analizado. Esta inyección manual la ejecutas tú, contra un buzón
      que controlas — no lo dirijas nunca a terceros.
    """)


# --------------------------------------------------------------------------
# Spoof Lab — REAL delivery drill (in-domain only).
#
# Sends the spoofed drill message for real, directly to the MX of the
# ANALYZED domain (or the operator's own relay), captures the full SMTP
# transcript and reports the server's verdict: accepted (250) vs rejected
# (5xx). Optionally verifies actual arrival via IMAP (inbox vs junk).
# HARD GUARD: the recipient must belong to the analyzed domain — the domain
# the operator declares as their own. No third-party recipients, ever.
# --------------------------------------------------------------------------

class _TranscriptSMTP(smtplib.SMTP):
    """SMTP client that captures the whole conversation (client+server lines)."""
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.transcript = []

    def _print_debug(self, *args):
        try:
            self.transcript.append(" ".join(str(a) for a in args).strip())
        except Exception:
            pass


def _resolve_target_mx(domain: str) -> list:
    from . import dnsx
    entries = []
    for r in (dnsx.smart_resolve(domain, "MX") or []):
        data = (r.get("data") or "").strip().rstrip(".")
        if not data:
            continue
        if "pref" in r:
            pref, host = r.get("pref", 0), data
        else:
            parts = data.split(None, 1)
            try:
                pref, host = int(parts[0]), (parts[1] if len(parts) > 1 else data)
            except (ValueError, IndexError):
                pref, host = 0, data
        if host:
            entries.append((pref, host.rstrip(".")))
    entries.sort()
    if not entries:
        # No MX: RFC 5321 fallback = A record of the domain itself.
        a = dnsx.smart_resolve(domain, "A")
        if a:
            entries.append((0, domain))
    return [(p, h) for p, h in entries]


def send_spoof_drill(domain: str, to_addr: str, exec_name: str = "CEO",
                     motif: str = "invoice", smtp_host: str = "",
                     smtp_port: int = 0, smtp_user: str = "",
                     smtp_pass: str = "", helo_name: str = "drill.mailforge.local",
                     timeout: int = 25) -> dict:
    """Send the spoofed drill for real and report the server verdict.

    Envelope-from is spoof-drill@<domain> (exact-domain spoof) from an
    unauthorized IP → expected Authentication-Results: spf=fail dkim=none
    dmarc=fail. Whether it is ACCEPTED (then inbox/junk is up to the filters)
    or REJECTED (5xx) is exactly what the drill reveals.
    """
    domain = domain.lower().rstrip(".")
    recipient_domain = to_addr.rsplit("@", 1)[-1].lower().rstrip(".") \
        if "@" in to_addr else ""
    if recipient_domain != domain:
        return {"sent": False, "verdict": "blocked", "error":
                "destinatario fuera de dominio: el drill real solo puede "
                "enviarse a un buzón del dominio analizado (que declaras tuyo)"}

    preview = build_spoof_preview(domain, exec_name=exec_name, motif=motif)
    msg_bytes = preview["message"].encode("utf-8")
    mail_from = f"spoof-drill@{domain}"

    # Target: operator relay (if given) or the domain's own MX chain.
    targets = []
    if smtp_host:
        targets.append((0, smtp_host))
    else:
        targets = _resolve_target_mx(domain)
    if not targets:
        return {"sent": False, "verdict": "error", "error":
                f"sin MX ni A resoluble para '{domain}' — no hay a quién enviar"}

    last_err = None
    for _pref, host in targets[:3]:
        port = smtp_port or 25
        client = None
        try:
            client = _TranscriptSMTP(host, port, timeout=timeout)
            client.set_debuglevel(1)
            code, banner = client.connect(host, port)
            client.ehlo(helo_name)
            features = client.esmtp_features
            # Opportunistic STARTTLS (like real senders) — unverified ctx is
            # fine: we are the sender probing THEIR MTA.
            if "starttls" in features:
                try:
                    import ssl as _ssl
                    client.starttls(context=_ssl._create_unverified_context())
                    client.ehlo(helo_name)
                except smtplib.SMTPException:
                    pass
            if smtp_user and smtp_pass:
                client.login(smtp_user, smtp_pass)

            refused = client.sendmail(mail_from, [to_addr], msg_bytes)
            client.quit()
            return {
                "sent": True, "verdict": "accepted",
                "mx": host, "port": port,
                "envelope_from": mail_from,
                "recipient": to_addr,
                "message_id": re.search(r"Message-ID:\s*<([^>]+)>",
                                        preview["message"]).group(1),
                "transcript": client.transcript,
                "recipients_refused": {k: list(v) for k, v in (refused or {}).items()},
                "profile": preview["profile"],
                "note": ("ACEPTADO por el servidor. Ahora depende de sus filtros: "
                         "INBOX, cuarentena o spam. Usa --imap para verificar llegada.")
                        if not refused else
                        ("aceptado con avisos para algunos destinatarios"),
            }
        except smtplib.SMTPRecipientsRefused as exc:
            codes = {k: list(v) for k, v in exc.recipients.items()}
            transcript = client.transcript if client else []
            try:
                client.quit()
            except Exception:
                pass
            return {"sent": False, "verdict": "rejected", "mx": host, "port": port,
                    "envelope_from": mail_from, "recipient": to_addr,
                    "recipients_refused": codes, "transcript": transcript,
                    "profile": preview["profile"],
                    "error": f"RECHAZADO por {host}: " + "; ".join(
                        f"{k} → {v[0]} {v[1].decode('utf-8', 'replace')[:120]}"
                        for k, v in codes.items()),
                    "note": "✅ Tu DMARC/SPF RECHAZÓ la suplantación (p=reject activo)"}
        except (smtplib.SMTPSenderRefused, smtplib.SMTPDataError) as exc:
            transcript = client.transcript if client else []
            try:
                client.quit()
            except Exception:
                pass
            return {"sent": False, "verdict": "rejected", "mx": host, "port": port,
                    "envelope_from": mail_from, "recipient": to_addr,
                    "transcript": transcript, "profile": preview["profile"],
                    "error": f"rechazado por {host}: {exc.smtp_code} {exc.smtp_error.decode('utf-8', 'replace')[:140] if isinstance(exc.smtp_error, bytes) else exc.smtp_error}",
                    "note": "El MTA rechazó la transacción (protección activa)"}
        except (smtplib.SMTPException, OSError, socket.timeout) as exc:
            last_err = f"{type(exc).__name__}: {exc}"
            if client:
                try:
                    client.quit()
                except Exception:
                    pass
            continue   # next MX
    return {"sent": False, "verdict": "error", "error":
            f"no se pudo contactar ningún servidor de {domain}: {last_err}",
            "profile": preview["profile"]}


IMAP_FOLDERS = ("INBOX", "Junk", "Spam", "Junk Email", "[Gmail]/Spam",
                "[Gmail]/All Mail")


def check_drill_arrival(imap_host: str, imap_user: str, imap_pass: str,
                        wait_seconds: int = 0, port: int = 993,
                        timeout: int = 20) -> dict:
    """Verify (via IMAP) where the drill actually landed: inbox, junk or nowhere.
    Credentials are used in-memory only and never appear in the output."""
    if wait_seconds:
        time.sleep(min(wait_seconds, 300))
    try:
        imap = imaplib.IMAP4_SSL(imap_host, port, timeout=timeout)
    except (OSError, imaplib.IMAP4.error, socket.timeout) as exc:
        return {"checked": False, "error": f"IMAP no disponible: {exc}"}
    try:
        imap.login(imap_user, imap_pass)
    except imaplib.IMAP4.error as exc:
        try:
            imap.logout()
        except Exception:
            pass
        return {"checked": False, "error": "login IMAP fallido (credenciales?)"}

    criteria = '(HEADER X-Mailer "MailForge-SpoofLab")'
    found = {"inbox": False, "junk": False, "folders_hit": []}
    for folder in IMAP_FOLDERS:
        try:
            status, _ = imap.select(folder, readonly=True)
            if status != "OK":
                continue
            status, data = imap.search(None, criteria)
            if status == "OK" and data and data[0].split():
                ids = data[0].split()
                if folder == "INBOX":
                    found["inbox"] = True
                else:
                    found["junk"] = True
                found["folders_hit"].append({"folder": folder, "count": len(ids)})
            imap.close()
        except imaplib.IMAP4.error:
            continue   # folder does not exist in this server
    try:
        imap.logout()
    except Exception:
        pass
    if found["inbox"]:
        found["verdict"] = "LLEGÓ A INBOX — tu dominio NO bloquea el spoof ❗"
    elif found["junk"]:
        found["verdict"] = "Llegó a SPAM/CUARENTENA — filtrado parcial ⚠"
    else:
        found["verdict"] = ("No localizado aún — puede estar en tránsito o "
                            "rechazado; reintenta con --imap-wait 60")
    found["checked"] = True
    return found


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
