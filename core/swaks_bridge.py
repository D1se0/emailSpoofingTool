#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MailForge Core — swaks bridge: REAL sending through the installed swaks binary.

`swaks_send()` composes the exact message with compose_spoof_email(), writes a
temp .eml, locates the swaks binary and runs it with a safe argv (never a raw
shell string). The SMTP transcript is parsed into a structured verdict
(accepted / rejected / error) so callers can report "did it arrive?"-style
results like the tool the user knows from emkei.cz.

SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess
import tempfile
import time

from . import hardening  # noqa: F401  (re-exported helpers below)


def _find_swaks() -> str | None:
    """Locate the swaks binary: PATH, then /usr/local/bin, /usr/bin, /opt."""
    p = shutil.which("swaks")
    if p:
        return p
    for cand in ("/usr/local/bin/swaks", "/usr/bin/swaks", "/opt/swaks/swaks"):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,253}$")


def _is_email(s: str) -> bool:
    return bool(_EMAIL_RE.match((s or "").strip()))


def _tls_opt(tls_mode: str) -> list:
    """swaks TLS flags: -tls (opportunistic), -tls-optional, -tls-only, none."""
    if tls_mode == "tls":
        return ["-tls"]
    if tls_mode == "tls-optional":
        return ["-tls-optional"]
    if tls_mode == "tls-only":
        return ["-tls-only"]
    return []


def parse_transcript(text: str) -> dict:
    """Parse `swaks` transcript text into a structured verdict.

    Returns {verdict, code, message, attempts[], transcript}.
    verdict ∈ accepted | rejected | error
    """
    transcript = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    attempts = []          # [(stage, code, message)]
    verdict, code, message = "error", None, "sin transcripción"

    # The last numeric SMTP response in the transcript decides the outcome.
    codes = []
    for ln in transcript:
        m = re.search(r"^<~\s+(\d{3})(?:[- ])?\s*(.*)$", ln)
        if m:
            codes.append((int(m.group(1)), m.group(2).strip()))
            continue
        m = re.search(r"^\*\*\s+(\d{3})\s+(.*)$", ln)
        if m:
            codes.append((int(m.group(1)), m.group(2).strip()))
            continue
        m = re.search(r"^\*\*\s+(?:Unknown|Error|.*?error)\b(.*)$", ln, re.I)
        if m and "connection" in ln.lower():
            verdict = "error"

    # Stage tracking: which command produced the last response.
    stage = "banner"
    for ln in transcript:
        if re.match(r"^ ~> MAIL", ln):
            stage = "MAIL FROM"
        elif re.match(r"^ ~> RCPT", ln):
            stage = "RCPT TO"
        elif re.match(r"^ ~> DATA", ln) or "Enter message" in ln:
            stage = "DATA"
        elif re.match(r"^ ~> QUIT", ln):
            stage = "QUIT"
        m = re.match(r"^<~\s+(\d{3})(?:[- ])?\s*(.*)$", ln)
        if m:
            attempts.append((stage, int(m.group(1)), m.group(2).strip()))

    if codes:
        # The delivery verdict is the response to end-of-DATA ('.'), i.e. the
        # last meaningful code excluding the 221 connection-close.
        meaningful = [(c, m) for c, m in codes if c != 221]
        if meaningful:
            code, message = meaningful[-1]
            if 200 <= code < 300:
                verdict = "accepted"
            elif code in (421, 450, 451, 452):
                verdict = "error"          # transient → retry later
            else:
                verdict = "rejected"

    # Connection-level failures leave no final code.
    if verdict == "error" and not codes:
        for ln in transcript:
            low = ln.lower()
            if ("timed out" in low or "connection refused" in low
                    or "unable to" in low or "error" in low and "connect" in low):
                message = ln.strip()
                break
        else:
            if transcript:
                message = transcript[-1]
    return {
        "verdict": verdict,
        "code": code,
        "message": message,
        "attempts": [{"stage": s, "code": c, "message": m} for s, c, m in attempts],
        "transcript": transcript,
    }


def swaks_send(from_name: str = "", from_email: str = "", to: str = "",
               subject: str = "", text: str = "", reply_to: str = "",
               attachments: list = None, priority: str = "normal",
               smtp_host: str = "", smtp_port: int = 25,
               smtp_user: str = "", smtp_pass: str = "",
               tls_mode: str = "tls", timeout: int = 45) -> dict:
    """Send the composed message FOR REAL through the installed swaks binary.

    Every argument the user supplies is mapped onto swaks flags; the exact
    composed .eml (attachments included) travels as `--data @file`, so what
    the recipient sees is byte-for-byte what MailForge produced.

    Returns {sent, verdict, code, message, server, port, envelope_from,
             recipient, message_id, swaks_path, elapsed_s, transcript,
             attempts, command_preview, errors[]}.
    """
    t0 = time.monotonic()
    errors = []
    from_email = (from_email or "").strip()
    to = (to or "").strip()
    if not _is_email(from_email):
        return {"sent": False, "verdict": "error",
                "errors": ["From E-mail no es una dirección válida"]}
    if not _is_email(to):
        return {"sent": False, "verdict": "error",
                "errors": ["To no es una dirección válida"]}
    if priority not in ("normal", "high", "low"):
        priority = "normal"

    composed = hardening.compose_spoof_email(
        from_name=from_name, from_email=from_email, to=to, subject=subject,
        text=text, reply_to=reply_to, attachments=attachments,
        priority=priority)
    msg_id = composed["headers"].get("Message-ID", "").strip("<>")

    # Target server: operator's value, else auto-resolve recipient MX.
    server = (smtp_host or "").strip()
    if not server:
        recip_domain = to.rsplit("@", 1)[-1]
        try:
            mx = hardening._resolve_target_mx(recip_domain)
            server = mx[0][1] if mx else ""
        except Exception:
            server = ""
    if not server:
        return {"sent": False, "verdict": "error",
                "errors": [f"no se pudo resolver el MX de {to.rsplit('@', 1)[-1]} — "
                           "especifica --server"], **{"transcript": []}}

    swaks = _find_swaks()
    if not swaks:
        return {"sent": False, "verdict": "error", "server": server,
                "errors": ["swaks no está instalado — instálalo con "
                           "`apt install swaks` / `brew install swaks` o usa "
                           "los comandos manuales que genera `compose`"],
                "transcript": []}

    # Write the exact .eml to a temp file (0600, cleaned up afterwards).
    fd, eml_path = tempfile.mkstemp(prefix="mf-drill-", suffix=".eml")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(composed["message"])
        os.chmod(eml_path, 0o600)

        argv = [
            swaks,
            "--to", to,
            "--from", from_email,
            "--ehlo", from_email.rsplit("@", 1)[-1],
            "--server", server,
            "--port", str(smtp_port or 25),
            "--data", f"@{eml_path}",
        ]
        argv += _tls_opt(tls_mode)
        if smtp_user:
            argv += ["--auth", "LOGIN", "--auth-user", smtp_user,
                     "--auth-password", smtp_pass or ""]

        # Human-readable preview (values shell-quoted for copy-paste).
        def q(v):
            return "'" + str(v).replace("'", "'\\''") + "'"
        preview = " ".join(
            argv[:1] + [q(a) for a in argv[1:]]
        ).replace(q(eml_path), "@/tmp/spoof-drill.eml")

        env = dict(os.environ)
        env.setdefault("PERL5LIB", "")
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=timeout,
                env=env, stdin=subprocess.DEVNULL)
            out = proc.stdout or ""
            err = proc.stderr or ""
        except subprocess.TimeoutExpired as exc:
            out = (exc.stdout or b"").decode("utf-8", "replace") \
                if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            err = "tiempo de espera agotado"
            proc = None

        parsed = parse_transcript(out + ("\n" + err if err and not out else ""))
        # Enrich: attach envelope info the parser cannot know.
        parsed.update({
            "sent": parsed["verdict"] == "accepted",
            "server": server,
            "port": smtp_port or 25,
            "envelope_from": from_email,
            "recipient": to,
            "message_id": msg_id,
            "swaks_path": swaks,
            "elapsed_s": round(time.monotonic() - t0, 2),
            "command_preview": preview,
            "errors": errors,
        })
        if parsed["verdict"] == "accepted":
            parsed["note"] = ("✅ ACEPTADO por el servidor (250). La entrega a "
                              "INBOX o spam depende de sus filtros.")
        elif parsed["verdict"] == "rejected":
            parsed["note"] = "⛔ El servidor RECHAZÓ el mensaje."
        else:
            parsed["note"] = "⚠ No se pudo completar la transacción SMTP."
        return parsed
    finally:
        try:
            os.unlink(eml_path)
        except OSError:
            pass


# Convenience re-exports so callers can import everything from one module.
from .hardening import compose_spoof_email, generate_freeform_commands  # noqa: E402,F401
