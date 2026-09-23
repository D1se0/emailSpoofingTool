# Security Policy

## Scope

MailForge is a **defensive** anti-spoofing suite. It performs passive DNS
analysis, vulnerability scoring, and generates hardening configurations.
It deliberately does **not** send spoofed email to third parties: the only
send path is a single authorized self-test to a mailbox of the domain being
analyzed (double-guarded in `server/index.js` and `core/hardening.py`).

## Reporting a vulnerability

Email: open a private GitHub security advisory ("Report a vulnerability"
button on the Security tab). Please include:

- affected version/commit
- steps to reproduce
- impact assessment

We aim to acknowledge reports within 72 hours.

## Hard guarantees

1. `core/hardening.send_selftest` refuses recipients outside the analyzed domain.
2. `server/index.js` re-checks the recipient domain before invoking Python.
3. The analysis pipeline never opens an SMTP session except in the self-test.
4. `_rsalite.py` implements verification only — it cannot sign or encrypt.

## What is NOT a vulnerability

- "The tool can analyze any domain" — DNS queries are passive and public.
- "The self-test can send to my own mailbox without my permission" — it
  requires explicit operator confirmation by design.
