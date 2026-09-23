#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MailForge Core — anti-spoofing analysis toolkit (stdlib-only).

Modules:
    dnsx      — DNS UDP/TCP/DoH client with DNSSEC detection
    spf       — RFC 7208 parser/evaluator
    dkim      — RFC 6376 discovery + crypto verification
    dmarc     — RFC 7489 parser + org-domain discovery
    _rsalite  — RSA/Ed25519 verify-only crypto
    scorer    — vulnerability scoring + attack vector simulation
    hardening — defensive record generator + authorized self-test

SPDX-License-Identifier: MIT
"""
from . import dnsx, spf, dkim, dmarc, scorer, hardening  # noqa: F401

__version__ = "1.0.0"
__all__ = ["dnsx", "spf", "dkim", "dmarc", "scorer", "hardening"]
