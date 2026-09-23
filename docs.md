# MailForge — Documentación técnica extendida

> La misma documentación está disponible en la web (sección **Docs**).
> Este fichero la mantiene en el repo para consulta offline.

## 1. Qué hace (y qué no hace)

| Hace ✅ | No hace ❌ |
|---|---|
| Analiza SPF/DKIM/DMARC/DNSSEC/MTA-STS de cualquier dominio por DNS público | Enviar emails suplantados a terceros |
| Simula 8 vectores de ataque y estima su viabilidad | Automatizar phishing |
| Genera registros DNS y configs de servidor defensivas | Firmar correos (la crypto es verify-only) |
| Self-test: **1 email** a un buzón **del dominio analizado** (declarado propio) | Envío masivo o a dominios externos |

## 2. Requisitos

- Python **3.9+** (core), `rich` opcional para la CLI bonita
- Node **18+** (solo si quieres la web/API)
- Sin bases de datos, sin telemetría, stateless

## 2b. Las dos webs

| Artefacto | Propósito | Backend |
|---|---|---|
| `web/` + `server/` — **consola local** | testeo interactivo: analyzer, **Spoof Lab**, hardening, self-test | sí (`npm start` → :8787) |
| `site/` — **web pública (Pages)** | documentación, arquitectura, descargas | ninguno (estática) |

## 3. Arquitectura

```
┌────────────┐   spawn    ┌────────────┐  import  ┌──────────────┐
│  Web React │ ─────────► │  API Node  │ ───────► │  core Python │
│  (esbuild) │   HTTP     │ (stdlib)   │  api.py  │  (stdlib)    │
└────────────┘            └────────────┘          └──────┬───────┘
      │                                                  │
      └────────────── CLI mailforge.py ──────────────────┘
                                                         │
                                                  DNS UDP/TCP/DoH
```

## 4. Modelo de scoring

```
score = 0.20·SPF + 0.10·DKIM + 0.40·DMARC + 0.10·DNSSEC + 0.10·TLS + 0.10·Extras
```

| Sub-score | Regla principal |
|---|---|
| SPF | `-all`=100 · `~all`=70 · `+all`/`?all`=5 · errores −15 c/u · >10 lookups −10 · `ptr` −5 |
| DKIM | 45·claves_activas (cap 100) · <2048 bits −10 c/u |
| DMARC | reject 85 · quarantine 55 · none 15 · pct<100 prorratea · adkim/aspf=s +2 · rua +1 |
| DNSSEC | 100 si (AD ∨ RRSIG ∨ DS ∨ DNSKEY) |
| TLS | verified=70/95 (con MTA-STS) · unknown=30-50 · no-starttls=0 |
| Extras | MTA-STS 55 + TLS-RPT 25 + BIMI 20 (cap 100) |

## 5. Vectores de ataque simulados

1. **Direct spoof** — From desalineado con dominio propio del atacante (mitiga: DMARC).
2. **Exact-domain spoof** — MAIL FROM en tu dominio desde IP ajena (mitiga: SPF `-all`).
3. **Lookalike domain** — typosquat/homoglifo (mitiga: marca, BIMI, formación).
4. **DKIM replay** — reenvío de mensaje firmado (mitiga: reject, h= completo, x= corto).
5. **Null reverse-path** — abuso de bounces (mitiga: alineación + reject).
6. **Subdomain escape** — subdominios sin política (mitiga: `sp=reject`).
7. **Display-name impersonation** — no bloqueable por protocolo (mitiga: BIMI, formación).
8. **STARTTLS downgrade** — MITM sin MTA-STS/DANE (mitiga: MTA-STS enforce).

## 6. API HTTP

| Endpoint | Método | Descripción |
|---|---|---|
| `/api/health` | GET | estado + versión de Python |
| `/api/analyze?domain=` | GET | análisis completo (JSON del core) |
| `/api/dkim?domain=` | GET | caza de selectores |
| `/api/harden?domain=&ips=&selector=&policy=` | GET | genera registros/configs |
| `/api/rollout?domain=` | GET | plan DMARC por fases |
| `/api/spooftest?domain=&motif=` | GET | drill del Spoof Lab: mensaje + veredicto + comandos de inyección |
| `/api/selftest` | POST | `{domain, to, dry_run}` — solo in-domain (403 si no) |
| `/api/verify` | POST | `{raw}` verifica firmas DKIM de un email pegado |

## 7. Comandos CLI

Ver `python3 mailforge.py --help` y la sección Docs de la web.

```bash
python3 mailforge.py analyze <dominio>        # análisis completo + score
python3 mailforge.py dkim <dominio> [sel…]    # caza de selectores DKIM
python3 mailforge.py spooftest <dominio> [motivo]  # drill red-team (sin envío)
python3 mailforge.py harden <dominio>         # registros DNS + config
python3 mailforge.py rollout <dominio>        # plan DMARC por fases
python3 mailforge.py selftest <dom> <buzon>   # email de prueba autorizado
python3 mailforge.py report <dominio> html    # informe HTML/JSON
python3 mailforge.py watch <dominio> 60       # monitorización continua
python3 mailforge.py                          # modo interactivo
```

## 8. Desarrollo

```bash
python3 -m pytest tests/ -m "not network" -q   # unitarios offline
python3 -m pytest tests/ -m "network" -q       # integración DNS real
cd server && node --test test/api.test.js      # puente Node↔Python
cd web && npm run build && node --test test/   # web
```

## 9. Spoof Lab: predicción vs envío real (v1.2.0)

| Comando | Qué hace | Riesgo |
|---|---|---|
| `spooftest <dom> [motivo]` | renderiza el mensaje suplantado + veredicto previsto + comandos para ti | cero (no conecta) |
| `drill <dom> <buzon@dom> [flags]` | **envío real** al MX del dominio (o `--relay`), transcripción SMTP y veredicto (250 aceptado / 5xx rechazado) | 1 email real a TU buzón |
| `drill … --imap host[/user]` | tras el envío, consulta por IMAP si el drill llegó a INBOX o spam | credenciales solo en memoria |

Flags del drill: `--motif invoice|password|giftcard` · `--exec "CE0 Carlos Pérez"` ·
`--relay smtp.turelay.com --port 587` · `--imap imap.midominio.com/jefe@midominio.com` ·
`--imap-wait 45` · `--yes`.

Endpoints nuevos: `POST /api/spooflab/send` y `POST /api/spooflab/check` (guard in-domain → 403 si el
destinatario no pertenece al dominio analizado).

Manual exhaustivo: `site/docs.html` (publicado en Pages → /docs.html).
