<div align="center">

# 🛡 MailForge

**Anti-Spoofing Analysis & Hardening Suite — SPF · DKIM · DMARC · DNSSEC · MTA-STS**

`Python 3.9+ stdlib-core` · `Node 18+ web` · `React 18` · `MIT`

[Features](#-características) · [Install](#-instalación) · [CLI](#-cli) · [Web](#-web) · [Docs](#-docs) · [Legal](#-uso-legítimo)

</div>

---

> [!WARNING]
> **Uso legítimo únicamente.** MailForge analiza la protección anti-spoofing de dominios (SPF/DKIM/DMARC) y genera configuraciones *defensivas*. NO envía emails suplantados a terceros; el único envío que realiza es un **self-test** dirigido a un buzón **del dominio que tú analizas y declaras tuyo**. Suplantar dominios de terceros es ilegal (fraude, phishing, GDPR/normativa local).

---

## ✨ Características

| Área | Detalle |
|---|---|
| 🔎 **Análisis DNS completo** | SPF (RFC 7208), DKIM (RFC 6376), DMARC (RFC 7489), DNSSEC, MX, STARTTLS, MTA-STS, TLS-RPT, BIMI |
| 🌐 **Resolución robusta** | UDP → TCP → **DoH** (dns.google/Cloudflare) con fallback automático; funciona tras NAT restrictivo |
| 🧮 **Scoring 0–100** | Pondera SPF/DKIM/DMARC/DNSSEC/TLS + simula **8 vectores de ataque** (spoof directo, subdominios, replay DKIM, downgrade TLS…) |
| 🎨 **CLI interactiva** | Rich con banners arcoíris, barras de progreso, paneles y tablas; fallback plano sin dependencias |
| 🛠 **Hardening** | Genera TXT SPF/DMARC/MTA-STS listos para pegar, config Postfix+OpenDKIM, guía de rotación DKIM |
| 📈 **Rollout DMARC por fases** | p=none → quarantine pct=25 → pct=100 → reject (sin romper remitentes legítimos) |
| ✉️ **Self-test autorizado** | 1 email de prueba **solo a un buzón de TU dominio**, marcado con cabeceras `X-MailForge-Test` |
| 🎭 **Spoof Lab** | Genera el mensaje suplantado que un atacante crearía, predice el veredicto y te da los comandos para inyectarlo **tú** desde tu relay hacia un buzón tuyo (sin que MailForge envíe nada) |
| 🖥 **Consola local** | Dashboard React conectado al motor: análisis en vivo, scoring animado, Spoof Lab, hardening — requiere `server/` en `:8787` |
| 🌐 **Web pública** | GitHub Pages: documentación, arquitectura y descargas — estática pura, sin backend (`site/`) |
| 📄 **Informes** | JSON + HTML autocontenidos en `reports/` |
| 👁 **Monitor** | `watch` re-escanea periódicamente y avisa si cambia el score |
| 🚫 **Zero-deps core** | El motor es Python stdlib puro (parser DNS propio, RSA/Ed25519 verify-only) |

## 🚀 Instalación

```bash
git clone https://github.com/TU_USUARIO/emailSpoofingTool.git
cd emailSpoofingTool

# CLI (única dependencia opcional)
pip3 install -r requirements.txt
./mailforge.sh                    # Linux/macOS
mailforge.bat                     # Windows

# Web (opcional)
cd server && npm install && npm start        # API + web → http://localhost:8787
cd ../web && npm install && npm run build    # bundle React servido por la API
```

## 🧭 CLI — ejemplos detallados

> Todos los ejemplos usan **datos 100% ficticios** (`midominio.com`, `jefe@midominio.com`, `CE0 Carlos Pérez`, `203.0.113.7`). Sustitúyelos por los tuyos. Manual aún más extenso: [web de documentación](https://d1se0.github.io/emailSpoofingTool/docs.html) · [`docs.md`](docs.md).

### 1) Análisis completo

```bash
$ python3 mailforge.py analyze midominio.com --save

 Dominio: midominio.com   ·   Score: 34/100 (D — Vulnerable)
 SPF       ███████████░░░░░░░░░░░░░░░░░░░░  36/100
 DMARC     ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   6/100   ← sin DMARC
 DNSSEC    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   0/100

 ⛔ DMARC ausente — Cualquier tercero puede suplantar este dominio.
 ⚔ Vectores viables: Spoof directo (95%) · Subdomain escape (80%)
 💾 Informe guardado: reports/midominio.com-20260923-101500.json
```

### 2) Ver el ataque desde la perspectiva del atacante (SIN enviar nada)

```bash
$ python3 mailforge.py spooftest midominio.com password

╭ Mensaje suplantado (drill) — midominio.com ════════════════╗
│ From: "CE0 Carlos Pérez (aviso urgente)"                   │
│       <carlos.perez@midominio.com>        ← ¡suplantado!   │
│ Reply-To: drill-collector@mailforge.example.net ← secuestrado│
│ Subject: Alerta de seguridad: contraseña expirada          │
╚═════════════════════════════════════════════════════════════╝

  Veredicto previsto: BANDEJA DE ENTRADA — suplantable ❗
```

### 3) **ENVÍO REAL** del drill — ¿llega al destinatario o lo rechazan? 🚀

```bash
# Directo al MX del dominio (como un atacante real) hacia TU buzón:
$ python3 mailforge.py drill midominio.com jefe@midominio.com \
      --motif invoice --exec "CE0 Carlos Pérez"

╭ ⚠ CONFIRMACIÓN ═════════════════════════════════════════════╗
│ DRILL REAL DE SUPLANTACIÓN                                   │
│   Dominio (declaras ser el propietario): midominio.com       │
│   Buzón destino (tuyo): jefe@midominio.com                   │
│   Suplantado: CE0 Carlos Pérez <…@midominio.com>             │
╰══════════════════════════════════════════════════════════════╝
¿Confirmas que es tu dominio y quieres enviar el drill? [y/N]: y

╭ Transcripción SMTP — mx1.midominio.com:25 ═══════════════════╮
│ send: 'MAIL FROM:<spoof-drill@midominio.com>'                │
│ reply: '250 2.1.0 OK'                                        │
│ send: 'RCPT TO:<jefe@midominio.com>'                         │
│ reply: '250 2.1.5 OK'          ← el MTA ACEPTÓ el mensaje    │
│ reply: '250 2.0.0 OK — queued as 4Zx1q2'                     │
╰══════════════════════════════════════════════════════════════╝

  ✉ ENVIADO vía mx1.midominio.com:25 → ACEPTADO (250)
  💡 Verifica dónde aterrizó con --imap
```

```bash
# ¿Llegó de verdad a INBOX o fue a spam? (el "¿llegó?" de emkei.cz, defensivo):
$ python3 mailforge.py drill midominio.com jefe@midominio.com \
      --imap imap.midominio.com/jefe@midominio.com --imap-wait 45 --yes

  📥 LLEGÓ A INBOX — tu dominio NO bloquea el spoof ❗
     ↳ INBOX: 1 mensaje(s)
```

```bash
# El mismo drill tras aplicar el hardening → el veredicto cambia:
$ python3 mailforge.py drill midominio.com jefe@midominio.com --yes

  ✖ RECHAZADO por mx1.midominio.com:
     550 5.7.26 Sender DMARC evaluation failed
  ✅ Tu DMARC/SPF RECHAZÓ la suplantación (p=reject activo)
```

<details>
<summary><b>Todas las flags de <code>drill</code></b></summary>

| Flag | Default | Descripción |
|---|---|---|
| `--motif` | `invoice` | plantilla: `invoice` · `password` · `giftcard` |
| `--exec` | `"CEO"` | directivo suplantado en el From |
| `--relay` | MX del dominio | tu propio relay SMTP |
| `--port` | `25` | puerto del relay (587 con auth) |
| `--imap` | — | `host[/usuario]` para verificar llegada por IMAP |
| `--imap-wait` | `20` | segundos de espera antes de consultar IMAP |
| `--yes` | no | salta la confirmación (scripts) |

La contraseña IMAP se pide por teclado o con `MAILFORGE_IMAP_PASS` (nunca se guarda ni imprime).

</details>

### 4) Hardening + rollout

```bash
$ python3 mailforge.py harden midominio.com

╭ Registros DNS recomendados — midominio.com ═════════════════╗
│ TXT │ midominio.com          │ v=spf1 ip4:203.0.113.7 … -all │
│ TXT │ s1._domainkey.midomin… │ v=DKIM1; k=rsa; p=<…>         │
│ TXT │ _dmarc.midominio.com   │ v=DMARC1; p=reject; sp=reject │
│ TXT │ _mta-sts.midominio.com │ v=STSv1; id=sts3f9a1b2c4      │
╰══════════════════════════════════════════════════════════════╝

$ python3 mailforge.py rollout midominio.com   # plan none→quarantine→reject
```

### 5) Resto de comandos

```bash
python3 mailforge.py dkim midominio.com facturacion marketing2024  # caza selectores
python3 mailforge.py vectors midominio.com     # tabla de 8 vectores de ataque
python3 mailforge.py spf midominio.com         # detalle SPF (también: dmarc|dnssec|tls)
python3 mailforge.py report midominio.com html # informe HTML autocontenido
python3 mailforge.py watch midominio.com 300   # avisa si el score cambia
python3 mailforge.py selftest midominio.com jefe@midominio.com  # email técnico
python3 mailforge.py                           # modo interactivo (REPL)
```

## 🖥 Consola local (web de testeo)

```bash
cd server && npm install && npm start     # http://localhost:8787  (API + consola)
cd web && npm run build                   # reconstruir el bundle tras editar web/src
```

Consola con: análisis en vivo, gauge animado, **Spoof Lab** (drill red-team), matriz de vectores,
generador de hardening y self-test. Necesita el backend local corriendo.

## 🌐 Web pública (GitHub Pages)

`site/index.html` — documentación, arquitectura, RFCs y descargas. **Estática pura**:
sin backend ni llamadas a APIs. Se despliega sola en cada push a `main`.

También hay documentación offline en [`docs.md`](docs.md).

## 📚 Docs

La documentación completa vive en la web (sección **Docs**) y en [`docs.md`](docs.md):
arquitectura, RFCs cubiertos, modelo de scoring, explicación de cada vector, recetas de despliegue, FAQ.

## ⚖️ Uso legítimo

✅ Auditar **tus propios dominios** · ✅ Evaluar proveedores antes de contratar · ✅ Investigación publicada
❌ Suplantar dominios ajenos · ❌ Phishing · ❌ Envío masivo no solicitado

El envío real está limitado al **self-test in-domain** con confirmación explícita, coherente con herramientas
comerciales (dmarcian, EasyDMARC, MXToolbox).

## 📄 Licencia

MIT — ver [LICENSE](LICENSE).
