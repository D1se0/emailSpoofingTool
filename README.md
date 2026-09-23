<div align="center">

# 🛡 MailForge

**Anti-Spoofing Analysis, Attack Simulation & Hardening Suite — SPF · DKIM · DMARC · DNSSEC · MTA-STS**

`Python 3.9+ stdlib-core` · `Node 18+ web` · `React 18` · `MIT`

[Features](#-características) · [Primeros pasos](#-primeros-pasos-desde-cero) · [Parámetros](#-referencia-completa-de-parámetros-compose) · [Enviar de verdad](#-envío-real-cómo-funciona) · [Web](#-web-local-consola) · [Docs](#-docs) · [Legal](#-uso-legítimo)

</div>

---

> [!WARNING]
> **Uso legítimo únicamente.** MailForge es una suite **defensiva**: analiza la protección anti-spoofing de tu dominio, simula qué ataques succeedrían y genera la configuración para cerrarlos. Antes de cualquier envío real muestra un **aviso de entorno controlado**: dirige los mensajes solo a buzones **propios o con consentimiento explícito** (simulacros de phishing autorizados). Suplantar dominios de terceros es ilegal.

---

## ✨ Características

| Área | Detalle |
|---|---|
| 🔎 **Análisis DNS completo** | SPF (RFC 7208), DKIM (RFC 6376), DMARC (RFC 7489), DNSSEC, MX, STARTTLS, MTA-STS, TLS-RPT, BIMI |
| 🌐 **Resolución robusta** | UDP → TCP → **DoH** (dns.google/Cloudflare) con fallback automático; funciona tras NAT restrictivo |
| 🧮 **Scoring 0–100** | Pondera SPF/DKIM/DMARC/DNSSEC/TLS + simula **8 vectores de ataque** (spoof directo, subdominios, replay DKIM, downgrade TLS…) |
| 🧾 **Compositor libre** | From Name/Email, To, Subject, Text, Reply-To, prioridad y **adjuntos reales** → `.eml` exacto + comandos listos |
| 🚀 **Envío real integrado** | `--send` (CLI) o botón **Enviar AHORA** (web): ejecuta **swaks** por detrás con tus parámetros, resuelve el MX del destinatario, negocia STARTTLS y te devuelve el **veredicto del servidor** (250 aceptado / 5xx rechazado) con transcripción completa |
| 📥 **¿Llegó?** | Verificación IMAP opcional: dice si el drill aterrizó en INBOX, spam o no llegó |
| 🎨 **CLI interactiva** | Rich con banners, barras de progreso, paneles y tablas; fallback plano sin dependencias |
| 🛠 **Hardening** | TXT SPF/DMARC/MTA-STS listos para pegar, config Postfix+OpenDKIM, guía de rotación DKIM |
| 📈 **Rollout DMARC por fases** | p=none → quarantine pct=25 → pct=100 → reject (sin romper remitentes legítimos) |
| 🖥 **Consola local** | Dashboard React conectado al motor: análisis en vivo, scoring animado, Spoof Lab con envío real — `server/` en `:8787` |
| 🌐 **Web pública** | GitHub Pages: documentación exhaustiva y descargas — estática pura, sin backend (`site/`) |
| 📄 **Informes** | JSON + HTML autocontenidos en `reports/` |
| 👁 **Monitor** | `watch` re-escanea periódicamente y avisa si cambia el score |
| 🚫 **Zero-deps core** | El motor es Python stdlib puro (parser DNS propio, RSA/Ed25519 verify-only) |

---

## 🚀 Instalación

### Requisitos previos (explicado para principiantes)

| Software | ¿Para qué? | Cómo instalarlo |
|---|---|---|
| **Python ≥ 3.9** | El motor de análisis | `sudo apt install python3` (Debian/Kali/Ubuntu) — ya viene en macOS y la mayoría de Linux |
| **Node ≥ 18** *(opcional)* | La consola web local | `sudo apt install nodejs npm` o [nodejs.org](https://nodejs.org) |
| **swaks** *(para envío real)* | Motor de envío SMTP que MailForge ejecuta por detrás | `sudo apt install swaks` · `brew install swaks` · [jetmore.org/john/code/swaks](http://www.jetmore.org/john/code/swaks/) |
| **rich** *(opcional)* | Colores y tablas bonitas en la CLI | `pip3 install rich` — sin él la CLI funciona en modo plano |

```bash
git clone https://github.com/D1se0/emailSpoofingTool.git
cd emailSpoofingTool

# CLI
pip3 install -r requirements.txt      # solo 'rich' (opcional)
./mailforge.sh                        # Linux/macOS
mailforge.bat                         # Windows

# Consola web local (opcional)
cd server && npm install && npm start # API + web → http://localhost:8787
cd ../web && npm install && npm run build   # bundle React servido por la API
```

Comprueba que todo está listo:

```bash
python3 mailforge.py --version        # MailForge 1.3.0
swaks --version                       # v20240103.0 o similar
```

---

## 🌱 Primeros pasos desde cero

> **¿Qué es el email spoofing?** Es enviar un correo que *parece* venir de una dirección que no es tuya (p. ej. `jefe@tuempresa.com`) manipulando las cabeceras del mensaje. Funciona cuando el dominio suplantado **no publica** registros SPF/DKIM/DMARC que digan a los receptores quién puede enviar en su nombre. MailForge te deja **comprobarlo sobre tu propio dominio**: genera el mensaje que un atacante enviaría, lo envía de verdad a un buzón tuyo y te dice si el servidor lo aceptó o lo rechazó.

### Tu primer análisis (30 segundos)

```bash
python3 mailforge.py analyze gmail.com
```

Salida (resumida): tabla SPF/DKIM/DMARC/DNSSEC/MTA-STS, score **0–100** con letra (A–F) y los 8 vectores de ataque simulados. Nada se envía; solo consultas DNS.

### Tu primer drill completo (5 pasos)

```bash
# 1. Genera el mensaje suplantado + comandos (SIN enviar nada):
python3 mailforge.py spooftest midominio.com invoice

# 2. Rellena el compositor con tus datos y genera el .eml:
python3 mailforge.py compose \
    --from-name "CE0 Carlos Pérez" \
    --from-email jefe@midominio.com \
    --to test@midominio.com \
    --subject "URGENTE: Factura #4471 vencida" \
    --text "Adjunto la factura pendiente de abono." \
    --save drill.eml

# 3. Envíalo DE VERDAD (ejecuta swaks por detrás y te pide confirmación):
python3 mailforge.py compose \
    --from-name "CE0 Carlos Pérez" \
    --from-email jefe@midominio.com \
    --to test@midominio.com \
    --subject "URGENTE: Factura #4471 vencida" \
    --text "Adjunto la factura pendiente de abono." \
    --send

# 4. Comprueba en tu buzón: ¿llegó a INBOX o a spam?
#    (en las cabeceras del recibido busca "Authentication-Results:")

# 5. Cierra el agujero y repite el drill → ahora debe ser RECHAZADO:
python3 mailforge.py harden midominio.com
python3 mailforge.py compose ... --send   # → ⛔ RECHAZADO (5xx) ✅
```

---

## 📖 Referencia completa de parámetros (`compose`)

```
python3 mailforge.py compose [parámetros]
```

> **Convención de datos ficticios:** en todos los ejemplos, `midominio.com` es tu dominio, `jefe@midominio.com` la dirección suplantada (tu CEO ficticio), `test@midominio.com` tu buzón de prueba y `CE0 Carlos Pérez` el nombre visible del suplantado.

### `--from-name` — nombre visible del remitente

| | |
|---|---|
| **Qué es** | El nombre que el destinatario ve como "remitente" en su bandeja, antes incluso de abrir el correo. Es **solo cosmético**: no participa en la autenticación. |
| **Por detrás** | Se codifica con **RFC 2047** (`=?utf-8?q?...=`) para soportar acentos y símbolos; la dirección de correo nunca se codifica. El mensaje se construye con la librería `email` de Python (`EmailMessage`, `formataddr`). |
| **Simple** | `--from-name "Carlos"` |
| **Avanzado** | `--from-name "CE0 Carlos Pérez (Dirección Financiera)"` — con acentos y paréntesis, codificado automáticamente. |
| **Si lo omites** | Se usa la dirección (`jefe@midominio.com`) como nombre visible. |

### `--from-email` — dirección de envío *(obligatorio)*

| | |
|---|---|
| **Qué es** | La dirección que aparece en la cabecera `From:` y la que el receptor evalúa contra **DMARC**. Su dominio es el que MailForge analiza. |
| **Por detrás** | Define el dominio del `Message-ID` (`<timestamp.pid.random@dominio>`) y el EHLO del envío (`--ehlo dominio`). En el sobre SMTP (`MAIL FROM`) se usa la misma dirección. DMARC compara el dominio del `From:` con el del sobre y con el firmado por DKIM (**alineación**). |
| **Simple** | `--from-email jefe@midominio.com` |
| **Avanzado** | `--from-email soporte@sub.midominio.com` — prueba de suplantación por **subdominio** (DMARC `sp=` decide si se acepta). |
| **Errores comunes** | Sin `@` o con espacios → la herramienta lo rechaza con `uso: compose …`. Un dominio sin registros MX → el envío fallará en el paso de resolución. |

### `--to` — destinatario *(obligatorio)*

| | |
|---|---|
| **Qué es** | El buzón que recibirá el mensaje. Debe ser **tuyo o con consentimiento**: tu buzón corporativo, un alias propio, o un buzón temporal (Guerrilla Mail, etc.) para no tocar tu bandeja real. |
| **Por detrás** | Al enviar, MailForge consulta los registros **MX** del dominio del destinatario con su stack DNS (UDP→TCP→DoH) para saber a qué servidor entregar. También puedes fijarlo tú con `--relay`. |
| **Simple** | `--to test@midominio.com` |
| **Avanzado** | `--to yvt0wp+77xiollatz23c@sharklasers.com` — buzón temporal con etiqueta `+tag`; útil para drills desechables. |

### `--subject` — asunto

| | |
|---|---|
| **Qué es** | La línea de asunto. En los drills, la ingeniería social vive aquí ("URGENTE", "Factura vencida"…), igual que un atacante real. |
| **Por detrás** | Se recorta a 998 caracteres (límite RFC 5322) y se codifica RFC 2047 si lleva acentos. |
| **Simple** | `--subject "Hola"` |
| **Avanzado** | `--subject "RE: RE: FW: Factura #4471 — pago pendiente"` — encadenado realista de respuestas/reenvíos. |

### `--text` — cuerpo del mensaje

| | |
|---|---|
| **Qué es** | El contenido del correo (texto plano). |
| **Por detrás** | Se embebe como parte MIME `text/plain; charset=utf-8` con `Content-Transfer-Encoding: base64` (así los acentos sobreviven a cualquier servidor). Hasta 100.000 caracteres. |
| **Simple** | `--text "Hola, esto es una prueba."` |
| **Avanzado** | Texto multilínea con saltos: usa comillas y escribe `\n`, o pásalo con `$(cat cuerpo.txt)`. |

### `--reply-to` — dirección de respuesta *(opcional)*

| | |
|---|---|
| **Qué es** | Cabecera `Reply-To:`: si el destinatario pulsa "Responder", la respuesta va aquí y NO al From. Un atacante la usa para recibir respuestas aunque el From sea suplantado. |
| **Por detrás** | Se añade la cabecera tal cual (máx. 254 chars). Si la omites, las respuestas van al From. |
| **Simple** | `--reply-to carlos.perez@midominio.com` |
| **Avanzado (técnica real)** | `--reply-to recogida@otro-correo.com` — From suplantado + Reply-To ajeno: así responde la víctima al atacante. Si tu anti-phishing no alerta de esto, es un hallazgo. |

### `--attach` — adjuntos reales *(opcional, repetible)*

| | |
|---|---|
| **Qué es** | Ficheros que viajan dentro del correo (PDF, PNG, ZIP…). Máx. **10 ficheros**, 4 MB c/u. |
| **Por detrás** | Cada fichero se codifica base64 y se embebe como parte MIME con `Content-Disposition: attachment; filename="…"` y su MIME type autodetectado (`mimetypes`), convirtiendo el mensaje en `multipart/mixed`. En la web se suben en base64 por la API (límite ~6 MB total). |
| **Simple** | `--attach factura.pdf` |
| **Avanzado** | `--attach factura.pdf --attach logo.png --attach datos.csv` — tres partes adjuntas en un solo mensaje. |

### `--priority` — prioridad del mensaje *(opcional)*

| | |
|---|---|
| **Qué es** | Marca el correo como urgente (algunos clientes lo resaltan con `!!`). |
| **Por detrás** | `high` → cabeceras `X-Priority: 1` + `Importance: High`; `low` → `X-Priority: 5` + `Importance: Low`; `normal` (por defecto) no añade nada. |
| **Valores** | `normal` · `high` · `low` |
| **Simple** | `--priority high` |

### `--relay` y `--port` — servidor de salida *(opcionales)*

| | |
|---|---|
| **Qué es** | `--relay` fija a qué servidor SMTP se conecta MailForge. Sin él, se resuelve el **MX del destinatario** (entrega directa, como un atacante). `--port` cambia el puerto (25 directo, 587 submission). |
| **Por detrás** | El valor viaja a swaks como `--server host --port N`. Si tu relay exige login, añade `--smtp-user` y la contraseña en la variable de entorno `MAILFORGE_SMTP_PASS` (nunca en la línea de comandos, para que no quede en el historial). |
| **Simple** | `--relay smtp.midominio.com --port 587 --smtp-user drill@midominio.com` |
| **¿Cuándo?** | Si tu proveedor/ISP bloquea el puerto 25 saliente (lo habitual en redes domésticas y cloud), usa tu relay o un VPS. |

### `--no-tls` / `--tls-optional` / `--tls-only` — cifrado del canal

| | |
|---|---|
| **Qué es** | Controla el STARTTLS hacia el servidor de salida. |
| **Por detrás** | `tls` (por defecto) → swaks `-tls` (oportunista, como un emisor real); `tls-optional` → `-tls-optional` (continúa aunque el servidor no ofrezca TLS); `tls-only` → `-tls-only` (aborta si no hay TLS); `no-tls` → texto claro. |

### `--save` — guardar el `.eml` *(opcional)*

Escribe el mensaje exacto a un fichero para conservarlo, adjuntarlo a un informe o inyectarlo a mano: `--save drill.eml`.

### `--send` — envío real integrado

Ejecuta el envío **de verdad** con swaks (ver siguiente sección). Pide confirmación interactiva antes de conectar.

---

## 🚀 Envío real: cómo funciona

```
   TÚ (compose --send / botón web "Enviar AHORA")
        │  parámetros: from-name, from-email, to, subject, text, adjuntos…
        ▼
   MailForge core (Python)
        │  1. compose_spoof_email() → .eml exacto (tmp, 0600)
        │  2. DNS: MX del destinatario  (p.ej. mail.guerrillamail.com)
        │  3. swaks_send() → subprocess SIN shell:
        │       swaks --to <dest> --from <remitente> --ehlo <dominio>
        │             --server <MX> --port 25 -tls --data @/tmp/mf-drill-*.eml
        ▼
   Servidor SMTP del destinatario
        │  220 banner → EHLO → STARTTLS → MAIL FROM → RCPT TO → DATA
        ▼
   Veredicto parseado de la transcripción
        ├─ 250 → ✅ ACEPTADO (encolado) → depende de filtros: INBOX/spam
        ├─ 5xx → ⛔ RECHAZADO (protección activa: DMARC p=reject, etc.)
        └─ 4xx → ⚠ error transitorio (reintenta más tarde)
```

### Ejemplo real de principio a fin (datos ficticios)

```bash
$ python3 mailforge.py compose \
    --from-name "CE0 Carlos Pérez" \
    --from-email jefe@midominio.com \
    --to test@midominio.com \
    --subject "URGENTE: Factura #4471 vencida" \
    --text "Adjunto la factura pendiente de abono." \
    --send

  ⚠ USO EN ENTORNO CONTROLADO: …
  ¿Enviar de verdad este mensaje por SMTP? [y/N]: y

╭ Transcripción SMTP — mx1.midominio.com:25 ═══════════════════╮
│ -> 'MAIL FROM:<jefe@midominio.com>'                          │
│ <~  '250 2.1.0 OK'                                           │
│ -> 'RCPT TO:<test@midominio.com>'                            │
│ <~  '250 2.1.5 OK'                                           │
│ <~  '250 2.0.0 OK — queued as 4Zx1q2'   ← ACEPTADO           │
╰══════════════════════════════════════════════════════════════╝

  ✉ ENVIADO de verdad vía mx1.midominio.com:25 → ACEPTADO (250) en 0.7s
  💡 Comprueba la bandeja del destinatario (INBOX o spam) y las cabeceras
     Authentication-Results del mensaje.
```

### Códigos SMTP que verás (chuleta)

| Código | Significado | Qué hacer |
|---|---|---|
| `250` | Aceptado y encolado | Revisa INBOX/spam del destinatario |
| `550 5.7.26` | Rechazado por evaluación DMARC | ✅ Tu protección funciona |
| `550 5.1.1` | Buzón inexistente | Corrige el `--to` |
| `421 / 450` | Transitorio (greylisting, sobrecarga) | Reintenta en minutos |
| `554` | Rechazado por políticas (spam, RBL) | Revisa IP/reputación |

### ¿Qué pasa después de que el servidor acepte?

El mensaje llega al buzón y el receptor estampa su veredicto en las cabeceras. Ábrelo y busca:

```
Authentication-Results: mx.destinatario.com;
   spf=fail (sender IP is 203.0.113.7) smtp.mailfrom=midominio.com;
   dkim=none (no signature);
   dmarc=none action=none header.from=midominio.com
```

- `dmarc=none action=none` + mensaje en INBOX → **tu dominio es suplantable** ❗ → ejecuta `harden`.
- Tras aplicar el hardening, el mismo drill da `dmarc=fail action=quarantine/reject` o un `550` directo.

### Verificación IMAP opcional (¿llegó a INBOX o a spam?)

```bash
python3 mailforge.py drill midominio.com test@midominio.com \
    --imap imap.midominio.com/test@midominio.com --imap-wait 45 --yes

  📥 LLEGÓ A INBOX — tu dominio NO bloquea el spoof ❗
```

La contraseña se pide por teclado o con `MAILFORGE_IMAP_PASS`; nunca se guarda.

---

## 🧭 Resto de comandos

```bash
python3 mailforge.py analyze gmail.com          # análisis completo + score
python3 mailforge.py analyze gmail.com --save   # + informe en reports/
python3 mailforge.py dkim gmail.com             # caza de selectores DKIM (~60)
python3 mailforge.py dkim gmail.com google s1   # selectores concretos
python3 mailforge.py spf gmail.com              # detalle SPF (raw + all)
python3 mailforge.py dmarc gmail.com            # detalle DMARC
python3 mailforge.py dnssec example.com         # DS/AD/RRSIG/DNSKEY
python3 mailforge.py tls gmail.com              # MX/STARTTLS/MTA-STS/TLS-RPT
python3 mailforge.py vectors gmail.com          # 8 vectores con probabilidad
python3 mailforge.py harden midominio.com       # registros DNS + Postfix/OpenDKIM
python3 mailforge.py rollout midominio.com      # plan DMARC por fases
python3 mailforge.py spooftest midominio.com password --to test@midominio.com
python3 mailforge.py drill midominio.com test@midominio.com --yes   # envío in-domain
python3 mailforge.py selftest midominio.com test@midominio.com
python3 mailforge.py verify --file mensaje.eml  # verifica DKIM de un mensaje
python3 mailforge.py report midominio.com html  # informe JSON/HTML
python3 mailforge.py watch midominio.com 300    # monitor cada 5 min
python3 mailforge.py                            # REPL interactivo (help)
```

`spooftest` admite los motivos `invoice` (factura urgente), `password` (contraseña expirada) y `giftcard` (bono/regalo) — las 3 plantillas de ingeniería social más comunes, para que veas exactamente qué habría circulado.

---

## 🖥 Web local (consola)

```bash
cd server && npm install && npm start   # → http://localhost:8787
```

| Pestaña | Qué hace |
|---|---|
| **Analyzer** | Análisis completo en vivo con score animado |
| **Spoof Lab** | Formulario completo (From Name/Email, To, Subject, Text, adjuntos con "attach another file", prioridad, Reply-To) → genera el `.eml` descargable + comandos, y el botón **✉ Enviar AHORA (real, vía swaks)** con puerto, TLS y auth configurables; transcripción SMTP y veredicto en pantalla |
| **Hardening** | Registros recomendados copiables con un click |

La web pública de GitHub Pages (`site/`) es solo documentación — sin backend, sin API.

---

## ⚙️ API local (para integraciones)

| Endpoint | Método | Descripción |
|---|---|---|
| `/api/analyze?domain=` | GET | Análisis completo |
| `/api/spooftest?domain=&motif=` | GET | Drill sin envío + veredicto previsto |
| `/api/spooflab/compose` | POST | Compositor: campos libres → `.eml` + comandos |
| **`/api/spooflab/swaks`** | **POST** | **Envío REAL vía swaks** con los parámetros del formulario |
| `/api/spooflab/send` | POST | Envío in-domain (guard de dominio propio) |
| `/api/spooflab/check` | POST | Verificación IMAP |
| `/api/rollout?domain=` | GET | Plan DMARC por fases |

```bash
# Envío real por API:
curl -X POST http://localhost:8787/api/spooflab/swaks \
  -H 'Content-Type: application/json' \
  -d '{"from_name":"CE0 Carlos Pérez","from_email":"jefe@midominio.com",
       "to":"test@midominio.com","subject":"Drill","text":"Prueba",
       "priority":"high","tls_mode":"tls"}'
# → {"sent":true,"verdict":"accepted","code":250,"transcript":[…],…}
```

---

## 🔬 Cómo funciona por dentro

```
mailforge.py (CLI Rich)          server/index.js (API Node)        web/ (React)
        │                               │  JSON sobre HTTP            │
        └───────────────┬───────────────┴──────────────┬──────────────┘
                        ▼                              ▼
                     api.py  ◄──── puente JSON (##JSON##) ────►  callCore()
                        │
        ┌───────────────┼───────────────────────────────┐
        ▼               ▼                               ▼
   core/dnsx.py    core/spf|dkim|dmarc.py          core/scorer.py
   UDP→TCP→DoH     parsers RFC 7208/6376/7489      scoring 0-100 + 8 vectores
        │               │                               │
        └───────┬───────┴───────────┬───────────────────┘
                ▼                   ▼
        core/hardening.py      core/swaks_bridge.py
        hardening + drills     compose_spoof_email() → .eml
        selftest, IMAP         swaks_send() → subprocess swaks
                               parse_transcript() → veredicto
```

- **DNS**: cliente propio (RFC 1035) con EDNS0(4096)+DNSSEC OK, compresión de punteros, fallback UDP→TCP→DoH (dns.google/Cloudflare JSON) con throttle+retry.
- **Mensaje**: `EmailMessage` + `formataddr` (RFC 2047 solo en el nombre visible), MIME `multipart/mixed` para adjuntos.
- **Envío**: `subprocess.run(argv)` con lista de argumentos (nunca shell → imposible la inyección de comandos), fichero `.eml` temporal con permisos 0600 y borrado garantizado, `--data @fichero` para entrega byte a byte.
- **Veredicto**: parser de la transcripción swaks (`<~` respuestas, `**` errores); el código del fin-de-DATA decide (el 221 de cierre se ignora).

---

## 🩺 Solución de problemas

| Síntoma | Causa probable | Solución |
|---|---|---|
| `swaks no está instalado` | Falta el binario | `sudo apt install swaks` · `brew install swaks` |
| Timeout / "no se pudo contactar" | Puerto 25 saliente bloqueado (ISP/cloud) | Usa `--relay smtp.turelay.com --port 587` o un VPS |
| `550 5.7.26` en drills hacia TU dominio | Tu DMARC está en `p=reject` | ✅ Es el resultado esperado tras el hardening |
| El correo no aparece en INBOX | Filtros del receptor | Revisa spam/cuarentena; también es resultado válido |
| `421` / `450` | Greylisting | Reintenta en 5-15 min |
| En la web "swaks no está instalado" | El binario falta donde corre `server/` | Instala swaks en la misma máquina que el servidor |
| DoH lento/errores DNS | Red restrictiva | Automático: cae a TCP/53 y luego DoH; revisa firewall |

---

## 📚 Docs

- **Manual exhaustivo en la web**: <https://d1se0.github.io/emailSpoofingTool/docs.html> — cada comando, cada flag, ejemplos paso a paso, glosario y arquitectura interna.
- **`docs.md`**: la misma referencia en Markdown, dentro del repo.
- **`.github/RELEASE_NOTES_*.md`**: qué cambia en cada versión.

## 🤝 Uso legítimo

MailForge existe para **defender**: analiza, simula sobre tu propiedad y hardeniza. Los envíos reales están pensados para **simulacros de phishing autorizados** sobre buzones propios (como marcan ISO 27001, NIST 800-115 o los programas de pentest internos). Ejecutar suplantación contra terceros con esta (o cualquier) herramienta es ilegal. El aviso de entorno controlado se muestra antes de cada envío; respétalo.

## 📄 Licencia

MIT — ver [LICENSE](LICENSE).

---

<div align="center">

**MailForge v1.3.0** · hecho con 🛡 para la comunidad · [web de documentación](https://d1se0.github.io/emailSpoofingTool/docs.html)

</div>
