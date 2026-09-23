# MailForge v1.2.0 — "Real Delivery"

Tercera release de **MailForge**: el Spoof Lab ahora **envía de verdad** y te
dice si el mensaje llegó al destinatario, como pedía el flujo clásico de
emkei.cz — pero defensivo: el drill solo apunta a buzones del dominio que
analizas y declaras tuyo.

## 🚀 Nuevo: envío real del drill con veredicto del servidor

- **Entrega real por SMTP**: conecta directamente al MX del dominio analizado
  (o a tu relay con `--relay/--port`), negocia STARTTLS si está disponible y
  envía el mensaje suplantado de verdad.
- **Transcripción SMTP completa**: cada línea `send:`/`reply:` de la conversación
  (EHLO, MAIL FROM, RCPT TO, DATA…) queda expuesta en CLI y consola web.
- **Veredicto inequívoco**:
  - `ACEPTADO (250)` → el MTA encoló el mensaje; la llegada a INBOX/spam depende
    de los filtros.
  - `RECHAZADO (5xx)` → tu DMARC/SPF bloqueó la suplantación (con el código
    exacto, p. ej. `550 5.7.26 Sender DMARC evaluation failed`).
- **¿Llegó de verdad? — verificación IMAP**: tras un envío aceptado, consulta tu
  buzón por IMAP y busca el drill (cabecera `X-Mailer: MailForge-SpoofLab`) en
  INBOX, Junk, Spam, Gmail/Spam… y te dice: **INBOX (suplantable)**, **spam
  (filtrado parcial)** o **no localizado (rechazado/en tránsito)**. La contraseña
  IMAP se usa solo en memoria.
- **Nuevos flags del comando `drill`**: `--motif`, `--exec`, `--relay`, `--port`,
  `--imap host[/usuario]`, `--imap-wait`, `--yes`.
- **Nuevos endpoints**: `POST /api/spooflab/send` y `POST /api/spooflab/check`
  (con el guard in-domain: 403 para cualquier destinatario externo).

## 📚 Nuevo: documentación exhaustiva como página aparte

- **`site/docs.html`** — manual hiperdetallado, separado de la portada:
  convenciones y datos ficticios, sintaxis y tabla de flags de **cada comando**
  (`analyze`, `dkim`, `spf`, `dmarc`, `dnssec`, `tls`, `vectors`, `harden`,
  `rollout`, `spooftest`, `drill`, `selftest`, `verify`, `report`, `watch`,
  REPL), guía paso a paso de la consola web, referencia completa de la API
  local con ejemplos `curl`, variables de entorno, tabla de troubleshooting y
  **recetas de principio a fin**.
- **README.md** reescrito con ejemplos de sintaxis y ejecuciones ficticias
  completas (entradas y salidas).

## 📦 Instalación / actualización

```bash
git pull origin main
python3 mailforge.py drill midominio.com jefe@midominio.com \
    --imap imap.midominio.com --imap-wait 45
```

## ⚖️ Nota de alcance

El envío real está limitado por diseño a buzones del dominio analizado (guard
en CLI, API y core). El objetivo es medir si TU dominio resiste la suplantación,
no suplantar a terceros.
