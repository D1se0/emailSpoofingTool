# MailForge v1.3.0 — "Real Send"

## 🚀 Envío real integrado (CLI y web)
- **CLI**: `compose --send` ejecuta el envío de verdad con los parámetros que
  especifiques — la herramienta invoca **swaks** por detrás con argv seguro
  (nunca shell), entrega tu `.eml` exacto byte a byte vía `--data @file`,
  resuelve el MX del destinatario automáticamente y muestra la transcripción
  SMTP completa con el veredicto del servidor (250 aceptado / 5xx rechazado).
- **Web**: el Spoof Lab ahora envía de verdad con el botón **"✉ Enviar AHORA
  (real, vía swaks)"** — puerto, modo TLS (oportunista/forzado/sin) y auth
  SMTP configurables desde la interfaz; veredicto y transcripción en pantalla.
- **API**: nuevo endpoint `POST /api/spooflab/swaks` para integraciones.
- Confirmación interactiva antes de cada envío + aviso de entorno controlado.
- Verificación IMAP opcional: ¿llegó a INBOX o a spam?

## 🧾 Compositor
- Nuevas flags: `--smtp-user`, `--port`, `--no-tls` / `--tls-optional` /
  `--tls-only` (contraseñas por `MAILFORGE_SMTP_PASS`, nunca en historial).

## 📚 Documentación para toda la comunidad
- README reescrito: guía desde cero, referencia de CADA parámetro de `compose`
  (qué es, cómo funciona por detrás, ejemplo simple y avanzado), chuleta de
  códigos SMTP, solución de problemas y arquitectura interna.
- docs.html: nueva referencia parámetro a parámetro, sección "Envío real
  (swaks por detrás)" con el flujo completo, arquitectura interna y glosario
  para principiantes (SPF/DKIM/DMARC/envelope/MX/greylisting…).

## 🔧 Interno
- `core/swaks_bridge.py`: `swaks_send()` + `parse_transcript()` con tests.
