# MailForge v1.0.0 — "First Forge"

Primera release pública de **MailForge**, la suite defensiva anti-email-spoofing.

## ✨ Qué incluye

### Motor de análisis (Python, stdlib-only)
- **SPF (RFC 7208)**: parser completo con calificadores, modifiers, límite de
  lookups, aviso de `+all` implícito y seguimiento de `redirect=` (como el de
  `gmail.com → _spf.google.com`).
- **DKIM (RFC 6376)**: caza de ~60 selectores comunes (incluye estilo fechas de
  Google Workspace), seguimiento de **CNAMEs** (Microsoft 365), detección de
  claves revocadas (`p=` vacío), **wildcards DNS con clave vacía** y verificación
  criptográfica real de firmas (RSA PKCS#1 v1.5 + Ed25519, verify-only).
- **DMARC (RFC 7489)**: descubrimiento con fallback al dominio organizacional,
  validación completa de tags, `sp=`/`pct`/alineación estricta.
- **DNSSEC**: detección triple (AD bit, RRSIG, DS en zona padre).
- **MTA-STS + TLS-RPT + BIMI** y prueba **STARTTLS real** contra tus MX.
- **Scoring 0–100 ponderado** con grados A–F y desglose por pilar.
- **8 vectores de ataque simulados** con probabilidad y mitigación.
- Resolución DNS **UDP → TCP → DoH** con fallback automático: funciona incluso
  con el puerto 53 bloqueado.

### Experiencia
- **CLI interactiva** (`mailforge.py`) con Rich: banner arcoíris, barras,
  paneles, 14 comandos y modo REPL.
- **Web dashboard React**: landing con terminal animada, analyzer en vivo con
  gauge de score animado, matriz de vectores, generador de hardening y sección
  **Docs** completa.
- **API Node stdlib-only** que sirve la web y expone `/api/analyze`,
  `/api/harden`, `/api/rollout`, `/api/selftest`, `/api/verify`.

### Defensas generadas
- Registros DNS listos para producción (SPF/DKIM/DMARC/MTA-STS/TLS-RPT).
- Config Postfix + OpenDKIM y guía de **rotación de claves DKIM**.
- **Plan de rollout DMARC por fases** (none → quarantine → reject).

### Seguridad por diseño
- El análisis **nunca envía email**. El único envío es el **self-test
  autorizado**, restringido por doble guard a buzones del dominio analizado.
- Criptografía verify-only; sin telemetría ni estado.

## 📦 Instalación

```bash
git clone https://github.com/TU_USUARIO/emailSpoofingTool.git
cd emailSpoofingTool
pip3 install -r requirements.txt
./mailforge.sh analyze gmail.com

# Web opcional:
cd server && npm install && npm start   # :8787
cd web && npm install && npm run build  # servida por la API
```

## 🙏 Créditos

Inspirado en las mejores de dmarcian, EasyDMARC y MXToolbox — en un solo
binario portable y open source.

**SHA256 del tarball**: publicado en la release de GitHub.
