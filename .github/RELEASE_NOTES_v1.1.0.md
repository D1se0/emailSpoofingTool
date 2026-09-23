# MailForge v1.1.0 — "Spoof Lab"

Segunda release de **MailForge**, la suite defensiva anti-email-spoofing.

## 🎭 Nuevo: Spoof Lab (la perspectiva del atacante)

La función más solicitada: ver el spoofing **desde el lado del atacante** sin
convertir la herramienta en phishing.

- **Render del ataque**: genera el email suplantado realista que un atacante
  crearía contra tu dominio — `From: "CEO (aviso urgente)" <ceo@tudominio>`,
  `Reply-To` secuestrado, y 3 motivos de ingeniería social (factura urgente,
  contraseña expirada, bonus/giftcard).
- **Predicción de veredicto**: consulta tu postura DNS en vivo y predice si el
  drill acabaría en *bandeja de entrada* (dominio suplantable), *cuarentena* o
  *rechazo 550* — con la base de la predicción (`DMARC p=…`, `SPF all=…`).
- **Inyección por el operador**: MailForge **nunca conecta al MX de destino**
  para este drill; entrega los comandos exactos (`swaks` / `sendmail`) para que
  tú lo inyectes desde **tu relay** hacia **un buzón tuyo**, y observes el
  resultado real: inbox vs spam vs rechazo, `Authentication-Results` y el
  informe rua del día.

## 🖥🌐 Arquitectura web separada

Hasta ahora la web pública y la consola de testeo compartían código; ahora son
dos artefactos independientes:

| Artefacto | Qué es | Dónde |
|---|---|---|
| **Web pública** (`site/`) | Documentación, arquitectura, RFCs, descargas. **Estática pura**, sin backend, sin llamadas a API. | GitHub Pages |
| **Consola local** (`web/` + `server/`) | Dashboard de testeo conectado al motor: Analyzer en vivo, **Spoof Lab**, Hardening, Self-test. | `cd server && npm start` → `:8787` |

La web pública explica explícitamente que el análisis interactivo vive en la
consola local — cero confusión.

## ✨ Mejoras menores

- Badge "modo local" en la consola para distinguirla de la web pública.
- Nuevo endpoint `/api/spooftest` con guard in-domain.
- Nuevo comando CLI `spooftest <dominio> [motivo]`.
- Release notes por tag (`.github/RELEASE_NOTES_<tag>.md`).

## 📦 Instalación

```bash
git clone https://github.com/D1se0/emailSpoofingTool.git
cd emailSpoofingTool
pip3 install -r requirements.txt
./mailforge.sh spooftest midominio.com invoice   # el drill, sin enviar nada
./mailforge.sh                                   # modo interactivo
```

## 🙏 Créditos

Inspirado en dmarcian, EasyDMARC y MXToolbox — en una sola suite portable.
