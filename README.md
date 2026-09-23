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

## 🧭 CLI

```bash
python3 mailforge.py analyze gmail.com        # análisis completo + score
python3 mailforge.py dkim gmail.com google s1 # caza selectores concretos
python3 mailforge.py harden midominio.com     # registros DNS + config servidores
python3 mailforge.py rollout midominio.com    # plan DMARC por fases
python3 mailforge.py spooftest midominio.com invoice  # drill red-team (sin envío)
python3 mailforge.py report midominio.com html
python3 mailforge.py watch midominio.com 60
python3 mailforge.py                          # modo interactivo
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
