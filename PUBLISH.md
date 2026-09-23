# 🚀 Guía de publicación en GitHub — MailForge

Todo está **commiteado localmente** (branch `main`) y testado. Sigue estos pasos
en orden; lleva ~5 minutos.

## 1. Crear el repositorio

1. Ve a <https://github.com/new>
2. Nombre: `emailSpoofingTool` · Visibilidad: pública o privada (a tu gusto)
3. **NO** inicialices con README/license (ya existen aquí)
4. Crea el repo.

## 2. Añadir la clave SSH (deploy key)

Ya tienes el par generado en la raíz del proyecto (RSA-4096, **ignorado por git**,
nunca se sube):

- 🔑 Privada: `deploy_key_rsa` — **guárdala en un sitio seguro, no la compartas**
- 🔒 Pública: `deploy_key_rsa.pub` — esta es la que va a GitHub

**Opción A — Deploy key (recomendada para este repo):**

1. En el repo: `Settings` → `Deploy keys` → `Add deploy key`
2. Título: `mailforge-deploy` · Key: pega el contenido de `deploy_key_rsa.pub`
3. Marca **no** necesitas "Allow write access" salvo que quieras push con ella
4. Añade la clave a tu agente ssh para usarla al pushear:

   ```bash
   eval $(ssh-agent)
   ssh-add deploy_key_rsa
   ```

**Opción B — Clave de tu cuenta (si prefieres SSH global):**

1. `Settings` → `SSH and GPG keys` → `New SSH key`
2. Pega el mismo contenido de `deploy_key_rsa.pub`

## 3. Conectar y subir

```bash
cd emailSpoofingTool
git remote add origin git@github.com:TU_USUARIO/emailSpoofingTool.git
git push -u origin main
```

(Con la opción B y HTTPS sería `https://github.com/TU_USUARIO/emailSpoofingTool.git`.)

## 4. Activar GitHub Pages (modo Actions)

1. `Settings` → `Pages` → **Source: GitHub Actions**
2. El workflow `pages.yml` ya está incluido; en cada push a `main` publicará
   automáticamente la web (landing + docs) en:
   `https://TU_USUARIO.github.io/emailSpoofingTool/`
3. La web en Pages corre en **modo estático**: el Analyzer te indicará que
   arranques la API local (`cd server && npm start`) para análisis en vivo.
   Landing, Docs y Hardening funcionan igualmente.

## 5. Crear la Release v1.0.0

El workflow `release.yml` se dispara al crear un tag:

```bash
git tag -a v1.0.0 -m "MailForge v1.0.0 — First Forge"
git push origin v1.0.0
```

Automáticamente creará la Release con:

- 📦 `emailSpoofingTool-v1.0.0.tar.gz` y `.zip` portables
- 🔐 `SHA256SUMS.txt` con checksums
- 📝 Release notes (de `.github/RELEASE_NOTES_v1.0.0.md`) + notas autogeneradas

O, si prefieres hacerlo a mano: `Releases` → `Draft a new release` → elige el
tag `v1.0.0` → pega el contenido de `.github/RELEASE_NOTES_v1.0.0.md` → adjunta
los tarballs → `Publish release`.

## 6. CI automático

Con cada push/PR, `.github/workflows/tests.yml` ejecuta:

- pytest offline (45 tests) + tests de red (best-effort)
- build de la web + node:test de web y servidor

## 7. Verificación final

```bash
git clone git@github.com:TU_USUARIO/emailSpoofingTool.git /tmp/mf-check
cd /tmp/mf-check && pip3 install -r requirements.txt
./mailforge.sh analyze example.com    # debe mostrar score B y DNSSEC firmado
```

---

**Resumen de archivos clave para la publicación:**

| Fichero | Propósito |
|---|---|
| `deploy_key_rsa.pub` | clave pública → GitHub Deploy keys |
| `deploy_key_rsa` | clave privada (NUNCA al repo) |
| `.github/workflows/pages.yml` | Pages en modo Actions |
| `.github/workflows/release.yml` | Release automática por tag |
| `.github/workflows/tests.yml` | CI de tests |
| `.github/RELEASE_NOTES_v1.0.0.md` | notas de la v1.0.0 |
