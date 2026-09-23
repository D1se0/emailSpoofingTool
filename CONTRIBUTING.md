# Contributing to MailForge

¡Gracias por tu interés! Este proyecto mantiene un **alcance estrictamente
defensivo**: análisis, scoring y hardening. No se aceptarán contribuciones que
añadan envío de emails suplantados a terceros, generación de phishing o
automatización de spam.

## Cómo contribuir

1. Haz fork y crea una rama: `git checkout -b feat/mi-mejora`
2. Añade tests para cualquier cambio:
   - Core Python: `tests/test_core.py` (pytest, markers `network`)
   - Servidor: `server/test/api.test.js` (node:test)
   - Web: `web/test/web.test.js`
3. Ejecuta las suites localmente:
   ```bash
   python3 -m pytest tests/ -m "not network" -q
   cd server && node --test test/api.test.js
   cd web && npm run build && node --test test/web.test.js
   ```
4. Commit claro y PR describiendo el *por qué* del cambio.

## Convenciones

- Core Python: **stdlib-only** (rich opcional). Sin dependencias nuevas sin discusión previa.
- Servidor Node: **stdlib-only** por diseño (puente ligero).
- Los mensajes de commit siguen el estilo `area: resumen breve` (ej. `dkim: follow CNAME chains on selector lookup`).

## Reporte de bugs

Abre un issue con: dominio de prueba (o `example.com`), comando ejecutado,
salida completa y versión de Python/Node.
