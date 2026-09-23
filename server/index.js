#!/usr/bin/env node
/**
 * MailForge API server (Node stdlib-only, zero npm deps).
 *
 * Endpoints:
 *   GET  /api/health               → { ok, python }
 *   GET  /api/analyze?domain=…     → full analysis JSON
 *   GET  /api/dkim?domain=…        → selector hunt
 *   GET  /api/harden?domain=…&ips=…&selector=…&policy=… → DNS records JSON
 *   GET  /api/rollout?domain=…     → phased DMARC plan (text)
 *   POST /api/selftest             → authorized in-domain test email (dry_run supported)
 *   POST /api/verify               → verify DKIM signature of a pasted raw email
 *
 * Security posture: analysis is read-only DNS. The only send path is the
 * Python core's in-domain self-test, double-guarded here and in Python.
 */
"use strict";

const http = require("http");
const { spawn } = require("child_process");
const path = require("path");
const url = require("url");
const fs = require("fs");

const PORT = process.env.PORT || 8787;
const PY = process.env.PYTHON || "python3";
const CORE_DIR = path.join(__dirname, "..");
const API_SCRIPT = path.join(CORE_DIR, "api.py");

const ALLOWED_ORIGINS = new Set([
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "http://localhost:5000",
  "http://127.0.0.1:5000",
  process.env.ALLOWED_ORIGIN,
].filter(Boolean));

// ---------------------------------------------------------------------------
// Python bridge
// ---------------------------------------------------------------------------

const MAX_DOMAIN = 253;
const DOMAIN_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})*\.[a-z]{2,63}$/i;

function validDomain(d) {
  return typeof d === "string" && d.length <= MAX_DOMAIN && DOMAIN_RE.test(d);
}

function runPython(args, stdinData, timeoutMs = 120000) {
  return new Promise((resolve, reject) => {
    const proc = spawn(PY, args, { cwd: CORE_DIR, env: process.env });
    let out = "", err = "", killed = false;
    const timer = setTimeout(() => {
      killed = true;
      proc.kill("SIGKILL");
      reject(new Error("python timeout"));
    }, timeoutMs);
    proc.stdout.on("data", (c) => { out += c; });
    proc.stderr.on("data", (c) => { err += c; });
    proc.on("error", (e) => { clearTimeout(timer); reject(e); });
    proc.on("close", (code) => {
      if (killed) return;
      clearTimeout(timer);
      if (code !== 0 && !out.trim()) {
        return reject(new Error(err.trim() || `python exit ${code}`));
      }
      resolve(out);
    });
    if (stdinData) proc.stdin.write(stdinData);
    proc.stdin.end();
  });
}

async function callCore(action, payload, timeoutMs) {
  const argv = ["api.py", action];
  if (payload && typeof payload === "object") {
    argv.push(JSON.stringify(payload));
  }
  const raw = await runPython(argv, payload ? JSON.stringify(payload) : null, timeoutMs);
  const line = raw.split("\n").filter((l) => l.startsWith("##JSON##")).pop();
  if (!line) throw new Error("core returned no JSON");
  return JSON.parse(line.replace("##JSON##", ""));
}

// ---------------------------------------------------------------------------
// Static file serving (web/ build output)
// ---------------------------------------------------------------------------

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".map": "application/json",
};

function serveStatic(req, res, pathname) {
  const webRoot = path.join(CORE_DIR, "web", "build");
  let rel = pathname === "/" ? "/index.html" : pathname;
  const file = path.normalize(path.join(webRoot, rel));
  if (!file.startsWith(webRoot)) {
    res.writeHead(403); res.end("forbidden"); return;
  }
  fs.readFile(file, (err, data) => {
    if (err) {
      // SPA fallback
      fs.readFile(path.join(webRoot, "index.html"), (err2, index) => {
        if (err2) { res.writeHead(404); res.end("web build not found — run: cd web && npm run build"); return; }
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(index);
      });
      return;
    }
    const ext = path.extname(file).toLowerCase();
    res.writeHead(200, { "Content-Type": MIME[ext] || "application/octet-stream" });
    res.end(data);
  });
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

function cors(req, res) {
  const origin = req.headers.origin;
  if (origin && (ALLOWED_ORIGINS.has(origin) || process.env.ALLOW_ALL_ORIGINS === "1")) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  }
}

function readBody(req, limit = 512 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) { reject(new Error("body too large")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function send(res, code, obj) {
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(obj));
}

// ---------------------------------------------------------------------------

const server = http.createServer(async (req, res) => {
  cors(req, res);
  if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }

  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  try {
    if (pathname === "/api/health") {
      let python = "unknown";
      try {
        const raw = await runPython(["-c", "import sys;print(sys.version.split()[0])"], null, 5000);
        python = raw.trim();
      } catch (_) { python = "not found"; }
      return send(res, 200, { ok: true, service: "mailforge-api", python });
    }

    if (pathname === "/api/analyze" || pathname === "/api/dkim") {
      const domain = (parsed.query.domain || "").toString().toLowerCase().trim();
      if (!validDomain(domain)) return send(res, 400, { error: "invalid domain" });
      const action = pathname === "/api/analyze" ? "analyze" : "dkim";
      const data = await callCore(action, { domain }, 180000);
      return send(res, 200, data);
    }

    if (pathname === "/api/harden") {
      const domain = (parsed.query.domain || "").toString().toLowerCase().trim();
      if (!validDomain(domain)) return send(res, 400, { error: "invalid domain" });
      const ips = (parsed.query.ips || "").split(",").map(s => s.trim())
        .filter(Boolean).slice(0, 20);
      const selector = (parsed.query.selector || "s1").toString()
        .replace(/[^a-z0-9._-]/gi, "").slice(0, 63) || "s1";
      const policy = ["reject", "quarantine", "none"].includes(parsed.query.policy)
        ? parsed.query.policy : "reject";
      const data = await callCore("harden",
        { domain, ips, selector, policy, rua: (parsed.query.rua || "").toString().slice(0, 254) });
      return send(res, 200, data);
    }

    if (pathname === "/api/spooftest") {
      const domain = (parsed.query.domain || "").toString().toLowerCase().trim();
      if (!validDomain(domain)) return send(res, 400, { error: "invalid domain" });
      const motif = (parsed.query.motif || "invoice").toString()
        .replace(/[^a-z]/g, "").slice(0, 20) || "invoice";
      const to = (parsed.query.to || "").toString().toLowerCase().trim();
      const data = await callCore("spooftest",
        { domain, motif, to: to || undefined });
      return send(res, 200, data);
    }

    if (pathname === "/api/spooflab/compose" && req.method === "POST") {
      const body = JSON.parse((await readBody(req)) || "{}");
      const atts = Array.isArray(body.attachments) ? body.attachments.slice(0, 10) : [];
      const totalB64 = atts.reduce((n, a) => n + String(a.content_b64 || "").length, 0);
      if (totalB64 > 8 * 1024 * 1024) {
        return send(res, 413, { error: "adjuntos demasiado grandes (máx ~6MB en base64)" });
      }
      const data = await callCore("compose", {
        from_name: body.from_name, from_email: body.from_email,
        to: body.to, subject: body.subject, text: body.text,
        reply_to: body.reply_to, attachments: atts,
        priority: body.priority, smtp_host: body.smtp_host,
      }, 60000);
      return send(res, 200, data);
    }

    if (pathname === "/api/spooflab/send" && req.method === "POST") {
      const body = JSON.parse((await readBody(req)) || "{}");
      const domain = (body.domain || "").toString().toLowerCase().trim();
      const to = (body.to || "").toString().toLowerCase().trim();
      if (!validDomain(domain)) return send(res, 400, { error: "invalid domain" });
      if (!/^[^@\s]{1,64}@[^@\s]{1,253}$/.test(to)) {
        return send(res, 400, { error: "invalid recipient" });
      }
      if (!to.endsWith("@" + domain)) {
        return send(res, 403, {
          error: "recipient outside analyzed domain",
          detail: "El envío real del drill solo apunta a buzones del dominio analizado (que el operador declara propio).",
        });
      }
      const data = await callCore("drill_send", {
        domain, to,
        exec_name: body.exec_name, motif: body.motif,
        smtp_host: body.smtp_host, smtp_port: body.smtp_port,
        smtp_user: body.smtp_user, smtp_pass: body.smtp_pass,
        helo: body.helo,
      }, 120000);
      return send(res, 200, data);
    }

    if (pathname === "/api/spooflab/check" && req.method === "POST") {
      const body = JSON.parse((await readBody(req)) || "{}");
      const data = await callCore("drill_check", {
        imap_host: body.imap_host, imap_user: body.imap_user,
        imap_pass: body.imap_pass, wait_seconds: body.wait_seconds,
        imap_port: body.imap_port,
      }, 320000);
      return send(res, 200, data);
    }

    if (pathname === "/api/rollout") {
      const domain = (parsed.query.domain || "").toString().toLowerCase().trim();
      if (!validDomain(domain)) return send(res, 400, { error: "invalid domain" });
      const data = await callCore("rollout", { domain });
      return send(res, 200, data);
    }

    if (pathname === "/api/selftest" && req.method === "POST") {
      const body = JSON.parse((await readBody(req)) || "{}");
      const domain = (body.domain || "").toString().toLowerCase().trim();
      const to = (body.to || "").toString().toLowerCase().trim();
      if (!validDomain(domain)) return send(res, 400, { error: "invalid domain" });
      if (!/^[^@\s]{1,64}@[^@\s]{1,253}$/.test(to)) {
        return send(res, 400, { error: "invalid recipient" });
      }
      if (!to.endsWith("@" + domain)) {
        return send(res, 403, {
          error: "recipient outside analyzed domain",
          detail: "MailForge only sends authorized self-tests to mailboxes of the domain being analyzed (ownership confirmed by the operator).",
        });
      }
      const data = await callCore("selftest",
        { domain, to, dry_run: !!body.dry_run, smtp_host: body.smtp_host || "" });
      return send(res, 200, data);
    }

    if (pathname === "/api/verify" && req.method === "POST") {
      const body = JSON.parse((await readBody(req)) || "{}");
      const raw = (body.raw || "").toString();
      if (!raw || raw.length > 1024 * 1024) return send(res, 400, { error: "raw email required (≤1MB)" });
      const data = await callCore("verify", { raw }, 60000);
      return send(res, 200, data);
    }

    // static web build with SPA fallback
    if (req.method === "GET" && !pathname.startsWith("/api/")) {
      return serveStatic(req, res, pathname);
    }

    send(res, 404, { error: "not found" });
  } catch (e) {
    send(res, 500, { error: e.message || "internal error" });
  }
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`[mailforge-api] listening on http://localhost:${PORT}`);
    console.log(`[mailforge-api] python core: ${API_SCRIPT}`);
  });
}

module.exports = { server, callCore, validDomain };
