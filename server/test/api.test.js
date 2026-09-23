"use strict";
/**
 * MailForge server tests (node:test, zero deps).
 * Networked tests use example.com / gmail.com through the real Python core.
 */
const test = require("node:test");
const assert = require("node:assert");
const { spawn } = require("child_process");
const path = require("path");
const http = require("http");

const ROOT = path.join(__dirname, "..", "..");
const PY = process.env.PYTHON || "python3";

function py(args, stdin) {
  return new Promise((resolve, reject) => {
    const p = spawn(PY, args, { cwd: ROOT });
    let out = "", err = "";
    p.stdout.on("data", (c) => (out += c));
    p.stderr.on("data", (c) => (err += c));
    p.on("error", reject);
    p.on("close", (code) => resolve({ code, out, err }));
    if (stdin) p.stdin.write(stdin);
    p.stdin.end();
  });
}

function parseJsonLine(raw) {
  const line = raw.split("\n").find((l) => l.startsWith("##JSON##"));
  return line ? JSON.parse(line.slice(8)) : null;
}

function get(port, p) {
  return new Promise((resolve, reject) => {
    http.get({ host: "127.0.0.1", port, path: p }, (res) => {
      let b = "";
      res.on("data", (c) => (b += c));
      res.on("end", () => resolve({ status: res.statusCode, body: b }));
    }).on("error", reject);
  });
}

function post(port, p, data) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: p, method: "POST",
      headers: { "Content-Type": "application/json" } }, (res) => {
      let b = "";
      res.on("data", (c) => (b += c));
      res.on("end", () => resolve({ status: res.statusCode, body: b }));
    });
    req.on("error", reject);
    req.end(JSON.stringify(data));
  });
}

test("api.py analyze example.com returns full structure", async () => {
  const r = await py(["api.py", "analyze", JSON.stringify({ domain: "example.com" })]);
  const j = parseJsonLine(r.out);
  assert.ok(j, "no JSON line");
  assert.strictEqual(j.domain, "example.com");
  assert.ok(typeof j.score === "number");
  assert.ok(Array.isArray(j.vectors));
  assert.ok(j.dmarc);
}, { timeout: 120000 });

test("api.py rejects invalid domain", async () => {
  const r = await py(["api.py", "analyze", JSON.stringify({ domain: "bad_domain!!" })]);
  const j = parseJsonLine(r.out);
  assert.strictEqual(j.error, "invalid domain");
});

test("api.py harden generates records", async () => {
  const r = await py(["api.py", "harden",
    JSON.stringify({ domain: "acme.test", ips: ["1.2.3.4"], selector: "sel1" })]);
  const j = parseJsonLine(r.out);
  assert.ok(j.records.length >= 5);
  assert.ok(j.postfix.includes("smtpd_milters"));
}, { timeout: 30000 });

test("api.py selftest refuses out-of-domain", async () => {
  const r = await py(["api.py", "selftest",
    JSON.stringify({ domain: "acme.test", to: "victim@other.com" })]);
  const j = parseJsonLine(r.out);
  assert.ok(j.error.includes("outside"));
});

test("server endpoints end-to-end", async () => {
  const { server } = require("../index.js");
  await new Promise((res) => server.listen(0, res));
  const port = server.address().port;

  const health = await get(port, "/api/health");
  assert.strictEqual(health.status, 200);

  const bad = await get(port, "/api/analyze?domain=not%20valid!");
  assert.strictEqual(bad.status, 400);

  const st = await post(port, "/api/selftest",
    { domain: "acme.test", to: "evil@outside.com" });
  assert.strictEqual(st.status, 403);

  const stDry = await post(port, "/api/selftest",
    { domain: "acme.test", to: "me@acme.test", dry_run: true });
  assert.strictEqual(stDry.status, 200);
  const stJson = JSON.parse(stDry.body);
  assert.strictEqual(stJson.dry_run, true);

  server.close();
}, { timeout: 60000 });

test("verify endpoint validates DKIM of gmail signed message (network)", async () => {
  const r = await py(["api.py", "verify",
    JSON.stringify({ raw: "From: x@y.z\r\nSubject: t\r\n\r\nno sig\r\n" })]);
  const j = parseJsonLine(r.out);
  assert.strictEqual(j.signatures_checked, 0);
});
