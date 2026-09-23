"use strict";
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");

test("web build output exists (app.js + index.html)", () => {
  assert.ok(fs.existsSync(path.join(ROOT, "build", "app.js")), "run: npm run build");
  assert.ok(fs.existsSync(path.join(ROOT, "build", "index.html")));
  const js = fs.readFileSync(path.join(ROOT, "build", "app.js"), "utf8");
  assert.ok(js.length > 50000, "bundle suspiciously small");
  assert.ok(!js.includes("MAILFORGE_API_URL"), "no placeholder left");
});

test("index.html references bundle assets", () => {
  const html = fs.readFileSync(path.join(ROOT, "build", "index.html"), "utf8");
  assert.ok(html.includes("app.js"));
  assert.ok(html.includes("app.css"));
});

test("styles define key design tokens", () => {
  const css = fs.readFileSync(path.join(ROOT, "src", "styles.css"), "utf8");
  for (const token of ["--accent", "aurora", "score-ring", "vec-table", "@keyframes"]) {
    assert.ok(css.includes(token), `missing token: ${token}`);
  }
});
