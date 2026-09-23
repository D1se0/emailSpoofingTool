import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

// ─────────────────────────────────────────────────────────────────
// tiny hash router
// ─────────────────────────────────────────────────────────────────
function useRoute() {
  const [route, setRoute] = useState(window.location.hash.replace(/^#/, "") || "/");
  useEffect(() => {
    const fn = () => setRoute(window.location.hash.replace(/^#/, "") || "/");
    window.addEventListener("hashchange", fn);
    return () => window.removeEventListener("hashchange", fn);
  }, []);
  return route;
}

function navigate(to) {
  window.location.hash = to;
  window.scrollTo({ top: 0 });
}

// ─────────────────────────────────────────────────────────────────
// API client
// ─────────────────────────────────────────────────────────────────
async function api(path, opts) {
  let res, data;
  try {
    res = await fetch(path, opts);
    data = await res.json();
  } catch (_) {
    throw new Error("API no disponible — esta consola necesita el backend local: " +
      "ejecuta `cd server && npm start` y abre http://localhost:8787");
  }
  if (!res.ok || data.error) throw new Error(data.error || `HTTP ${res.status}`);
  if (!data || typeof data !== "object") throw new Error("respuesta inválida de la API");
  return data;
}

const analyzeDomain = (d) => api(`/api/analyze?domain=${encodeURIComponent(d)}`);
const hardenDomain = (d, extra = "") => api(`/api/harden?domain=${encodeURIComponent(d)}${extra}`);

// ─────────────────────────────────────────────────────────────────
// shared UI
// ─────────────────────────────────────────────────────────────────
function Nav({ route }) {
  const links = [
    ["/", "Inicio"],
    ["/analyzer", "Analyzer"],
    ["/spooflab", "Spoof Lab"],
    ["/harden", "Hardening"],
    ["/docs", "Docs"],
  ];
  return (
    <nav className="nav">
      <div className="container nav-inner">
        <a className="brand" href="#/">
          <span className="shield">🛡</span>
          Mail<em>Forge</em>
        </a>
        <div className="nav-links">
          {links.map(([to, label]) => (
            <a key={to} href={`#${to}`} className={route === to ? "active" : ""}>
              {label}
            </a>
          ))}
          <a className="nav-cta" href="#/analyzer">Escanear ahora</a>
          <span className="local-badge" title="Consola local conectada al motor">🖥 modo local</span>
        </div>
      </div>
    </nav>
  );
}

function Footer() {
  return (
    <footer>
      <div className="container foot-inner">
        <div>
          🛡 <b>MailForge</b> — Anti-Spoofing Suite · MIT License
        </div>
        <div>
          <a href="#/docs">Docs</a>
          <a href="https://github.com/" target="_blank" rel="noreferrer">GitHub</a>
        </div>
      </div>
    </footer>
  );
}

function ScoreRing({ score, grade, label }) {
  const [shown, setShown] = useState(0);
  useEffect(() => {
    let raf;
    const t0 = performance.now();
    const tick = (t) => {
      const k = Math.min(1, (t - t0) / 1100);
      const eased = 1 - Math.pow(1 - k, 3);
      setShown(Math.round(eased * score));
      if (k < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [score]);

  const R = 78, C = 2 * Math.PI * R;
  const color = score >= 85 ? "#5be49b" : score >= 70 ? "#a3e635" :
                score >= 50 ? "#ffd24d" : score >= 25 ? "#ff8a4d" : "#ff5c7a";
  return (
    <div className="score-ring">
      <svg width="190" height="190">
        <circle cx="95" cy="95" r={R} stroke="rgba(120,140,255,0.12)" strokeWidth="14" fill="none" />
        <circle cx="95" cy="95" r={R} stroke={color} strokeWidth="14" fill="none"
          strokeLinecap="round" strokeDasharray={C}
          strokeDashoffset={C - (C * shown) / 100}
          style={{ filter: `drop-shadow(0 0 10px ${color}66)` }} />
      </svg>
      <div className="num">
        <b style={{ color }}>{score}</b>
        <span>{grade} — {label}</span>
      </div>
    </div>
  );
}

function Bar({ label, value }) {
  const [w, setW] = useState(0);
  useEffect(() => {
    const t = setTimeout(() => setW(value), 60);
    return () => clearTimeout(t);
  }, [value]);
  const cls = value >= 85 ? "good" : value >= 50 ? "mid" : "bad";
  return (
    <div className="bar-row">
      <div className="lbl">{label}</div>
      <div className="bar-track"><div className={`bar-fill ${cls}`} style={{ width: `${w}%` }} /></div>
      <div className="val">{value}/100</div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// Landing (hero + animated terminal + features)
// ─────────────────────────────────────────────────────────────────
const TERM_LINES = [
  ["t-dim", "$ mailforge analyze midominio.com"],
  ["t-cmd", "→ Resolviendo SPF · DKIM · DMARC · DNSSEC · MTA-STS…"],
  ["t-ok",  "✔ SPF        v=spf1 … -all            100/100"],
  ["t-ok",  "✔ DMARC      p=reject adkim=s aspf=s   92/100"],
  ["t-warn", "⚠ DKIM       selector2 (1024 bits)     45/100"],
  ["t-bad",  "✖ DNSSEC     zona sin firmar            0/100"],
  ["t-dim", "─────────────────────────────────────────────"],
  ["t-bad", "SCORE 41/100 · Grado D — Vulnerable"],
  ["t-warn", "→ 3 vectores de ataque viables detectados"],
  ["t-ok",  "→ harden genera tus registros en 1 comando"],
];

function Terminal() {
  const [n, setN] = useState(0);
  useEffect(() => {
    if (n >= TERM_LINES.length) return;
    const t = setTimeout(() => setN(n + 1), n === 0 ? 500 : 620);
    return () => clearTimeout(t);
  }, [n]);
  return (
    <div className="term fade-up">
      <div className="term-bar"><i /><i /><i /></div>
      <div className="term-body">
        {TERM_LINES.slice(0, n).map(([cls, txt], i) => (
          <div key={i} className={cls}>{txt}</div>
        ))}
        <span className="cursor" />
      </div>
    </div>
  );
}

function Landing() {
  return (
    <div>
      <section className="hero">
        <div className="container">
          <div className="badge"><span className="dot" /> open-source · MIT · stdlib-core</div>
          <h1>
            Tu dominio de email,<br />
            <span className="grad">imposible de suplantar.</span>
          </h1>
          <p className="lead">
            MailForge analiza SPF, DKIM, DMARC, DNSSEC, STARTTLS y MTA-STS de cualquier
            dominio, simula 8 vectores de ataque de spoofing y te genera la configuración
            exacta para blindarlo. Todo desde la terminal o desde esta web.
          </p>
          <div className="hero-actions">
            <a className="btn btn-primary" href="#/analyzer">🔍 Escanear mi dominio</a>
            <a className="btn btn-ghost" href="#/docs"> Leer la documentación</a>
          </div>
        </div>
      </section>

      <section className="container section" style={{ paddingTop: 20 }}>
        <Terminal />
      </section>

      <section className="container section">
        <h2 className="section-title">Todo lo que un atacante probaría. <span style={{ color: "var(--accent)" }}>Antes que él.</span></h2>
        <p className="section-sub">Motor de análisis 100% read-only sobre DNS público + simulación de amenazas + generador de defensas.</p>
        <div className="grid grid-3">
          {[
            ["🧭", "Descubrimiento DNS total", "SPF (incluye redirect), DKIM con caza de 40+ selectores y CNAMEs, DMARC con política de dominio organizacional, DNSSEC vía DS, MTA-STS, TLS-RPT y BIMI."],
            ["🧮", "Scoring ponderado 0-100", "Puntúa cada control con pesos realistas (DMARC 40%, SPF 20%…) y resume tu exposición en un grado A-F con desglose por pilar."],
            ["⚔️", "8 vectores simulados", "Spoof directo, escape por subdominios, replay DKIM, lookalike, bounces nulos, downgrade TLS… con probabilidad estimada y mitigación."],
            ["🛠", "Hardening en 1 click", "Genera TXT de SPF/DMARC/MTA-STS/TLS-RPT listos para producción, config de Postfix+OpenDKIM y guía de rotación de claves DKIM."],
            ["📈", "Rollout DMARC por fases", "Plan p=none → quarantine → reject sin romper remitentes legítimos, con informes rua y ventana de monitorización."],
            ["✉️", "Self-test autorizado", "Un email de prueba a un buzón de TU dominio, marcado con cabeceras de test, para ver los fallos en tus informes DMARC."],
          ].map(([icon, t, d]) => (
            <div className="card" key={t}>
              <div className="icon">{icon}</div>
              <h3>{t}</h3>
              <p>{d}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="container section" style={{ textAlign: "center" }}>
        <h2 className="section-title">¿Tu dominio sobreviviría?</h2>
        <p className="section-sub" style={{ margin: "0 auto 30px" }}>
          Escaneo gratuito, sin registro y read-only. No enviamos ningún email durante el análisis.
        </p>
        <a className="btn btn-primary" href="#/analyzer">Analizar ahora →</a>
      </section>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// Spoof Lab page — red-team drill preview (no send)
// ─────────────────────────────────────────────────────────────────
const MOTIFS = [
  ["invoice", "💳 Factura urgente"],
  ["password", "🔐 Contraseña expirada"],
  ["giftcard", "🎁 Bonus / giftcard"],
];

function SpoofLab() {
  // free-form composer fields (como emkei: From Name/Email, To, Subject, Text, adjuntos)
  const [fromName, setFromName] = useState("");
  const [fromEmail, setFromEmail] = useState("");
  const [to, setTo] = useState("");
  const [subject, setSubject] = useState("");
  const [text, setText] = useState("");
  const [replyTo, setReplyTo] = useState("");
  const [priority, setPriority] = useState("normal");
  const [attachments, setAttachments] = useState([]);   // {filename, content_b64, size}
  const [relay, setRelay] = useState("");
  const [ack, setAck] = useState(false);                // aviso entorno controlado
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [data, setData] = useState(null);               // preview + comandos
  // in-domain fast path (drill real)
  const [inDomain, setInDomain] = useState(true);
  const [sendResult, setSendResult] = useState(null);
  const [sending, setSending] = useState(false);
  const [imap, setImap] = useState("");
  const [imapPass, setImapPass] = useState("");
  const [checking, setChecking] = useState(false);
  const [checkResult, setCheckResult] = useState(null);

  const addFiles = (fileList) => {
    const files = [...fileList].slice(0, 10 - attachments.length);
    files.forEach(f => {
      if (f.size > 4 * 1024 * 1024) { setError(`«${f.name}» supera 4MB`); return; }
      const reader = new FileReader();
      reader.onload = () => setAttachments(prev => [...prev, {
        filename: f.name, mime: f.type || "application/octet-stream",
        content_b64: btoa(new Uint8Array(reader.result).reduce(
          (s, b) => s + String.fromCharCode(b), "")), size: f.size,
      }]);
      reader.readAsArrayBuffer(f);
    });
  };

  const compose = async () => {
    setLoading(true); setError(""); setData(null);
    setSendResult(null); setCheckResult(null);
    try {
      setData(await api("/api/spooflab/compose", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ from_name: fromName, from_email: fromEmail, to,
          subject, text, reply_to: replyTo, attachments, priority,
          smtp_host: relay.trim() || undefined }),
      }));
    } catch (err) { setError(err.message); } finally { setLoading(false); }
  };

  const sendNow = async () => {
    setSending(true); setSendResult(null);
    try {
      setSendResult(await api("/api/spooflab/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: (fromEmail.split("@")[1] || "").trim().toLowerCase(),
          to: to.trim(), motif: "invoice", exec_name: fromName || "CEO",
          smtp_host: relay.trim() || undefined }),
      }));
    } catch (err) { setSendResult({ verdict: "error", error: err.message }); }
    finally { setSending(false); }
  };

  const checkInbox = async () => {
    setChecking(true); setCheckResult(null);
    try {
      const [host, user] = imap.includes("/") ? imap.split("/") : [imap, to];
      setCheckResult(await api("/api/spooflab/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ imap_host: host, imap_user: user || to,
          imap_pass: imapPass, wait_seconds: 20 }),
      }));
    } catch (err) { setCheckResult({ checked: false, error: err.message }); }
    finally { setChecking(false); }
  };

  const verdictColor = (v) => (v || "") + "" === "" ? "var(--muted)"
    : (v.includes("ACEPTADO") || v.includes("INBOX")) ? "var(--bad)"
    : (v.includes("RECHAZADO") || v.includes("REJECT")) ? "var(--good)"
    : "var(--warn)";

  const fieldStyle = { width: "100%", background: "rgba(7,10,19,0.6)", border: "1px solid var(--line-strong)", color: "var(--text)", borderRadius: 10, padding: "11px 14px", fontSize: "0.95rem", outline: "none" };

  return (
    <section className="container section">
      <h2 className="section-title">🎭 Spoof Lab</h2>
      <p className="section-sub">
        Compositor libre al estilo de las herramientas de spoofing: rellena los
        campos, adjunta ficheros, genera el .eml exacto y los comandos de inyección.
        El envío automatizado solo apunta a tu propio dominio; para otros destinos
        usa los comandos manuales que se generan (tú los ejecutas).
      </p>

      <div className="warnbox" style={{ border: "1px solid rgba(255,92,122,0.4)", background: "rgba(255,92,122,0.06)", color: "var(--bad)", borderRadius: 12, padding: "14px 18px", marginBottom: 22, fontSize: "0.9rem", lineHeight: 1.6 }}>
        ⚠ <b>Aviso obligatorio:</b> usa esta herramienta únicamente en un <b>entorno
        controlado</b> y sobre <b>tu propio dominio</b> o con consentimiento explícito
        (simulacros de phishing autorizados). Suplantar dominios de terceros es ilegal.
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <h3 style={{ marginBottom: 14 }}>🧾 Campos del mensaje</h3>
        <div className="grid grid-2" style={{ gap: 14 }}>
          <div>
            <label style={{ color: "var(--muted)", fontSize: "0.82rem" }}>From Name (nombre visible)</label>
            <input style={fieldStyle} placeholder="CE0 Carlos Pérez" value={fromName} onChange={(e) => setFromName(e.target.value)} />
          </div>
          <div>
            <label style={{ color: "var(--muted)", fontSize: "0.82rem" }}>From E-mail (email de envío)</label>
            <input style={fieldStyle} placeholder="jefe@midominio.com" value={fromEmail} onChange={(e) => setFromEmail(e.target.value)} spellCheck={false} />
          </div>
          <div>
            <label style={{ color: "var(--muted)", fontSize: "0.82rem" }}>To (email destinatario)</label>
            <input style={fieldStyle} placeholder="destinatario@correo.com" value={to} onChange={(e) => setTo(e.target.value)} spellCheck={false} />
          </div>
          <div>
            <label style={{ color: "var(--muted)", fontSize: "0.82rem" }}>Subject (asunto)</label>
            <input style={fieldStyle} placeholder="URGENTE: Factura vencida" value={subject} onChange={(e) => setSubject(e.target.value)} />
          </div>
        </div>
        <div style={{ marginTop: 14 }}>
          <label style={{ color: "var(--muted)", fontSize: "0.82rem" }}>Text (descripción / cuerpo)</label>
          <textarea rows={6} style={{ ...fieldStyle, resize: "vertical", fontFamily: "var(--mono)", fontSize: "0.86rem" }}
            placeholder="Cuerpo del mensaje…" value={text} onChange={(e) => setText(e.target.value)} />
        </div>
        <div className="grid grid-3" style={{ gap: 14, marginTop: 14 }}>
          <div>
            <label style={{ color: "var(--muted)", fontSize: "0.82rem" }}>Reply-To (opcional)</label>
            <input style={fieldStyle} placeholder="recoger@otro-dominio.com" value={replyTo} onChange={(e) => setReplyTo(e.target.value)} spellCheck={false} />
          </div>
          <div>
            <label style={{ color: "var(--muted)", fontSize: "0.82rem" }}>Prioridad</label>
            <select style={fieldStyle} value={priority} onChange={(e) => setPriority(e.target.value)}>
              <option value="normal">normal</option>
              <option value="high">high (X-Priority 1)</option>
              <option value="low">low</option>
            </select>
          </div>
          <div>
            <label style={{ color: "var(--muted)", fontSize: "0.82rem" }}>Relay SMTP (opcional)</label>
            <input style={fieldStyle} placeholder="smtp.turelay.com" value={relay} onChange={(e) => setRelay(e.target.value)} spellCheck={false} />
          </div>
        </div>

        <div style={{ marginTop: 16 }}>
          <label style={{ color: "var(--muted)", fontSize: "0.82rem" }}>Attachments (máx. 10 · 4MB c/u)</label>
          <input type="file" multiple onChange={(e) => addFiles(e.target.files)}
            style={{ width: "100%", color: "var(--muted)", fontSize: "0.85rem" }} />
          {attachments.length > 0 && (
            <div style={{ marginTop: 8 }}>
              {attachments.map((a, i) => (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "7px 11px", border: "1px solid var(--line)", borderRadius: 9, margin: "5px 0", fontSize: "0.85rem" }}>
                  <span>📎 {a.filename}</span>
                  <span style={{ color: "var(--muted)", marginLeft: "auto", fontFamily: "var(--mono)" }}>{(a.size / 1024).toFixed(1)} KB</span>
                  <button type="button" className="btn btn-ghost btn-sm" onClick={() => setAttachments(attachments.filter((_, j) => j !== i))}>✕</button>
                </div>
              ))}
              <input type="file" multiple onChange={(e) => addFiles(e.target.files)}
                style={{ width: "100%", color: "var(--muted)", fontSize: "0.82rem", marginTop: 6 }} />
              <div style={{ color: "var(--muted)", fontSize: "0.78rem", marginTop: 3 }}>📎 Attach another file (opcional)</div>
            </div>
          )}
        </div>

        <div style={{ display: "flex", gap: 12, alignItems: "center", marginTop: 18, flexWrap: "wrap" }}>
          <label style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--muted)", fontSize: "0.88rem", cursor: "pointer" }}>
            <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
            Confirmo que uso esto en un entorno controlado / con dominio propio
          </label>
          <button className="btn btn-primary" onClick={compose} disabled={loading || !ack || !fromEmail.includes("@") || !to.includes("@")}>
            {loading ? <><span className="spinner" /> Generando…</> : "⚡ Generar mensaje + comandos"}
          </button>
        </div>
      </div>

      {error && <div className="err-box">⚠ {error}</div>}

      {data && (
        <div className="fade-up">
          {data.warnings && data.warnings.length > 0 && (
            <div className="err-box">⚠ {data.warnings.join(" · ")}</div>
          )}
          {data.notice && (
            <div style={{ border: "1px solid rgba(255,210,77,.4)", background: "rgba(255,210,77,.07)", color: "var(--warn)", borderRadius: 12, padding: "12px 16px", margin: "0 0 16px", fontSize: "0.88rem" }}>{data.notice}</div>
          )}

          <div className="card" style={{ marginBottom: 18 }}>
            <h3>✉️ Mensaje .eml exacto (con adjuntos)</h3>
            <pre style={{ fontSize: "0.74rem", overflowX: "auto", lineHeight: 1.6, background: "rgba(0,0,0,0.4)", padding: 16, borderRadius: 10, maxHeight: 340 }}>{data.message}</pre>
            <div style={{ marginTop: 10, display: "flex", gap: 8, flexWrap: "wrap" }}>
              <button className="btn btn-ghost btn-sm" onClick={() => navigator.clipboard && navigator.clipboard.writeText(data.message)}>📋 Copiar .eml</button>
              <button className="btn btn-ghost btn-sm" onClick={() => {
                const blob = new Blob([data.message], { type: "message/rfc822" });
                const a = document.createElement("a");
                a.href = URL.createObjectURL(blob); a.download = "spoof-drill.eml"; a.click();
              }}>⬇ Descargar .eml</button>
            </div>
          </div>

          <div className="card" style={{ marginBottom: 18 }}>
            <h3>🚀 Inyección manual (tú ejecutas los comandos)</h3>
            <pre style={{ fontSize: "0.74rem", overflowX: "auto", lineHeight: 1.6, whiteSpace: "pre-wrap", background: "rgba(0,0,0,0.4)", padding: 16, borderRadius: 10 }}>{data.commands}</pre>
          </div>

          {/* in-domain fast path: envío automatizado con guard */}
          {fromEmail.includes("@") && to.trim().toLowerCase().endsWith("@" + fromEmail.split("@")[1].trim().toLowerCase()) && (
            <div className="card" style={{ borderColor: "rgba(91,228,155,.4)" }}>
              <h3>📮 Envío automatizado disponible</h3>
              <p style={{ color: "var(--muted)", fontSize: "0.86rem" }}>
                El destinatario pertenece al mismo dominio del From (tu dominio):
                MailForge puede enviarlo por ti al MX con transcripción completa.
              </p>
              <button className="btn btn-primary" onClick={sendNow} disabled={sending || !to.includes("@")}>
                {sending ? <><span className="spinner" /> Enviando…</> : "✉ Enviar drill real (in-domain)"}
              </button>
              {sendResult && (
                <div className="fade-up" style={{ marginTop: 14 }}>
                  <div style={{ padding: "12px 16px", borderRadius: 10, border: "1px solid var(--line-strong)", background: "rgba(0,0,0,.3)" }}>
                    <b style={{ color: sendResult.sent ? "var(--warn)" : sendResult.verdict === "rejected" ? "var(--good)" : "var(--bad)" }}>
                      {sendResult.sent ? "✅ ACEPTADO POR EL SERVIDOR (250)" :
                       sendResult.verdict === "rejected" ? "⛔ RECHAZADO POR EL SERVIDOR" :
                       "⚠ " + (sendResult.error || sendResult.verdict)}
                    </b>
                    {sendResult.mx && <span style={{ color: "var(--muted)" }}> — vía {sendResult.mx}:{sendResult.port}</span>}
                    {sendResult.error && <div style={{ color: "var(--muted)", fontSize: "0.85rem", marginTop: 6 }}>{sendResult.error}</div>}
                  </div>
                  {sendResult.transcript && sendResult.transcript.length > 0 && (
                    <pre style={{ fontSize: "0.72rem", background: "rgba(0,0,0,.45)", border: "1px solid var(--line)", borderRadius: 10, padding: 14, overflowX: "auto", marginTop: 10, lineHeight: 1.55, color: "#c9d4ff" }}>
                      {sendResult.transcript.slice(-26).join("\n")}
                    </pre>
                  )}
                  {sendResult.sent && (
                    <div style={{ marginTop: 12, display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                      <input placeholder="imap.tudominio.com[/usuario]" value={imap} onChange={(e) => setImap(e.target.value)}
                        style={{ background: "rgba(7,10,19,0.6)", border: "1px solid var(--line-strong)", color: "var(--text)", borderRadius: 10, padding: "10px 13px", fontFamily: "var(--mono)", minWidth: 200 }} />
                      <input type="password" placeholder="contraseña IMAP (no se guarda)" value={imapPass} onChange={(e) => setImapPass(e.target.value)}
                        style={{ background: "rgba(7,10,19,0.6)", border: "1px solid var(--line-strong)", color: "var(--text)", borderRadius: 10, padding: "10px 13px", fontFamily: "var(--mono)", minWidth: 190 }} />
                      <button className="btn btn-ghost btn-sm" onClick={checkInbox} disabled={checking || !imap.trim()}>
                        {checking ? <><span className="spinner" /> Buscando…</> : "📥 ¿Llegó? (IMAP)"}
                      </button>
                    </div>
                  )}
                  {checkResult && (
                    <div className="fade-up" style={{ marginTop: 10, padding: "11px 15px", borderRadius: 10, background: "rgba(0,0,0,.3)", border: "1px solid var(--line)", fontWeight: 700, color: checkResult.checked ? verdictColor(checkResult.verdict) : "var(--warn)" }}>
                      {checkResult.checked ? `📥 ${checkResult.verdict}` : `⚠ ${checkResult.error}`}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </section>
  );
}
// ─────────────────────────────────────────────────────────────────
// Analyzer page
// ─────────────────────────────────────────────────────────────────
function Analyzer() {
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [res, setRes] = useState(null);

  const run = async (e) => {
    e && e.preventDefault();
    if (!domain.trim()) return;
    setLoading(true); setError(""); setRes(null);
    try {
      const data = await analyzeDomain(domain.trim().toLowerCase());
      if (!data.domain) throw new Error("respuesta inesperada de la API");
      setRes(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="container section analyzer-panel">
      <h2 className="section-title" style={{ textAlign: "center" }}>Analyzer</h2>
      <p className="section-sub" style={{ margin: "0 auto 30px", textAlign: "center" }}>
        Análisis pasivo completo vía DNS público. Ningún correo se envía.
      </p>
      <form className="scan-box" onSubmit={run}>
        <input
          placeholder="acme.com"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          disabled={loading}
          spellCheck={false}
          autoFocus
        />
        <button className="btn btn-primary" disabled={loading || !domain.trim()}>
          {loading ? <><span className="spinner" /> Escaneando…</> : "Escanear"}
        </button>
      </form>

      {error && <div className="err-box">⚠ {error}</div>}

      {loading && (
        <div style={{ textAlign: "center", color: "var(--muted)", marginTop: 34 }}>
          <div className="spinner" style={{ borderTopColor: "var(--accent)", width: 28, height: 28 }} />
          <p style={{ marginTop: 12 }}>Consultando SPF · DKIM · DMARC · DNSSEC · MTA-STS…</p>
        </div>
      )}

      {res && <AnalysisView res={res} />}
    </section>
  );
}

function AnalysisView({ res }) {
  const spfScore = res.spf?.record ? (
    { "-all": 100, "~all": 70, "+all": 5, "?all": 5 }[res.spf.record.all_policy] ?? 40
  ) : 0;
  const dkimScore = Math.min(100, 45 * (res.dkim?.keys_found || 0));
  const dmarcScore = res.dmarc?.score ?? 0;
  const dnssecScore = res.dnssec?.signed ? 100 : 0;
  const tlsScore = res.starttls?.status === "verified"
    ? (res.mta_sts?.present ? 95 : 70) : 30;

  return (
    <div className="fade-up">
      <div className="score-ring-wrap">
        <ScoreRing score={res.score} grade={res.grade} label={res.summary} />
        <div style={{ minWidth: 300, flex: 1 }}>
          <Bar label="SPF" value={spfScore} />
          <Bar label="DKIM" value={dkimScore} />
          <Bar label="DMARC" value={dmarcScore} />
          <Bar label="DNSSEC" value={dnssecScore} />
          <Bar label="STARTTLS" value={tlsScore} />
        </div>
      </div>

      <div className="grid grid-2">
        <div className="card">
          <h3>⚔️ Vectores de ataque simulados</h3>
          <table className="vec-table">
            <thead><tr><th>Vector</th><th>¿Viable?</th><th>Prob.</th></tr></thead>
            <tbody>
              {res.vectors.map((v) => (
                <tr key={v.name}>
                  <td>
                    <b>{v.name}</b>
                    <div style={{ color: "var(--muted)", fontSize: "0.8rem", marginTop: 3 }}>{v.description}</div>
                  </td>
                  <td><span className={`chip ${v.feasible ? "yes" : "no"}`}>{v.feasible ? "SÍ" : "NO"}</span></td>
                  <td><b style={{ fontFamily: "var(--mono)" }}>{v.likelihood}%</b></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div>
          <div className="card" style={{ marginBottom: 18 }}>
            <h3>🔎 Postura técnica</h3>
            <table className="vec-table">
              <tbody>
                <tr><td>SPF</td><td style={{ fontFamily: "var(--mono)", fontSize: "0.78rem" }}>{res.spf?.raw || "—"}</td></tr>
                <tr><td>DKIM</td><td>{res.dkim?.keys_found ? `${res.dkim.keys_found} clave(s) activa(s)` : (res.dkim?.note || "sin claves públicas visibles")}</td></tr>
                <tr><td>DMARC</td><td style={{ fontFamily: "var(--mono)", fontSize: "0.78rem" }}>{res.dmarc?.raw || "—"}</td></tr>
                <tr><td>MX</td><td style={{ fontFamily: "var(--mono)", fontSize: "0.78rem" }}>{res.mx?.map(m => m.host).slice(0, 3).join(", ") || "—"}</td></tr>
                <tr><td>STARTTLS</td><td><span className={`chip ${res.starttls?.status === "verified" ? "ok" : "med"}`}>{res.starttls?.status || "unknown"}</span></td></tr>
                <tr><td>MTA-STS</td><td><span className={`chip ${res.mta_sts?.present ? "ok" : "bad"}`}>{res.mta_sts?.present ? "publicado" : "ausente"}</span></td></tr>
                <tr><td>DNSSEC</td><td><span className={`chip ${res.dnssec?.signed ? "ok" : "bad"}`}>{res.dnssec?.signed ? "firmado" : "sin firmar"}</span></td></tr>
              </tbody>
            </table>
          </div>

          <div className="card">
            <h3>🚨 Hallazgos</h3>
            {res.findings.map((f, i) => (
              <div key={i} className={`finding ${f.severity}`}>
                <div>
                  <div className="f-title">{f.title}</div>
                  <div className="f-detail">{f.detail}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="card" style={{ marginTop: 18 }}>
        <h3>🧭 Plan de acción</h3>
        <ol style={{ color: "var(--muted)", lineHeight: 2, paddingLeft: 20 }}>
          {res.recommendations.map((r, i) => <li key={i}>{r}</li>)}
        </ol>
        <div style={{ marginTop: 18, display: "flex", gap: 10, flexWrap: "wrap" }}>
          <button className="btn btn-primary btn-sm" onClick={() => navigate(`/harden?d=${res.domain}`)}>
            🛠 Generar configuración defensiva
          </button>
          <a className="btn btn-ghost btn-sm" href={`#/?d=${res.domain}`}>Repetir análisis</a>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// Harden page
// ─────────────────────────────────────────────────────────────────
function Harden({ initialDomain }) {
  const [domain, setDomain] = useState(initialDomain || "");
  const [ips, setIps] = useState("");
  const [selector, setSelector] = useState("s1");
  const [policy, setPolicy] = useState("reject");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const run = async (e) => {
    e && e.preventDefault();
    if (!domain.trim()) return;
    setLoading(true); setError(""); setData(null);
    try {
      const qs = ips.trim() ? `&ips=${encodeURIComponent(ips.trim())}` : "";
      setData(await hardenDomain(domain.trim().toLowerCase(), qs));
    } catch (err) { setError(err.message); } finally { setLoading(false); }
  };

  useEffect(() => { if (initialDomain) run(); }, []);  // eslint-disable-line

  const copy = (text) => navigator.clipboard && navigator.clipboard.writeText(text);

  return (
    <section className="container section">
      <h2 className="section-title">🛠 Hardening generator</h2>
      <p className="section-sub">Registros DNS y configuración de servidor para blindar tu dominio contra spoofing.</p>

      <form className="scan-box" onSubmit={run} style={{ maxWidth: 760 }}>
        <input placeholder="midominio.com" value={domain} onChange={(e) => setDomain(e.target.value)} spellCheck={false} />
        <input placeholder="IPs envío (opcional, coma)" value={ips} onChange={(e) => setIps(e.target.value)} style={{ maxWidth: 240 }} spellCheck={false} />
        <button className="btn btn-primary" disabled={loading || !domain.trim()}>
          {loading ? <span className="spinner" /> : "Generar"}
        </button>
      </form>

      <div style={{ display: "flex", gap: 14, margin: "14px 0 22px", flexWrap: "wrap" }}>
        <label style={{ color: "var(--muted)", fontSize: "0.88rem" }}>
          Selector DKIM:{" "}
          <input value={selector} onChange={(e) => setSelector(e.target.value)}
            style={{ background: "rgba(7,10,19,0.6)", border: "1px solid var(--line-strong)", color: "var(--text)", borderRadius: 8, padding: "7px 10px", width: 110, fontFamily: "var(--mono)" }} />
        </label>
        <label style={{ color: "var(--muted)", fontSize: "0.88rem" }}>
          Política DMARC:{" "}
          <select value={policy} onChange={(e) => setPolicy(e.target.value)}
            style={{ background: "rgba(7,10,19,0.6)", border: "1px solid var(--line-strong)", color: "var(--text)", borderRadius: 8, padding: "7px 10px" }}>
            <option value="reject">reject</option>
            <option value="quarantine">quarantine</option>
            <option value="none">none</option>
          </select>
        </label>
      </div>

      {error && <div className="err-box">⚠ {error}</div>}

      {data && (
        <div className="fade-up">
          <h3 style={{ margin: "26px 0 6px" }}>📄 Registros DNS a publicar</h3>
          <p style={{ color: "var(--muted)", fontSize: "0.88rem", marginBottom: 10 }}>
            Copia cada registro en tu proveedor DNS. TTL recomendado: 3600s.
          </p>
          {data.records.map((r, i) => (
            <div className="record-row" key={i}>
              <div className="rtype">{r.type}</div>
              <div>
                <div className="rname">{r.name}</div>
                <div className="rval" onClick={() => copy(r.value)} title="click para copiar">{r.value}</div>
                <div className="note">💡 {r.note}</div>
              </div>
            </div>
          ))}

          <div className="grid grid-2" style={{ marginTop: 26 }}>
            <div className="card">
              <h3>⚙️ Postfix + OpenDKIM</h3>
              <pre style={{ fontSize: "0.74rem", overflowX: "auto", lineHeight: 1.55 }}>{data.postfix}</pre>
            </div>
            <div className="card">
              <h3>🔑 Rotación de claves DKIM</h3>
              <pre style={{ fontSize: "0.74rem", overflowX: "auto", lineHeight: 1.55, whiteSpace: "pre-wrap" }}>{data.dkim_guide}</pre>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

// ─────────────────────────────────────────────────────────────────
// Docs page
// ─────────────────────────────────────────────────────────────────
function Docs() {
  const toc = [
    ["what", "¿Qué es MailForge?"],
    ["architecture", "Arquitectura"],
    ["scoring", "Modelo de scoring"],
    ["vectors", "Vectores de ataque"],
    ["controls", "SPF · DKIM · DMARC"],
    ["cli", "Referencia CLI"],
    ["web", "Uso de la web"],
    ["selftest", "Self-test autorizado"],
    ["rollout", "Rollout DMARC"],
    ["faq", "FAQ"],
  ];
  return (
    <section className="container section">
      <h2 className="section-title">📚 Documentación</h2>
      <p className="section-sub">Guía completa de la suite: arquitectura, modelo de amenazas y recetas de despliegue.</p>
      <div className="docs-layout">
        <aside className="docs-toc">
          {toc.map(([id, label]) => (
            <a key={id} href={`#${id}`} onClick={(e) => {
              e.preventDefault();
              document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
            }}>{label}</a>
          ))}
        </aside>
        <div className="docs-body">
          <h2 id="what">¿Qué es MailForge?</h2>
          <p>
            MailForge es una <b>suite defensiva anti-spoofing</b> que audita qué tan fácil es
            suplantar un dominio de email y genera la configuración para evitarlo. Cubre los
            estándares <code>SPF (RFC 7208)</code>, <code>DKIM (RFC 6376)</code>,{" "}
            <code>DMARC (RFC 7489)</code>, <code>DNSSEC</code>, <code>MTA-STS (RFC 8460)</code>{" "}
            y <code>TLS-RPT</code>.
          </p>
          <div className="warnbox">
            ⚠ MailForge <b>no envía correos suplantados</b>. El análisis es 100% pasivo (DNS público).
            El único envío posible es el <b>self-test</b>: un único mensaje de prueba dirigido a un
            buzón del dominio analizado, que el operador declara propio.
          </div>

          <h2 id="architecture">Arquitectura</h2>
          <pre>{`emailSpoofingTool/
├── core/            # motor Python (stdlib puro)
│   ├── dnsx.py      #   DNS UDP/TCP/DoH + DNSSEC (DS/AD/RRSIG)
│   ├── spf.py       #   parser RFC 7208 + redirect
│   ├── dkim.py      #   caza de selectores + CNAME + verificación crypto
│   ├── dmarc.py     #   RFC 7489 + dominio organizacional
│   ├── _rsalite.py  #   RSA PKCS#1 v1.5 + Ed25519 (verify-only)
│   ├── scorer.py    #   scoring 0-100 + 8 vectores de ataque
│   └── hardening.py #   generador de defensas + self-test
├── mailforge.py     # CLI interactiva (Rich)
├── api.py           # puente JSON para el servidor
├── server/          # API Node (stdlib-only) + static hosting
├── web/             # dashboard React (esbuild)
└── tests/           # pytest + node:test`}</pre>
          <p>
            El core no tiene dependencias obligatorias: implementa su propio cliente DNS
            (con fallback a DNS-over-HTTPS) y verificación criográfica verify-only. <code>rich</code>{" "}
            es opcional y solo embellece la CLI.
          </p>

          <h2 id="scoring">Modelo de scoring</h2>
          <p>Cada pilar se puntúa 0-100 y se pondera:</p>
          <table>
            <thead><tr><th>Pilar</th><th>Peso</th><th>Qué puntúa</th></tr></thead>
            <tbody>
              <tr><td>DMARC</td><td>40%</td><td>política efectiva (p/sp), pct, alineación estricta, informes rua</td></tr>
              <tr><td>SPF</td><td>20%</td><td>presencia, mecanismo <code>all</code>, errores, límite de 10 lookups, uso de ptr</td></tr>
              <tr><td>DKIM</td><td>10%</td><td>claves públicas activas, fuerza (≥2048 bits), revocadas</td></tr>
              <tr><td>DNSSEC</td><td>10%</td><td>DS en la zona padre / AD bit / RRSIG</td></tr>
              <tr><td>STARTTLS</td><td>10%</td><td>negociación TLS real contra tus MX + MTA-STS + TLS-RPT</td></tr>
              <tr><td>Extras</td><td>10%</td><td>MTA-STS, TLS-RPT, BIMI</td></tr>
            </tbody>
          </table>
          <p>Grados: <code>A ≥ 85</code> · <code>B ≥ 70</code> · <code>C ≥ 50</code> · <code>D ≥ 25</code> · <code>F &lt; 25</code>.</p>

          <h2 id="vectors">Vectores de ataque</h2>
          <ul>
            <li><b>Spoof directo (From desalineado)</b> — el atacante usa su dominio pero imita tu marca; DMARC p=none/ausente lo deja pasar.</li>
            <li><b>Spoof exacto</b> — MAIL FROM en tu dominio desde IP ajena; explota SPF débil (+all/~all).</li>
            <li><b>Lookalike</b> — registra tuempresa.co o un homoglifo IDN; solo mitigable con marca/BIMI/concienciación.</li>
            <li><b>Replay DKIM</b> — reenvía un mensaje legítimamente firmado a miles de destinatarios.</li>
            <li><b>Bounces nulos</b> — abusa de MAIL FROM:&lt;&gt; para inyectar contenido vía DSN.</li>
            <li><b>Escape por subdominio</b> — usa sp=none o subdominios sin política heredada.</li>
            <li><b>Display-name</b> — "CEO &lt;atacante@evil&gt;"; ningún protocolo lo bloquea.</li>
            <li><b>Downgrade STARTTLS</b> — sin MTA-STS/DANE un MITM puede forzar texto claro.</li>
          </ul>

          <h2 id="controls">SPF · DKIM · DMARC en 60 segundos</h2>
          <ul>
            <li><b>SPF</b> autoriza <i>qué servidores</i> pueden enviar por tu dominio (MAIL FROM). Termina siempre en <code>-all</code>.</li>
            <li><b>DKIM</b> firma el correo con clave privada; el DNS publica la pública en <code>selector._domainkey</code>.</li>
            <li><b>DMARC</b> exige que SPF o DKIM pasen <i>y</i> estén alineados con el <code>From:</code> visible; define qué hacer si fallan y a dónde reportar.</li>
          </ul>
          <div className="tipbox">
            💡 Los tres son necesarios: SPF solo cubre el envelope, DKIM puede romperse en tránsito
            (listas de correo), y DMARC es el que realmente decide en la bandeja del destinatario.
          </div>

          <h2 id="cli">Referencia CLI</h2>
          <pre>{`python3 mailforge.py analyze <dominio>       # análisis completo + score
python3 mailforge.py dkim <dominio> [sel…]   # caza de selectores DKIM
python3 mailforge.py harden <dominio>        # registros DNS + config
python3 mailforge.py rollout <dominio>       # plan DMARC por fases
python3 mailforge.py selftest <dom> <to>     # email de prueba autorizado
python3 mailforge.py report <dominio> html   # informe HTML/JSON
python3 mailforge.py watch <dominio> 60      # monitorización continua
python3 mailforge.py                         # modo interactivo`}</pre>

          <h2 id="web">Uso de la web</h2>
          <p>
            Arranca la API (<code>cd server && npm start</code>, puerto 8787) y la web
            (<code>cd web && npm run build</code>; el propio servidor sirve <code>web/build</code>).
            La pestaña <b>Analyzer</b> ejecuta el mismo motor que la CLI; <b>Hardening</b> genera
            los registros; <b>Docs</b> es esta página.
          </p>

          <h2 id="selftest">Self-test autorizado</h2>
          <p>
            El self-test comprueba en la práctica si tu dominio rechaza un fallo de autenticación:
            envía <b>un único</b> mensaje con <code>MAIL FROM: mailforge-selftest@tudominio</code>,
            sin firmar y desde una IP no autorizada, a un buzón tuyo. En{" "}
            <code>Authentication-Results</code> deberías ver <code>spf=fail dkim=none dmarc=fail</code>{" "}
            y el correo debería ir a cuarentena o ser rechazado si p=reject.
          </p>
          <ul>
            <li>Doble guard: el servidor Node y el core Python rechazan destinatarios fuera del dominio.</li>
            <li>Cabecera <code>X-MailForge-Test: authorized-security-selftest</code> + <code>Auto-Submitted: auto-generated</code>.</li>
            <li>Confirmación interactiva del operador antes de cada envío.</li>
          </ul>

          <h2 id="rollout">Rollout DMARC por fases</h2>
          <pre>{`FASE 0   p=none; rua=mailto:…        2-4 semanas: recopilar informes
FASE 1   p=quarantine; pct=25        25% de fallos a spam
FASE 2   p=quarantine; pct=100       si no hay falsos positivos
FASE 3   p=reject; sp=reject; adkim=s; aspf=s   estado final
FASE 4   + MTA-STS enforce + TLS-RPT + BIMI`}</pre>

          <h2 id="faq">FAQ</h2>
          <h3>¿Puedo escanear cualquier dominio?</h3>
          <p>Sí: las consultas DNS son públicas y pasivas. La ética dicta usarlo en dominios propios o con permiso, igual que cualquier escáner de seguridad.</p>
          <h3>¿Guardáis datos?</h3>
          <p>No. El servidor es stateless; no hay base de datos ni telemetría.</p>
          <h3>¿Por qué mi DKIM no aparece?</h3>
          <p>MailForge prueba 40+ selectores comunes; si el tuyo es único, pásalo explícitamente: <code>dkim dominio mi-selector</code>.</p>
          <h3>¿Funciona tras un firewall que bloquea el puerto 53?</h3>
          <p>Sí: el core cae automáticamente a DNS-over-HTTPS (dns.google / Cloudflare).</p>
        </div>
      </div>
    </section>
  );
}

// ─────────────────────────────────────────────────────────────────
// App root
// ─────────────────────────────────────────────────────────────────
function App() {
  const route = useRoute();
  const [path, query] = route.split("?");
  const params = new URLSearchParams(query || "");
  let page;
  if (path === "/analyzer") page = <Analyzer />;
  else if (path === "/spooflab") page = <SpoofLab />;
  else if (path === "/harden") page = <Harden initialDomain={params.get("d") || ""} />;
  else if (path === "/docs") page = <Docs />;
  else page = <Landing />;
  return (
    <>
      <div className="aurora" />
      <div className="orb orb-1" />
      <div className="orb orb-2" />
      <Nav route={path} />
      {page}
      <Footer />
    </>
  );
}

createRoot(document.getElementById("root")).render(<App />);
