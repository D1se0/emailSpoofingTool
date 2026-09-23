#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MailForge CLI — interactive terminal UI (Rich-powered, stdlib fallback).

Commands (interactive menu + one-shot flags):
    analyze <domain>          full passive anti-spoofing analysis
    spf <domain>              SPF deep-dive
    dkim <domain> [selectors] DKIM selector hunt + key audit
    dmarc <domain>            DMARC deep-dive + org-policy
    dnssec <domain>           DNSSEC posture
    tls <domain>              MX / STARTTLS / MTA-STS / TLS-RPT
    vectors <domain>          attack-vector simulation table
    harden <domain>           generate DNS records + server configs
    rollout <domain>          phased DMARC deployment plan
    selftest <domain> <to>    authorized in-domain test email
    report <domain>           export JSON / HTML report
    watch <domain>            periodic re-scan (monitoring)
    config                    settings (colors, save dir, sensitivity)
    banner / about / quit

SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import time

# Make `core` importable both as script and as module.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from core import dnsx, dkim, dmarc, spf, scorer, hardening  # noqa: E402

# Rich is optional: fallback to plain ANSI if missing.
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    from rich.progress import Progress
    from rich.prompt import Prompt, Confirm
    RICH = True
except ImportError:  # pragma: no cover
    RICH = False
    Console = Table = Panel = Text = box = Progress = Prompt = Confirm = None

APP = "MailForge"
VERSION = "1.0.0"
SAVE_DIR = os.path.join(_HERE, "reports")
CONFIG_PATH = os.path.join(_HERE, ".mailforge.json")

if RICH:
    console = Console()
else:
    class _Plain:
        def print(self, *a, **k):
            print(*a)
        def rule(self, *a, **k):
            print("─" * 60)
    console = _Plain()


# --------------------------------------------------------------------------
# Visual identity
# --------------------------------------------------------------------------

BANNER_ART = r"""
 ██████╗ ██╗    ██╗███╗   ███╗
██╔═══██╗██║    ██║████╗ ████║   A N T I - S P O O F I N G   S U I T E
██║   ██║██║ █╗ ██║██╔████╔██║   ────────────────────────────────────
██║▄▄ ██║██║███╗██║██║╚██╔╝██║   SPF · DKIM · DMARC · DNSSEC · MTA-STS
╚██████╔╝╚███╔███╔╝██║ ╚═╝ ██║   Scoring · Hardening · Self-Test
 ╚══▀▀═╝  ╚══╝╚══╝ ╚═══════╝    v{v} — defensive edition
"""


def _rgb(r, g, b):
    return f"rgb({r},{g},{b})"


def show_banner(rainbow: bool = True) -> None:
    if not RICH:
        print(BANNER_ART.format(v=VERSION))
        return
    raw = BANNER_ART.format(v=VERSION)
    if rainbow:
        colors = [(255, 96, 96), (255, 170, 70), (255, 230, 90),
                  (110, 230, 130), (90, 190, 255), (170, 120, 255)]
        art = Text()
        for i, line in enumerate(raw.split("\n")):
            c = colors[i % len(colors)]
            art.append(line + "\n", style=f"bold {_rgb(*c)}")
    else:
        art = Text(raw, style="bold")
    console.print(Panel(art, border_style="magenta", subtitle=f"[{APP} v{VERSION}]",
                        subtitle_align="right"))


def grade_color(score: int) -> str:
    if score >= 85:
        return "green"
    if score >= 70:
        return "bright_green"
    if score >= 50:
        return "yellow"
    if score >= 25:
        return "orange_red1"
    return "red"


SEV_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow",
             "low": "cyan", "ok": "green", "info": "dim"}


# --------------------------------------------------------------------------
# Rendering helpers
# --------------------------------------------------------------------------

def _panel(title, body, border="cyan"):
    if RICH:
        console.print(Panel(body, title=title, border_style=border, expand=True))
    else:
        print(f"── {title} " + "─" * max(0, 50 - len(title)))
        print(body)


def _kv_table(rows: list, title: str):
    if not RICH:
        for k, v in rows:
            print(f"  {k:<22} {v}")
        return
    t = Table(box=box.SIMPLE_HEAD, show_header=False, padding=(0, 2))
    t.add_column(style="bold cyan", no_wrap=True)
    t.add_column()
    for k, v in rows:
        t.add_row(k, str(v))
    _panel(title, t)


def _print_bar(label: str, score: int, width: int = 30):
    filled = int(width * score / 100)
    color = grade_color(score)
    if RICH:
        console.print(f"{label:<28}[{color}]{'█' * filled}{'░' * (width - filled)}[/{color}] {score:>3}/100")
    else:
        print(f"  {label:<28}{'#' * filled}{'.' * (width - filled)} {score}/100")


def print_vector_table(vectors):
    if RICH:
        t = Table(title="Vectores de ataque simulados", box=box.DOUBLE_EDGE,
                  title_style="bold")
        t.add_column("Vector", style="bold")
        t.add_column("Factible", justify="center")
        t.add_column("Prob.", justify="right")
        t.add_column("Notas")
        for v in vectors:
            feas = "[green]No[/green]" if not v.feasible else "[red]Sí[/red]"
            lik_color = grade_color(100 - v.likelihood)
            t.add_row(v.name, feas, f"[{lik_color}]{v.likelihood}%[/{lik_color}]",
                      v.notes[:60])
        console.print(t)
    else:
        print("  %-40s %-8s %s" % ("Vector", "Factible", "Prob."))
        for v in vectors:
            print("  %-40s %-8s %d%%" % (v.name, "SÍ" if v.feasible else "no", v.likelihood))


def print_findings(findings):
    if not findings:
        return
    for f in findings:
        style = SEV_STYLE.get(f["severity"], "")
        icon = {"critical": "⛔", "high": "🔴", "medium": "🟠",
                "low": "🔵", "ok": "✅"}.get(f["severity"], "•")
        if RICH:
            console.print(f" {icon} [{style}]{f['title']}[/{style}] — {f['detail'][:110]}")
        else:
            print(f" {icon} {f['title']} — {f['detail'][:110]}")


def print_recommendations(recs):
    _panel("Plan de acción recomendado", Text("\n".join(
        f"  {i}. {r}" for i, r in enumerate(recs, 1)), justify=None), border="green")


def print_analysis(res: scorer.AnalysisResult, full: bool = True):
    color = grade_color(res.score)
    if RICH:
        head = Text.assemble(
            (" Dominio: ", "bold"), (res.domain, "cyan"),
            ("   ·   Score: ", "bold"),
            (f"{res.score}/100 ({res.grade} — {res.summary})", f"bold {color}"),
            ("   ·   ", "dim"),
            (res.scanned_at[:19], "dim"))
        console.print(Panel(head, border_style=color))
    else:
        print(f"  Dominio: {res.domain}  Score: {res.score}/100 ({res.grade} — {res.summary})")

    _print_bar("SPF", _spf_score(res))
    _print_bar("DKIM", _dkim_score(res))
    _print_bar("DMARC", res.dmarc.get("score", 0))
    _print_bar("DNSSEC", 100 if res.dnssec.get("signed") else 0)
    _print_bar("STARTTLS/MTA-STS", _tls_score(res))

    if full:
        spf_rec = res.spf.get("record")
        _kv_table([
            ("SPF raw", (res.spf.get("raw") or "—")[:78]),
            ("SPF política", spf_rec.all_policy if spf_rec else "—"),
            ("SPF lookups", str(res.spf.get("lookup_count", 0))),
            ("DKIM selectores", ", ".join(k["selector"] for k in res.dkim.get("keys", [])) or "ninguno"),
            ("DMARC", (res.dmarc.get("raw") or "—")[:78]),
            ("DMARC org-policy", "sí (heredada)" if res.dmarc.get("record") and res.dmarc["record"].is_org_policy else "no"),
            ("MX", ", ".join(f"{m['pref']} {m['host']}" for m in res.mx[:4]) or "—"),
            ("STARTTLS", "✅ soportado" if res.starttls.get("supported") else "❌ no verificado"),
            ("MTA-STS", "✅ publicado" if res.mta_sts.get("present") else "❌ ausente"),
            ("TLS-RPT", "✅" if res.tls_rpt.get("present") else "❌"),
            ("BIMI", "✅" if res.bimi.get("present") else "❌"),
            ("DNSSEC", "✅ firmado" if res.dnssec.get("signed") else "❌ sin firmar"),
        ], "Postura técnica")

        print_findings(res.findings)
        if res.vectors:
            print_vector_table(res.vectors)
        print_recommendations(res.recommendations)


def _spf_score(res) -> int:
    rec = res.spf.get("record")
    if res.spf.get("status") != "found" or not rec:
        return 0
    s = {"-all": 100, "~all": 70, "+all": 5, "?all": 5}.get(rec.all_policy, 40)
    if rec.errors:
        s -= 15 * len(rec.errors)
    if res.spf.get("uses_ptr"):
        s -= 5
    return max(0, s)


def _dkim_score(res) -> int:
    s = min(100, 45 * res.dkim.get("keys_found", 0))
    if res.dkim.get("weak_keys"):
        s -= 10 * res.dkim["weak_keys"]
    return max(0, min(s, 100))


def _tls_score(res) -> int:
    if not res.starttls.get("supported"):
        return 0
    s = 70
    if res.mta_sts.get("present"):
        s = 95
    if res.tls_rpt.get("present"):
        s = min(100, s + 5)
    return s


# --------------------------------------------------------------------------
# Report persistence
# --------------------------------------------------------------------------

def save_report(res: scorer.AnalysisResult, fmt: str = "json") -> str:
    os.makedirs(SAVE_DIR, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    base = os.path.join(SAVE_DIR, f"{res.domain}-{stamp}")
    if fmt == "json":
        path = base + ".json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(res.to_dict(), fh, indent=2, ensure_ascii=False, default=str)
        return path
    path = base + ".html"
    html = _render_html(res)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return path


def _render_html(res: scorer.AnalysisResult) -> str:
    color = grade_color(res.score)
    rows = "".join(
        f"<tr><td>{v['name']}</td><td class=\"{'no' if not v['feasible'] else 'yes'}\">"
        f"{'Sí' if v['feasible'] else 'No'}</td><td>{v['likelihood']}%</td></tr>"
        for v in res.vectors)
    recs = "".join(f"<li>{r}</li>" for r in res.recommendations)
    findings = "".join(
        f"<div class='f {f['severity']}'><b>{f['title']}</b><br>{f['detail']}</div>"
        for f in res.findings)
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<title>MailForge — {res.domain}</title><style>
body{{font-family:system-ui,sans-serif;background:#0b0e17;color:#e7eaf3;margin:2rem}}
.card{{background:#121726;border-radius:12px;padding:1.2rem 1.6rem;margin:1rem 0}}
.score{{font-size:3.2rem;font-weight:800;color:{color}}}
table{{border-collapse:collapse;width:100%}}td,th{{padding:.5rem .8rem;border-bottom:1px solid #232b3f;text-align:left}}
.yes{{color:#ff6b6b;font-weight:700}}.no{{color:#5be49b;font-weight:700}}
.f{{padding:.6rem 1rem;border-left:4px solid #555;margin:.4rem 0;background:#161c2c}}
.f.critical{{border-color:#ff4d5e}}.f.high{{border-color:#ff8a4d}}.f.medium{{border-color:#ffd24d}}
.f.low{{border-color:#4dc3ff}}.f.ok{{border-color:#5be49b}}
h1{{letter-spacing:.5px}}code{{color:#8ab4ff}}
</style></head><body>
<h1>🛡 MailForge — Informe {res.domain}</h1>
<div class="card"><span class="score">{res.score}</span>/100 — {res.grade}: {res.summary}
<br><small>{res.scanned_at}</small></div>
<div class="card"><h3>Vectores simulados</h3><table><tr><th>Vector</th><th>Factible</th><th>Prob.</th></tr>{rows}</table></div>
<div class="card"><h3>Hallazgos</h3>{findings}</div>
<div class="card"><h3>Recomendaciones</h3><ol>{recs}</ol></div>
</body></html>"""


# --------------------------------------------------------------------------
# Actions
# --------------------------------------------------------------------------

def do_analyze(domain: str, save: bool = False, fmt: str = "json") -> scorer.AnalysisResult:
    if RICH:
        with Progress(transient=True) as prog:
            task = prog.add_task("[cyan]Analizando…", total=6)
            for _ in range(6):
                time.sleep(0.08)
                prog.advance(task)
    res = scorer.analyze_domain(domain)
    print_analysis(res)
    if save:
        path = save_report(res, fmt)
        console.print(f"  💾 Informe guardado: [bold]{path}[/bold]")
    return res


def do_dkim_hunt(domain: str, selectors=()) -> list:
    console.print(f"  🔍 Rastreando selectores DKIM en [bold cyan]{domain}[/] …")
    keys = dkim.guess_selectors(domain, extra=selectors)
    if not keys:
        console.print("  ❌ No se encontraron claves DKIM con selectores comunes.")
        console.print("     Prueba manualmente: dig TXT <selector>._domainkey.%s" % domain)
        return []
    for k in keys:
        bits = k.weak_bits or "?"
        flag = "⚠ REVOCADA" if k.revoked else ("⚠ DÉBIL (%s bits)" % bits
                                                if k.weak_bits and k.weak_bits < 2048 else "✅")
        _kv_table([
            ("Selector", k.selector),
            ("Tipo", k.key_type),
            ("Bits", str(bits)),
            ("Algoritmos hash", ",".join(k.hash_algs)),
            ("Flags", ",".join(k.flags) or "—"),
            ("Estado", flag),
        ], f"DKIM · {k.selector}.{domain}")
    return keys


def do_hardening(domain: str, ips=(), selector="s1", policy="reject"):
    recs = hardening.generate_records(domain, spf_ips=list(ips), dkim_selector=selector,
                                      dmarc_policy=policy)
    if RICH:
        from rich.markdown import Markdown
        t = Table(box=box.ROUNDED, title=f"Registros DNS recomendados — {domain}",
                  title_style="bold green")
        t.add_column("Tipo", style="bold")
        t.add_column("Nombre", style="cyan", no_wrap=True)
        t.add_column("Valor")
        t.add_column("TTL", justify="right")
        for r in recs:
            t.add_row(r["type"], r["name"], r["value"], str(r["ttl"]))
        console.print(t)
    else:
        for r in recs:
            print(f"  [{r['type']}] {r['name']}  {r['value']}")
    console.print("\n[bold]Notas:[/]")
    for r in recs:
        console.print(f"  • {r['note']}")
    _panel("Config Postfix/OpenDKIM", hardening.generate_postfix_config(domain, selector),
           border="blue")


def do_spooftest(domain: str, to_addr: str = "", motif: str = "invoice"):
    """Red-team drill: render spoofed message + injection commands (no send)."""
    from core import dmarc as _dmarc, spf as _spf
    preview = hardening.build_spoof_preview(domain, motif=motif)
    to_addr = to_addr or f"tu-buzon@{domain}"

    pol_label, pol_color = "desconocido", "dim"
    try:
        drec, _ = _dmarc.fetch_dmarc(domain)
        pol = drec.effective_policy() if drec else "missing"
        pol_label = {"reject": "RECHAZADO (550) — p=reject funciona",
                     "quarantine": "CUARENTENA/SPAM — p=quarantine",
                     "none": "BANDEJA DE ENTRADA — suplantable ❗",
                     "missing": "BANDEJA DE ENTRADA — sin DMARC ❗"}.get(pol, pol)
        pol_color = {"reject": "green", "quarantine": "yellow",
                     "none": "red", "missing": "red"}.get(pol, "dim")
    except Exception:
        pol = None

    _panel(f"Mensaje suplantado (drill) — {domain}", Text(preview["message"][:900]),
           border="red")
    if RICH:
        console.print(f"  Veredicto previsto: [bold {pol_color}]{pol_label}[/]")
    else:
        print(f"  Veredicto previsto: {pol_label}")
    _panel("Comandos de inyección (tú ejecutas, desde TU relay)",
           Text(hardening.generate_injection_commands(domain, to_addr)),
           border="yellow")


def do_selftest(domain: str, to_addr: str, dry=False):
    res = hardening.send_selftest(domain, to_addr, dry_run=dry)
    if res.get("dry_run"):
        console.print("  [yellow]DRY-RUN[/] — mensaje generado (no enviado):")
        console.print(res["message"][:1200])
        return
    if res.get("sent"):
        console.print(f"  ✉ Enviado a [bold]{to_addr}[/] vía MX {res['mx']}")
        console.print("  Revisa la carpeta INBOX/spam y el informe DMARC rua de hoy.")
        console.print("  Esperado en Authentication-Results: [red]spf=fail dkim=none dmarc=fail[/]")
    else:
        console.print(f"  ❌ {res.get('error', 'fallo desconocido')}")


def do_watch(domain: str, interval: int = 300):
    console.print(f"  👁 Monitorizando [bold]{domain}[/] cada {interval}s — Ctrl+C para parar")
    last = None
    try:
        while True:
            res = scorer.analyze_domain(domain)
            if last is not None and res.score != last:
                console.print(f"  [bold {'green' if res.score > last else 'red'}]"
                              f"{time.strftime('%H:%M:%S')} score {last} → {res.score}[/]")
            else:
                console.print(f"  {time.strftime('%H:%M:%S')} score estable: {res.score}/100")
            last = res.score
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("  👋 monitor detenido")


# --------------------------------------------------------------------------
# Config + REPL
# --------------------------------------------------------------------------

def load_config() -> dict:
    defaults = {"rainbow": True, "autosave": False, "sensitivity": "normal"}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as fh:
                defaults.update(json.load(fh))
        except (OSError, ValueError):
            pass
    return defaults


def save_config(cfg: dict) -> None:
    with open(CONFIG_PATH, "w") as fh:
        json.dump(cfg, fh, indent=2)


def config_menu():
    cfg = load_config()
    console.print(f"  rainbow={cfg['rainbow']}  autosave={cfg['autosave']}  "
                  f"sensitivity={cfg['sensitivity']}")
    if RICH:
        cfg["rainbow"] = Confirm.ask("¿Banner arcoíris?", default=cfg["rainbow"])
        cfg["autosave"] = Confirm.ask("¿Guardar informe tras cada análisis?", default=cfg["autosave"])
    else:
        cfg["rainbow"] = input("¿Banner arcoíris? (s/N): ").lower().startswith("s")
        cfg["autosave"] = input("¿Autoguardar informes? (s/N): ").lower().startswith("s")
    save_config(cfg)
    console.print("  ✅ configuración guardada")


def interactive_repl() -> None:
    cfg = load_config()
    show_banner(cfg.get("rainbow", True))
    console.print("  Escribe [bold]help[/] para ver comandos · [bold]quit[/] para salir\n")
    while True:
        try:
            line = Prompt.ask("[bold magenta]mailforge[/]").strip() if RICH \
                else input("mailforge> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        parts = line.split()
        cmd, args = parts[0].lower(), parts[1:]
        if cmd in ("quit", "exit", "q"):
            break
        elif cmd == "help":
            console.print("""  [bold]analyze[/] <dominio>       análisis completo
  [bold]spf[/] <dominio>            detalle SPF
  [bold]dkim[/] <dominio> [sel…]    caza de selectores DKIM
  [bold]dmarc[/] <dominio>          detalle DMARC
  [bold]dnssec[/] <dominio>         estado DNSSEC
  [bold]tls[/] <dominio>            MX/STARTTLS/MTA-STS
  [bold]vectors[/] <dominio>        simulación de vectores
  [bold]harden[/] <dominio>         genera registros/configs
  [bold]rollout[/] <dominio>        plan DMARC por fases
  [bold]selftest[/] <dom> <to>      email de prueba autorizado (in-domain)
  [bold]spooftest[/] <dom> [motivo] drill red-team: mensaje + comandos (sin envío)
  [bold]report[/] <dominio> [json|html]  guarda informe
  [bold]watch[/] <dominio> [seg]    monitorización continua
  [bold]config[/]  ·  [bold]about[/]  ·  [bold]quit[/]""")
        elif cmd == "about":
            console.print(f"  {APP} v{VERSION} — suite defensiva anti-email-spoofing. MIT.")
        elif cmd == "config":
            config_menu()
            cfg = load_config()
        elif cmd == "analyze":
            if args:
                do_analyze(args[0], save=cfg.get("autosave"))
        elif cmd == "dkim":
            if args:
                do_dkim_hunt(args[0], selectors=args[1:])
        elif cmd == "harden":
            if args:
                do_hardening(args[0])
        elif cmd == "spooftest":
            if args:
                do_spooftest(args[0], motif=args[1] if len(args) > 1 else "invoice")
        elif cmd == "selftest":
            if len(args) >= 2:
                if RICH:
                    ok = Confirm.ask(f"Confirmo que {args[0]} es MI dominio y {args[1]} "
                                     "un buzón mío", default=False)
                else:
                    ok = input("¿Es tu dominio/buzón? (s/N): ").lower().startswith("s")
                if ok:
                    do_selftest(args[0], args[1])
                else:
                    console.print("  [red]Cancelado: el self-test solo opera sobre tu propio dominio.[/]")
        elif cmd == "report":
            if args:
                res = scorer.analyze_domain(args[0])
                fmt = args[1] if len(args) > 1 else "json"
                console.print(f"  💾 {save_report(res, fmt)}")
        elif cmd == "watch":
            if args:
                do_watch(args[0], int(args[1]) if len(args) > 1 else 300)
        elif cmd in ("spf", "dmarc", "dnssec", "tls", "vectors", "rollout"):
            if args:
                res = scorer.analyze_domain(args[0])
                if cmd == "spf":
                    _kv_table([("raw", res.spf.get("raw") or "—"),
                               ("all", res.spf.get("all_policy") or "—")], "SPF")
                elif cmd == "dmarc":
                    _kv_table([("raw", res.dmarc.get("raw") or "—")], "DMARC")
                elif cmd == "dnssec":
                    _kv_table(list(res.dnssec.items()), "DNSSEC")
                elif cmd == "tls":
                    _kv_table([("MX", str(res.mx[:3])), ("starttls", str(res.starttls.get("supported"))),
                               ("mta_sts", str(res.mta_sts.get("present"))),
                               ("tls_rpt", str(res.tls_rpt.get("present")))], "TLS")
                elif cmd == "vectors":
                    print_vector_table(res.vectors)
                elif cmd == "rollout":
                    console.print(hardening.generate_rollout_plan(args[0]))
        else:
            console.print(f"  ? comando desconocido: {cmd} (prueba [bold]help[/])")


def main() -> None:
    parser = argparse.ArgumentParser(prog="mailforge",
                                     description=f"{APP} — anti-spoofing suite")
    parser.add_argument("--version", action="version", version=f"{APP} {VERSION}")
    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("command", nargs="?", default=None,
                        help="analyze|dkim|harden|selftest|report|watch|…")
    parser.add_argument("args", nargs="*", help="argumentos del comando")
    ns = parser.parse_args()

    if ns.command is None:
        interactive_repl()
        return
    cmd, args = ns.command.lower(), ns.args
    if not ns.no_banner:
        show_banner(rainbow=load_config().get("rainbow", True))
    if cmd == "analyze":
        do_analyze(args[0] if args else "gmail.com", save="--save" in args)
    elif cmd == "dkim":
        do_dkim_hunt(args[0], selectors=args[1:])
    elif cmd == "harden":
        do_hardening(args[0])
    elif cmd == "spooftest":
        do_spooftest(args[0] if args else "example.com",
                     motif=args[1] if len(args) > 1 else "invoice")
    elif cmd == "selftest":
        if len(args) < 2:
            console.print("uso: selftest <dominio> <buzon@dominio>")
        else:
            do_selftest(args[0], args[1])
    elif cmd == "report":
        res = scorer.analyze_domain(args[0])
        console.print(f"  💾 {save_report(res, args[1] if len(args) > 1 else 'json')}")
    elif cmd == "watch":
        do_watch(args[0], int(args[1]) if len(args) > 1 else 300)
    elif cmd in ("spf", "dmarc", "dnssec", "tls", "vectors", "rollout"):
        res = scorer.analyze_domain(args[0])
        if cmd == "rollout":
            console.print(hardening.generate_rollout_plan(args[0]))
        else:
            print_analysis(res, full=False)
    else:
        console.print(f"comando desconocido: {cmd}")
        sys.exit(2)


if __name__ == "__main__":
    main()
