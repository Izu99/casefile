"""Exports a case file as a standalone HTML report and a PDF - something to hand to a
client or a security analyst. Secrets stay redacted; fonts are embedded so the file
looks the same anywhere.
"""
import base64
import html
import math
import subprocess
import time
from pathlib import Path

OUT = Path.home() / "Documents" / "Casefile reports"
FONTS = Path(__file__).resolve().parent.parent / "app/assets/fonts"
SEV = ["critical", "high", "medium", "low"]


def _font(family, file, weight=400):
    p = FONTS / file
    if not p.exists():
        return ""
    fmt = "opentype" if p.suffix == ".otf" else "truetype"
    data = base64.b64encode(p.read_bytes()).decode()
    return f"@font-face{{font-family:'{family}';src:url(data:font/{p.suffix[1:]};base64,{data}) format('{fmt}');font-weight:{weight}}}"


def _dial(checks, size=210):
    c, r, n = size / 2, size / 2 - 12, len(checks)
    dots = []
    for i, k in enumerate(checks):
        a = i / n * 2 * math.pi - math.pi / 2
        x, y = c + r * math.cos(a), c + r * math.sin(a)
        st = k["status"]
        if st == "pass":
            dots.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="5" fill="#161412"/>')
        elif st == "fail":
            dots.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="6.5" fill="#C22A1E"/>')
        elif st == "na":
            dots.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="1.8" fill="#9C9384"/>')
        else:
            dots.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" fill="none" stroke="#5E574C" stroke-width="1.4"/>')
    return f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}">{"".join(dots)}</svg>'


def _e(s):
    return html.escape(str(s or ""))


def _snip(s):
    return _e(s).replace("█", '<span class="bar">█</span>')


def render(rep, meta):
    checks = rep["checks"]
    f_open = [f for f in rep["findings"] if not f.get("ignored")]
    f_safe = [f for f in rep["findings"] if f.get("ignored")]
    status_word = {"pass": "Passed", "fail": "Found", "unchecked": "Not checked", "na": "Not used"}
    rows, fig = [], 0
    for area in dict.fromkeys(c["area"] for c in checks):
        rows.append(f'<tr class="area"><td colspan="4">{_e(area)}</td></tr>')
        for c in (c for c in checks if c["area"] == area):
            fig += 1
            label = f'{c["count"]} found' if c["status"] == "fail" else status_word[c["status"]]
            rows.append(f'<tr class="{c["status"]}"><td class="fig">Fig. {fig:02d}</td><td><span class="mk {c["status"]}"></span></td>'
                        f'<td><b>{_e(c["title"])}</b><div class="why">{_e(c.get("note") or c["why"])}</div>'
                        f'<div class="ref">{_e(" · ".join(c.get("refs", [])))}</div></td><td class="st">{_e(label)}</td></tr>')

    def finding(f):
        ex = f.get("explain") or {}
        where = _e(f["file"]) + (f':{f["line"]}' if f.get("line") else "")
        adv = ""
        if f.get("advisories"):
            adv = "<ul class='adv'>" + "".join(f"<li><b>{_e(a['id'])}</b> {_e(a['summary'])} <i>{_e(a['severity'])}</i></li>"
                                               for a in f["advisories"][:8]) + "</ul>"
        v = f.get("verdict")
        return (f'<div class="f"><div class="fh"><span class="chip {f["severity"]}">{f["severity"]}</span><b>{_e(f["title"])}</b></div>'
                f'<div class="where">{where} · {_e(f["tool"])}</div>'
                + (f'<pre>{_snip(f["snippet"])}</pre>' if f.get("snippet") else "")
                + (f'<p class="note">{_e(f["note"])}</p>' if f.get("note") else "")
                + (f'<p><b class="k">What can happen</b> {_e(ex.get("risk"))}</p>' if ex.get("risk") else "")
                + (f'<p><b class="k">When it is fine</b> {_e(ex.get("ok"))}</p>' if ex.get("ok") else "")
                + adv
                + (f'<p><b class="k">Fix</b> {_e(f["fix"])}</p>' if f.get("fix") else "")
                + (f'<p class="verdict"><b class="k">Claude</b> {_e(v.get("verdict"))} - {_e(v.get("reason"))}</p>' if v else "")
                + (f'<p class="safe"><b class="k">Marked safe</b> {_e(f["ignored"].get("reason"))}</p>' if f.get("ignored") else "")
                + "</div>")

    by_sev = "".join(
        f'<h3>{s.capitalize()} ({len(L)})</h3>' + "".join(finding(f) for f in L)
        for s in SEV for L in [[f for f in f_open if f["severity"] == s]] if L)
    routes = rep.get("routes") or []
    route_rows = "".join(
        f'<tr><td class="m">{_e(r["method"])}</td><td class="mono">{_e(r["path"])}</td>'
        f'<td>{"yes" if r["auth"] else ("public on purpose" if r["public"] else "<b class=red>NO</b>")}</td>'
        f'<td>{"yes" if r["role"] else "-"}</td><td class="mono small">{_e(", ".join(r["mws"]))}</td></tr>' for r in routes)
    unchecked = [c for c in checks if c["status"] == "unchecked"]
    tools = rep.get("tools") or {}
    css = (_font("Bowlby", "BowlbyOne-Regular.ttf") + _font("Supreme", "Supreme-Regular.otf") + _font("Supreme", "Supreme-Bold.otf", 700)
           + _font("Courier", "CourierPrime-Regular.ttf") + CSS)
    stack = rep.get("stack") or {}
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Casefile - {_e(rep['project'])}</title>
<style>{css}</style></head><body>
<section class="cover">
  <div class="tab">CASE FILE · SECURITY REPORT</div>
  <div class="band"><h1>{_e(rep['project'])}</h1><div class="mono">{_e(rep['path'])}</div>
  <div class="mono small">{_e(' · '.join(stack.get('parts', [])))}</div></div>
  <div class="verdict"><div class="dial">{_dial(checks)}<div class="num">{rep['passed']}<small>/{rep['looked']}</small><div class="cap">checks passed</div></div></div>
  <div><div class="stamp {'clear' if rep['open'] == 0 else ''}">{'ALL CLEAR' if rep['open'] == 0 else str(rep['open']) + ' OPEN'}</div>
  <div class="chips">{''.join(f'<span class="chip {s}">{rep["counts"][s]} {s}</span>' for s in SEV)}</div>
  <p class="mono small">Scanned {_e(rep['when'])} · {rep.get('unchecked', 0)} not checked · {rep.get('na', 0)} not used in this project</p>
  <p class="mono small">Tools: {_e(', '.join(f'{k} {v}' for k, v in tools.items() if v))}<br>Rule packs: {_e(rep.get('rules_date') or '-')}</p></div></div>
</section>
<h2>Checklist, one item at a time</h2>
<table class="checks">{''.join(rows)}</table>
<h2>Open findings ({len(f_open)})</h2>{by_sev or '<p>None.</p>'}
{f'<h2>Marked safe ({len(f_safe)})</h2>' + ''.join(finding(f) for f in f_safe) if f_safe else ''}
{f'<h2>Route map ({len(routes)} routes)</h2><table class="routes"><tr><th>Method</th><th>Path</th><th>Login</th><th>Role</th><th>Middleware</th></tr>{route_rows}</table>' if routes else ''}
<h2>What this report does not cover</h2>
<ul>{''.join(f'<li>{_e(c["title"])}</li>' for c in unchecked) or '<li>Every applicable item was checked.</li>'}</ul>
<p class="small">Automated scanners and an AI review find known patterns; they cannot prove the absence of every bug.
Business rules, server configuration and anything outside this folder need their own review.</p>
<footer class="mono small">Casefile · generated {time.strftime('%Y-%m-%d %H:%M')}</footer>
</body></html>"""


CSS = """
:root{--manila:#D8B97A;--paper:#F4EFE4;--ink:#161412;--ink2:#3A352E;--muted:#5E574C;--rule:#D9CFBD;--red:#C22A1E;--amber:#E39B1B;--ok:#1F5D3A}
@page{size:A4;margin:16mm 14mm}
body{font:400 10.5pt/1.5 Supreme,system-ui,sans-serif;color:var(--ink);background:#fff;margin:0}
h1{font:400 34pt/1 Bowlby,sans-serif;text-transform:uppercase;margin:0 0 6px;letter-spacing:-.5px}
h2{font:400 15pt/1.1 Bowlby,sans-serif;text-transform:uppercase;margin:28px 0 10px;border-top:2px solid var(--ink);padding-top:10px;break-after:avoid}
h3{font-size:11pt;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin:18px 0 6px;break-after:avoid}
.mono,pre,.fig,.where{font-family:Courier,ui-monospace,monospace}.small{font-size:8.5pt;color:var(--ink2)}
.cover{break-after:page}.tab{display:inline-block;background:var(--manila);padding:6px 14px;border-radius:8px 8px 0 0;font:700 8pt Courier,monospace;letter-spacing:.06em}
.band{background:var(--manila);padding:18px 22px;border-radius:0 8px 8px 8px}
.verdict{display:flex;gap:30px;align-items:center;margin-top:26px}.dial{position:relative;width:210px;height:210px}
.num{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;font:400 46pt/1 Bowlby,sans-serif}
.num small{font-size:16pt;color:var(--muted)}.cap{font:400 8pt Courier,monospace;color:var(--muted)}
.stamp{display:inline-block;font:400 26pt/1 Bowlby,sans-serif;color:var(--red);border:4px solid var(--red);padding:6px 14px 4px;border-radius:6px;transform:rotate(-5deg)}
.stamp.clear{color:var(--ok);border-color:var(--ok)}
.chips{margin:16px 0 8px}.chip{display:inline-block;border-radius:99px;padding:2px 10px;font-weight:700;font-size:8.5pt;margin-right:6px}
.chip.critical{background:var(--red);color:#fff}.chip.high{background:var(--ink);color:var(--paper)}.chip.medium{background:var(--amber);color:var(--ink)}
.chip.low{box-shadow:inset 0 0 0 1.5px var(--ink)}
table{width:100%;border-collapse:collapse}td,th{padding:6px 6px;border-top:1px solid var(--rule);vertical-align:top;text-align:left}
tr.area td{font-weight:700;font-size:8pt;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);border-top:0;padding-top:14px}
.checks tr{break-inside:avoid}.fig{font-size:8pt;color:var(--muted);width:50px}.why{font-size:9pt;color:var(--muted)}.ref{font-size:7.5pt;color:var(--muted)}
.st{font-size:8pt;font-weight:700;text-transform:uppercase;white-space:nowrap}tr.fail .st{color:var(--red)}tr.unchecked .st,tr.na .st{color:var(--muted)}
.mk{display:inline-block;width:11px;height:11px;border-radius:50%;margin-top:4px}.mk.pass{background:var(--ink)}.mk.fail{background:var(--red)}
.mk.unchecked{box-shadow:inset 0 0 0 2px var(--muted)}.mk.na{width:5px;height:5px;background:#9C9384;margin:7px 3px 0}
.f{border-top:1px solid var(--rule);padding:10px 0;break-inside:avoid}.fh{display:flex;gap:8px;align-items:baseline}.where{font-size:8.5pt;color:var(--ink2);margin:3px 0}
pre{background:var(--ink);color:#EDE6D6;padding:8px 10px;border-radius:2px;white-space:pre-wrap;word-break:break-all;font-size:8pt}
.bar{background:#000;color:#000}.k{font-size:7.5pt;letter-spacing:.1em;text-transform:uppercase;margin-right:6px}
p{margin:4px 0}.note{font-family:Courier,monospace;font-size:9pt}.adv{font-size:8.5pt;margin:4px 0;padding-left:18px}
.routes td{font-size:8.5pt}.m{font-weight:700}.red{color:var(--red)}footer{margin-top:30px;border-top:1px solid var(--rule);padding-top:8px}
"""


def headless_shell():
    base = Path.home() / ".cache/ms-playwright"
    for d in sorted(base.glob("chromium_headless_shell-*"), reverse=True):
        for c in d.glob("*/chrome-headless-shell"):
            return str(c)
    return None


def export(rep, meta):
    OUT.mkdir(parents=True, exist_ok=True)
    stem = f"{rep['project']}-{rep['when'].replace(' ', '-').replace(':', '')}"
    html_path = OUT / f"{stem}.html"
    html_path.write_text(render(rep, meta))
    pdf_path = None
    shell = headless_shell()
    if shell:
        pdf = OUT / f"{stem}.pdf"
        p = subprocess.run([shell, "--headless", "--disable-gpu", "--no-pdf-header-footer", f"--print-to-pdf={pdf}",
                            html_path.as_uri()], capture_output=True, timeout=120)
        if pdf.exists() and pdf.stat().st_size > 1000:
            pdf_path = str(pdf)
    return {"html": str(html_path), "pdf": pdf_path}
