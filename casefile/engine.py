"""One scan, start to finish: map the project, run every scanner that applies, refine,
evaluate the checklist, save. Used by the app (server.py) and the command line (cli.py).
"""
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import checklist, kb, refine, routes, scanners, store, tools, web
from .detect import detect

ENGINE = 2  # bump when finding identities change, so history doesn't report fake "new/fixed"
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

S_MAP = "Project map"
S_SEMGREP = "Code patterns (Semgrep)"
S_ROUTES = "Route map (which routes need login)"
S_GITLEAKS = "Secrets in code and git history (Gitleaks)"
S_OSV = "Known holes & malicious packages (OSV)"
S_HOUSE = "App, Android, iOS and config settings"
S_WEB = "Website headers & exposed files"
S_NUCLEI = "Known CVEs & exposures (Nuclei)"
S_ZAP = "ZAP crawl of the website"
S_PORTS = "Server ports"
S_SSH = "Server SSH (ssh-audit)"
S_LYNIS = "Server hardening (Lynis over SSH)"
S_CLAUDE = "Claude review (logic, access, tenants)"


def scan_steps(meta, opts):
    s = [S_MAP, S_SEMGREP, S_ROUTES, S_GITLEAKS, S_OSV, S_HOUSE]
    if meta.get("url"):
        s.append(S_WEB)
        if opts.get("nuclei"):
            s.append(S_NUCLEI)
        if opts.get("zap"):
            s.append(S_ZAP)
    if meta.get("ssh"):
        s += [S_PORTS, S_SSH] + ([S_LYNIS] if opts.get("lynis") else [])
    if opts.get("claude"):
        s.append(S_CLAUDE)
    return s


def run_scan(path, opts, meta, step=lambda name, **kw: None):
    path = str(Path(path).resolve())
    step(S_MAP, state="running")
    stack = detect(path)
    step(S_MAP, state="done", count=len(stack["parts"]), note="; ".join(stack["parts"])[:120] or "nothing recognised")

    findings, errors, verified, facts = [], {}, {}, []
    ran_tools, failed = set(), set()
    host = (meta.get("ssh") or "").split("@")[-1].split(":")[0]

    def sem():
        f, errs, fx = scanners.semgrep(path, stack, opts.get("tests"), lambda s: step(S_SEMGREP, note=s))
        facts.extend(fx)
        return f, errs

    tasks = {
        S_SEMGREP: ("semgrep", sem),
        S_GITLEAKS: ("gitleaks", lambda: scanners.gitleaks(path)),
        S_OSV: ("osv", lambda: scanners.osv(path)),
        S_HOUSE: ("house", lambda: scanners.house(path, stack)),
    }
    if meta.get("url"):
        tasks[S_WEB] = ("web", lambda: (web.headers_check(meta["url"]), []))
        if opts.get("nuclei"):
            tasks[S_NUCLEI] = ("nuclei", lambda: (web.nuclei_scan(meta["url"], lambda s: step(S_NUCLEI, note=s)), []))
        if opts.get("zap"):
            tasks[S_ZAP] = ("zap", lambda: (web.zap_scan(meta["url"], progress=lambda s: step(S_ZAP, note=s)), []))
    if meta.get("ssh"):
        tasks[S_PORTS] = ("ports", lambda: (web.ports_check(host, lambda s: step(S_PORTS, note=s)), []))
        tasks[S_SSH] = ("ssh-audit", lambda: (web.ssh_audit(host, int(meta["ssh"].rsplit(":", 1)[1]) if ":" in meta["ssh"] else 22), []))
        if opts.get("lynis"):
            tasks[S_LYNIS] = ("lynis", lambda: (web.lynis_ssh(meta["ssh"], lambda s: step(S_LYNIS, note=s)), []))

    def one(name):
        tool, fn = tasks[name]
        step(name, state="running")
        t = time.time()
        try:
            got, extra = fn()
            if extra:
                errors[name] = "; ".join(extra)[:400]
            findings.extend(got)
            ran_tools.add(tool)
            step(name, state="done", count=len(got), note=f"{time.time() - t:.0f}s")
        except Exception as e:
            traceback.print_exc()
            errors[name] = str(e)[:400]
            failed.add(tool)
            step(name, state="failed", error=str(e)[:200])

    with ThreadPoolExecutor(4) as pool:
        list(pool.map(one, list(tasks)))

    route_table = []
    if "semgrep" in ran_tools and stack["flags"].get("express"):
        step(S_ROUTES, state="running")
        route_table, rf = routes.build(path, facts)
        findings.extend(rf)
        step(S_ROUTES, state="done", count=len(rf),
             note=f"{len(route_table)} routes, {sum(r['auth'] for r in route_table)} need login")
    elif "semgrep" in ran_tools:
        step(S_ROUTES, state="done", count=0, note="No Express API in this project")
    else:
        step(S_ROUTES, state="failed", error="needs Semgrep")

    findings = refine.refine(path, stack, findings)

    if opts.get("claude"):
        step(S_CLAUDE, state="running")
        t = time.time()
        try:
            open_routes = [f"{r['method']} {r['path']}" for r in route_table if not r["auth"]]
            got, verified = scanners.claude_review(path, stack, open_routes, lambda s: step(S_CLAUDE, note=s))
            findings.extend(got)
            ran_tools.add("claude")
            step(S_CLAUDE, state="done", count=len(got), note=f"{(time.time() - t) / 60:.1f} min, {len(verified)} items verified")
        except Exception as e:
            traceback.print_exc()
            errors[S_CLAUDE] = str(e)[:400]
            failed.add("claude")
            step(S_CLAUDE, state="failed", error=str(e)[:200])

    report = build_report(path, findings, ran_tools, errors, verified, failed, stack, route_table)
    return store.save_scan(path, report)


def build_report(path, findings, ran_tools, errors, verified, failed, stack, route_table, when=None):
    ig = store.ignored(path)
    verdicts = store.verdicts(path)
    for f in findings:
        f.pop("ignored", None)
        f.pop("verdict", None)
        checklist.assign(f)
        risk, ok = kb.explain(f)
        f["explain"] = {"risk": risk, "ok": ok} if risk or ok else None
        if f["fp"] in ig:
            f["ignored"] = ig[f["fp"]]
        v = verdicts.get(f["fp"])
        if v:
            f["verdict"] = v
            if v.get("verdict") == "false-positive" and f["fp"] not in ig:
                f["ignored"] = {"reason": "Claude: " + v.get("reason", "false positive"), "at": v.get("at")}
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["check"], f["file"], f["line"]))
    ran = set(ran_tools) - set(failed)
    checks = checklist.evaluate(findings, ran, stack["flags"], verified)
    live = [f for f in findings if not f.get("ignored")]
    looked = [c for c in checks if c["status"] in ("pass", "fail")]
    passed = sum(c["status"] == "pass" for c in looked)
    return {
        "engine": ENGINE, "project": Path(path).name, "path": str(Path(path).resolve()),
        "when": when or time.strftime("%Y-%m-%d %H:%M"),
        "findings": findings, "checks": checks, "ran_tools": sorted(ran), "failed": sorted(failed), "errors": errors,
        "verified": verified, "stack": {"parts": stack["parts"], "flags": stack["flags"]}, "routes": route_table,
        "tools": tools.versions(), "rules_date": tools.rules_date(),
        "score": round(100 * passed / len(looked)) if looked else 0, "passed": passed, "looked": len(looked),
        "unchecked": sum(c["status"] == "unchecked" for c in checks), "na": sum(c["status"] == "na" for c in checks),
        "open": len(live), "counts": {s: sum(f["severity"] == s for f in live) for s in SEV_ORDER},
    }


def refresh(path):
    """Re-apply ignores/verdicts to the latest scan without re-running tools."""
    rep = store.latest(path)
    if not rep or rep.get("engine") != ENGINE:
        return rep if rep and rep.get("engine") == ENGINE else None
    stack = rep.get("stack") or {"parts": [], "flags": {}}
    new = build_report(path, rep["findings"], set(rep.get("ran_tools", [])) | set(rep.get("failed", [])), rep.get("errors", {}),
                       rep.get("verified", {}), rep.get("failed", []), stack, rep.get("routes", []), when=rep["when"])
    new["diff"] = rep.get("diff")
    new["tools"], new["rules_date"] = rep.get("tools", {}), rep.get("rules_date")
    return new


def live_report(target, findings, kind, ran_tools):
    """Report for a stand-alone Website or Server check (not tied to a project)."""
    for f in findings:
        checklist.assign(f)
        risk, ok = kb.explain(f)
        f["explain"] = {"risk": risk, "ok": ok} if risk or ok else None
    findings.sort(key=lambda f: SEV_ORDER.get(f["severity"], 9))
    flags = {"server": True, "web": True}
    checks = [c for c in checklist.evaluate(findings, set(ran_tools), flags) if c["kind"] == kind]
    looked = [c for c in checks if c["status"] in ("pass", "fail")]
    passed = sum(c["status"] == "pass" for c in looked)
    return {"engine": ENGINE, "project": target, "path": target, "when": time.strftime("%Y-%m-%d %H:%M"),
            "findings": findings, "checks": checks, "ran_tools": sorted(ran_tools), "failed": [], "errors": {},
            "verified": {}, "stack": None, "routes": [], "diff": None,
            "score": round(100 * passed / len(looked)) if looked else 0, "passed": passed, "looked": len(looked),
            "unchecked": sum(c["status"] == "unchecked" for c in checks), "na": 0, "open": len(findings),
            "counts": {s: sum(f["severity"] == s for f in findings) for s in SEV_ORDER}}
