"""Runs each scanner on a project folder and turns its output into one finding shape:

    {fp, tool, rule, severity, title, message, fix, file, line, snippet, tags, link}

severity is one of critical / high / medium / low. `fp` (fingerprint) ignores the
line number, so a finding keeps its identity when code above it moves - that is
what lets the history say "fixed" and "new" correctly.
"""
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
from pathlib import Path

from . import tools
from .detect import walk

HERE = Path(__file__).parent
BIN = Path.home() / ".local/bin"

SKIP_DIRS = {
    "node_modules", ".git", "build", "dist", ".dart_tool", ".next", "coverage", "logs",
    "Pods", ".gradle", ".idea", ".vscode", "vendor", "__pycache__", ".venv", "venv",
    "out", ".turbo", ".cache", "ephemeral", ".symlinks",
}
TEST_DIRS = ["__tests__", "test", "tests", "test-helpers", "integration_test", "spec", "fixtures"]


def which(name):
    p = BIN / name
    return str(p) if p.exists() else shutil.which(name)


def fingerprint(*parts):
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:16]


SECRET_PREFIX = re.compile(r"(AKIA|ASIA|AIza|sk_live_|sk_test_|rk_live_|ghp_|gho_|github_pat_|xox[abpr]-|eyJ[A-Za-z0-9_-]{10,}\.|"
                           r"-----BEGIN|mongodb(\+srv)?://[^:\s]+:[^@\s]+@)")


def _entropy(s):
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def redact(text, strict=False):
    """Never show a full secret in the UI or in saved reports.

    strict (secret findings): every quoted value and every key=value secret is barred, while
    names stay readable (MANAGER_PASSWORD = 'Ma█████'). Otherwise only values that look like
    secrets are barred - known key prefixes, or long random-looking strings."""
    def bar(s):
        return s[:2] + "█" * min(max(len(s) - 2, 3), 18)

    def maybe(m):
        s = m.group(0)
        if SECRET_PREFIX.match(s) or (len(s) >= 24 and _entropy(s) > 4.0 and re.search(r"\d", s)
                                      and re.search(r"[a-z]", s) and re.search(r"[A-Z]", s)):
            return bar(s)
        return s
    text = re.sub(r"mongodb(\+srv)?://[^:\s'\"]+:([^@\s'\"]+)@", lambda m: m.group(0).replace(m.group(2), "█" * 8), text or "")
    if strict:
        text = re.sub(r"""(['"`])([^'"`\n]{3,})\1""", lambda m: m.group(1) + bar(m.group(2)) + m.group(1), text)
        text = re.sub(r"(?im)^(\s*[\w.-]*(?:pass|secret|token|key|pwd|auth)[\w.-]*\s*[=:]\s*)([^\s'\"`]{3,})\s*$",
                      lambda m: m.group(1) + bar(m.group(2)), text)
    return re.sub(r"[A-Za-z0-9+/_\-.=]{20,}", maybe, text)


def _run(cmd, cwd=None, timeout=900):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def _rel(root, path):
    try:
        return str(Path(path).resolve().relative_to(Path(root).resolve()))
    except ValueError:
        return str(path)


def _lines(path, start, end):
    """The flagged code, read from the file (Semgrep without a login returns "requires login")."""
    try:
        with open(path, errors="ignore") as fh:
            lines = fh.read().splitlines()[start - 1:min(end, start + 5)]
        return "\n".join(ln.rstrip() for ln in lines).strip()[:400]
    except OSError:
        return ""


def _span(path, a, b):
    """The exact matched source (Semgrep offsets are bytes)."""
    try:
        return Path(path).read_bytes()[a:b].decode("utf-8", "ignore")
    except OSError:
        return ""


# ---------------------------------------------------------------- semgrep
SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def semgrep(root, stack, include_tests=False, on_note=lambda s: None):
    """Returns (findings, errors, facts). Facts are the route-map call sites."""
    flags = stack["flags"]
    packs, pack_errors = tools.pack_paths(stack["packs"], on_note)
    configs = [str(HERE / "rules/house.yml")] + packs
    if flags.get("dart"):
        configs.append(str(HERE / "rules/dart.yml"))
    if flags.get("electron"):
        configs.append(str(HERE / "rules/electron.yml"))
    if flags.get("express"):
        configs.append(str(HERE / "rules/facts.yml"))
    cmd = [which("semgrep"), "scan", "--metrics", "off", "--json", "-q", "--disable-version-check",
           "--timeout", "20", "--max-target-bytes", "1500000", "--jobs", "2"]
    for c in configs:
        cmd += ["--config", c]
    for d in SKIP_DIRS | (set() if include_tests else set(TEST_DIRS)):
        cmd += ["--exclude", d]
    if not include_tests:
        for g in ("*.test.js", "*.spec.js", "*.test.ts", "*.spec.ts", "*_test.dart", "*.min.js"):
            cmd += ["--exclude", g]
    cmd.append(str(root))
    on_note("Semgrep reading the code with %d rule sets" % len(configs))
    code, out, err = _run(cmd, timeout=1500)
    try:
        data = json.loads(out or "{}")
    except json.JSONDecodeError:
        data = {}
    if not data and code:
        raise RuntimeError(err.strip()[-400:] or "semgrep failed")
    findings, facts = [], []
    for r in data.get("results", []):
        cid = r["check_id"]
        rule = cid.split(".")[-1]
        if rule.startswith("fact-"):
            facts.append(r)
            continue
        if ".good." in cid:
            continue  # njsscan "good practice found" notices (helmet present, rate limiter present) - not problems
        ex = r["extra"]
        meta = ex.get("metadata", {})
        tags = ["tool:semgrep", "rule:" + rule]
        for key in ("regex_dos", "nosqli", "jwt"):
            if key in cid:
                tags.append("rule:" + key)
        cwes = meta.get("cwe") or []
        for c in (cwes if isinstance(cwes, list) else [cwes]):
            m = re.match(r"(?i)cwe-(\d+)", str(c))
            if m:
                tags.append("cwe-" + m.group(1))
        if meta.get("tag"):
            tags.append("house:" + meta["tag"])
        sev = SEV.get(ex.get("severity"), "low")
        secret = "cwe-798" in tags
        if secret:
            sev = "critical"
        file = _rel(root, r["path"])
        snippet = redact(_lines(r["path"], r["start"]["line"], r["end"]["line"]), strict=secret)
        findings.append(dict(
            tool="semgrep", rule=rule, severity=sev,
            title=ex.get("message", rule).split("\n")[0][:160],
            message=ex.get("message", ""),
            fix=meta.get("fix") or ex.get("fix") or "",
            file=file, line=r["start"]["line"], snippet=snippet, tags=tags,
            link=meta.get("source") or meta.get("shortlink") or "",
            fp=fingerprint("semgrep", rule, file, snippet),
            _span=_span(r["path"], r["start"]["offset"], r["end"]["offset"])[:4000], _abs=r["path"],
        ))
    errors = [e.get("message", "")[:200] for e in data.get("errors", []) if e.get("level") == "error"]
    return findings, errors + pack_errors, facts


# ---------------------------------------------------------------- gitleaks
PUBLIC_KEY_FILES = re.compile(r"(google-services\.json|GoogleService-Info\.plist|firebase_options\.dart|firebase(Config)?\.(js|ts))$")


def gitleaks(root):
    is_git = (Path(root) / ".git").exists()
    cmd = [which("gitleaks"), "git" if is_git else "dir", str(root), "--report-format", "json",
           "--report-path", "-", "--no-banner", "--redact", "--log-level", "error"]
    code, out, err = _run(cmd)
    try:
        items = json.loads(out or "[]")
    except json.JSONDecodeError:
        raise RuntimeError(err.strip()[-300:] or "gitleaks failed")
    findings, seen = [], set()
    for it in items:
        file = it.get("File", "")
        if any(part in SKIP_DIRS for part in Path(file).parts):
            continue
        rule = it.get("RuleID", "secret")
        fp = fingerprint("gitleaks", rule, file, it.get("Fingerprint", "").split(":")[-2:-1])
        if fp in seen:
            continue
        seen.add(fp)
        commit = it.get("Commit", "")
        where = f" (in git history, commit {commit[:8]} by {it.get('Author', '?')}, {it.get('Date', '')[:10]})" if commit else ""
        sev, extra = "critical", ""
        if PUBLIC_KEY_FILES.search(file) or rule in ("gcp-api-key",) and "AIza" in it.get("Match", ""):
            sev = "low"
            extra = (" This looks like a Firebase / Google API key: these ship inside every app build and are meant to be public. "
                     "Make sure the key is restricted (allowed apps/sites and APIs) in Google Cloud > Credentials.")
        elif re.search(r"(?i)(seed|demo|sample|example|fixture|mock)", file):
            sev = "medium"
            extra = " It is in a seed/demo file - fine if this password is not used on any real account or server."
        findings.append(dict(
            tool="gitleaks", rule=rule, severity=sev,
            title=f"{it.get('Description') or rule} found{where}",
            message=("A secret is in the code" + (" or git history. Deleting the file does not remove it from history." if commit else ".")) + extra,
            fix="Rotate it first (make a new key/password and disable the old one) - that is the real fix. "
                "Then move it to .env, and if the repo was ever shared, clean history with git filter-repo.",
            file=file, line=it.get("StartLine", 0), snippet=redact(it.get("Match", ""), strict=True),
            tags=["tool:gitleaks", "cwe-798"], link="", fp=fp,
        ))
    return findings, []


# ---------------------------------------------------------------- osv-scanner
def _cvss_sev(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "medium"
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"


def _ver(v):
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-+]", re.sub(r"^[^\d]*", "", v or "0"))[:4])


SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def osv(root):
    """One finding per vulnerable package version (all its advisories inside), so 60 lines
    of advisories become ~15 'upgrade X' actions."""
    cmd = [which("osv-scanner"), "scan", "source", "-r", "--format", "json", "--verbosity", "error", str(root)]
    code, out, err = _run(cmd)
    if code not in (0, 1) and not out.strip():
        if "no package sources found" in (err + out).lower():
            return [], []
        raise RuntimeError(err.strip()[-300:] or "osv-scanner failed")
    data = json.loads(out or "{}")
    direct_cache = {}

    def direct(src_dir, name, eco):
        key = (src_dir, eco)
        if key not in direct_cache:
            names = set()
            try:
                if eco == "npm":
                    pj = json.loads((Path(root) / src_dir / "package.json").read_text())
                    names = set(pj.get("dependencies", {})) | {"dev:" + n for n in pj.get("devDependencies", {})}
                elif eco == "Pub":
                    txt = (Path(root) / src_dir / "pubspec.yaml").read_text()
                    names = set(re.findall(r"^  ([a-z0-9_]+):", txt, re.M))
            except (OSError, json.JSONDecodeError):
                pass
            direct_cache[key] = names
        names = direct_cache[key]
        return "dev" if "dev:" + name in names else "direct" if name in names else "indirect"

    lock_dev = {}

    def npm_dev(lock, name, version):
        """package-lock.json marks packages only needed for building/testing with "dev": true."""
        if lock not in lock_dev:
            m = {}
            try:
                for key, v in json.loads(Path(lock).read_text()).get("packages", {}).items():
                    if "node_modules/" in key:
                        n = key.rsplit("node_modules/", 1)[1]
                        m.setdefault((n, v.get("version")), []).append(bool(v.get("dev") or v.get("devOptional")))
            except (OSError, json.JSONDecodeError):
                pass
            lock_dev[lock] = m
        flags = lock_dev[lock].get((name, version))
        return bool(flags) and all(flags)

    findings = []
    for res in data.get("results", []):
        src = _rel(root, res.get("source", {}).get("path", ""))
        if any(part in SKIP_DIRS for part in Path(src).parts):
            continue
        src_dir = str(Path(src).parent)
        for pkg in res.get("packages", []):
            p = pkg.get("package", {})
            name, version, eco = p.get("name"), p.get("version"), p.get("ecosystem")
            vulns = {v["id"]: v for v in pkg.get("vulnerabilities", [])}
            advisories, worst, fixes, malicious = [], "low", [], False
            for g in pkg.get("groups", []):
                ids = g.get("ids", [])
                v = next((vulns[i] for i in ids if i in vulns), {})
                is_mal = any(i.startswith("MAL-") for i in ids)
                malicious |= is_mal
                sev = "critical" if is_mal else _cvss_sev(g.get("max_severity"))
                fixed = sorted({ev["fixed"] for a in v.get("affected", []) for r in a.get("ranges", [])
                                for ev in r.get("events", []) if "fixed" in ev}, key=_ver)
                need = next((f for f in fixed if _ver(f) > _ver(version)), fixed[-1] if fixed else None)
                if need:
                    fixes.append(need)
                alias = next((i for i in ids + g.get("aliases", []) if i.startswith("CVE-")), ids[0] if ids else "")
                advisories.append({"id": alias, "summary": (v.get("summary") or "")[:160], "severity": sev,
                                   "fixed": need or "", "link": f"https://osv.dev/vulnerability/{ids[0]}" if ids else ""})
                if SEV_RANK[sev] > SEV_RANK[worst]:
                    worst = sev
            if not advisories:
                continue
            kind = direct(src_dir, name, eco)
            if kind != "dev" and eco == "npm" and src.endswith("package-lock.json") and npm_dev(str(Path(root) / src), name, version):
                kind = "dev"
            if name == "electron":
                kind = "direct"  # listed as a dev dependency, but it IS the runtime every Electron build ships
            note = ""
            if kind == "dev" and not malicious:
                worst = {"critical": "medium", "high": "medium", "medium": "low"}.get(worst, worst)
                note = " It's a dev dependency (build/test tools) - it doesn't run inside the live server, so it matters less."
            target = max(fixes, key=_ver) if fixes else None
            if malicious:
                fix = (f"Remove {name} {version} now, delete node_modules and the lockfile entry, reinstall, and rotate every token/key "
                       "on machines that installed it (npm tokens, GitHub tokens, .env values, SSH keys).")
            elif target:
                how = {"npm": f"npm install {name}@^{target}" if kind != "indirect" else
                       f"it comes in through another package - run `npm update` / `npm audit fix`, or add an \"overrides\" entry for {name} >= {target}",
                       "Pub": f"raise the {name} constraint in pubspec.yaml and run `flutter pub upgrade {name}`"}.get(eco, f"upgrade to {target}")
                fix = f"Upgrade {name} to {target} or newer: {how}."
            else:
                fix = f"No fixed version yet - check whether you use the affected part of {name}, or replace it."
            n = len(advisories)
            title = (f"MALICIOUS package: {name} {version}" if malicious else
                     f"{name} {version}: {n} known hole{'s' if n > 1 else ''}" + (f" - {advisories[0]['summary']}" if n == 1 and advisories[0]['summary'] else ""))
            findings.append(dict(
                tool="osv", rule=name, severity=worst, title=title[:180],
                message=f"{eco} package, {kind} dependency, from {src}.{note}",
                fix=fix, file=src, line=0, snippet="", advisories=advisories,
                tags=["tool:osv", "osv:malicious" if malicious else "osv:vuln"],
                link=advisories[0]["link"], fp=fingerprint("osv", eco, name, version, src),
            ))
    return findings, []


# ---------------------------------------------------------------- house checks (files & config)
HTTP_OK = re.compile(r"http://(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|"
                     r"www\.w3\.org|schemas\.|ns\.adobe|xmlns|purl\.org|json-schema|example\.(com|org)|\[|\$|\{|"
                     r"schemas\.android\.com|apache\.org/licenses|www\.apache\.org|opensource\.org)")
HTTP_ANY = re.compile(r"""['"]http://[^'"\s]+""")
CODE_EXT = {".dart", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".kt", ".java", ".swift", ".plist", ".env", ".example"}
PLACEHOLDER = re.compile(r"(?i)^(change_?me|changeme|secret|your[_-].*|xxx+|password|test|dev|default|replace.*|todo|example|<.*>)$")


def _house(rule, sev, title, fix, file, line=0, snippet="", tag=None, cwe=None, message=""):
    tags = ["tool:house", "house:" + (tag or rule)] + (["cwe-" + str(cwe)] if cwe else [])
    return dict(tool="house", rule=rule, severity=sev, title=title, message=message or title, fix=fix,
                file=file, line=line, snippet=redact(snippet), tags=tags, link="",
                fp=fingerprint("house", rule, file, snippet if rule != "http-url" else snippet.split("http://", 1)[-1][:60]))


def _git_files(root):
    if not (Path(root) / ".git").exists():
        return None
    code, out, _ = _run(["git", "-C", str(root), "ls-files"])
    return out.splitlines() if code == 0 else None


def house(root, stack):
    root = Path(root)
    flags = stack["flags"]
    findings = []
    tracked = _git_files(root)
    if tracked is not None:
        for f in tracked:
            name = Path(f).name
            if re.fullmatch(r"\.env(\..+)?", name) and not re.search(r"example|sample|template|dist", name):
                findings.append(_house("env-tracked", "critical", f"{f} is committed to git",
                                       "git rm --cached the file, add it to .gitignore, and rotate every value in it - it is in history.",
                                       f, tag="env-tracked", cwe=798))
            if re.search(r"\.(jks|keystore|p12)$", name) or name == "key.properties":
                findings.append(_house("signing-key-tracked", "critical", f"{f} (app signing key / its passwords) is committed to git",
                                       "Move it outside the repo (e.g. ~/keys), git rm --cached it, and keep key.properties in .gitignore. "
                                       "If the repo was ever shared, treat the key as known.", f, tag="signing-key-tracked", cwe=321))
        envs = [p for p in walk(root) if re.fullmatch(r"\.env(\.(local|production|prod|development))?", p.name)]
        for e in envs:
            c, _, _ = _run(["git", "-C", str(root), "check-ignore", "-q", str(e)])
            if c != 0 and _rel(root, e) not in tracked:
                findings.append(_house("env-gitignore", "high", f"{_rel(root, e)} is not ignored by git",
                                       "Add `.env*` (and `!.env.example`) to .gitignore.", _rel(root, e), tag="env-gitignore"))

    servers = [n for n in stack["node"] if n["server"]]
    for n in servers:
        d = root / n["dir"]
        deps = set(n["deps"])
        where = n["dir"] if n["dir"] != "." else "the API"
        code_text = _concat(d)
        if "express" in deps and "helmet" not in deps:
            findings.append(_house("no-helmet", "medium", f"Express app in {where} doesn't use helmet",
                                   "npm i helmet; app.use(helmet()) before the routes.", f"{n['dir']}/package.json", tag="no-helmet"))
        if not flags.get("ratelimit"):
            findings.append(_house("no-rate-limit", "high", f"{where} has no rate limiter",
                                   "npm i express-rate-limit; put a strict limiter on login, OTP and password reset - "
                                   "count failures only (skipSuccessfulRequests: true), so a shop sharing one IP isn't locked out.",
                                   f"{n['dir']}/package.json", tag="no-rate-limit", cwe=307))
        elif "express-rate-limit" in deps and "trust proxy" not in code_text:
            findings.append(_house("no-trust-proxy", "medium", f"{where} rate-limits by IP but never sets 'trust proxy'",
                                   "Behind nginx add app.set('trust proxy', 1) so the limiter sees the visitor's IP, not 127.0.0.1.",
                                   f"{n['dir']}/package.json", tag="no-trust-proxy", cwe=307))
        if re.search(r"password\w*\s*:\s*\{?\s*(type\s*:\s*)?String", code_text) and not (deps & {
                "bcrypt", "bcryptjs", "argon2", "@node-rs/argon2", "@node-rs/bcrypt"}) and "scrypt" not in code_text:
            findings.append(_house("no-hash-lib", "critical", f"{where} has a password field but no password hashing library",
                                   "npm i bcryptjs; store bcrypt.hash(password, 12) and compare with bcrypt.compare().",
                                   f"{n['dir']}/package.json", tag="no-hash-lib", cwe=256))
        for mf in sorted((d / "models").glob("*.[jt]s")) if (d / "models").is_dir() else []:
            txt = mf.read_text(errors="ignore")
            m = re.search(r"\b(password(?:Hash)?)\s*:\s*\{[^}]*\}", txt)
            if m and "select: false" not in m.group(0).replace("select:false", "select: false"):
                findings.append(_house("password-selectable", "low", f"{_rel(root, mf)}: {m.group(1)} is returned by default",
                                       f"Add select: false to {m.group(1)} in the schema, and .select('+{m.group(1)}') only in login.",
                                       _rel(root, mf), txt[:m.start()].count("\n") + 1, m.group(0).strip()[:160],
                                       tag="password-selectable", cwe=200))
        ex = d / ".env.example"
        if ex.is_file():
            for i, line in enumerate(ex.read_text(errors="ignore").splitlines(), 1):
                m = re.match(r"\s*([A-Z0-9_]*(SECRET|KEY|PASSWORD|TOKEN)[A-Z0-9_]*)\s*=\s*['\"]?([^'\"#\s]*)", line)
                if m and m.group(3) and PLACEHOLDER.match(m.group(3)):
                    findings.append(_house("env-placeholder", "low", f"{_rel(root, ex)}: {m.group(1)} has the placeholder '{m.group(3)}'",
                                           "Make sure production's .env uses a long random value: openssl rand -hex 32. "
                                           "Casefile can't see the server's .env - check it there.",
                                           _rel(root, ex), i, line.strip(), tag="env-placeholder"))

    for f in stack["flutter"]:
        findings += _android(root, root / f["dir"])
        findings += _ios(root, root / f["dir"])

    for p in walk(root, SKIP_DIRS | set(TEST_DIRS)):
        ext = p.suffix.lower()
        if ext not in CODE_EXT or "lock" in p.name or p.name.endswith(".min.js"):
            continue
        try:
            if p.stat().st_size > 800_000:
                continue
            lines = p.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        rel = _rel(root, p)
        for i, line in enumerate(lines, 1):
            for m in HTTP_ANY.finditer(line):
                url = m.group(0)[1:]
                if HTTP_OK.match(url) or line.lstrip().startswith(("//", "#", "*", "<!--")):
                    continue
                findings.append(_house("http-url", "medium", f"Plain http:// address: {url[:60]}",
                                       "Use https://. Over http, logins and data can be read on any shared network.",
                                       rel, i, line.strip()[:200], tag="http-url", cwe=319))
    return findings, []


def _concat(d, limit=4_000_000):
    """All server source text (for project-wide facts like 'trust proxy')."""
    out, size = [], 0
    for p in walk(d, SKIP_DIRS | set(TEST_DIRS)):
        if p.suffix in (".js", ".ts", ".mjs", ".cjs") and size < limit:
            try:
                t = p.read_text(errors="ignore")
            except OSError:
                continue
            out.append(t)
            size += len(t)
    return "\n".join(out)


def _android(root, app):
    out = []
    man = app / "android/app/src/main/AndroidManifest.xml"
    if not man.is_file():
        return out
    rel = _rel(root, man)
    txt = man.read_text(errors="ignore")

    def ln(pat):
        m = re.search(pat, txt)
        return (txt[:m.start()].count("\n") + 1) if m else 0
    if re.search(r'usesCleartextTraffic\s*=\s*"true"', txt):
        out.append(_house("cleartext", "high", "Android app allows plain http (usesCleartextTraffic=true)",
                          "Remove it, or allow only your LAN host with a network_security_config domain-config.", rel,
                          ln("usesCleartextTraffic"), 'android:usesCleartextTraffic="true"', tag="cleartext", cwe=319))
    if re.search(r'debuggable\s*=\s*"true"', txt):
        out.append(_house("android-debuggable", "high", "Android app is built debuggable",
                          "Remove android:debuggable from the manifest; release builds set it off.", rel,
                          ln("debuggable"), 'android:debuggable="true"', tag="android-debuggable"))
    custom_rules = re.search(r"(fullBackupContent|dataExtractionRules)\s*=", txt)
    if not re.search(r'allowBackup\s*=\s*"false"', txt) and "<application" in txt and not custom_rules:
        lib = "\n".join(p.read_text(errors="ignore") for p in (app / "lib").rglob("*.dart")) if (app / "lib").is_dir() else ""
        keeps_token = re.search(r"(?i)(refresh_?token|access_?token|token\.json|setString\([^)]*token|credentials\.json|_kToken)", lib)
        own_backup = re.search(r"(?i)(drive.*backup|backup.*drive|googleapis/drive)", lib)
        sev = "medium" if keeps_token else "low"
        why = ("This app saves a login token on the phone, and Android copies app files into phone backups "
               "(and into `adb backup` on Android 11 and older). " if keeps_token else
               "Android copies this app's files into phone backups (and into `adb backup` on Android 11 and older). ")
        why += ("The app has its own backup, so turning Android's off loses nothing." if own_backup else
                "Turning it off means a new phone won't restore the app's data automatically.")
        out.append(_house("android-backup", sev, "Android allows backup of app data (allowBackup not false)",
                          'Add android:allowBackup="false" to <application> - or keep backup and exclude the token file '
                          "with android:dataExtractionRules (Android 12+) and android:fullBackupContent (older).",
                          rel, ln("<application"), "<application ... (no android:allowBackup)", tag="android-backup",
                          message=why))
    for m in re.finditer(r"<(activity|service|receiver|provider)\b[^>]*?>", txt, re.S):
        tag = m.group(0)
        if 'exported="true"' not in tag or "android:permission" in tag:
            continue
        end = txt.find(f"</{m.group(1)}>", m.end())
        body = txt[m.end():end] if end > 0 and not tag.endswith("/>") else ""
        if "android.intent.category.LAUNCHER" in body or "APPWIDGET_UPDATE" in body:
            continue
        name = re.search(r'android:name\s*=\s*"([^"]+)"', tag)
        out.append(_house("android-exported", "medium", f"{m.group(1).capitalize()} {name.group(1) if name else ''} can be opened by other apps",
                          'Set android:exported="false" unless other apps must open it; if they must, add android:permission '
                          "and check every value it receives.", rel, txt[:m.start()].count("\n") + 1, tag.strip()[:200],
                          tag="android-exported", cwe=926))
    nsc = re.search(r'networkSecurityConfig\s*=\s*"@xml/([\w_]+)"', txt)
    if nsc:
        x = app / f"android/app/src/main/res/xml/{nsc.group(1)}.xml"
        if x.is_file():
            xt = x.read_text(errors="ignore")
            base = re.sub(r"<debug-overrides>.*?</debug-overrides>", "", xt, flags=re.S)
            if re.search(r'<base-config[^>]*cleartextTrafficPermitted\s*=\s*"true"', base):
                out.append(_house("android-netconfig", "high", "Network config allows plain http to every host",
                                  "Allow cleartext only in a <domain-config> for your LAN address.", _rel(root, x), 0,
                                  'base-config cleartextTrafficPermitted="true"', tag="android-netconfig", cwe=319))
            if re.search(r'<certificates\s+src\s*=\s*"user"', base):
                out.append(_house("android-netconfig", "high", "App trusts user-installed certificates (traffic can be intercepted)",
                                  "Move <certificates src=\"user\"/> inside <debug-overrides>.", _rel(root, x), 0,
                                  '<certificates src="user"/>', tag="android-netconfig", cwe=295))
    for g in ("android/app/build.gradle.kts", "android/app/build.gradle"):
        gp = app / g
        if gp.is_file():
            gt = gp.read_text(errors="ignore")
            rel_block = re.search(r"release\s*\{[^}]*\}", gt, re.S)
            if rel_block and re.search(r"signingConfig\s*=?\s*signingConfigs\.(getByName\(\"debug\"\)|debug)", rel_block.group(0)):
                out.append(_house("android-debug-signing", "low", "Release builds are signed with the debug key",
                                  "Create an upload keystore (keytool -genkey ...), keep it outside git, and point release.signingConfig at it.",
                                  _rel(root, gp), gt[:rel_block.start()].count("\n") + 1, "signingConfig = signingConfigs.debug",
                                  tag="android-debug-signing"))
    return out


def _ios(root, app):
    pl = app / "ios/Runner/Info.plist"
    if not pl.is_file():
        return []
    t = pl.read_text(errors="ignore")
    if re.search(r"<key>NSAllowsArbitraryLoads</key>\s*<true\s*/>", t):
        return [_house("ios-ats", "high", "iOS App Transport Security is switched off (NSAllowsArbitraryLoads)",
                       "Remove NSAllowsArbitraryLoads; if one LAN host needs http, add an NSExceptionDomains entry for it only.",
                       _rel(root, pl), 0, "<key>NSAllowsArbitraryLoads</key><true/>", tag="ios-ats", cwe=319)]
    return []


# ---------------------------------------------------------------- Claude (read-only review)
CLAUDE_PROMPT = """You are a security auditor. Review this project READ-ONLY (do not edit, run, install or
contact anything). {skill}

Stack Casefile detected: {parts}.
Routes with no login check according to Casefile's route map: {open_routes}.

Check these items one by one and report only REAL problems you can point to in the code:
- authz: every API route requires login AND the right role/permission for what it does.
- tenant: every query on company data is scoped by the logged-in user's company (never an id from the request);
  side effects too (file deletes, image cleanup).
- idor: fetching/updating by id also checks the record belongs to the caller's company/user.
- roleesc: no route lets a user set a role at or above their own.
- revocation: login checks user.active and company.active; suspended users' tokens stop working quickly.
- overfetch: no password hashes, tokens or owner-only figures in JSON responses.
- logic: prices/totals recomputed from the database, quantities validated positive, money/stock writes safe
  when the same request is sent twice at once.
- clientsecret: no admin keys, server secrets or privileged API keys inside client/mobile/desktop code.
Reply with ONLY a JSON array, no prose. Each problem:
{{"check":"authz|tenant|idor|roleesc|revocation|overfetch|logic|clientsecret","severity":"critical|high|medium|low",
"title":"short","file":"relative/path","line":123,"message":"what an attacker sends and what they get","fix":"concrete fix"}}
For every check id you looked at and found clean, add {{"check":"<id>","verified":true,"message":"what you looked at"}}."""


def _claude_json(text, opener, closer):
    """Pull the JSON array/object out of a reply that may have prose or code fences around it."""
    m = re.search(r"```(?:json)?\s*(%s.*%s)\s*```" % (re.escape(opener), re.escape(closer)), text, re.S)
    if m:
        return json.loads(m.group(1))
    a, b = text.find(opener), text.rfind(closer)
    if a < 0 or b < a:
        raise ValueError("no JSON in Claude's reply")
    return json.loads(text[a:b + 1])


def _claude_stream(root, prompt, tools_allowed, on_note, timeout):
    """Run claude -p with streamed events so the UI can show what it's reading."""
    cmd = [which("claude"), "-p", prompt, "--output-format", "stream-json", "--verbose", "--allowedTools", tools_allowed]
    proc = subprocess.Popen(cmd, cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    result, reads = "", 0
    try:
        for line in proc.stdout:
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("type") == "assistant":
                for block in ev.get("message", {}).get("content", []):
                    if block.get("type") == "tool_use":
                        inp = block.get("input", {})
                        what = inp.get("file_path") or inp.get("pattern") or inp.get("path") or ""
                        reads += 1
                        on_note(f"{block.get('name')} {_rel(root, what) if what.startswith('/') else what}"[:90] + f"  ({reads} looks)")
            elif ev.get("type") == "result":
                result = ev.get("result", "")
        proc.wait(timeout=timeout)
    finally:
        if proc.poll() is None:
            proc.kill()
    if not result:
        raise RuntimeError((proc.stderr.read() or "claude returned nothing")[-300:])
    return result


def claude_review(root, stack, open_routes, on_note=lambda s: None):
    skill = ("Use the app-security-audit skill (load it with the Skill tool) - it describes this exact stack."
             if (Path.home() / ".claude/skills/app-security-audit").exists() else "")
    prompt = CLAUDE_PROMPT.format(skill=skill, parts="; ".join(stack["parts"]) or "unknown",
                                  open_routes=", ".join(open_routes[:30]) or "none")
    text = _claude_stream(root, prompt, "Read,Grep,Glob,Skill", on_note, 2400)
    items = _claude_json(text, "[", "]")
    findings, verified = [], {}
    for it in items:
        if it.get("verified"):
            verified[it.get("check")] = it.get("message", "")
            continue
        findings.append(dict(
            tool="claude", rule=it.get("check", "other"), severity=it.get("severity", "medium"),
            title=it.get("title", "")[:160], message=it.get("message", ""), fix=it.get("fix", ""),
            file=it.get("file", ""), line=it.get("line") or 0, snippet="", check=it.get("check"),
            tags=["tool:claude"], link="", fp=fingerprint("claude", it.get("check"), it.get("file"), it.get("title")),
        ))
    return findings, verified


def claude_verify(root, finding, on_note=lambda s: None):
    """Ask Claude whether one finding is real. Returns {verdict, reason, fix}."""
    keep = ("tool", "rule", "title", "message", "file", "line", "snippet")
    prompt = (f"READ-ONLY. A security scanner reported this in the project:\n{json.dumps({k: finding.get(k) for k in keep})}\n"
              "Open the file and the code around it (and what calls it, and any global middleware that applies) and decide "
              "if it is a real, exploitable problem in THIS app. Reply with ONLY JSON: "
              "{\"verdict\":\"real|false-positive|unsure\",\"reason\":\"2-3 plain sentences a non-expert understands\","
              "\"fix\":\"concrete fix if real\"}")
    text = _claude_stream(root, prompt, "Read,Grep,Glob", on_note, 900)
    try:
        return _claude_json(text, "{", "}")
    except (ValueError, json.JSONDecodeError):
        return {"verdict": "unsure", "reason": text[:400]}
