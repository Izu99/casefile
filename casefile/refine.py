"""Second look at raw findings with project context - the step that turns scanner output
into findings worth reading. Each rule here exists because a scanner was right about the
pattern but wrong about this app:

  - async handlers: Semgrep ignores the `async` keyword in patterns, and Express 5 /
    express-async-errors make the whole class moot;
  - NoSQL injection: req.params is always a string, and a global operator filter
    (noOperators, express-mongo-sanitize, sanitizeFilter) blocks the body or query;
  - big body limits mounted after login; Firebase keys; ids checked a few lines later.

Nothing is deleted silently except true duplicates and impossible matches; everything
else is downgraded WITH a note saying why, so the reader can disagree.
"""
import re
from pathlib import Path

from .scanners import SKIP_DIRS, TEST_DIRS
from .detect import walk

AUTH_WORDS = re.compile(r"(?i)\b(protect|auth\w*|requireAuth|verifyToken|ownerOnly|adminOnly|requireRole|requirePage)\b")


def _server_text(root, stack):
    out = []
    for n in stack["node"]:
        if not n["server"]:
            continue
        for p in walk(Path(root) / n["dir"], SKIP_DIRS | set(TEST_DIRS)):
            if p.suffix in (".js", ".ts", ".mjs", ".cjs"):
                try:
                    out.append((str(p), p.read_text(errors="ignore")))
                except OSError:
                    pass
    return out


def operator_guards(root, stack):
    """Which parts of a request are protected from Mongo operator injection, project-wide."""
    files = _server_text(root, stack)
    g = {"body": None, "query": None, "params": "Express route params are always strings"}
    joined = "\n".join(t for _, t in files)
    if re.search(r"sanitizeFilter['\"]?\s*,\s*true|sanitizeFilter\s*:\s*true", joined):
        g["body"] = g["query"] = "mongoose sanitizeFilter is on"
    if re.search(r"\b(mongoSanitize|expressMongoSanitize)\s*\(", joined) or "express-mongo-sanitize" in joined:
        g["body"] = g["query"] = g["body"] or "express-mongo-sanitize"
    if re.search(r"""['"]query parser['"]\s*,\s*(['"]simple['"]|false)""", joined):
        g["query"] = g["query"] or "app.set('query parser', 'simple')"
    for m in re.finditer(r"app\.use\(\s*(?:require\(\s*['\"]([^'\"]*(?:noOperators|rejectOperators|sanitize)[^'\"]*)['\"]\s*\)|"
                         r"(\w*(?:noOperators|rejectOperators|sanitize)\w*))", joined, re.I):
        name = m.group(1) or m.group(2)
        src = next((t for p, t in files if Path(p).stem.lower() in name.lower().rsplit("/", 1)[-1]), "")
        if "req.body" in src or not src:
            g["body"] = g["body"] or f"global {Path(name).stem} middleware"
        if "req.query" in src:
            g["query"] = g["query"] or f"global {Path(name).stem} middleware"
    return g


def refine(root, stack, findings):
    flags = stack["flags"]
    guards = operator_guards(root, stack) if flags.get("mongo") else {}
    tenant = any(re.search(r"\b(companyId|tenantId|orgId|organizationId|shopId)\b", t) for _, t in _server_text(root, stack)[:400]) \
        if flags.get("server") else False
    out, seen = [], set()
    for f in findings:
        key = (f["tool"], f["rule"], f["file"], f["line"])
        if key in seen:
            continue
        seen.add(key)
        span = f.pop("_span", "") or f.get("snippet", "")
        abs_path = f.pop("_abs", None)
        rule = f["rule"]

        if rule == "async-no-catch":
            if not re.search(r"\basync\b", span) or not flags.get("express4") or flags.get("async_errors_patched"):
                continue
            if re.search(r"\b(asyncHandler|catchAsync|wrapAsync|tryCatch|asyncWrap)\s*\(", span):
                continue

        if rule == "node_nosqli_injection" or "rule:nosqli" in f.get("tags", []):
            ctx = _line_ctx(abs_path, f["line"], 2, before=15) + "\n" + span
            parts = {p for p in ("body", "query", "params") if f"req.{p}" in span} or \
                {p for p in ("body", "query", "params") if f"req.{p}" in ctx}
            open_parts = [p for p in parts if not guards.get(p)]
            # a string method on the value throws for {"$ne": ...} objects, so it works as a type check
            coerced = re.search(r"typeof\s+[\w.?\[\]'\"]+\s*===?\s*['\"]string['\"]|String\(|\.toString\(\)|isValidObjectId|"
                                r"ObjectId\.isValid|mongoose\.Types\.ObjectId\(|escapeRegex\(|parseInt\(|Number\(|"
                                r"\.(trim|toLowerCase|toUpperCase)\(\)", ctx)
            if not parts:
                f["severity"] = "low"
                f["note"] = ("No request data in the 15 lines before this query - the value probably comes from the database "
                             "or the login token. Worth a look only if it is passed in from a request elsewhere.")
            elif open_parts and coerced:
                f["severity"] = "low"
                f["note"] = "Probably safe: the value is checked or converted to a plain string/number/ObjectId just before the query."
            elif not open_parts:
                f["severity"] = "low"
                f["note"] = "Probably safe: " + "; ".join(sorted({guards[p] for p in parts})) + "."
            elif guards.get("body") and "query" in open_parts:
                f["note"] = (f"The {guards['body']} protects the body, but req.query can still carry operators "
                             "(?status[$ne]=x) unless the query parser is 'simple'.")

        if rule == "json-big-limit" and AUTH_WORDS.search(span + " " + _line_ctx(abs_path, f["line"], 3)):
            f["severity"] = "low"
            f["note"] = "Mounted together with a login/owner check, so only logged-in users can send big bodies."

        if rule == "idor-candidate":
            after = _line_ctx(abs_path, f["line"], 8, before=0)
            if re.search(r"companyId|tenantId|orgId|\.user(Id)?\b.*(!==|===|equals)", after):
                continue
            if not tenant:
                f["severity"] = "low"
                f["note"] = "This project doesn't look multi-company; still check the record belongs to the caller."

        if rule == "listen-all-interfaces" and not flags.get("server"):
            continue

        if rule == "node_username":
            f["severity"] = "low"
            f["note"] = "A username alone isn't a secret - only worth fixing if a password sits next to it."
        elif rule in ("node_password", "node_secret", "node_api_key", "hardcoded_jwt_secret", "hardcoded-jwt-secret") and \
                re.search(r"(?i)(seed|demo|sample|example|fixture|mock)", f["file"]):
            f["severity"] = "medium"
            f["note"] = "In a seed/demo script - fine if this password isn't used on any real account or server."

        if rule == "dart-token-in-prefs":
            app = next((a for a in stack["flutter"] if f["file"].startswith(a["dir"].rstrip("/") + "/") or a["dir"] == "."), None)
            if app and not {"android", "ios"} & set(app["platforms"]):
                f["severity"] = "low"
                f["note"] = ("Desktop build: preferences are a file in the user's own profile folder. flutter_secure_storage would "
                             "keep it in the system keyring (libsecret / Windows Credential Manager) instead.")

        if rule == "github-actions-mutable-action-tag":
            f["severity"] = "low"  # supply-chain hardening (pin to a commit SHA), not an open hole

        if f["severity"] == "info":
            f["severity"] = "low"
        if {"house:tls-bypass", "house:electron-cert"} & set(f.get("tags", [])) and f["rule"] != "dart-http-overrides":
            f["severity"] = "critical"  # one line turns every connection into one anyone on the Wi-Fi can read
        out.append(f)
    return out


def _line_ctx(path, line, n, before=None):
    if not path:
        return ""
    try:
        lines = Path(path).read_text(errors="ignore").splitlines()
    except OSError:
        return ""
    b = n if before is None else before
    return "\n".join(lines[max(0, line - 1 - b): line - 1 + n])
