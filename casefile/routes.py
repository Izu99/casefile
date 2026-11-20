"""Route map: rebuilds the Express route table the way Express itself runs it, so
"which routes can be called without logging in" is answered from the code, not guessed.

Semgrep (rules/facts.yml) finds every app.use / router.<method> / router.route() call;
the arguments are read from the source text here. Express semantics that matter:
  - middleware only applies to routes registered AFTER it (app.use order),
  - app.use('/api', protect) applies to every later mount under /api,
  - router.use(mw) applies to the routes after it in that router file,
  - the args before the handler in router.get(path, a, b, handler) run first.
"""
import os
import re
from pathlib import Path

AUTH = re.compile(r"(?i)(protect|authenticat|auth(?!or)|verifytoken|verifyjwt|jwt|requirelogin|loggedin|requireuser|"
                  r"guard|validatetoken|checktoken|tokenrequired|requiresignin|requiresession|clerk|passport|"
                  r"api_?key|verifykey|hmac|signature|basicauth)")
NOT_AUTH = re.compile(r"(?i)(limit|rate|route|router|controller|ctrl|cors|helmet|json|static|parser|logger|morgan)")
ROLE = re.compile(r"(?i)(role|page|permission|perm\b|owner|admin|access|authori[sz]e|\bcan\b|restrict|allow|policy|"
                  r"scope|platform|onlyfor|only\()")
PUBLIC = re.compile(r"(?i)(login|logout|signin|sign-in|signup|sign-up|register|authenticate|forgot|reset|refresh|token|verify|"
                    r"confirm|activate|health|status|ping|version|public|webhook|callback|oauth|otp|captcha|"
                    r"app-update|update-check|manifest|robots|sitemap|docs|swagger|metrics|^/?$)")
PUBLIC_STATIC = re.compile(r"(?i)(public|assets|static|images?|img|css|js|fonts|favicon|downloads?|releases?)")
WRITE = {"POST", "PUT", "PATCH", "DELETE", "ALL"}


def split_args(s):
    """Split a JS argument list at top-level commas (strings, templates, comments, brackets aware)."""
    out, depth, cur, i, n = [], 0, [], 0, len(s)
    while i < n:
        ch = s[i]
        if ch in "'\"`":
            j = i + 1
            while j < n and s[j] != ch:
                j += 2 if s[j] == "\\" else 1
            cur.append(s[i:j + 1])
            i = j + 1
            continue
        if s.startswith("//", i):
            j = s.find("\n", i)
            i = n if j < 0 else j
            continue
        if s.startswith("/*", i):
            j = s.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    last = "".join(cur).strip()
    if last:
        out.append(last)
    return out


def _call_parts(text):
    """'router.get(a, b)' -> ('router', 'get', ['a', 'b'])."""
    m = re.match(r"\s*([\w$.]+?)\s*\.\s*(\w+)\s*\(", text)
    if not m:
        return None, None, []
    open_at = m.end() - 1
    depth = 0
    for i in range(open_at, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return m.group(1), m.group(2), split_args(text[open_at + 1:i])
    return m.group(1), m.group(2), split_args(text[open_at + 1:])


def _extend_chain(text, b):
    """router.route('/').get(a).post(b): Semgrep matches only up to .get(a) - read on to the last call."""
    n = len(text)
    while True:
        i = b
        while i < n and text[i] in " \t\r\n":
            i += 1
        m = re.match(r"\.\s*(get|post|put|patch|delete|all)\s*\(", text[i:])
        if not m:
            return b
        j, depth = i + m.end() - 1, 0
        while j < n:
            if text[j] == "(":
                depth += 1
            elif text[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        b = j + 1


GENERIC = re.compile(r"(?i)^(cors|express\.(json|urlencoded|raw|text)|bodyParser|helmet|morgan|compression|cookieParser|"
                     r"session|hpp|xss|mongoSanitize|requestLogger|logger|noOperators|rejectOperators)\b")


def _str(arg):
    m = re.fullmatch(r"\s*(['\"`])(.*)\1\s*", arg or "", re.S)
    return m.group(2) if m else None


def _join(a, b):
    p = "/" + "/".join(x.strip("/") for x in (a, b) if x and x.strip("/"))
    return p if p != "" else "/"


def _under(path, prefix):
    if not prefix or prefix == "/":
        return True
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def _name(arg):
    """A short readable name for a middleware argument: requireRole('owner'), protect, noOperators."""
    a = re.sub(r"\s+", " ", arg.strip())
    m = re.match(r"require\(\s*['\"][^'\"]*?([\w-]+)(?:\.js)?['\"]\s*\)$", a)
    if m:
        return m.group(1)
    return a if len(a) <= 48 else a[:45] + "..."


def _app(stack, full):
    """App-level middleware registered so far whose prefix covers this full path."""
    return [m for p, ms in stack if _under(full, p) for m in ms]


def _ident(name):
    """The callable's own name, without its arguments: requireRole('owner') -> requireRole."""
    return re.split(r"\(", name, 1)[0].strip()


def _is_auth(names):
    return any(AUTH.search(_ident(m)) and not NOT_AUTH.search(_ident(m)) for m in names)


def _is_role(names):
    return any(ROLE.search(_ident(m)) and "feature" not in m.lower() for m in names)


def _shown(names):
    return [m for m in names if not GENERIC.match(m) and not re.match(r"(?i)(rateLimit|slowDown)\s*\(\s*\{", m)]


class _File:
    def __init__(self, path):
        self.path = path
        self.data = Path(path).read_bytes()  # Semgrep offsets are byte offsets
        self.text = self.data.decode("utf-8", "ignore")
        self.facts = []
        self.requires = {}
        for m in re.finditer(r"(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*['\"](\.{1,2}/[^'\"]+)['\"]\s*\)", self.text):
            self.requires[m.group(1)] = m.group(2)
        for m in re.finditer(r"import\s+(\w+)\s+from\s+['\"](\.{1,2}/[^'\"]+)['\"]", self.text):
            self.requires[m.group(1)] = m.group(2)
        self.apps = set(re.findall(r"(\w+)\s*=\s*express\s*\(\s*\)", self.text))
        self.routers = set(re.findall(r"(\w+)\s*=\s*(?:express\s*\.\s*|require\(\s*['\"]express['\"]\s*\)\s*\.\s*)?Router\s*\(", self.text))

    def line(self, offset):
        return self.data.count(b"\n", 0, offset) + 1

    def slice(self, a, b, chain=False):
        tail = self.data[a:].decode("utf-8", "ignore")
        end = len(self.data[a:b].decode("utf-8", "ignore"))
        return tail[:_extend_chain(tail, end) if chain else end]

    def resolve(self, spec):
        base = (Path(self.path).parent / spec)
        for cand in (base, Path(str(base) + ".js"), Path(str(base) + ".ts"), base / "index.js", base / "index.ts"):
            if cand.is_file():
                return str(cand.resolve())
        return None


def build(root, facts):
    """facts: semgrep results for rules fact-route / fact-use / fact-chain.
    Returns (routes, findings) - routes is the table shown in the UI."""
    files = {}
    for r in facts:
        p = str(Path(r["path"]).resolve())
        if p not in files:
            try:
                files[p] = _File(p)
            except OSError:
                continue
        f = files[p]
        a, b = r["start"]["offset"], r["end"]["offset"]
        kind = r["check_id"].rsplit(".", 1)[-1]
        f.facts.append((a, kind, f.slice(a, b, chain=kind == "fact-chain")))
    for f in files.values():
        f.facts.sort()

    routes = []

    def mount_target(f, arg):
        arg = arg.strip()
        m = re.fullmatch(r"require\(\s*['\"](\.{1,2}/[^'\"]+)['\"]\s*\)(?:\.\w+)?", arg)
        if m:
            return f.resolve(m.group(1)), None
        if arg in f.routers:
            return f.path, arg
        if arg in f.requires:
            return f.resolve(f.requires[arg]), None
        return None, None

    def walk_router(path, receiver, prefix, app_stack, inherited, seen):
        f = files.get(path)
        if not f or (path, receiver, prefix) in seen:
            return
        seen = seen | {(path, receiver, prefix)}
        recv = {receiver} if receiver else (f.routers or {"router"})
        local = []  # router.use(...) middleware so far: (subprefix, [names])
        for off, kind, text in f.facts:
            obj, meth, args = _call_parts(text)
            if obj not in recv:
                continue
            if kind == "fact-use":
                sub = _str(args[0]) if args else None
                rest = args[1:] if sub is not None else args
                mws = []
                for a in rest:
                    tgt, rcv = mount_target(f, a)
                    if tgt and tgt in files:
                        walk_router(tgt, rcv, _join(prefix, sub or ""), app_stack,
                                    inherited + [m for s, ms in local for m in ms] + mws, seen)
                    else:
                        mws.append(_name(a))
                if mws and not any(mount_target(f, a)[0] for a in rest):
                    local.append((sub or "", mws))
            elif kind == "fact-route":
                sub = _str(args[0]) or ""
                full = _join(prefix, sub)
                emit(f, off, meth.upper(), full,
                     _app(app_stack, full) + inherited + [m for s, ms in local if _under(sub, s) for m in ms]
                     + [_name(a) for a in args[1:-1]], args[-1:])
            elif kind == "fact-chain":
                m = re.match(r"\s*[\w$.]+\s*\.\s*route\(\s*(['\"`])(.*?)\1\s*\)", text, re.S)
                if not m:
                    continue
                sub = m.group(2)
                for cm in re.finditer(r"\.\s*(get|post|put|patch|delete|all)\s*\(", text[m.end():]):
                    _, _, cargs = _call_parts("x." + text[m.end() + cm.start() + 1:])
                    full = _join(prefix, sub)
                    emit(f, off, cm.group(1).upper(), full,
                         _app(app_stack, full) + inherited + [m2 for s, ms in local if _under(sub, s) for m2 in ms]
                         + [_name(a) for a in cargs[:-1]], cargs[-1:])

    def emit(f, off, method, path, mws, handler):
        routes.append({"method": method, "path": path, "file": os.path.relpath(f.path, root), "line": f.line(off),
                       "mws": _shown(mws), "auth": _is_auth(mws), "role": _is_role(mws), "static": False,
                       "public": bool(PUBLIC.search(path.rsplit("/", 2)[-2] + "/" + path.rsplit("/", 1)[-1] if path.count("/") > 1 else path)),
                       "handler": _name(handler[0]) if handler else ""})

    for path, f in files.items():
        for app in f.apps:
            stack = []  # (prefix, [names]) app-level middleware, in order
            for off, kind, text in f.facts:
                obj, meth, args = _call_parts(text)
                if obj != app:
                    continue
                if kind == "fact-use":
                    pre = _str(args[0]) if args else None
                    rest = args[1:] if pre is not None else args
                    pre = pre or ""
                    inline, mounted = [], False
                    for a in rest:
                        tgt, rcv = mount_target(f, a)
                        if tgt and tgt in files:
                            walk_router(tgt, rcv, pre, list(stack), list(inline), set())
                            mounted = True
                        elif re.match(r"\s*express\s*\.\s*static\s*\(", a):
                            mws = _app(stack, _join(pre, "x")) + inline
                            routes.append({"method": "FILES", "path": _join(pre, "*"), "file": os.path.relpath(f.path, root),
                                           "line": f.line(off), "mws": _shown(mws), "auth": _is_auth(mws),
                                           "role": False, "static": True,
                                           "public": bool(PUBLIC_STATIC.search(pre or "/")) or pre in ("", "/"),
                                           "handler": _name(a)})
                            mounted = True
                        else:
                            inline.append(_name(a))
                    if not mounted:
                        stack.append((pre, inline))
                elif kind == "fact-route":
                    sub = _str(args[0]) or ""
                    emit(f, off, meth.upper(), sub, _app(stack, sub) + [_name(a) for a in args[1:-1]], args[-1:])

    # de-duplicate (a router mounted twice is listed twice on purpose; same path+method+line is not)
    seen, uniq = set(), []
    for r in routes:
        k = (r["method"], r["path"], r["file"], r["line"])
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    uniq.sort(key=lambda r: (r["path"], r["method"]))
    return uniq, findings_for(uniq)


def findings_for(routes):
    from .scanners import fingerprint
    if not any(r["auth"] for r in routes):
        return []  # no login system at all: a public API by design - shown in the map, not flagged
    out = []
    for r in routes:
        if r["auth"] or r["public"]:
            continue
        if r["static"]:
            out.append(dict(tool="routes", rule="public-static", severity="medium",
                            title=f"Files under {r['path']} are served without login",
                            message="Anyone who knows or guesses a file name can download it - including other companies' files.",
                            fix="Serve uploads through a route that checks login and company (res.sendFile after a tenant check), "
                                "or move the static mount after the auth middleware.",
                            file=r["file"], line=r["line"], snippet="", tags=["routes:public-static"], link="",
                            fp=fingerprint("routes", "static", r["path"])))
            continue
        sev = "high" if r["method"] in WRITE else "medium"
        out.append(dict(tool="routes", rule="no-auth", severity=sev,
                        title=f"{r['method']} {r['path']} has no login check",
                        message="No login middleware runs before this route (Casefile followed every app.use in order). "
                                + ("Middleware it does run: " + ", ".join(r["mws"]) if r["mws"] else "It runs no middleware at all."),
                        fix="Mount it after the auth middleware (app.use('/api', protect) before the router), or add protect to the route.",
                        file=r["file"], line=r["line"], snippet=f"{r['method']} {r['path']}  ->  {r['handler']}",
                        tags=["routes:no-auth"], link="", fp=fingerprint("routes", r["method"], r["path"])))
    return out
