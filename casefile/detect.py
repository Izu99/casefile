"""Works out what a project is made of, so the checklist can say "not used here"
instead of a silent pass, and so each scanner only loads rules that apply.

    detect(root) -> {
      "parts":   ["Express 4 API · company/server", "Flutter app (Android, Linux) · company/client", ...],
      "flags":   {"express": True, "mongo": True, "android": True, ...},
      "node":    [{dir, name, deps, express_major, server, next, react, electron}],
      "flutter": [{dir, name, deps, platforms}],
      "packs":   ["p/javascript", ...],   # Semgrep registry packs worth running
      "langs":   {"js": n, "ts": n, "dart": n, "kotlin": n, ...}
    }
"""
import json
import os
import re
from pathlib import Path

SKIP = {"node_modules", ".git", "build", "dist", ".dart_tool", ".next", "coverage", "logs", "Pods",
        ".gradle", ".idea", ".vscode", "vendor", "__pycache__", ".venv", "venv", "out", ".turbo",
        ".cache", "ephemeral", ".symlinks", "generated"}

SERVER_LIBS = ("express", "fastify", "koa", "@nestjs/core", "@hapi/hapi", "hono")
SQL_LIBS = ("pg", "mysql", "mysql2", "sqlite3", "better-sqlite3", "sequelize", "knex", "typeorm",
            "@prisma/client", "mssql", "oracledb", "drizzle-orm", "postgres", "@neondatabase/serverless")
JWT_LIBS = ("jsonwebtoken", "jose", "express-jwt", "passport-jwt", "@nestjs/jwt", "next-auth", "@auth/core")
HASH_LIBS = ("bcrypt", "bcryptjs", "argon2", "@node-rs/argon2", "@node-rs/bcrypt", "scrypt-js")
UPLOAD_LIBS = ("multer", "busboy", "formidable", "express-fileupload", "multiparty", "@fastify/multipart")
COOKIE_LIBS = ("express-session", "cookie-session", "next-auth", "@auth/core", "iron-session", "lucia")
TEMPLATE_LIBS = ("ejs", "pug", "handlebars", "express-handlebars", "nunjucks", "hbs")
WEB_LIBS = ("next", "react-dom", "vue", "svelte", "@angular/core", "nuxt", "astro")
LIMIT_LIBS = ("express-rate-limit", "rate-limiter-flexible", "express-slow-down", "express-brute", "@upstash/ratelimit")
EXT = {".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js", ".ts": "ts", ".tsx": "ts", ".dart": "dart",
       ".kt": "kotlin", ".java": "java", ".swift": "swift", ".py": "python", ".go": "go", ".php": "php"}


def walk(root, skip=SKIP):
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in skip and not (d.startswith(".") and d != ".github")]
        for f in files:
            yield Path(dirpath) / f


def _major(spec):
    m = re.search(r"(\d+)", spec or "")
    return int(m.group(1)) if m else None


def _rel(root, p):
    r = os.path.relpath(p, root)
    return "." if r == "." else r


def _pubspec_deps(text):
    deps, section = set(), None
    for line in text.splitlines():
        if re.match(r"^(dependencies|dev_dependencies|dependency_overrides):", line):
            section = line.split(":")[0]
            continue
        if re.match(r"^\S", line):
            section = None
        m = re.match(r"^  ([a-z0-9_]+):", line)
        if section and m:
            deps.add(m.group(1))
    return deps


def detect(root):
    root = Path(root)
    node, flutter = [], []
    langs = {}
    has = {"dockerfile": False, "nginx": False, "workflows": False, "android_native": False, "ios_swift": 0,
           "html": False}
    for p in walk(root):
        ext = p.suffix.lower()
        if ext in EXT:
            langs[EXT[ext]] = langs.get(EXT[ext], 0) + 1
            if ext in (".kt", ".java") and "/android/" in str(p) and "GeneratedPluginRegistrant" not in p.name:
                has["android_native"] = True
        if p.name == "package.json":
            try:
                pj = json.loads(p.read_text(errors="ignore"))
            except (OSError, json.JSONDecodeError):
                continue
            deps = {**pj.get("dependencies", {}), **pj.get("devDependencies", {})}
            prod = set(pj.get("dependencies", {}))
            node.append({
                "dir": _rel(root, p.parent), "name": pj.get("name") or p.parent.name, "deps": sorted(deps),
                "prod": sorted(prod), "express_major": _major(deps.get("express")),
                "server": any(k in deps for k in SERVER_LIBS),
                "next": "next" in deps, "react": "react" in deps,
                "electron": "electron" in deps,
            })
        elif p.name == "pubspec.yaml":
            text = p.read_text(errors="ignore")
            plats = [d for d in ("android", "ios", "linux", "windows", "macos", "web") if (p.parent / d).is_dir()]
            name = re.search(r"^name:\s*(\S+)", text, re.M)
            flutter.append({"dir": _rel(root, p.parent), "name": name.group(1) if name else p.parent.name,
                            "deps": sorted(_pubspec_deps(text)), "platforms": plats,
                            "flutter": "flutter:" in text and "sdk: flutter" in text})
        elif p.name == "Dockerfile" or p.name.endswith(".dockerfile"):
            has["dockerfile"] = True
        elif ext == ".conf" and p.stat().st_size < 200_000:
            try:
                if re.search(r"^\s*server\s*\{", p.read_text(errors="ignore"), re.M):
                    has["nginx"] = True
            except OSError:
                pass
        elif ".github/workflows" in str(p) and ext in (".yml", ".yaml"):
            has["workflows"] = True
        elif ext == ".swift" and "/ios/" in str(p):
            has["ios_swift"] += 1
        elif ext == ".html" and "/test" not in str(p):
            has["html"] = True

    all_deps = set().union(*[set(n["deps"]) for n in node]) if node else set()
    servers = [n for n in node if n["server"]]
    express_majors = [n["express_major"] for n in servers if n["express_major"]]
    android = any((root / f["dir"] / "android").is_dir() for f in flutter) or any(
        p.name == "AndroidManifest.xml" for p in (root.glob("**/src/main/AndroidManifest.xml")) if "node_modules" not in str(p))
    ios = any((root / f["dir"] / "ios").is_dir() for f in flutter)
    flags = {
        "node": bool(node), "server": bool(servers), "express": any("express" in n["deps"] for n in servers),
        "express4": bool(express_majors) and min(express_majors) < 5,
        "async_errors_patched": "express-async-errors" in all_deps,
        "mongo": bool({"mongoose", "mongodb"} & all_deps),
        "sql": bool(set(SQL_LIBS) & all_deps),
        "jwt": bool(set(JWT_LIBS) & all_deps),
        "hashlib": bool(set(HASH_LIBS) & all_deps),
        "upload": bool(set(UPLOAD_LIBS) & all_deps),
        "cookie_auth": bool(set(COOKIE_LIBS) & all_deps),
        "templating": bool(set(TEMPLATE_LIBS) & all_deps),
        "ratelimit": bool(set(LIMIT_LIBS) & all_deps),
        "web": bool(set(WEB_LIBS) & all_deps) or any("web" in f["platforms"] for f in flutter)
               or bool(set(TEMPLATE_LIBS) & all_deps)
               or (has["html"] and any(not n["electron"] for n in node)),  # an Electron app's offline.html is not a website
        "next": any(n["next"] for n in node), "react": any(n["react"] for n in node),
        "electron": any(n["electron"] for n in node),
        "flutter": bool(flutter), "dart": langs.get("dart", 0) > 0,
        "android": android, "ios": ios, "mobile": android or ios,
        "client": bool(flutter) or any(n["electron"] or n["next"] or n["react"] for n in node),
        "lockfile": any((root / n["dir"] / lf).exists() for n in node for lf in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"))
                    or any((root / f["dir"] / "pubspec.lock").exists() for f in flutter),
        "ts": langs.get("ts", 0) > 0, "js": langs.get("js", 0) + langs.get("ts", 0) > 0,
        **{k: bool(v) for k, v in has.items()},
    }

    parts = []
    for n in servers:
        kind = "Express %s API" % (n["express_major"] or "") if n["express_major"] else "Node API"
        parts.append(f"{kind.replace('  ', ' ')} · {n['dir']}")
    for n in node:
        if n["electron"]:
            parts.append(f"Electron desktop app · {n['dir']}")
        elif n["next"]:
            parts.append(f"Next.js site · {n['dir']}")
        elif n["react"] and not n["server"]:
            parts.append(f"React app · {n['dir']}")
    for f in flutter:
        plats = ", ".join(p.capitalize() if p != "ios" else "iOS" for p in f["platforms"]) or "no platforms"
        parts.append(f"{'Flutter' if f['flutter'] else 'Dart'} app ({plats}) · {f['dir']}")

    packs = ["p/secrets", "p/owasp-top-ten"]
    if flags["js"]:
        packs += ["p/javascript"]
    if flags["ts"]:
        packs += ["p/typescript"]
    if flags["server"]:
        packs += ["p/nodejsscan"]
    if flags["jwt"]:
        packs += ["p/jwt"]
    if flags["react"] or flags["next"]:
        packs += ["p/react"]
    if flags["next"]:
        packs += ["p/nextjs"]
    if has["android_native"]:
        packs += ["p/kotlin", "p/java"]
    if has["dockerfile"]:
        packs += ["p/dockerfile"]
    if has["nginx"]:
        packs += ["p/nginx"]
    if has["workflows"]:
        packs += ["p/github-actions"]

    return {"parts": parts, "flags": flags, "node": node, "flutter": flutter, "packs": packs, "langs": langs}
