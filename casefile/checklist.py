"""The checklist: every item Casefile checks, one by one.

Built from OWASP ASVS / Top 10 (2021) / CWE Top 25 and the app-security-audit skill,
cut to Node/Express + Mongoose APIs with Flutter, Electron and Next.js clients.

Each item says how it is verified:
  tools  - a finding whose tag matches `match` fails it; tools running clean passes it
  claude - needs judgement (logic, permissions, tenants). Tool findings can still FAIL it,
           but only the Claude review can PASS it
  web    - checked against a live URL
  server - checked against a live server

Statuses: pass / fail / unchecked (nothing looked) / na (the project doesn't use it).
`applies(flags)` decides na from detect.py; an item nobody could look at stays
"unchecked" - never a silent pass.
"""

A = {  # OWASP Top 10 2021
    "A01": "OWASP A01 Broken Access Control", "A02": "OWASP A02 Cryptographic Failures",
    "A03": "OWASP A03 Injection", "A04": "OWASP A04 Insecure Design",
    "A05": "OWASP A05 Security Misconfiguration", "A06": "OWASP A06 Vulnerable Components",
    "A07": "OWASP A07 Auth Failures", "A08": "OWASP A08 Integrity Failures",
    "A09": "OWASP A09 Logging Failures", "A10": "OWASP A10 SSRF",
}


def _f(*names):
    """applies() helper: true when any of the detect.py flags is set."""
    return lambda fl: any(fl.get(n) for n in names)


ALWAYS = lambda fl: True  # noqa: E731

CHECKS = [
    # --- Secrets ---------------------------------------------------------------------
    dict(id="secrets", area="Secrets", kind="tools", applies=ALWAYS,
         match=["cwe-798", "tool:gitleaks", "house:env-tracked", "house:fallback-secret"],
         by=["Gitleaks: whole git history, 150+ key types", "Semgrep p/secrets", "Casefile: fallback secrets in code"],
         ref=["A07", "CWE-798"],
         title="No passwords, keys or tokens in code or git history",
         why="Anyone with the code (a past developer, a leaked laptop, a public repo) gets the keys to production."),
    dict(id="env-ignored", area="Secrets", kind="tools", applies=_f("node", "flutter"),
         match=["house:env-gitignore", "house:env-placeholder"],
         by=["Casefile: git check-ignore on every .env", ".env.example placeholders"], ref=["A05", "CWE-538"],
         title=".env files are ignored by git, and examples hold no live values",
         why="One `git add .` puts every production password into history forever."),
    dict(id="signing", area="Secrets", kind="tools", applies=_f("android"),
         match=["house:signing-key-tracked"], na="No Android app",
         by=["Casefile: .jks / .keystore / key.properties tracked in git"], ref=["A02", "CWE-321"],
         title="Android signing key and its passwords are not in git",
         why="The signing key is the app's identity: whoever has it can publish 'updates' that phones accept."),
    dict(id="clientsecret", area="Secrets", kind="claude", applies=_f("client"),
         match=["house:next-public-secret"], na="No client app",
         by=["Casefile: NEXT_PUBLIC_ secrets", "Claude review of client code"], ref=["A02", "CWE-312"],
         title="No admin keys or server secrets shipped inside apps",
         why="Anything in an APK, a desktop build or a NEXT_PUBLIC_ variable can be read by anyone in minutes."),
    # --- Dependencies ------------------------------------------------------------------
    dict(id="deps", area="Dependencies", kind="tools", applies=_f("lockfile"), match=["osv:vuln"],
         na="No lockfile (package-lock.json / pubspec.lock) to check",
         by=["OSV-Scanner: npm, Pub, Go, PyPI... (Google's database, updated daily)"], ref=["A06", "CWE-1395"],
         title="No packages with known security holes",
         why="Most real attacks use a published hole in a library, not a bug you wrote."),
    dict(id="malicious", area="Dependencies", kind="tools", applies=_f("lockfile"), match=["osv:malicious"],
         na="No lockfile to check",
         by=["OSV-Scanner + OpenSSF malicious-packages list (hijacked and fake npm packages)"], ref=["A08", "CWE-506"],
         title="No hijacked or fake (malicious) packages",
         why="Worms like the 2025 npm attacks publish poisoned versions of popular packages that steal tokens on install."),
    # --- Injection ------------------------------------------------------------------------
    dict(id="nosqli", area="Injection", kind="tools", applies=_f("mongo"), na="No MongoDB",
         match=["cwe-943", "rule:nosqli", "house:regex-from-input", "house:where"],
         by=["Semgrep p/nodejsscan", "Casefile: $where, regex from input", "Casefile: knows global operator filters"],
         ref=["A03", "CWE-943"],
         title="User input can't change a database query (NoSQL operator injection)",
         why='`{"password": {"$ne": ""}}` in a login body logs in as anyone if the input reaches the filter raw.'),
    dict(id="sqli", area="Injection", kind="tools", applies=_f("sql"), match=["cwe-89"],
         na="No SQL database (MongoDB has no SQL - operator injection above is the real equivalent)",
         by=["Semgrep p/javascript, p/owasp-top-ten"], ref=["A03", "CWE-89"],
         title="No SQL built by joining strings", why="Classic SQL injection: read or delete every table."),
    dict(id="cmdi", area="Injection", kind="tools", applies=_f("node"), match=["cwe-78", "cwe-77"],
         by=["Semgrep p/javascript, p/nodejsscan"], ref=["A03", "CWE-78"],
         title="No shell commands built from user input", why="Runs any command on the server."),
    dict(id="code-eval", area="Injection", kind="tools", applies=_f("node"), match=["cwe-94", "cwe-95", "cwe-502"],
         by=["Semgrep p/javascript"], ref=["A08", "CWE-94"],
         title="No eval / dynamic code from input", why="Runs attacker code inside the API process."),
    dict(id="xss", area="Injection", kind="tools", applies=_f("web"), match=["cwe-79", "cwe-80"], na="No web pages",
         by=["Semgrep p/react, p/nextjs, p/javascript"], ref=["A03", "CWE-79"],
         title="Output is escaped (no XSS)", why="Script injected into a page steals the sessions of staff who open it."),
    dict(id="proto", area="Injection", kind="tools", applies=_f("server"), na="No API server",
         match=["cwe-1321", "cwe-915", "house:mass-assign"],
         by=["Casefile: whole req.body saved", "Semgrep: prototype pollution"], ref=["A08", "CWE-915"],
         title="Request body can't set fields it shouldn't (mass assignment)",
         why='Sending `"role":"admin"`, `"balance":0` or `"companyId":"<other>"` in a body that is saved whole.'),
    dict(id="redos", area="Injection", kind="tools", applies=_f("node"), match=["cwe-1333", "cwe-400", "rule:regex_dos"],
         by=["Semgrep p/nodejsscan"], ref=["A05", "CWE-1333"],
         title="No regex that user input can make hang (ReDoS)", why="One request freezes the whole Node process."),
    dict(id="path", area="Injection", kind="tools", applies=_f("node"), match=["cwe-22", "cwe-73", "cwe-23"],
         by=["Semgrep p/javascript, p/nodejsscan"], ref=["A01", "CWE-22"],
         title="File paths can't be steered by input (path traversal)", why="`../../.env` downloads your config."),
    dict(id="ssrf", area="Injection", kind="tools", applies=_f("server"), match=["cwe-918"], na="No API server",
         by=["Semgrep p/javascript, p/owasp-top-ten"], ref=["A10", "CWE-918"],
         title="Server doesn't fetch URLs the user chooses (SSRF)", why="Reaches internal services and cloud metadata."),
    dict(id="redirect", area="Injection", kind="tools", applies=_f("server", "web"), match=["cwe-601"],
         by=["Semgrep p/javascript"], ref=["A01", "CWE-601"],
         title="No open redirects", why="Your domain sends users to a phishing page."),
    # --- Login & sessions -------------------------------------------------------------------
    dict(id="pwhash", area="Login & sessions", kind="tools", applies=_f("server"), na="No API server",
         match=["cwe-916", "cwe-759", "cwe-760", "house:bcrypt-rounds", "house:weak-hash", "house:no-hash-lib"],
         by=["Casefile: bcrypt cost, MD5/SHA1, password field with no hashing library"], ref=["A02", "CWE-916"],
         title="Passwords hashed with bcrypt/argon2, cost 10 or more",
         why="A leaked database with weak hashes gives every user's real password."),
    dict(id="jwt", area="Login & sessions", kind="tools", applies=_f("jwt"), na="No JWT library",
         match=["cwe-347", "cwe-613", "rule:jwt", "house:jwt-no-expiry"],
         by=["Semgrep p/jwt", "Casefile: tokens without expiry"], ref=["A07", "CWE-613"],
         title="Tokens expire and are signed safely", why="A stolen token that never expires is a permanent login."),
    dict(id="ratelimit", area="Login & sessions", kind="tools", applies=_f("server"), na="No API server",
         match=["cwe-307", "house:no-rate-limit", "house:no-trust-proxy"],
         by=["Casefile: rate-limit library, trust proxy behind nginx"], ref=["A07", "CWE-307"],
         title="Login and OTP routes are rate limited (and see real IPs behind nginx)",
         why="Without it a script tries every password or OTP; behind nginx without 'trust proxy' every user shares one limit."),
    dict(id="random", area="Login & sessions", kind="tools", applies=ALWAYS,
         match=["cwe-330", "cwe-338", "house:math-random-token", "house:dart-random-token"],
         by=["Casefile: Math.random / Random() making codes"], ref=["A02", "CWE-338"],
         title="Tokens, OTPs and reset codes use secure randomness", why="Math.random() and Random() codes can be predicted."),
    dict(id="crypto", area="Login & sessions", kind="tools", applies=ALWAYS, match=["cwe-327", "cwe-328", "cwe-326"],
         by=["Semgrep p/javascript, p/owasp-top-ten"], ref=["A02", "CWE-327"],
         title="No broken crypto (MD5, SHA1, DES, ECB)", why="Broken algorithms can be reversed or forged."),
    dict(id="session", area="Login & sessions", kind="tools", applies=_f("cookie_auth"), na="No cookie sessions (tokens sent in headers)",
         match=["house:session-cookie", "house:cookie-flags"],
         by=["Casefile: express-session / res.cookie options"], ref=["A07", "CWE-614"],
         title="Session cookies are Secure, HttpOnly and SameSite",
         why="Cookies readable by scripts or sent over http are stolen; missing SameSite opens CSRF."),
    # --- Access control ------------------------------------------------------------------------
    dict(id="routes-auth", area="Access control", kind="tools", applies=_f("express"), na="No Express API",
         match=["routes:no-auth", "routes:public-static"],
         by=["Casefile route map: every app.use / router.* mount, in the order Express runs them"], ref=["A01", "CWE-306"],
         title="Every API route needs login, except the ones that are public on purpose",
         why="The #1 real-world bug: one route mounted before the auth middleware exposes everything behind it."),
    dict(id="authz", area="Access control", kind="claude", applies=_f("server"), na="No API server",
         by=["Route map (role column)", "Claude review"], ref=["A01", "CWE-285"],
         title="Each module checks role/permission, not just login",
         why="A cashier calling the owner's endpoints directly - the UI hiding a screen is not access control."),
    dict(id="tenant", area="Access control", kind="claude", applies=_f("server"), na="No API server",
         match=["house:idor-candidate"],
         by=["Casefile: findById(req.params...) without company check", "Claude review"], ref=["A01", "CWE-639"],
         title="Company A can never read or change company B's data (tenant scoping, IDOR)",
         why="/invoices/123 -> /invoices/124 is the most common data leak; every query must filter by the caller's company."),
    dict(id="roleesc", area="Access control", kind="claude", applies=_f("server"), na="No API server",
         match=["house:role-from-client"], by=["Casefile: role taken from the body", "Claude review"], ref=["A01", "CWE-269"],
         title="Users can't give themselves or others a higher role",
         why="A staff account that can set role:'owner' owns the company."),
    dict(id="revocation", area="Access control", kind="claude", applies=_f("server"), na="No API server",
         by=["Claude review"], ref=["A07", "CWE-613"],
         title="Suspending a user or company takes effect at once",
         why="If issued tokens keep working until they expire, a fired employee keeps access."),
    dict(id="overfetch", area="Access control", kind="claude", applies=_f("server"), na="No API server",
         match=["house:password-selectable"], by=["Casefile: password field without select:false", "Claude review"],
         ref=["A01", "CWE-200"],
         title="Responses never include password hashes, tokens or owner-only figures",
         why="Hiding a field in the app doesn't help - anyone can read the raw JSON."),
    # --- Business rules -----------------------------------------------------------------------------
    dict(id="logic", area="Business rules", kind="claude", applies=_f("server"), na="No API server",
         match=["house:money-from-client"], by=["Casefile: money fields taken from the body", "Claude review"],
         ref=["A04", "CWE-840"],
         title="Money, stock and balances can't be faked, made negative or double-applied",
         why="A client-sent price, a negative quantity, or the same payment sent twice at once."),
    dict(id="docnumbers", area="Business rules", kind="tools", applies=_f("mongo"), na="No MongoDB",
         match=["house:count-plus-one"], by=["Casefile: countDocuments() + 1"], ref=["A04", "CWE-362"],
         title="Invoice and document numbers can't repeat under load",
         why="Two saves at the same moment both read the same count and get the same number."),
    # --- Server setup ------------------------------------------------------------------------------------
    dict(id="headers", area="Server setup", kind="tools", applies=_f("express"), na="No Express API",
         match=["house:no-helmet"], by=["Casefile: helmet installed"], ref=["A05", "CWE-693"],
         title="Security headers are set (helmet)", why="Blocks clickjacking, sniffing and some XSS for free."),
    dict(id="cors", area="Server setup", kind="tools", applies=_f("server"), na="No API server",
         match=["cwe-942", "house:cors"], by=["Casefile: cors() options"], ref=["A05", "CWE-942"],
         title="CORS only allows your own sites", why="`origin: *` lets any website call your API from a staff browser."),
    dict(id="bodylimit", area="Server setup", kind="tools", applies=_f("express"), na="No Express API",
         match=["house:body-limit"], by=["Casefile: express.json limits"], ref=["A05", "CWE-770"],
         title="Request body size is limited", why="Huge JSON bodies take the API down."),
    dict(id="upload", area="Server setup", kind="tools", applies=_f("upload"), na="No file uploads",
         match=["cwe-434", "house:upload-filter"], by=["Casefile: multer fileFilter and limits"], ref=["A04", "CWE-434"],
         title="Uploads check file type and size", why="An uploaded .html/.svg served back is stored XSS, or worse."),
    dict(id="errors", area="Server setup", kind="tools", applies=_f("server"), na="No API server",
         match=["cwe-209", "cwe-215", "cwe-489", "house:stack-leak", "house:async-no-catch"],
         by=["Casefile: stack traces in responses", "Casefile: async routes without a catch (Express 4)"], ref=["A05", "CWE-209"],
         title="Errors don't leak internals, and a thrown error can't hang the server",
         why="Stack traces map your code for an attacker; on Express 4 an unwrapped async error hangs the request."),
    dict(id="logging", area="Server setup", kind="tools", applies=_f("server"), na="No API server",
         match=["cwe-532", "house:log-body", "house:dart-log-secret"], by=["Casefile: logging request bodies / tokens"],
         ref=["A09", "CWE-532"],
         title="Logs don't contain passwords or tokens", why="Log files get copied, shared and backed up."),
    dict(id="bind", area="Server setup", kind="tools", applies=_f("server"), na="No API server",
         match=["house:listen-all"], by=["Casefile: app.listen host", "Port check (Server tab)"], ref=["A05", "CWE-668"],
         title="The API listens on 127.0.0.1 behind nginx, not on every network",
         why="A Node port open to the internet skips nginx, Cloudflare, HTTPS and their limits."),
    # --- Apps ------------------------------------------------------------------------------------------------
    dict(id="tls", area="Apps", kind="tools", applies=ALWAYS,
         match=["house:tls-bypass", "house:electron-cert", "cwe-295"],
         by=["Casefile: badCertificateCallback, rejectUnauthorized:false, ignore-certificate-errors"], ref=["A02", "CWE-295"],
         title="Nothing switches off HTTPS certificate checks",
         why="One `=> true` lets anyone on the same Wi-Fi read and change all traffic, logins included."),
    dict(id="transport", area="Apps", kind="tools", applies=_f("client"), na="No client app",
         match=["cwe-319", "house:http-url", "house:cleartext", "house:ios-ats"],
         by=["Casefile: http:// addresses, Android cleartext, iOS ATS"], ref=["A02", "CWE-319"],
         title="Apps talk to the API over HTTPS only", why="Plain http on café or office Wi-Fi shows passwords to anyone listening."),
    dict(id="tokens", area="Apps", kind="tools", applies=_f("flutter"), na="No Flutter app",
         match=["house:token-in-prefs"], by=["Casefile: tokens in SharedPreferences"], ref=["A02", "CWE-922"],
         title="Login tokens are kept in the phone's secure storage",
         why="SharedPreferences is a plain file: backups, rooted phones and malware can read it."),
    dict(id="android", area="Apps", kind="tools", applies=_f("android"), na="No Android app",
         match=["house:android-debuggable", "house:android-backup", "house:android-exported", "house:android-netconfig",
                "house:android-debug-signing"],
         by=["Casefile: manifest, network security config, Gradle signing"], ref=["A05", "CWE-926"],
         title="Android build is locked down (not debuggable, no open components, no user CAs)",
         why="Debuggable builds, exported screens and trusted user certificates let other apps or a laptop get in."),
    dict(id="electron", area="Apps", kind="tools", applies=_f("electron"), na="No Electron app",
         match=["house:electron-prefs", "house:electron-open-external", "house:electron-http", "house:electron-ipc"],
         by=["Casefile: BrowserWindow webPreferences, shell.openExternal, IPC bridge"], ref=["A05", "CWE-1188"],
         title="Electron windows are locked down (contextIsolation on, nodeIntegration off)",
         why="With Node in the page, any XSS or loaded web page becomes full control of the PC."),
    # --- Website (live) ---------------------------------------------------------------------------------------
    dict(id="w-https", area="Website", kind="web", applies=_f("server", "web"), na="No website or API in this project", match=["web:https"], by=["Casefile live check"], ref=["A02", "CWE-319"],
         title="HTTP redirects to HTTPS, certificate valid", why="Without it the first request can be intercepted."),
    dict(id="w-hsts", area="Website", kind="web", applies=_f("server", "web"), na="No website or API in this project", match=["web:hsts"], by=["Casefile live check"], ref=["A05", "CWE-523"],
         title="HSTS header set", why="The browser refuses plain http afterwards."),
    dict(id="w-csp", area="Website", kind="web", applies=_f("server", "web"), na="No website or API in this project", match=["web:csp"], by=["Casefile live check"], ref=["A05", "CWE-1021"],
         title="Content-Security-Policy set", why="Limits the damage of any XSS."),
    dict(id="w-frame", area="Website", kind="web", applies=_f("server", "web"), na="No website or API in this project", match=["web:frame"], by=["Casefile live check"], ref=["A05", "CWE-1021"],
         title="Can't be framed (clickjacking)", why="Your page inside a hidden iframe."),
    dict(id="w-sniff", area="Website", kind="web", applies=_f("server", "web"), na="No website or API in this project", match=["web:nosniff", "web:referrer"], by=["Casefile live check"],
         ref=["A05", "CWE-693"], title="nosniff and Referrer-Policy set", why="Small headers, cheap wins."),
    dict(id="w-cookies", area="Website", kind="web", applies=_f("server", "web"), na="No website or API in this project", match=["web:cookie"], by=["Casefile live check"], ref=["A05", "CWE-614"],
         title="Cookies are Secure, HttpOnly, SameSite", why="Session cookies stolen by script or over http."),
    dict(id="w-leak", area="Website", kind="web", applies=_f("server", "web"), na="No website or API in this project", match=["web:version"], by=["Casefile live check"], ref=["A05", "CWE-200"],
         title="Server doesn't announce software versions", why="Tells attackers which exploit to use."),
    dict(id="w-files", area="Website", kind="web", applies=_f("server", "web"), na="No website or API in this project", match=["web:exposed"], by=["Casefile: 17 well-known leak paths"],
         ref=["A05", "CWE-538"], title="No .env, .git or backups reachable from the web",
         why="The most damaging one-request leak there is."),
    dict(id="w-cors", area="Website", kind="web", applies=_f("server", "web"), na="No website or API in this project", match=["web:cors"], by=["Casefile live check"], ref=["A05", "CWE-942"],
         title="API doesn't trust any origin", why="Reflected origin + credentials = any site can use a logged-in staff session."),
    dict(id="w-nuclei", area="Website", kind="web", applies=_f("server", "web"), na="No website or API in this project", match=["tool:nuclei"],
         by=["Nuclei: 14,000+ community templates for CVEs, exposures and misconfigurations"], ref=["A06", "CWE-1395"],
         title="No known CVEs, exposed panels or misconfigurations (Nuclei)",
         why="New CVEs get a Nuclei template within days - this is where 'the new problem on social media' gets checked."),
    dict(id="w-zap", area="Website", kind="web", applies=_f("server", "web"), na="No website or API in this project", match=["tool:zap"], by=["OWASP ZAP crawl + passive scan"],
         ref=["A05"], title="ZAP finds no medium/high alerts", why="OWASP's own scanner, crawling the site like an attacker."),
    # --- Server (live) ------------------------------------------------------------------------------------------
    dict(id="s-ports", area="Server", kind="server", applies=_f("server"), na="No server in this project", match=["tool:ports"], by=["Casefile port check (with ISP control scan)"],
         ref=["A05", "CWE-668"], title="No database or app ports open to the internet",
         why="An open MongoDB or Node port is the #1 way VPS data leaks - no password guessing needed if auth is off."),
    dict(id="s-ssh", area="Server", kind="server", applies=_f("server"), na="No server in this project", match=["tool:ssh-audit"], by=["ssh-audit"], ref=["A02", "CWE-327"],
         title="SSH uses only modern, safe algorithms", why="Old key exchange and ciphers can be downgraded or broken."),
    dict(id="s-lynis", area="Server", kind="server", applies=_f("server"), na="No server in this project", match=["tool:lynis"], by=["Lynis, run over SSH (read-only)"],
         ref=["A05"], title="System hardening (Lynis) has no warnings", why="Updates, firewall, file permissions, services."),
]

BY_ID = {c["id"]: c for c in CHECKS}
for _c in CHECKS:
    _c["refs"] = [A.get(r, r) for r in _c.pop("ref", [])]


def public(c):
    """A check without its applies() function - safe to send as JSON."""
    return {k: v for k, v in c.items() if k != "applies"}


# Which scanners must have finished for an item to count as checked (default: Semgrep for
# code items, Claude for judgement items). A failed or skipped scanner leaves its items
# "unchecked" - never passed.
REQUIRES = {
    "secrets": {"gitleaks", "semgrep"}, "env-ignored": {"house"}, "signing": {"house"}, "deps": {"osv"},
    "malicious": {"osv"}, "ratelimit": {"house"}, "headers": {"house"}, "android": {"house", "semgrep"},
    "transport": {"house", "semgrep"}, "pwhash": {"house", "semgrep"}, "routes-auth": {"semgrep"},
    "w-nuclei": {"nuclei"}, "w-zap": {"zap"}, "s-ports": {"ports"}, "s-ssh": {"ssh-audit"}, "s-lynis": {"lynis"},
}


def requires(c):
    if c["id"] in REQUIRES:
        return REQUIRES[c["id"]]
    return {"claude": {"claude"}, "web": {"web"}, "server": {"ports"}}.get(c["kind"], {"semgrep"})


def evaluate(findings, ran_tools, flags=None, verified=None):
    """Return [{...check, status, count}] - status is pass / fail / unchecked / na."""
    flags = flags or {}
    verified = verified or {}
    out = []
    for c in CHECKS:
        tags = set(c.get("match", []))
        hits = [f for f in findings if not f.get("ignored") and
                (f.get("check") == c["id"] or tags & set(f.get("tags", [])))]
        if flags and "applies" in c and not c["applies"](flags) and not hits:
            status = "na"
        elif hits:
            status = "fail"
        elif c["kind"] == "claude":
            status = "pass" if c["id"] in verified and "claude" in ran_tools else "unchecked"
        elif requires(c) <= set(ran_tools):
            status = "pass"
        else:
            status = "unchecked"
        item = {**public(c), "status": status, "count": len(hits)}
        if status == "na":
            item["note"] = c.get("na", "Not used in this project")
        elif c["kind"] == "claude" and status == "pass":
            item["note"] = "Claude: " + str(verified[c["id"]])[:300]
        out.append(item)
    return out


def assign(finding):
    """Attach the first checklist item a finding belongs to (for grouping in the UI)."""
    if finding.get("check"):
        return finding
    tags = set(finding.get("tags", []))
    for c in CHECKS:
        if tags & set(c.get("match", [])):
            finding["check"] = c["id"]
            return finding
    finding["check"] = "other"
    return finding
