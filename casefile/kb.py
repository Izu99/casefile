"""Plain-words explanations for findings: what can happen, and when it is a false alarm.

Looked up by rule id first (house rules, common pack rules, live checks), then by
checklist item - so every finding answers "is this real for me?" without asking Claude.
"""

RULES = {
    # --- secrets
    "gitleaks": ("Anyone who ever gets a copy of the repo (old laptop, ex-developer, a mistaken public push) can use this key. "
                 "Deleting it from the code does not remove it from git history.",
                 "Fine if it's a test key that works nowhere, or a public identifier (Firebase/Google Maps browser keys). "
                 "If it ever worked in production: rotate it - that is the real fix."),
    "fallback-secret": ("If the server ever starts without the .env value (new server, typo, pm2 started from the wrong folder), "
                        "tokens get signed with this string - which is in your code, so anyone can forge an admin token.",
                        "Fine only in a script that never runs in production."),
    "env-tracked": ("Every password in this file is now in git history; anyone with the repo has them.",
                    "Fine if it only holds local development values that are used nowhere else."),
    "env-gitignore": ("The next `git add .` commits it.", "Fine if the file has only placeholder values."),
    "env-placeholder": ("Example files are often copied to the server unchanged; a placeholder like change_me then becomes the real secret.",
                        "Fine if production's .env has its own long random value - check on the server."),
    "signing-key-tracked": ("Whoever has the keystore and its password can sign an APK that Android accepts as an update of your app.",
                            "Fine if the repo is private and the key is only a test key - but release keys belong outside git."),
    "next-public-secret": ("NEXT_PUBLIC_ values are pasted into the JavaScript every visitor downloads.",
                           "Fine if the value is really public (a publishable key, a site id) and only the name sounds secret."),
    # --- deps
    "osv": ("A published, documented hole: attackers scan for exactly these versions.",
            "Often not reachable: the hole is in a part of the package you don't call, or it's a dev-only tool that never runs "
            "on the server. Upgrading is still the cheap, safe fix."),
    "osv-malicious": ("A known poisoned package version: it can steal tokens, SSH keys and .env files the moment it is installed.",
                      "Never a false alarm. Remove it, delete node_modules, reinstall, and rotate secrets on any machine that installed it."),
    # --- injection
    "nosqli": ("If a request can send an object where a string is expected, {\"$ne\": null} becomes a query operator - "
               "logging in without a password or reading other records.",
               "Fine when the value is a route parameter (always a string), when the field is coerced with String(), "
               "or when a global filter rejects $-keys for that part of the request."),
    "regex-from-input": ("A search like .* matches everything; a crafted pattern can freeze the server for seconds per request.",
                         "Fine if the input is escaped (escapeRegex) and length-capped before reaching the regex."),
    "mongo-where": ("$where runs JavaScript inside the database.", "Never needed in normal app code."),
    "mass-assignment": ("The client can add fields you didn't plan for: role, companyId, balance, isPaid, createdBy.",
                        "Fine when the model has no sensitive fields, or a global filter strips them (ownFields), "
                        "or the schema is strict and the route is owner-only."),
    "regex_dos": ("A regular expression that takes exponential time on crafted input - one request ties up the server.",
                  "Fine if the input is short and length-limited before it reaches the regex."),
    # --- auth
    "jwt-no-expiry": ("A token copied from a phone, a log or a browser works forever.", "Fine for internal service-to-service tokens that are rotated."),
    "bcrypt-low-rounds": ("Each extra round doubles the cracking cost; below 10 a leaked database is cracked quickly.", "Never fine for user passwords."),
    "weak-password-hash": ("MD5/SHA1 hashes are cracked by the billion per second.", "Fine for file checksums or cache keys - not for passwords or signatures."),
    "no-hash-lib": ("A password field with no hashing library in the project usually means passwords are stored as typed.",
                    "Fine if passwords are hashed some other way (crypto.scrypt) or another service handles login."),
    "math-random-token": ("Math.random() can be predicted from a few outputs; an attacker can guess the next OTP or reset code.",
                          "Fine for things that protect nothing (colours, shuffles, demo data)."),
    "dart-random-token": ("Random() is not cryptographically secure; codes can be predicted.", "Fine for UI, games and demo data."),
    "no-rate-limit": ("Without a limit, a script can try thousands of passwords or OTPs per minute.",
                      "Fine if nginx or Cloudflare rate-limits the login path instead - check that it really does."),
    "no-trust-proxy": ("Behind nginx every request looks like it comes from 127.0.0.1, so the limiter either blocks everyone together or nobody.",
                       "Fine if the app is not behind a proxy."),
    "session-cookie-insecure": ("Cookies without Secure go over plain http; without HttpOnly any XSS reads them.", "Fine only in local development."),
    "cookie-without-flags": ("A login cookie readable by page scripts or sent over http is easy to steal.", "Fine if it holds nothing secret."),
    # --- access
    "no-auth": ("Anyone on the internet can call this route without logging in.",
                "Fine if it is public on purpose (a price list, a webhook with its own signature check) - then mark it safe with that reason."),
    "public-static": ("Anyone with the link (or a guessed file name) can download these files - another company's invoice PDF, for example.",
                      "Fine if the files are public anyway (logos, product photos) and names are long random ids."),
    "idor-candidate": ("Change the id in the URL and you may get another company's record.",
                       "Fine if the code right after checks the record's companyId against the logged-in user, or a middleware does it for every query."),
    "role-from-client": ("If the role comes from the request, a staff member can make themselves owner.",
                         "Fine when the route is owner-only and the role is checked against an allow-list below the caller's own."),
    "money-from-client": ("The client decides the price or total - a cashier (or a script) can sell at 0.",
                          "Fine for manual price overrides that are a real business rule and limited to a role - confirm with the shop."),
    "password-selectable": ("Any route that returns the user document returns the password hash too, unless every query remembers .select('-password').",
                            "Fine if every user query already excludes it - select: false makes that automatic."),
    "count-plus-one": ("Two invoices saved in the same second get the same number.", "Fine if the number has a unique index and the save retries."),
    # --- server setup
    "cors-open": ("Any website can call your API with a logged-in user's browser (when cookies are used) or read public responses.",
                  "Fine for a public, read-only API with token auth in headers."),
    "json-big-limit": ("Anyone can send hundreds of MB per request and fill memory.",
                       "Fine when the big limit applies only after login on one route (like a backup restore)."),
    "multer-no-filter": ("Uploading .html, .svg or .js that is later served from your domain runs in your users' browsers.",
                         "Fine if files are re-encoded (sharp), renamed, size-limited and never served as HTML."),
    "stack-in-response": ("Stack traces show file paths, library versions and code structure.", "Fine only in development."),
    "async-no-catch": ("On Express 4 an error thrown in an async handler is never answered: the request hangs and the socket leaks. "
                       "If it's a public route, it's a free way to tie up the server.",
                       "Fine on Express 5 or with express-async-errors installed (Casefile already skips those)."),
    "log-request-body": ("Passwords, OTPs and tokens in request bodies land in log files.", "Fine if the route never receives secrets."),
    "listen-all-interfaces": ("If the VPS firewall ever opens the port, the API is reachable directly - skipping nginx, HTTPS and Cloudflare.",
                              "Fine when the firewall blocks the port (check with the Server > Ports check)."),
    "tls-reject-unauthorized": ("Certificate checks off: anyone between you and the server can read and change the traffic.",
                                "Fine only against localhost in development."),
    # --- apps
    "dart-bad-certificate": ("Any Wi-Fi owner or network attacker can pretend to be your API and read every login.",
                             "Fine only when limited to debug builds and to localhost."),
    "dart-http-overrides": ("A global override is how certificate checks usually get switched off for the whole app.",
                            "Fine if the override doesn't touch badCertificateCallback."),
    "dart-token-in-prefs": ("SharedPreferences is a plain XML/JSON file: phone backups, rooted phones and adb on old Android can read it.",
                            "Fine for desktop builds where there is no keystore, if the file is in the user's private folder."),
    "dart-log-secret": ("Logs can be read with adb and end up in bug reports.", "Fine in debug-only code paths."),
    "http-url": ("Plain http: anyone on the same network sees and can change the data.", "Fine for localhost and LAN development addresses."),
    "cleartext": ("The app may send data over plain http.", "Fine if limited to a LAN host with a network security config."),
    "ios-ats": ("App Transport Security is off: the iOS app may use plain http anywhere.", "Fine only for a dev build."),
    "android-debuggable": ("Anyone with the phone and a USB cable can attach a debugger and read the app's memory and files.", "Never fine for a release build."),
    "android-backup": ("App data (including saved login tokens) is copied into phone backups; on Android 11 and older, `adb backup` "
                       "can pull it from an unlocked phone with USB debugging on.",
                       "Low risk if the app stores no login tokens, or if it has its own backup and doesn't need Android's."),
    "android-exported": ("Other apps on the phone can open this screen or call this component directly.",
                         "Fine if it is meant to be opened by other apps and checks what it receives."),
    "android-netconfig": ("The network config allows plain http or trusts user-installed certificates (anyone can install one to intercept).",
                          "Fine inside <debug-overrides> only."),
    "android-debug-signing": ("Release builds signed with the debug key can't be updated from the Play Store and aren't tied to you.",
                              "Fine for personal sideloaded builds."),
    "electron-unsafe-webprefs": ("With Node in the page, any XSS or any web page the window shows can run programs on the PC.",
                                 "Never fine for a window that shows remote content."),
    "electron-cert-bypass": ("Any network attacker can impersonate your server.", "Never fine in a shipped app."),
    "electron-open-external": ("A crafted link (file://, smb://, custom protocols) can start programs.", "Fine if the URL is checked to be https first."),
    "electron-load-http": ("The page that runs inside your app can be replaced on the network.", "Fine for localhost dev servers."),
    "electron-ipc-passthrough": ("Every IPC handler becomes callable by any script in the page.", "Fine if the page only ever loads your own bundled files."),
    # --- live
    "web": ("Missing browser protections make other bugs (XSS, clickjacking) easier to exploit.",
            "Usually low on a JSON API - these headers matter most on HTML pages."),
    "ports": ("A database or app port open to the internet can be attacked directly - no website, login page or Cloudflare in the way.",
              "Fine for 80/443 (and 22 with key-only login)."),
    "ssh-audit": ("Old algorithms can be downgraded or broken by a well-placed attacker.",
                  "Post-quantum warnings are about the future; they are low priority today."),
    "nuclei": ("A community template matched a known problem on this site.", "Some templates are informational - read the matched evidence."),
    "zap": ("ZAP saw this while crawling the site.", "ZAP is cautious; check the evidence before acting on low alerts."),
}

# Fallback by checklist item when the rule itself has no entry (registry pack rules).
CHECKS = {
    "cmdi": "Fine if the command is fixed text and user input never reaches it.",
    "code-eval": "Fine if the evaluated text never comes from a request.",
    "xss": "Fine if the HTML is your own constant text or is sanitized (DOMPurify) first.",
    "path": "Fine if the name is passed through path.basename() and the resolved path is checked to stay inside the folder.",
    "ssrf": "Fine if the URL is fixed or checked against an allow-list of hosts.",
    "redirect": "Fine if the target is a relative path or checked against an allow-list.",
    "secrets": "Fine if it's a test value that works nowhere - otherwise rotate it.",
    "crypto": "Fine for non-security uses like checksums.",
}

ALIASES = {"node_nosqli_injection": "nosqli", "node_password": "gitleaks", "node_secret": "gitleaks",
           "node_api_key": "gitleaks", "node_username": "gitleaks", "hardcoded_jwt_secret": "gitleaks",
           "hardcoded-jwt-secret": "gitleaks"}


def explain(f):
    """(risk, when_fine) for a finding - may be (None, None)."""
    rule = f.get("rule") or ""
    key = ALIASES.get(rule, rule)
    if f["tool"] == "gitleaks":
        key = "gitleaks"
    elif f["tool"] == "osv":
        key = "osv-malicious" if "osv:malicious" in f.get("tags", []) else "osv"
    elif f["tool"] in ("web", "ports", "ssh-audit", "nuclei", "zap") and key not in RULES:
        key = f["tool"]
    elif f["tool"] == "routes":
        key = rule
    if key in RULES:
        return RULES[key]
    from .checklist import BY_ID
    c = BY_ID.get(f.get("check"))
    if c:
        return c["why"], CHECKS.get(c["id"])
    return None, None
