"""Casefile's own tests: every planted bug in fixtures/vuln must be found, and the
well-written fixtures/clean must come back without code findings. Offline: only
Casefile's own rules run (no registry packs, no network scanners).

    cd ~/Documents/self/casefile && python3 -m unittest -v tests.test_engine
"""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from casefile import refine, routes, scanners
from casefile.detect import detect

HERE = Path(__file__).parent / "fixtures"


def scan(name):
    tmp = Path(tempfile.mkdtemp(prefix="casefile-test-"))
    root = tmp / name
    shutil.copytree(HERE / name, root)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x"], cwd=root, check=True)
    stack = detect(root)
    stack["packs"] = []  # offline: house, dart, electron and route rules only
    found, errors, facts = scanners.semgrep(root, stack)
    assert not errors, errors
    found += scanners.house(root, stack)[0]
    table, rf = routes.build(root, facts)
    found = refine.refine(root, stack, found + rf)
    shutil.rmtree(tmp)
    return stack, found, table


class Vulnerable(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stack, cls.found, cls.routes = scan("vuln")
        cls.rules = {f["rule"] for f in cls.found}

    def test_stack(self):
        f = self.stack["flags"]
        for flag in ("express", "express4", "mongo", "jwt", "flutter", "android", "ios", "electron", "next"):
            self.assertTrue(f[flag], flag)
        self.assertFalse(f["sql"])

    def test_every_planted_bug_is_found(self):
        expected = {
            # server
            "jwt-no-expiry", "fallback-secret", "bcrypt-low-rounds", "cors-open", "json-big-limit", "mass-assignment",
            "money-from-client", "role-from-client", "idor-candidate", "regex-from-input", "mongo-where",
            "math-random-token", "stack-in-response", "async-no-catch", "count-plus-one", "log-request-body",
            "multer-no-filter", "tls-reject-unauthorized", "session-cookie-insecure", "cookie-without-flags",
            "listen-all-interfaces", "env-tracked", "no-rate-limit", "no-helmet", "password-selectable", "env-placeholder",
            # routes
            "no-auth", "public-static",
            # flutter / android / ios
            "dart-bad-certificate", "dart-token-in-prefs", "dart-random-token", "dart-log-secret", "http-url",
            "cleartext", "android-debuggable", "android-backup", "android-exported", "android-netconfig",
            "android-debug-signing", "signing-key-tracked", "ios-ats",
            # electron / next
            "electron-unsafe-webprefs", "electron-cert-bypass", "electron-open-external", "electron-load-http",
            "electron-ipc-passthrough", "next-public-secret",
        }
        self.assertEqual(sorted(expected - self.rules), [])

    def test_async_rule_needs_async(self):
        # app.get('/health', (req, res) => ...) is not async and must not be flagged
        async_hits = [f for f in self.found if f["rule"] == "async-no-catch"]
        self.assertTrue(async_hits)
        self.assertFalse(any(f["file"].endswith("app.js") for f in async_hits))

    def test_route_map(self):
        by = {(r["method"], r["path"]): r for r in self.routes}
        self.assertFalse(by[("DELETE", "/api/items/:id")]["auth"])
        self.assertTrue(by[("POST", "/api/invoices")]["auth"])  # router.route() chain
        self.assertTrue(by[("POST", "/api/invoices")]["role"])
        self.assertTrue(by[("POST", "/api/auth/login")]["public"])
        no_auth = {f["title"] for f in self.found if f["rule"] == "no-auth"}
        self.assertIn("DELETE /api/items/:id has no login check", no_auth)
        self.assertFalse(any("/login" in t or "/health" in t for t in no_auth))

    def test_android_backup_is_low_without_tokens(self):
        f = next(f for f in self.found if f["rule"] == "android-backup")
        self.assertEqual(f["severity"], "medium")  # the fixture keeps a token in SharedPreferences

    def test_secrets_redacted(self):
        for f in self.found:
            self.assertNotIn("hunter2-long-secret-value", f.get("snippet", ""))


class Clean(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stack, cls.found, cls.routes = scan("clean")

    def test_no_findings(self):
        self.assertEqual([(f["rule"], f["file"], f["line"], f["title"]) for f in self.found], [])

    def test_routes_all_protected_or_public(self):
        by = {(r["method"], r["path"]): r for r in self.routes}
        self.assertTrue(by[("GET", "/api/items")]["auth"])
        self.assertTrue(by[("GET", "/api/settings")]["role"])
        self.assertFalse(by[("GET", "/api/items")]["role"])
        self.assertTrue(by[("POST", "/api/auth/login")]["public"])
        self.assertIn("loginLimiter", by[("POST", "/api/auth/login")]["mws"])
        self.assertTrue(by[("POST", "/api/settings/sync")]["auth"])  # API-key middleware counts as a login check


class Redact(unittest.TestCase):
    def test_keeps_code_hides_keys(self):
        self.assertEqual(scanners.redact("requireActiveCompanyMiddleware(req)"), "requireActiveCompanyMiddleware(req)")
        self.assertIn("█", scanners.redact("key = 'AKIAIOSFODNN7EXAMPLE'"))
        self.assertIn("█", scanners.redact("mongodb+srv://user:Sup3rPass@cluster0.x.mongodb.net/db"))
        self.assertIn("█", scanners.redact("token: 'q8Zr2LmX9vT4nB7kP1sW6yH3jD5fG0aE'"))
        strict = scanners.redact("const MANAGER_PASSWORD = 'Manager#123';", strict=True)
        self.assertIn("MANAGER_PASSWORD", strict)
        self.assertNotIn("Manager#123", strict)
        self.assertNotIn("hunter2", scanners.redact("storePassword=hunter2", strict=True))


if __name__ == "__main__":
    unittest.main()
