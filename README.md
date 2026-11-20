# Casefile

Desktop security checker: choose a project folder and it runs every check that applies,
one by one, and keeps a case file of the results.

## What it does
- **Maps the project** (`detect.py`): Express API, Flutter (Android/iOS/desktop), Electron, Next.js.
  Checklist items that don't apply say "not used here" instead of passing silently.
- **Scanners**: Semgrep (registry packs picked per stack, cached weekly), Gitleaks (whole git history),
  OSV-Scanner (known holes + malicious packages, grouped one finding per package), Casefile's own rules
  (`rules/house.yml`, `dart.yml`, `electron.yml`) and config checks (Android manifest, network config,
  signing keys, iOS ATS, .env handling).
- **Route map** (`routes.py`): rebuilds the Express route table in the order Express runs it and flags
  routes with no login check.
- **Context pass** (`refine.py`): knows global operator filters, string coercion, Express 5,
  Firebase keys, seed scripts, desktop-only builds - and downgrades with a note instead of hiding.
- **Explanations** (`kb.py`): every finding says what can happen and when it's a false alarm.
- **Live checks**: website headers/exposed files, Nuclei (14,000+ templates), OWASP ZAP; server ports
  (with an ISP control scan), ssh-audit, Lynis over SSH.
- **Claude**: optional full review (permissions, tenants, money) and per-finding "is this real?",
  read-only tools only.
- **History, ignore-with-reason, PDF export** (`export.py`) to `~/Documents/Casefile reports`.

## Run
- App: `cd app && flutter run -d linux` (starts the engine `python3 -m casefile` itself).
- Terminal: `python3 -m casefile scan <folder> [--claude] [--fail-on high] [--json]`
  (exit code 1 when an open finding is at least that severe - use it before a publish).
- Tests: `python3 -m unittest -v tests.test_engine` (planted bugs found, clean app stays clean)
  and `CASEFILE_SCAN=<saved scan .json> flutter test test/screens_test.dart` in `app/`.

Scanners live in `~/.local/bin` and `~/.local/share` (per user, no sudo); "Update scanners & rules"
in the app updates them, verifying each download's SHA-256 against the release's own checksum file.

## Safety
Everything is read-only. Website checks are plain GETs; Nuclei runs without intrusive/DoS/fuzzing
templates at 25 requests/second; the ZAP attack scan is refused for anything that isn't localhost/LAN.
Lynis runs from a temp folder on the server and deletes it. Secrets are redacted before they reach the
UI or a report. Scan history lives in `~/.local/share/casefile`, never in the project.
