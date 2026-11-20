"""Scanner installs, versions and updates - and the local copy of Semgrep's rule packs.

Rule packs are kept in ~/.local/share/casefile/rules and refreshed weekly (or with
"Update scanners"), so two scans a day apart use the same rules: a finding that
appears or disappears then means the CODE changed, not the rules.
"""
import hashlib
import io
import json
import re
import shutil
import subprocess
import tarfile
import time
import urllib.request
import zipfile
from pathlib import Path

HOME = Path.home()
BIN = HOME / ".local/bin"
DATA = HOME / ".local/share/casefile"
RULES = DATA / "rules"
LYNIS_DIR = HOME / ".local/share/lynis"
NUCLEI_TEMPLATES = HOME / ".local/share/nuclei-templates"
ALL_PACKS = ["p/secrets", "p/owasp-top-ten", "p/javascript", "p/typescript", "p/nodejsscan", "p/jwt", "p/react",
             "p/nextjs", "p/kotlin", "p/java", "p/dockerfile", "p/nginx", "p/github-actions"]
UA = {"User-Agent": "Casefile/1.0"}
MAX_AGE = 7 * 86400


def which(name):
    p = BIN / name
    return str(p) if p.exists() else shutil.which(name)


def _get(url, timeout=60):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
        return r.read()


# ---------------------------------------------------------------- rule packs
def _pack_file(pack):
    return RULES / (pack.replace("/", "_") + ".yml")


def pack_paths(packs, on_note=lambda s: None, force=False):
    """Local paths for the packs, downloading missing or week-old ones. Returns (paths, errors)."""
    RULES.mkdir(parents=True, exist_ok=True)
    paths, errors = [], []
    for pack in packs:
        f = _pack_file(pack)
        stale = not f.exists() or force or time.time() - f.stat().st_mtime > MAX_AGE
        if stale:
            try:
                on_note(f"Downloading rule pack {pack}")
                data = _get(f"https://semgrep.dev/c/{pack}", 60)
                if not data.lstrip().startswith(b"rules"):
                    raise ValueError("unexpected reply")
                tmp = f.with_suffix(".tmp")
                tmp.write_bytes(data)
                tmp.replace(f)
            except Exception as e:  # offline or registry down: an old copy is fine
                if not f.exists():
                    errors.append(f"Rule pack {pack} could not be downloaded ({type(e).__name__}) - skipped")
                    continue
        paths.append(str(f))
    return paths, errors


def rules_date():
    files = list(RULES.glob("*.yml"))
    return time.strftime("%Y-%m-%d", time.localtime(max(f.stat().st_mtime for f in files))) if files else None


# ---------------------------------------------------------------- versions
_VERSIONS = {}


def _ver(cmd, pattern=r"(\d+\.\d+\.\d+)", cwd=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30, cwd=cwd)
        m = re.search(pattern, p.stdout + p.stderr)
        return m.group(1) if m else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def versions(refresh=False):
    if _VERSIONS and not refresh:
        return dict(_VERSIONS)
    zap = sorted((HOME / ".local/share").glob("ZAP_*"))
    _VERSIONS.update({
        "semgrep": which("semgrep") and _ver([which("semgrep"), "--version", "--disable-version-check"]),
        "gitleaks": which("gitleaks") and _ver([which("gitleaks"), "version"]),
        "osv-scanner": which("osv-scanner") and _ver([which("osv-scanner"), "--version"]),
        "nuclei": which("nuclei") and _ver([which("nuclei"), "-version", "-duc"]),
        "zap": zap[-1].name.split("_")[1] if zap and which("zap.sh") else None,
        "ssh-audit": which("ssh-audit") and _ver([which("ssh-audit"), "-h"]),
        "lynis": (LYNIS_DIR / "lynis").exists() and _ver(["./lynis", "--version"], cwd=str(LYNIS_DIR)),
        "claude": which("claude") and _ver([which("claude"), "--version"]),
    })
    return dict(_VERSIONS)


def status():
    v = versions()
    templates = sum(1 for _ in NUCLEI_TEMPLATES.rglob("*.yaml")) if NUCLEI_TEMPLATES.is_dir() else 0
    return {"tools": {k: bool(x) for k, x in v.items()}, "versions": {k: x for k, x in v.items() if x},
            "rules_date": rules_date(), "nuclei_templates": templates}


# ---------------------------------------------------------------- updates
def _sha256(b):
    return hashlib.sha256(b).hexdigest()


def _github_update(repo, current, asset_pat, sums_pat, extract, note):
    """Download a newer release binary from GitHub, verify its SHA-256 from the release's own
    checksum file, then replace ~/.local/bin/<tool>. Returns a status line."""
    rel = json.loads(_get(f"https://api.github.com/repos/{repo}/releases/latest", 30))
    latest = rel["tag_name"].lstrip("v")
    if current and tuple(map(int, re.findall(r"\d+", latest)[:3])) <= tuple(map(int, re.findall(r"\d+", current)[:3])):
        return f"up to date ({current})"
    assets = {a["name"]: a["browser_download_url"] for a in rel["assets"]}
    name = next(n for n in assets if re.fullmatch(asset_pat.replace("{v}", re.escape(latest)), n))
    sums = next(n for n in assets if re.fullmatch(sums_pat.replace("{v}", re.escape(latest)), n))
    note(f"Downloading {name}")
    blob = _get(assets[name], 600)
    expected = next((ln.split()[0] for ln in _get(assets[sums], 60).decode().splitlines() if ln.strip().endswith(name)), None)
    if not expected or expected != _sha256(blob):
        raise RuntimeError(f"checksum mismatch for {name} - not installed")
    binary, tool = extract(blob, name)
    tmp = BIN / (tool + ".new")
    tmp.write_bytes(binary)
    tmp.chmod(0o755)
    tmp.replace(BIN / tool)
    return f"updated {current or '-'} -> {latest}"


def _from_tar(member):
    def ex(blob, name):
        with tarfile.open(fileobj=io.BytesIO(blob)) as t:
            return t.extractfile(member).read(), member
    return ex


def _from_zip(member):
    def ex(blob, name):
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            return z.read(member), member
    return ex


def update(note=lambda s: None):
    """Update every scanner and rule set. Returns [(name, result)]."""
    v = versions(refresh=True)
    out = []

    def step(name, fn):
        note(f"Updating {name}")
        try:
            out.append((name, fn() or "done"))
        except Exception as e:
            out.append((name, f"failed: {str(e)[:120]}"))

    step("Semgrep rule packs", lambda: f"{len(pack_paths(ALL_PACKS, note, force=True)[0])} packs refreshed")
    if shutil.which("pipx"):
        step("Semgrep", lambda: _pipx("semgrep"))
        step("ssh-audit", lambda: _pipx("ssh-audit"))
    step("Gitleaks", lambda: _github_update("gitleaks/gitleaks", v.get("gitleaks"), r"gitleaks_{v}_linux_x64\.tar\.gz",
                                            r"gitleaks_{v}_checksums\.txt", _from_tar("gitleaks"), note))
    step("OSV-Scanner", lambda: _github_update("google/osv-scanner", v.get("osv-scanner"), r"osv-scanner_linux_amd64",
                                               r"osv-scanner_SHA256SUMS", lambda b, n: (b, "osv-scanner"), note))
    step("Nuclei", lambda: _github_update("projectdiscovery/nuclei", v.get("nuclei"), r"nuclei_{v}_linux_amd64\.zip",
                                          r"nuclei_{v}_checksums\.txt", _from_zip("nuclei"), note))
    if which("nuclei"):
        step("Nuclei templates", lambda: _cmd([which("nuclei"), "-ut", "-ud", str(NUCLEI_TEMPLATES)], 900))
    if (LYNIS_DIR / ".git").exists():
        step("Lynis", lambda: _cmd(["git", "-C", str(LYNIS_DIR), "pull", "--ff-only", "-q"], 300))
    if which("zap.sh"):
        step("ZAP add-ons", lambda: _cmd([which("zap.sh"), "-cmd", "-addonupdate"], 900))
    versions(refresh=True)
    return out


def _pipx(pkg):
    p = subprocess.run(["pipx", "upgrade", pkg], capture_output=True, text=True, timeout=900)
    txt = (p.stdout + p.stderr).strip().splitlines()
    return (txt[-1] if txt else "done")[:120]


def _cmd(cmd, timeout):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout).strip()[-160:])
    lines = [ln for ln in re.sub(r"\x1b\[[0-9;]*m", "", p.stdout + p.stderr).splitlines() if ln.strip()]
    return (lines[-1] if lines else "done")[:120]
