"""Scan history, ignored findings and Claude verdicts, kept per project in
~/.local/share/casefile/projects/<id>/ - never inside the project folder itself.
"""
import hashlib
import json
import time
from pathlib import Path

ROOT = Path.home() / ".local/share/casefile/projects"


def pid(path):
    return hashlib.sha1(str(Path(path).resolve()).encode()).hexdigest()[:12]


def _dir(path):
    d = ROOT / pid(path)
    (d / "scans").mkdir(parents=True, exist_ok=True)
    return d


def _read(p, default):
    try:
        return json.loads(Path(p).read_text())
    except (OSError, json.JSONDecodeError):
        return default


def _write(p, data):
    tmp = Path(str(p) + ".tmp")
    tmp.write_text(json.dumps(data, indent=1))
    tmp.replace(p)


def meta(path):
    return _read(_dir(path) / "meta.json", {"path": str(Path(path).resolve()), "name": Path(path).name, "url": "", "ssh": ""})


def save_meta(path, **kw):
    m = meta(path)
    m.update({k: v for k, v in kw.items() if v is not None})
    _write(_dir(path) / "meta.json", m)
    return m


def ignored(path):
    return _read(_dir(path) / "ignored.json", {})


def set_ignored(path, fp, reason):
    ig = ignored(path)
    if reason is None:
        ig.pop(fp, None)
    else:
        ig[fp] = {"reason": reason, "at": time.strftime("%Y-%m-%d")}
    _write(_dir(path) / "ignored.json", ig)


def verdicts(path):
    return _read(_dir(path) / "verdicts.json", {})


def set_verdict(path, fp, verdict):
    v = verdicts(path)
    v[fp] = {**verdict, "at": time.strftime("%Y-%m-%d")}
    _write(_dir(path) / "verdicts.json", v)


def scans(path):
    return sorted((_dir(path) / "scans").glob("*.json"))


def latest(path):
    s = scans(path)
    return _read(s[-1], None) if s else None


def save_scan(path, report):
    prev = latest(path)
    if prev and prev.get("engine") != report.get("engine"):
        report["diff"] = {"new": [], "fixed": [], "since": prev["when"], "reset": True}
    elif prev:
        covered = set(report["ran_tools"]) | ({"routes"} if "semgrep" in report["ran_tools"] else set())
        old = {f["fp"]: f for f in prev["findings"]}
        now = {f["fp"] for f in report["findings"]}
        report["diff"] = {"new": [fp for fp in now if fp not in old],
                          "fixed": [{"title": f["title"], "severity": f["severity"], "file": f["file"]}
                                    for fp, f in old.items() if fp not in now and f["tool"] in covered],
                          "since": prev["when"]}
    else:
        report["diff"] = {"new": [], "fixed": [], "since": None}
    _write(_dir(path) / "scans" / time.strftime("%Y%m%d-%H%M%S.json"), report)
    save_meta(path, last_scan=report["when"], score=report["score"], open=report["open"])
    return report


def projects():
    out = []
    for d in ROOT.glob("*/meta.json"):
        m = _read(d, None)
        if m and Path(m["path"]).exists():
            out.append(m)
    return sorted(out, key=lambda m: m.get("last_scan") or "", reverse=True)
