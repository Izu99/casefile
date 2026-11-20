"""python3 -m casefile                 -> scan engine for the app: prints `PORT <n>`, serves until stdin closes
                                         (so the engine never outlives the app window that started it)
python3 -m casefile scan PATH [opts]  -> scan from the terminal (before a publish, or on a timer)

    --claude          add the Claude review (slow, uses your Claude plan)
    --fail-on LEVEL   exit 1 if an open finding is at least this severe (critical/high/medium/low)
    --json            print the whole report as JSON
"""
import argparse
import json
import sys

from . import engine, server, store


def cli(argv):
    ap = argparse.ArgumentParser(prog="casefile scan")
    ap.add_argument("path")
    ap.add_argument("--claude", action="store_true")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium", "low"])
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    meta = store.save_meta(a.path)

    def step(name, **kw):
        if kw.get("state") in ("done", "failed") and not a.json:
            what = kw.get("error") or (f"{kw.get('count')} found" if kw.get("count") is not None else "")
            print(f"  {'x' if kw['state'] == 'failed' else '.'} {name}: {what}", flush=True)
    rep = engine.run_scan(a.path, {"claude": a.claude}, meta, step)
    if a.json:
        print(json.dumps(rep, indent=1))
    else:
        c = rep["counts"]
        print(f"\n{rep['project']}: {rep['passed']}/{rep['looked']} checks passed, {rep['open']} open "
              f"({c['critical']} critical, {c['high']} high, {c['medium']} medium, {c['low']} low), "
              f"{rep['unchecked']} not checked, {rep['na']} not used")
        d = rep.get("diff") or {}
        if d.get("since") and not d.get("reset"):
            print(f"since {d['since']}: {len(d['new'])} new, {len(d['fixed'])} fixed")
        for f in [f for f in rep["findings"] if not f.get("ignored") and f["severity"] in ("critical", "high")][:20]:
            print(f"  [{f['severity']}] {f['title'][:90]}  ({f['file']}{':' + str(f['line']) if f['line'] else ''})")
    if a.fail_on:
        order = ["critical", "high", "medium", "low"]
        return 1 if any(rep["counts"][s] for s in order[:order.index(a.fail_on) + 1]) else 0
    return 0


if len(sys.argv) > 1 and sys.argv[1] == "scan":
    sys.exit(cli(sys.argv[2:]))

port = server.serve(int(sys.argv[1]) if len(sys.argv) > 1 else 0)
print(f"PORT {port}", flush=True)
try:
    sys.stdin.read()
except KeyboardInterrupt:
    pass
