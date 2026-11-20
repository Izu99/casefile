"""Local HTTP API for the app (127.0.0.1 only). Long work runs as background jobs that
the app polls; scans are saved through store.py.
"""
import json
import subprocess
import threading
import time
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import checklist, engine, export, scanners, store, tools, web

JOBS = {}


class Job:
    def __init__(self, steps):
        self.id = uuid.uuid4().hex[:10]
        self.state = "running"
        self.steps = [{"name": s, "state": "waiting", "count": None, "error": "", "note": ""} for s in steps]
        self.result = None
        self.error = ""
        JOBS[self.id] = self

    def step(self, name, **kw):
        for s in self.steps:
            if s["name"] == name:
                s.update(kw)

    def view(self):
        return {"id": self.id, "state": self.state, "steps": self.steps, "result": self.result, "error": self.error}


def start(job, fn):
    def wrap():
        try:
            job.result = fn()
            job.state = "done"
        except Exception as e:
            traceback.print_exc()
            job.error, job.state = str(e)[:400], "failed"
    threading.Thread(target=wrap, daemon=True).start()
    return job.view()


def pick_folder():
    p = subprocess.run(["zenity", "--file-selection", "--directory", "--title=Choose a project folder"],
                       capture_output=True, text=True)
    return p.stdout.strip()


def _open(path):
    subprocess.Popen(["xdg-open", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        p = u.path
        if p == "/api/tools":
            return self._send(200, tools.status())
        if p == "/api/projects":
            return self._send(200, store.projects())
        if p == "/api/checklist":
            return self._send(200, [checklist.public(c) for c in checklist.CHECKS])
        if p.startswith("/api/job/"):
            job = JOBS.get(p.rsplit("/", 1)[-1])
            return self._send(200 if job else 404, job.view() if job else {"error": "no job"})
        if p == "/api/report":
            return self._send(200, {"meta": store.meta(q["path"]), "report": engine.refresh(q["path"])})
        self._send(404, {"error": "unknown"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return self._send(400, {"error": "bad json"})
        p = urlsplit(self.path).path
        try:
            return self.api_post(p, body)
        except (KeyError, StopIteration) as e:
            return self._send(400, {"error": f"missing {e}"})
        except Exception as e:
            traceback.print_exc()
            return self._send(500, {"error": str(e)[:300]})

    def api_post(self, p, body):
        if p == "/api/pick":
            return self._send(200, {"path": pick_folder()})
        if p == "/api/open":
            f = (Path(body["path"]) / body["file"]).resolve()
            if Path(body["path"]).resolve() not in f.parents or not f.is_file():
                return self._send(400, {"error": "File not found"})
            if scanners.which("code"):
                subprocess.Popen([scanners.which("code"), "-g", f"{f}:{body.get('line') or 1}"])
            else:
                _open(str(f))
            return self._send(200, {})
        if p == "/api/link":
            if str(body.get("url", "")).startswith(("https://", "http://")):
                _open(body["url"])
            return self._send(200, {})
        if p == "/api/meta":
            return self._send(200, store.save_meta(body["path"], url=body.get("url"), ssh=body.get("ssh")))
        if p == "/api/scan":
            path = str(Path(body["path"]).expanduser().resolve())
            if not Path(path).is_dir():
                return self._send(400, {"error": "That folder doesn't exist."})
            m = store.save_meta(path)
            job = Job(engine.scan_steps(m, body))
            return self._send(200, start(job, lambda: engine.run_scan(path, body, m, job.step)))
        if p == "/api/ignore":
            store.set_ignored(body["path"], body["fp"], body.get("reason"))
            return self._send(200, engine.refresh(body["path"]))
        if p == "/api/verify":
            rep = store.latest(body["path"])
            f = next(x for x in rep["findings"] if x["fp"] == body["fp"])
            job = Job(["Claude reading the code"])

            def go():
                job.step("Claude reading the code", state="running")
                v = scanners.claude_verify(body["path"], f, lambda s: job.step("Claude reading the code", note=s))
                store.set_verdict(body["path"], f["fp"], v)
                job.step("Claude reading the code", state="done")
                return engine.refresh(body["path"])
            return self._send(200, start(job, go))
        if p == "/api/export":
            rep = engine.refresh(body["path"])
            if not rep:
                return self._send(400, {"error": "Scan the project first."})
            out = export.export(rep, store.meta(body["path"]))
            _open(out["pdf"] or out["html"])
            return self._send(200, out)
        if p == "/api/update-tools":
            job = Job(["Updating scanners and rules"])

            def go():
                job.step("Updating scanners and rules", state="running")
                res = tools.update(lambda s: job.step("Updating scanners and rules", note=s))
                job.step("Updating scanners and rules", state="done", count=len(res))
                return {"results": res, "status": tools.status()}
            return self._send(200, start(job, go))
        if p == "/api/web":
            return self.live_web(body)
        if p == "/api/server":
            return self.live_server(body)
        return self._send(404, {"error": "unknown"})

    def live_web(self, body):
        url = body["url"].strip()
        url = url if "://" in url else "https://" + url
        steps = ["Headers, cookies & exposed files"] + (["Nuclei (known CVEs & exposures)"] if body.get("nuclei") else []) \
            + (["ZAP " + ("attack scan" if body.get("active") else "crawl")] if body.get("zap") else [])
        job = Job(steps)

        def go():
            out, ran = [], set()
            job.step(steps[0], state="running")
            got = web.headers_check(url)
            out += got
            ran.add("web")
            job.step(steps[0], state="done", count=len(got))
            for name in steps[1:]:
                job.step(name, state="running")
                try:
                    if name.startswith("Nuclei"):
                        got = web.nuclei_scan(url, lambda s: job.step(name, note=s))
                        ran.add("nuclei")
                    else:
                        got = web.zap_scan(url, active=body.get("active"), progress=lambda s: job.step(name, note=s))
                        ran.add("zap")
                    out += got
                    job.step(name, state="done", count=len(got))
                except Exception as e:
                    job.step(name, state="failed", error=str(e)[:200])
            return engine.live_report(url, out, "web", ran)
        return self._send(200, start(job, go))

    def live_server(self, body):
        spec = body["host"].strip()
        host = spec.split("@")[-1].split(":")[0]
        port = int(spec.rsplit(":", 1)[1]) if ":" in spec.split("@")[-1] else 22
        steps = ["Open ports (with ISP control scan)", "SSH algorithms (ssh-audit)"] + (["Hardening (Lynis over SSH)"] if body.get("lynis") else [])
        job = Job(steps)

        def go():
            out, ran = [], set()
            plan = [(steps[0], "ports", lambda: web.ports_check(host, lambda s: job.step(steps[0], note=s))),
                    (steps[1], "ssh-audit", lambda: web.ssh_audit(host, port))]
            if body.get("lynis"):
                plan.append((steps[2], "lynis", lambda: web.lynis_ssh(spec, lambda s: job.step(steps[2], note=s))))
            for name, tool, fn in plan:
                job.step(name, state="running")
                try:
                    got = fn()
                    out += got
                    ran.add(tool)
                    job.step(name, state="done", count=len(got))
                except Exception as e:
                    job.step(name, state="failed", error=str(e)[:200])
            return engine.live_report(spec, out, "server", ran)
        return self._send(200, start(job, go))


def serve(port=0):
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    threading.Thread(target=tools.versions, daemon=True).start()  # warm the version cache
    return httpd.server_address[1]
