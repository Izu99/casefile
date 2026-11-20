"""Live checks against a website / API URL - what the browser extensions do, plus ZAP.

Everything here only reads: normal GET requests, the same a visitor's browser makes.
ZAP runs its spider + passive scan (it looks, it does not attack). The active attack
scan is only allowed against localhost / LAN addresses, never a production domain.
"""
import http.client
import ipaddress
import json
import re
import socket
import ssl
import subprocess
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from .scanners import fingerprint, which

UA = "Casefile/1.0 (security self-check)"


def _f(tag, sev, title, fix, url, detail=""):
    return dict(tool="web", rule=tag, severity=sev, title=title, message=detail or title, fix=fix,
                file=url, line=0, snippet=detail[:200], tags=["web:" + tag], link="",
                fp=fingerprint("web", tag, urllib.parse.urlsplit(url).netloc, title))


def _get(url, method="GET", headers=None, follow=False, timeout=12):
    u = urllib.parse.urlsplit(url)
    conn_cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(u.hostname, u.port, timeout=timeout)
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    conn.request(method, path, headers={"User-Agent": UA, **(headers or {})})
    r = conn.getresponse()
    body = r.read(4096) if method == "GET" else b""
    hdrs = {k.lower(): v for k, v in r.getheaders()}
    cookies = [v for k, v in r.getheaders() if k.lower() == "set-cookie"]
    conn.close()
    return r.status, hdrs, cookies, body


def is_local(url):
    host = urllib.parse.urlsplit(url).hostname or ""
    if host in ("localhost",):
        return True
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        return ip.is_private or ip.is_loopback
    except (OSError, ValueError):
        return False


def headers_check(url):
    if "://" not in url:
        url = "https://" + url
    u = urllib.parse.urlsplit(url)
    base = f"{u.scheme}://{u.netloc}"
    out = []

    # HTTPS redirect + certificate
    if u.scheme == "https":
        try:
            st, h, _, _ = _get(f"http://{u.netloc}/")
            if not (300 <= st < 400 and h.get("location", "").startswith("https://")):
                out.append(_f("https", "high", "http:// does not redirect to https://",
                              "Redirect all port-80 traffic to https (nginx: return 301 https://$host$request_uri).", url, f"HTTP status {st}"))
        except OSError:
            pass  # port 80 closed is fine
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((u.hostname, u.port or 443), timeout=10) as s:
                with ctx.wrap_socket(s, server_hostname=u.hostname) as tls:
                    cert = tls.getpeercert()
                    version = tls.version()
            exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            if days < 14:
                out.append(_f("https", "high", f"Certificate expires in {days} days", "Renew it now.", url))
            if version in ("TLSv1", "TLSv1.1"):
                out.append(_f("https", "medium", f"Old TLS version accepted ({version})", "Allow TLS 1.2 and 1.3 only.", url))
        except ssl.SSLCertVerificationError as e:
            out.append(_f("https", "critical", "Certificate is not valid", "Install a valid certificate.", url, str(e)[:200]))
        except OSError:
            pass
    else:
        out.append(_f("https", "high", "Site is served over plain http", "Serve it over https only.", url))

    st, h, cookies, body = _get(url)
    hs = h

    def need(tag, name, sev, fix):
        if name not in hs:
            out.append(_f(tag, sev, f"Missing {name} header", fix, url))

    if u.scheme == "https":
        need("hsts", "strict-transport-security", "medium", "Strict-Transport-Security: max-age=31536000; includeSubDomains")
    ct = hs.get("content-type", "")
    if "html" in ct:
        need("csp", "content-security-policy", "medium",
             "Add a Content-Security-Policy (start with default-src 'self' and add what the page really loads).")
        if "x-frame-options" not in hs and "frame-ancestors" not in hs.get("content-security-policy", ""):
            out.append(_f("frame", "medium", "Page can be put inside an iframe (clickjacking)",
                          "X-Frame-Options: DENY, or CSP frame-ancestors 'none'.", url))
    need("nosniff", "x-content-type-options", "low", "X-Content-Type-Options: nosniff")
    need("referrer", "referrer-policy", "low", "Referrer-Policy: strict-origin-when-cross-origin")
    for name in ("server", "x-powered-by", "x-aspnet-version"):
        v = hs.get(name, "")
        if name == "x-powered-by" and v or any(ch.isdigit() for ch in v):
            out.append(_f("version", "low", f"{name}: {v} - software and version are announced",
                          "nginx: server_tokens off; Express: app.disable('x-powered-by') (helmet does it).", url, f"{name}: {v}"))
    for c in cookies:
        low = c.lower()
        name = c.split("=", 1)[0]
        missing = [flag for flag, key in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite")) if key not in low]
        if missing:
            out.append(_f("cookie", "medium", f"Cookie {name} missing {', '.join(missing)}",
                          "Set session cookies with Secure; HttpOnly; SameSite=Lax (or Strict).", url, c[:200]))

    # CORS: does the server reflect any origin?
    evil = "https://casefile-probe.example"
    try:
        _, ch, _, _ = _get(url, headers={"Origin": evil})
        acao = ch.get("access-control-allow-origin", "")
        if acao == evil or (acao == "*" and ch.get("access-control-allow-credentials") == "true"):
            out.append(_f("cors", "high", "API trusts any website (reflects the Origin header)",
                          "Allow-list your own origins only in the CORS config.", url, f"Access-Control-Allow-Origin: {acao}"))
        elif acao == "*":
            out.append(_f("cors", "low", "Access-Control-Allow-Origin: *", "Fine for public data; not for anything behind login.", url))
    except OSError:
        pass

    # files that must never be public
    probes = ["/.env", "/.git/config", "/.git/HEAD", "/server/.env", "/api/.env", "/backup.zip", "/db.sql",
              "/dump.sql", "/.DS_Store", "/config.json", "/.vscode/sftp.json", "/phpinfo.php", "/server-status",
              "/api-docs", "/swagger.json", "/.npmrc", "/docker-compose.yml"]
    for p in probes:
        try:
            st, ph, _, pb = _get(base + p)
        except OSError:
            continue
        text = pb[:600].decode("utf-8", "ignore")
        real = st == 200 and (
            (p.endswith(".env") and "=" in text and "<html" not in text.lower()) or
            (p.startswith("/.git") and ("[core]" in text or text.startswith("ref:"))) or
            (p.endswith((".zip", ".sql")) and "html" not in ph.get("content-type", "")) or
            (p in ("/.npmrc", "/.vscode/sftp.json", "/docker-compose.yml", "/config.json") and "<html" not in text.lower() and len(text) > 10) or
            (p in ("/phpinfo.php", "/server-status") and ("phpinfo" in text.lower() or "apache status" in text.lower())) or
            (p in ("/api-docs", "/swagger.json") and ("swagger" in text.lower() or "openapi" in text.lower())))
        if real:
            sev = "low" if p in ("/api-docs", "/swagger.json") else "critical"
            out.append(_f("exposed", sev, f"{p} is publicly readable", "Block it in nginx (location ~ /\\. { deny all; }) "
                          "and if it held secrets, rotate them.", base + p, text[:120]))
    return out


# ---------------------------------------------------------------- ZAP
ZAP_PORT = 8095


def _zap(path, **params):
    q = urllib.parse.urlencode(params)
    with urllib.request.urlopen(f"http://127.0.0.1:{ZAP_PORT}{path}?{q}", timeout=30) as r:
        return json.loads(r.read())


def zap_scan(url, active=False, progress=lambda msg: None, max_minutes=10):
    if active and not is_local(url):
        raise ValueError("Attack scan is only allowed on localhost / LAN, never on a live site.")
    proc = subprocess.Popen([which("zap.sh"), "-daemon", "-port", str(ZAP_PORT), "-host", "127.0.0.1",
                             "-config", "api.disablekey=true", "-config", "api.addrs.addr.name=127.0.0.1",
                             "-config", "api.addrs.addr.regex=false", "-silent"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        progress("Starting ZAP")
        for _ in range(120):
            try:
                _zap("/JSON/core/view/version/")
                break
            except OSError:
                time.sleep(1)
        else:
            raise RuntimeError("ZAP did not start")
        deadline = time.time() + max_minutes * 60
        sid = _zap("/JSON/spider/action/scan/", url=url, maxChildren=30, recurse="true")["scan"]
        while int(_zap("/JSON/spider/view/status/", scanId=sid)["status"]) < 100 and time.time() < deadline:
            progress(f"ZAP crawling: {_zap('/JSON/spider/view/status/', scanId=sid)['status']}%")
            time.sleep(2)
        if active:
            aid = _zap("/JSON/ascan/action/scan/", url=url, recurse="true")["scan"]
            while int(_zap("/JSON/ascan/view/status/", scanId=aid)["status"]) < 100 and time.time() < deadline:
                progress(f"ZAP attack scan: {_zap('/JSON/ascan/view/status/', scanId=aid)['status']}%")
                time.sleep(3)
        while int(_zap("/JSON/pscan/view/recordsToScan/")["recordsToScan"]) > 0 and time.time() < deadline:
            progress("ZAP checking responses")
            time.sleep(1)
        alerts = _zap("/JSON/core/view/alerts/", baseurl=url, start=0, count=500)["alerts"]
    finally:
        try:
            _zap("/JSON/core/action/shutdown/")
        except OSError:
            pass
        try:
            proc.wait(20)
        except subprocess.TimeoutExpired:
            proc.kill()
    sev = {"High": "high", "Medium": "medium", "Low": "low", "Informational": None}
    grouped = {}
    for a in alerts:
        s = sev.get(a.get("risk"))
        if not s:
            continue
        key = a.get("pluginId"), a.get("alert")
        g = grouped.setdefault(key, {**a, "urls": []})
        g["urls"].append(a.get("url"))
    out = []
    for (pid, name), a in grouped.items():
        cwe = a.get("cweid")
        out.append(dict(tool="zap", rule=str(pid), severity=sev[a["risk"]], title=f"{name} ({len(a['urls'])} URL{'s' if len(a['urls']) > 1 else ''})",
                        message=a.get("description", ""), fix=a.get("solution", ""), file=a["urls"][0], line=0,
                        snippet=(a.get("evidence") or "")[:200], tags=["tool:zap"] + ([f"cwe-{cwe}"] if cwe and cwe != "-1" else []),
                        link=(a.get("reference") or "").split("\n")[0], fp=fingerprint("zap", pid, urllib.parse.urlsplit(url).netloc)))
    return out


# ---------------------------------------------------------------- SSH
def ssh_audit(host, port=22):
    p = subprocess.run([which("ssh-audit"), "-n", "-j", "-p", str(port), host], capture_output=True, text=True, timeout=120)
    try:
        data = json.loads(p.stdout)
    except json.JSONDecodeError:
        raise RuntimeError((p.stdout + p.stderr).strip()[-300:] or "ssh-audit failed")
    out = []
    for kind in ("kex", "key", "enc", "mac"):
        for alg in data.get(kind, []):
            notes = alg.get("notes", {})
            for level, sev in (("fail", "high"), ("warn", "medium")):
                for msg in notes.get(level, []):
                    out.append(dict(tool="ssh-audit", rule=f"{kind}:{alg.get('algorithm')}", severity="low" if "post-quantum" in msg else sev,
                                    title=f"{alg.get('algorithm')} ({kind}): {msg}",
                                    message=msg, fix=f"Remove {alg.get('algorithm')} from sshd_config ({ {'kex': 'KexAlgorithms', 'key': 'HostKeyAlgorithms', 'enc': 'Ciphers', 'mac': 'MACs'}[kind] }), then restart sshd.",
                                    file=f"{host}:{port}", line=0, snippet="", tags=["tool:ssh-audit"], link="https://www.ssh-audit.com/hardening_guides.html",
                                    fp=fingerprint("ssh", host, kind, alg.get("algorithm"), msg)))
    for cve in data.get("cves", []):
        out.append(dict(tool="ssh-audit", rule=cve.get("name"), severity="high", title=f"{cve.get('name')}: {cve.get('description')}",
                        message=cve.get("description", ""), fix="Update OpenSSH on the server.", file=f"{host}:{port}", line=0,
                        snippet="", tags=["tool:ssh-audit"], link=f"https://nvd.nist.gov/vuln/detail/{cve.get('name')}",
                        fp=fingerprint("ssh", host, cve.get("name"))))
    return out


# ---------------------------------------------------------------- Nuclei
def nuclei_scan(url, progress=lambda msg: None, max_minutes=15):
    """Nuclei's automatic scan: detect the site's technology, then run the matching
    community templates (CVEs, exposures, misconfigurations). Intrusive, DoS, fuzzing
    and brute-force templates are excluded, and requests are rate-limited."""
    if "://" not in url:
        url = "https://" + url
    cmd = [which("nuclei"), "-u", url, "-as", "-jsonl", "-silent", "-nc", "-duc", "-rl", "25", "-c", "8",
           "-timeout", "8", "-etags", "intrusive,dos,fuzz,bruteforce,brute-force,default-login",
           "-es", "info", "-stats", "-sj", "-si", "5"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    hits = []

    def read_stats():
        for line in proc.stderr:
            try:
                st = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "requests" in st and "total" in st:
                progress(f"Nuclei: {st.get('requests')}/{st.get('total')} requests, {st.get('matched', 0)} matched")

    import threading
    threading.Thread(target=read_stats, daemon=True).start()
    deadline = time.time() + max_minutes * 60
    try:
        for line in proc.stdout:
            try:
                hits.append(json.loads(line))
            except json.JSONDecodeError:
                pass
            if time.time() > deadline:
                break
    finally:
        if proc.poll() is None:
            proc.kill()
    out = []
    for h in hits:
        info = h.get("info", {})
        sev = info.get("severity", "low")
        if sev not in ("low", "medium", "high", "critical"):
            continue
        refs = info.get("reference") or []
        cls = info.get("classification") or {}
        cwe = [c.lower() for c in (cls.get("cwe-id") or []) if c]
        out.append(dict(tool="nuclei", rule=h.get("template-id", ""), severity=sev,
                        title=f"{info.get('name', h.get('template-id'))}",
                        message=(info.get("description") or "").strip()[:800],
                        fix=(info.get("remediation") or "Read the template's references for the fix.").strip()[:600],
                        file=h.get("matched-at") or url, line=0,
                        snippet=" ".join(str(x) for x in (h.get("extracted-results") or []))[:200],
                        tags=["tool:nuclei"] + cwe, link=refs[0] if isinstance(refs, list) and refs else "",
                        fp=fingerprint("nuclei", h.get("template-id"), urllib.parse.urlsplit(url).netloc, h.get("matcher-name", ""))))
    return out


# ---------------------------------------------------------------- ports
PORTS = {
    21: ("FTP", "high"), 23: ("Telnet", "high"), 25: ("SMTP", "low"), 445: ("Windows file sharing", "critical"),
    1433: ("MS SQL", "critical"), 2375: ("Docker API (no TLS)", "critical"), 2376: ("Docker API", "high"),
    3306: ("MySQL", "critical"), 5432: ("PostgreSQL", "critical"), 5601: ("Kibana", "high"), 5672: ("RabbitMQ", "high"),
    5984: ("CouchDB", "critical"), 6379: ("Redis", "critical"), 9200: ("Elasticsearch", "critical"),
    11211: ("Memcached", "critical"), 15672: ("RabbitMQ admin", "high"), 27017: ("MongoDB", "critical"),
    27018: ("MongoDB", "critical"), 9229: ("Node.js debugger", "critical"), 5555: ("Android adb", "critical"),
    8080: ("app / proxy", "high"), 8081: ("app", "high"), 8000: ("app", "high"), 8888: ("app / Jupyter", "high"),
    9000: ("app / PHP-FPM / Portainer", "high"), 9090: ("app / Prometheus", "high"), 4000: ("app", "high"),
    10000: ("Webmin", "high"), 2082: ("cPanel", "medium"), 2083: ("cPanel", "medium"), 8443: ("app (https)", "medium"),
    **{p: ("Node app", "high") for p in list(range(3000, 3011)) + list(range(5000, 5021))},
}
EXPECTED = {22: "SSH", 80: "HTTP", 443: "HTTPS"}
CLOUDFLARE = ["173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
              "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
              "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"]
CONTROL = "203.0.113.1"  # TEST-NET-3: nothing lives there, so anything "open" is the ISP, not the target


def _open(host, port, timeout=2.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def ports_check(target, progress=lambda msg: None):
    """TCP connect check of database/app ports. Read-only: it opens and closes a connection,
    sends nothing. A control scan of an empty address first removes ports this
    internet connection fakes as open (some ISPs answer for any host)."""
    from concurrent.futures import ThreadPoolExecutor
    host = urllib.parse.urlsplit(target).hostname if "://" in target else target.split("@")[-1].split(":")[0]
    try:
        ip = socket.gethostbyname(host)
    except OSError as e:
        raise RuntimeError(f"Can't resolve {host}: {e}")
    if any(ipaddress.ip_address(ip) in ipaddress.ip_network(n) for n in CLOUDFLARE):
        return [dict(tool="ports", rule="cloudflare", severity="low", title=f"{host} points to Cloudflare ({ip}), not to your server",
                     message="Scanning it would check Cloudflare's ports, not your VPS. Enter the server's own IP address instead.",
                     fix="Use the VPS IP (from your hosting panel). Behind Cloudflare, also allow 80/443 only from Cloudflare's IP ranges.",
                     file=host, line=0, snippet=ip, tags=["tool:ports-note"], link="https://www.cloudflare.com/ips/",
                     fp=fingerprint("ports", "cf", host))]
    ports = sorted(set(PORTS) | set(EXPECTED))
    progress(f"Control scan ({CONTROL}) to spot ports this connection fakes")
    with ThreadPoolExecutor(64) as pool:
        fake = {p for p, ok in zip(ports, pool.map(lambda p: _open(CONTROL, p, 1.5), ports)) if ok}
        progress(f"Checking {len(ports)} ports on {ip}" + (f" (ignoring {len(fake)} the ISP fakes)" if fake else ""))
        live = [p for p, ok in zip(ports, pool.map(lambda p: _open(ip, p), ports)) if ok and p not in fake]
    out = []
    for p in live:
        if p in EXPECTED:
            continue
        name, sev = PORTS[p]
        public_ip = not (ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback)
        out.append(dict(tool="ports", rule=str(p), severity=sev,
                        title=f"Port {p} ({name}) is open " + ("to the internet" if public_ip else f"on {ip}"),
                        message=f"{ip}:{p} accepted a connection from this laptop."
                                + (" A database reachable from the internet is one weak password (or none) away from a full leak."
                                   if sev == "critical" else ""),
                        fix=f"Block it in the firewall (ufw deny {p}) and bind the service to 127.0.0.1. "
                            "Check that the rule really holds: Docker publishes ports past ufw.",
                        file=f"{host}:{p}", line=0, snippet="", tags=["tool:ports"], link="",
                        fp=fingerprint("ports", ip, p)))
    if fake:
        out.append(dict(tool="ports", rule="isp", severity="low", title=f"Ports {', '.join(map(str, sorted(fake)))} were skipped",
                        message="This internet connection answers on them for every address (even an empty one), so they can't be tested from here.",
                        fix="Re-check those from another network (phone hotspot) if they matter.", file=host, line=0, snippet="",
                        tags=["tool:ports-note"], link="", fp=fingerprint("ports", "isp", host)))
    return out


# ---------------------------------------------------------------- Lynis over SSH
def _ssh_target(spec):
    """'root@1.2.3.4:2222' -> (['-p', '2222'], 'root@1.2.3.4')"""
    m = re.match(r"^(?:(?P<user>[^@]+)@)?(?P<host>[^:]+)(?::(?P<port>\d+))?$", spec.strip())
    if not m:
        raise ValueError("Use host, user@host or user@host:port")
    dest = (m.group("user") + "@" if m.group("user") else "") + m.group("host")
    return ["-p", m.group("port") or "22"], dest


def lynis_ssh(spec, progress=lambda msg: None):
    """Copies Lynis to a temp folder on the server, runs a quick read-only audit, prints its
    report and deletes the folder. Uses your normal SSH keys; it never asks for a password."""
    import io
    import tarfile
    from pathlib import Path
    src = Path.home() / ".local/share/lynis"
    if not (src / "lynis").exists():
        raise RuntimeError("Lynis is not installed")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        t.add(str(src), arcname="lynis", filter=lambda ti: None if "/.git" in ti.name else ti)
    port, dest = _ssh_target(spec)
    remote = ('d=$(mktemp -d) && tar xz --no-same-owner -C "$d" && cd "$d/lynis" && '
              '(sh ./lynis audit system --quick --no-colors --no-log --report-file "$d/r.dat" >/dev/null 2>&1; cat "$d/r.dat"); '
              'rm -rf "$d"')
    progress(f"Running Lynis on {dest} (2-4 minutes)")
    p = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", *port, dest, remote],
                       input=buf.getvalue(), capture_output=True, timeout=900)
    text = p.stdout.decode("utf-8", "ignore")
    if "hardening_index" not in text:
        raise RuntimeError((p.stderr.decode("utf-8", "ignore") or "Lynis produced no report").strip()[-300:])
    out = []
    index = re.search(r"^hardening_index=(\d+)", text, re.M)
    for kind, sev in (("warning", "medium"), ("suggestion", "low")):
        for m in re.finditer(rf"^{kind}\[\]=([^|]*)\|([^|]*)\|([^|]*)\|([^|\n]*)", text, re.M):
            tid, msg, detail, sol = (x.strip() for x in m.groups())
            out.append(dict(tool="lynis", rule=tid, severity=sev, title=f"{msg}" + (f" ({detail})" if detail and detail != "-" else ""),
                            message=f"Lynis test {tid}." + (f" Hardening index {index.group(1)}/100." if index else ""),
                            fix=sol if sol and sol != "-" else f"See https://cisofy.com/lynis/controls/{tid}/",
                            file=dest, line=0, snippet="", tags=["tool:lynis"], link=f"https://cisofy.com/lynis/controls/{tid}/",
                            fp=fingerprint("lynis", dest, tid, msg)))
    return out
