#!/usr/bin/env python3
"""Aeterra .onion Provider.

Tor-friendly web service that bruteforces custom vanity .onion (v3) domains
on request using the mkp224o binary, then lets the requester download the keys.

- stdlib only, no frameworks, no external assets (inline CSS, system fonts)
- No accounts: each job gets an unguessable token; /job/<token> is the capability URL
- Binds 127.0.0.1 only; PORT from env (default 18093)
"""
import hashlib
import html
import http.server
import io
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import tarfile
import threading
import time
import urllib.parse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
JOBS_DIR = os.path.join(BASE_DIR, "jobs")
DB_PATH = os.path.join(DATA_DIR, "provider.db")

PORT = int(os.environ.get("PORT", "18093"))
MKP224O_BIN = os.environ.get(
    "MKP224O_BIN", "/home/hatch/workspace/mkp224o-build/mkp224o/mkp224o"
)
KEYS_PER_SEC = int(os.environ.get("KEYS_PER_SEC", "20000000"))
MAX_BODY = 16 * 1024
SESSION_TTL = 30 * 86400
MAX_ACTIVE_PER_IP = 1
MAX_JOBS_PER_IP_24H = 5

FILTER_RE = re.compile(r"^[a-z2-7]{1,7}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
ONION_RE = re.compile(r"([a-z2-7]{56}\.onion)")

# ---------------------------------------------------------------- db

_db = None
_db_lock = threading.RLock()  # RLock: qone/qexec call db() while holding the lock


def db():
    global _db
    with _db_lock:
        if _db is None:
            os.makedirs(DATA_DIR, exist_ok=True)
            _db = sqlite3.connect(DB_PATH, check_same_thread=False)
            _db.execute("PRAGMA journal_mode=WAL")
            _db.execute(
                """CREATE TABLE IF NOT EXISTS jobs(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token TEXT UNIQUE NOT NULL,
                    filter TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'queued',
                    created_at INTEGER NOT NULL,
                    started_at INTEGER,
                    finished_at INTEGER,
                    hostname TEXT,
                    elapsed REAL,
                    error TEXT
                )"""
            )
            _db.execute(
                """CREATE TABLE IF NOT EXISTS sessions(
                    sid TEXT PRIMARY KEY,
                    csrf TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )"""
            )
            _db.commit()
        return _db


def qone(sql, args=()):
    with _db_lock:
        cur = db().execute(sql, args)
        return cur.fetchone()


def qexec(sql, args=()):
    with _db_lock:
        cur = db().execute(sql, args)
        db().commit()
        return cur


# ---------------------------------------------------------------- helpers


def esc(s):
    return html.escape(str(s), quote=True)


def now():
    return int(time.time())


def fmt_estimate(sec):
    if sec < 5:
        return "a few seconds"
    if sec < 90:
        return "about %d seconds" % int(round(sec))
    mins = sec / 60.0
    if mins < 90:
        return "about %d minutes" % int(round(mins))
    hours = sec / 3600.0
    if hours < 48:
        return "about %d hours" % int(round(hours))
    return "about %d days" % int(round(sec / 86400.0))


def estimate_for_filter(f):
    return fmt_estimate((32 ** len(f)) / float(KEYS_PER_SEC))


def fmt_ts(ts):
    if not ts:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def fmt_dur(sec):
    if sec is None:
        return "-"
    sec = int(sec)
    if sec < 60:
        return "%d detik" % sec
    if sec < 3600:
        return "%d min %d sec" % (sec // 60, sec % 60)
    return "%d hr %d min" % (sec // 3600, (sec % 3600) // 60)


STATUS_ID = {
    "queued": "Queued",
    "running": "Running",
    "done": "Done",
    "failed": "Failed",
    "cancelled": "Cancelled",
}


def client_ip(handler):
    return handler.client_address[0]


# ---------------------------------------------------------------- sessions / csrf


def get_session(handler):
    cookies = handler.headers.get("Cookie", "")
    sid = None
    for part in cookies.split(";"):
        part = part.strip()
        if part.startswith("aeterra_sid="):
            sid = part[len("aeterra_sid="):]
            break
    if sid and re.fullmatch(r"[A-Za-z0-9_-]{43}", sid):
        row = qone(
            "SELECT sid, csrf FROM sessions WHERE sid=? AND created_at>?",
            (sid, now() - SESSION_TTL),
        )
        if row:
            return row[0], row[1]
    sid = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    qexec(
        "INSERT INTO sessions(sid, csrf, created_at) VALUES (?,?,?)",
        (sid, csrf, now()),
    )
    # lazy cleanup of expired sessions
    qexec("DELETE FROM sessions WHERE created_at<?", (now() - SESSION_TTL,))
    handler._set_sid_cookie = sid
    return sid, csrf


# ---------------------------------------------------------------- worker

worker_state = {"token": None, "proc": None}
worker_state_lock = threading.Lock()


def claim_next_job():
    with _db_lock:
        c = db()
        row = c.execute(
            "SELECT id, token, filter FROM jobs WHERE status='queued'"
            " ORDER BY id LIMIT 1"
        ).fetchone()
        if not row:
            return None
        cur = c.execute(
            "UPDATE jobs SET status='running', started_at=? WHERE id=? AND status='queued'",
            (now(), row[0]),
        )
        c.commit()
        if cur.rowcount == 0:
            return None
        return {"id": row[0], "token": row[1], "filter": row[2]}


def job_dir(token):
    return os.path.join(JOBS_DIR, token)


def find_onion_dir(jdir):
    try:
        for name in os.listdir(jdir):
            if name.endswith(".onion") and os.path.isdir(os.path.join(jdir, name)):
                return os.path.join(jdir, name)
    except OSError:
        pass
    return None


def build_tarball(jdir, onion_dir, filt):
    out = os.path.join(jdir, "aeterra-%s.tar.gz" % filt)
    with tarfile.open(out, "w:gz") as tar:
        for name in ("hostname", "hs_ed25519_secret_key", "hs_ed25519_public_key"):
            p = os.path.join(onion_dir, name)
            if os.path.isfile(p):
                tar.add(p, arcname=name)
    return out


def finish_job(token, status, hostname=None, elapsed=None, error=None):
    with _db_lock:
        c = db()
        cur = c.execute(
            "UPDATE jobs SET status=?, finished_at=?, hostname=?, elapsed=?, error=?"
            " WHERE token=? AND status='running'",
            (status, now(), hostname, elapsed, error, token),
        )
        c.commit()
        return cur.rowcount > 0


def run_job(job):
    token, filt = job["token"], job["filter"]
    jdir = job_dir(token)
    os.makedirs(jdir, exist_ok=True)
    os.chmod(jdir, 0o700)
    # fresh run: drop leftovers from a killed earlier attempt (e.g. VM reset)
    for name in os.listdir(jdir):
        p = os.path.join(jdir, name)
        try:
            if name.endswith(".onion") and os.path.isdir(p):
                shutil.rmtree(p)
            elif name.endswith(".tar.gz") and os.path.isfile(p):
                os.remove(p)
        except OSError:
            pass
    t0 = time.time()
    proc = None
    try:
        if not (os.path.isfile(MKP224O_BIN) and os.access(MKP224O_BIN, os.X_OK)):
            raise RuntimeError("mkp224o binary not found: %s" % MKP224O_BIN)
        proc = subprocess.Popen(
            [MKP224O_BIN, "-d", jdir, "-n", "1", filt],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        with worker_state_lock:
            worker_state["token"] = token
            worker_state["proc"] = proc
        stdout, _stderr = proc.communicate()
        elapsed = time.time() - t0
        # check whether it was cancelled while running
        row = qone("SELECT status FROM jobs WHERE token=?", (token,))
        if not row or row[0] != "running":
            shutil.rmtree(jdir, ignore_errors=True)
            return
        if proc.returncode != 0:
            finish_job(token, "failed", elapsed=elapsed,
                       error="mkp224o exit code %d" % proc.returncode)
            return
        m = ONION_RE.search(stdout or "")
        onion_dir = find_onion_dir(jdir)
        hostname = None
        if onion_dir:
            hp = os.path.join(onion_dir, "hostname")
            try:
                with open(hp) as f:
                    hostname = f.read().strip()
            except OSError:
                hostname = None
        if not hostname and m:
            hostname = m.group(1)
        if not hostname or not onion_dir:
            finish_job(token, "failed", elapsed=elapsed,
                       error="mkp224o result not found")
            return
        build_tarball(jdir, onion_dir, filt)
        finish_job(token, "done", hostname=hostname, elapsed=elapsed)
    except Exception as e:  # noqa: BLE001 - mark job failed, never crash worker
        try:
            if proc and proc.poll() is None:
                proc.kill()
        except OSError:
            pass
        finish_job(token, "failed", elapsed=time.time() - t0,
                   error="error: %s" % e)
    finally:
        with worker_state_lock:
            if worker_state["token"] == token:
                worker_state["token"] = None
                worker_state["proc"] = None


def worker_loop():
    while True:
        try:
            job = claim_next_job()
        except Exception:
            job = None
        if job is None:
            time.sleep(1)
            continue
        run_job(job)


def cancel_job(token):
    with _db_lock:
        c = db()
        cur = c.execute(
            "UPDATE jobs SET status='cancelled', finished_at=?, error='cancelled by user'"
            " WHERE token=? AND status IN ('queued','running')",
            (now(), token),
        )
        c.commit()
        changed = cur.rowcount > 0
    if changed:
        with worker_state_lock:
            if worker_state["token"] == token and worker_state["proc"]:
                try:
                    worker_state["proc"].terminate()
                except OSError:
                    pass
    return changed


def delete_job(token):
    cancel_job(token)
    row = qone("SELECT status FROM jobs WHERE token=?", (token,))
    if not row:
        return False
    shutil.rmtree(job_dir(token), ignore_errors=True)
    qexec("DELETE FROM jobs WHERE token=?", (token,))
    return True


# ---------------------------------------------------------------- html

CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d0d10;color:#e8e8ea;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;line-height:1.6}
.wrap{max-width:640px;margin:0 auto;padding:24px 16px 64px}
header.top{display:flex;align-items:center;justify-content:space-between;padding:14px 0;border-bottom:1px solid #26262b;margin-bottom:28px}
.brand{font-weight:700;font-size:18px;letter-spacing:.5px}
.brand span{color:#c9a227}
a{color:#c9a227;text-decoration:none}
a:hover{text-decoration:underline}
h1{font-size:30px;line-height:1.25;margin:8px 0 12px}
h2{font-size:20px;margin:28px 0 10px}
p{margin:10px 0;color:#b9b9bf}
.card{background:#141417;border:1px solid #26262b;border-radius:12px;padding:20px;margin:16px 0}
label{display:block;font-size:13px;color:#9a9aa2;margin:12px 0 6px}
input[type=text]{width:100%;background:#0d0d10;border:1px solid #3a3a41;color:#fff;border-radius:8px;padding:12px;font-size:18px;font-family:ui-monospace,Menlo,Consolas,monospace;letter-spacing:2px}
input[type=text]:focus{outline:none;border-color:#c9a227}
button,.btn{display:inline-block;background:#c9a227;color:#111;border:0;border-radius:8px;padding:12px 22px;font-size:15px;font-weight:600;cursor:pointer;margin-top:14px}
button:hover,.btn:hover{background:#d9b545}
button.ghost{background:transparent;color:#c9a227;border:1px solid #c9a227}
button.danger{background:transparent;color:#e06c75;border:1px solid #e06c75}
.hint{font-size:13px;color:#8a8a92}
table{width:100%;border-collapse:collapse;margin:12px 0;font-size:14px}
td,th{padding:8px 10px;border-bottom:1px solid #26262b;text-align:left}
th{color:#8a8a92;font-weight:600}
code{background:#1c1c21;padding:2px 8px;border-radius:6px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;color:#ffd97a;word-break:break-all}
.badge{display:inline-block;padding:4px 12px;border-radius:20px;font-size:13px;font-weight:600}
.b-queued{background:#2a2a10;color:#ffd97a}
.b-running{background:#10283a;color:#7ab8ff}
.b-done{background:#0f2e1c;color:#6fe3a5}
.b-failed{background:#3a1215;color:#ff8a8a}
.b-cancelled{background:#26262b;color:#9a9aa2}
.kv{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #1e1e23;font-size:14px}
.kv span:first-child{color:#8a8a92}
.err{background:#3a1215;border:1px solid #e06c75;color:#ffb3b3;border-radius:8px;padding:12px;margin:12px 0;font-size:14px}
.ok{background:#0f2e1c;border:1px solid #6fe3a5;color:#bdf0d4;border-radius:8px;padding:12px;margin:12px 0;font-size:14px}
footer{margin-top:48px;padding-top:16px;border-top:1px solid #26262b;font-size:12px;color:#6a6a72}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace}
"""


def page(title, body, refresh=None):
    meta = (
        '<meta http-equiv="refresh" content="5">' if refresh else ""
    )
    return (
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        + meta
        + "<title>" + esc(title) + " - Aeterra .onion Provider</title>"
        "<style>" + CSS + "</style></head><body><div class='wrap'>"
        "<header class='top'><div class='brand'>Aeterra <span>.onion</span> Provider</div>"
        "<div><a href='/'>Home</a></div></header>"
        + body
        + "<footer>Aeterra .onion Provider &mdash; Tor v3 vanity address bruteforce service. "
        "Keep your job link safe: it is the only access to your keys.</footer>"
        "</div></body></html>"
    )


def estimate_table():
    rows = ""
    for n in range(1, 8):
        rows += "<tr><td class='mono'>%d chars</td><td>%s</td></tr>" % (
            n, estimate_for_filter("a" * n))
    return ("<table><tr><th>Prefix length</th><th>Estimated time</th></tr>"
            + rows + "</table>"
            "<p class='hint'>Estimate at a speed of ~%s keys/sec. "
            "Actual speed depends on server CPU.</p>"
            % esc(f"{KEYS_PER_SEC:,}").replace(",", "."))


def home_page(sid, csrf, error=None, stats_done=0):
    err = "<div class='err'>%s</div>" % esc(error) if error else ""
    body = """
<h1>Custom .onion domains, made for you.</h1>
<p>Aeterra .onion Provider is a Tor v3 vanity address bruteforce service.
You request a prefix (e.g. <code>myshop</code>), our server searches for keys
that produce an address like
<code>myshopXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.onion</code>.
Once found, you download the keys and can use them directly as a
Tor hidden service.</p>
<p class='hint'>No account needed. Every request gets a secret link &mdash;
anyone holding that link can download your keys. Do not share it.</p>
<div class='card'>
<h2 style='margin-top:0'>Request a domain</h2>
{err}
<form method='post' action='/request'>
<input type='hidden' name='csrf_token' value='{csrf}'>
<label for='prefix'>Desired prefix</label>
<input type='text' id='prefix' name='prefix' maxlength='7' required
  pattern='[a-z2-7]{{1,7}}' title='1-7 chars: lowercase a-z and digits 2-7'
  placeholder='myshop' autocomplete='off'>
<p class='hint'>Only lowercase <span class='mono'>a-z</span> and digits
<span class='mono'>2-7</span>, 1 to 7 characters. Longer takes more time.</p>
<button type='submit'>Find my domain</button>
</form>
</div>
<h2>Bruteforce time estimates</h2>
{table}
<h2>How to use the keys</h2>
<p>1. Download the <span class='mono'>.tar.gz</span> from your job page.<br>
2. Extract it into <span class='mono'>HiddenServiceDir</span> on your Tor server.<br>
3. Add to <span class='mono'>torrc</span>:
<span class='mono'>HiddenServicePort 80 127.0.0.1:&lt;app-port&gt;</span><br>
4. Restart tor &mdash; your .onion address goes live.</p>
<p class='hint'>Domains created so far: <b>{done}</b></p>
""".format(err=err, csrf=esc(csrf), table=estimate_table(), done=stats_done)
    return page("Home", body)


def job_page(sid, csrf, job):
    token, filt, status = job["token"], job["filter"], job["status"]
    badge = "<span class='badge b-%s'>%s</span>" % (
        status, esc(STATUS_ID.get(status, status)))
    created = fmt_ts(job["created_at"])
    started = fmt_ts(job["started_at"])
    finished = fmt_ts(job["finished_at"])
    elapsed = fmt_dur(job["elapsed"]) if job["elapsed"] else "-"
    if status in ("queued", "running") and job["started_at"]:
        elapsed = fmt_dur(time.time() - job["started_at"])
    est = estimate_for_filter(filt)
    kv = (
        "<div class='kv'><span>Prefix</span><code>%s</code></div>"
        "<div class='kv'><span>Status</span>%s</div>"
        "<div class='kv'><span>Bruteforce estimate</span><span>%s</span></div>"
        "<div class='kv'><span>Created</span><span>%s</span></div>"
        "<div class='kv'><span>Started</span><span>%s</span></div>"
        "<div class='kv'><span>Finished</span><span>%s</span></div>"
        "<div class='kv'><span>Processing time</span><span>%s</span></div>"
    ) % (esc(filt), badge, esc(est), esc(created), esc(started),
         esc(finished), esc(elapsed))
    extra = ""
    if status == "done" and job["hostname"]:
        extra += ("<div class='ok'>Your domain:<br><code>%s</code></div>"
                  % esc(job["hostname"]))
        extra += ("<a class='btn' href='/job/%s/download'>Download keys (.tar.gz)</a>"
                  % esc(token))
        extra += ("<p class='hint'>File contains <span class='mono'>hostname</span>, "
                  "<span class='mono'>hs_ed25519_secret_key</span>, "
                  "<span class='mono'>hs_ed25519_public_key</span>. "
                  "The secret key means ownership of the domain. Keep it safe.</p>")
    if status == "failed":
        extra += "<div class='err'>Failed: %s</div>" % esc(job["error"] or "unknown")
        extra += ("<p class='hint'>Please go back and try again, or choose "
                  "a shorter prefix.</p>")
    if status in ("queued", "running"):
        extra += (
            "<form method='post' action='/job/%s/cancel' style='display:inline'>"
            "<input type='hidden' name='csrf_token' value='%s'>"
            "<button type='submit' class='ghost'>Cancel</button></form> "
            "<p class='hint'>This page auto-refreshes every 5 seconds.</p>"
            % (esc(token), esc(csrf)))
    extra += (
        "<form method='post' action='/job/%s/delete' style='margin-top:8px'>"
        "<input type='hidden' name='csrf_token' value='%s'>"
        "<button type='submit' class='danger'>Delete job &amp; keys permanently</button></form>"
        % (esc(token), esc(csrf)))
    body = "<h1>Your job</h1><div class='card'>%s%s</div>" % (kv, extra)
    return page("Job " + filt, body, refresh=(status in ("queued", "running")))


# ---------------------------------------------------------------- http handler


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "Aeterra/1.0"

    def log_message(self, fmt, *args):  # quieter logs
        pass

    # -- response helpers
    def send_html(self, code, html_body, extra_headers=()):
        data = html_body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if getattr(self, "_set_sid_cookie", None):
            self.send_header(
                "Set-Cookie",
                "aeterra_sid=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d"
                % (self._set_sid_cookie, SESSION_TTL),
            )
            self._set_sid_cookie = None
        for k, v in extra_headers:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def redirect(self, loc):
        self.send_response(303)
        self.send_header("Location", loc)
        if getattr(self, "_set_sid_cookie", None):
            self.send_header(
                "Set-Cookie",
                "aeterra_sid=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d"
                % (self._set_sid_cookie, SESSION_TTL),
            )
            self._set_sid_cookie = None
        self.end_headers()

    def read_form(self):
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = 0
        if length > MAX_BODY or length < 0:
            return None
        raw = self.rfile.read(length) if length else b""
        try:
            return urllib.parse.parse_qs(raw.decode("utf-8"), keep_blank_values=True)
        except (UnicodeDecodeError, ValueError):
            return {}

    def check_csrf(self, form, csrf):
        tok = (form.get("csrf_token") or [""])[0]
        ok = bool(tok) and secrets.compare_digest(tok, csrf)
        if not ok:
            has_cookie = bool(self.headers.get("Cookie", ""))
            print("CSRF reject: cookie_present=%s token_present=%s" % (has_cookie, bool(tok)))
        return ok

    def csrf_error_page(self):
        return page("Session expired",
            "<div class='card'><div class='err'>Your session expired or is invalid. "
            "This can happen if cookies are blocked or the page was open a long time.</div>"
            "<p><a class='btn' href='/'>Back to home and try again</a></p></div>")

    # -- routing
    def do_GET(self):
        self._set_sid_cookie = None
        sid, csrf = get_session(self)
        path = urllib.parse.urlparse(self.path).path
        if path == "/":
            done = qone("SELECT COUNT(*) FROM jobs WHERE status='done'")[0]
            self.send_html(200, home_page(sid, csrf, stats_done=done))
            return
        m = re.fullmatch(r"/job/([A-Za-z0-9_-]+)", path)
        if m and TOKEN_RE.fullmatch(m.group(1)):
            job = self.get_job(m.group(1))
            if not job:
                self.send_html(404, page("404", "<h1>Not found</h1>"))
                return
            self.send_html(200, job_page(sid, csrf, job))
            return
        m = re.fullmatch(r"/job/([A-Za-z0-9_-]+)/download", path)
        if m and TOKEN_RE.fullmatch(m.group(1)):
            self.serve_download(m.group(1))
            return
        self.send_html(404, page("404", "<h1>Not found</h1><p><a href='/'>Back</a></p>"))

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        self._set_sid_cookie = None
        sid, csrf = get_session(self)
        path = urllib.parse.urlparse(self.path).path
        form = self.read_form()
        if form is None:
            self.send_html(413, page("Error", "<div class='err'>Body too large.</div>"))
            return
        if path == "/request":
            self.handle_request(sid, csrf, form)
            return
        m = re.fullmatch(r"/job/([A-Za-z0-9_-]+)/cancel", path)
        if m and TOKEN_RE.fullmatch(m.group(1)):
            if not self.check_csrf(form, csrf):
                self.send_html(403, self.csrf_error_page())
                return
            cancel_job(m.group(1))
            self.redirect("/job/" + m.group(1))
            return
        m = re.fullmatch(r"/job/([A-Za-z0-9_-]+)/delete", path)
        if m and TOKEN_RE.fullmatch(m.group(1)):
            if not self.check_csrf(form, csrf):
                self.send_html(403, self.csrf_error_page())
                return
            delete_job(m.group(1))
            self.redirect("/")
            return
        self.send_html(404, page("404", "<h1>Not found</h1>"))

    # -- actions
    def get_job(self, token):
        row = qone(
            "SELECT token, filter, status, created_at, started_at, finished_at,"
            " hostname, elapsed, error FROM jobs WHERE token=?",
            (token,),
        )
        if not row:
            return None
        keys = ("token", "filter", "status", "created_at", "started_at",
                "finished_at", "hostname", "elapsed", "error")
        return dict(zip(keys, row))

    def handle_request(self, sid, csrf, form):
        if not self.check_csrf(form, csrf):
            self.send_html(403, self.csrf_error_page())
            return
        filt = (form.get("prefix") or [""])[0].strip().lower()
        ip = client_ip(self)
        if not FILTER_RE.fullmatch(filt):
            done = qone("SELECT COUNT(*) FROM jobs WHERE status='done'")[0]
            self.send_html(
                400,
                home_page(sid, csrf, stats_done=done,
                          error="Invalid prefix. Only lowercase a-z and digits 2-7, 1-7 characters."),
            )
            return
        active = qone(
            "SELECT COUNT(*) FROM jobs WHERE ip=? AND status IN ('queued','running')",
            (ip,),
        )[0]
        if active >= MAX_ACTIVE_PER_IP:
            self.send_html(
                429,
                page("Queue full",
                     "<div class='card'><div class='err'>You still have an active job "
                     "(queued/running). Wait for it to finish or cancel it first, "
                     "max %d active jobs per IP.</div>"
                     "<p><a href='/'>Back</a></p></div>" % MAX_ACTIVE_PER_IP),
            )
            return
        day = qone(
            "SELECT COUNT(*) FROM jobs WHERE ip=? AND created_at>?",
            (ip, now() - 86400),
        )[0]
        if day >= MAX_JOBS_PER_IP_24H:
            self.send_html(
                429,
                page("Daily limit",
                     "<div class='card'><div class='err'>The %d-job per 24h limit "
                     "for this IP has been reached.</div><p><a href='/'>Back</a></p></div>"
                     % MAX_JOBS_PER_IP_24H),
            )
            return
        token = secrets.token_urlsafe(32)
        qexec(
            "INSERT INTO jobs(token, filter, ip, status, created_at)"
            " VALUES (?,?,?,?,?)",
            (token, filt, ip, "queued", now()),
        )
        self.redirect("/job/" + token)

    def serve_download(self, token):
        job = self.get_job(token)
        if not job or job["status"] != "done":
            self.send_html(404, page("404", "<h1>Not available yet</h1>"))
            return
        tar_path = os.path.join(job_dir(token), "aeterra-%s.tar.gz" % job["filter"])
        if not os.path.isfile(tar_path):
            self.send_html(404, page("404", "<h1>File not found</h1>"))
            return
        try:
            with open(tar_path, "rb") as f:
                data = f.read()
        except OSError:
            self.send_html(500, page("Error", "<div class='err'>Failed to read file.</div>"))
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/gzip")
        self.send_header("Content-Length", str(len(data)))
        self.send_header(
            "Content-Disposition",
            "attachment; filename=aeterra-%s.tar.gz" % job["filter"],
        )
        self.end_headers()
        self.wfile.write(data)


# ---------------------------------------------------------------- main

def recover_stale_jobs():
    """After a VM reset, jobs stuck in queued/running have no live worker.
    Re-queue them so the worker picks them up again; never leave them stuck."""
    try:
        n = qone("SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running')")[0]
        if n:
            qexec("UPDATE jobs SET status='queued', started_at=NULL WHERE status IN ('queued','running')")
            print("recovered %d stale job(s) back to queue" % n)
    except Exception as e:  # noqa: BLE001 - never crash startup on this
        print("stale-job recovery failed: %s" % e)


def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(JOBS_DIR, exist_ok=True)
    db()  # init schema
    recover_stale_jobs()
    if not (os.path.isfile(MKP224O_BIN) and os.access(MKP224O_BIN, os.X_OK)):
        print("WARNING: mkp224o binary not found/executable: %s" % MKP224O_BIN)
    t = threading.Thread(target=worker_loop, daemon=True)
    t.start()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print("Aeterra .onion Provider listening on 127.0.0.1:%d" % PORT)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
