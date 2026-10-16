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
import socket
import sqlite3
import subprocess
import tarfile
import threading
import time
import urllib.parse
import zipfile

import ed25519 as ed25519_lib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
JOBS_DIR = os.path.join(BASE_DIR, "jobs")
HOSTING_DIR = os.path.join(BASE_DIR, "hosting")
DB_PATH = os.path.join(DATA_DIR, "provider.db")

PORT = int(os.environ.get("PORT", "18093"))
MKP224O_BIN = os.environ.get(
    "MKP224O_BIN", "/home/hatch/workspace/mkp224o-build/mkp224o/mkp224o"
)
KEYS_PER_SEC = int(os.environ.get("KEYS_PER_SEC", "20000000"))
MAX_BODY = 16 * 1024
MAX_UPLOAD = 10 * 1024 * 1024
SESSION_TTL = 30 * 86400
MAX_ACTIVE_PER_IP = 1
MAX_JOBS_PER_IP_24H = 5
MAX_HOSTING_PER_IP = 20

FILTER_RE = re.compile(r"^[a-z2-7]{1,7}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
HOSTING_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16}$")
ONION_RE = re.compile(r"([a-z2-7]{56}\.onion)")

# Dynamic hosting hidden services (managed block inside /etc/tor/torrc)
TORRC_PATH = "/etc/tor/torrc"
TOR_HSDIR_PREFIX = "/var/lib/tor/aeterra-host-"
HOSTING_TORRC_BEGIN = "# Aeterra hosting projects BEGIN (managed by aeterra-provider, do not edit)"
HOSTING_TORRC_END = "# Aeterra hosting projects END"

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
            # kind: 'bruteforce' | 'instant' (added later; backfill for old DBs)
            try:
                _db.execute("ALTER TABLE jobs ADD COLUMN kind TEXT NOT NULL DEFAULT 'bruteforce'")
            except sqlite3.OperationalError:
                pass
            _db.execute(
                """CREATE TABLE IF NOT EXISTS hosting(
                    token TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    onion TEXT NOT NULL,
                    ip TEXT NOT NULL,
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


# ---------------------------------------------------------------- instant domains

def create_instant_job(ip):
    """Generate a fresh random v3 .onion domain immediately (no bruteforce).

    Returns the job token. Keys are written in the same layout as
    bruteforce jobs so download/delete flows work unchanged."""
    kp = ed25519_lib.generate_keypair()
    addr = kp["address"]
    hostname = addr + ".onion"
    token = secrets.token_urlsafe(32)
    jdir = job_dir(token)
    os.makedirs(jdir, exist_ok=True)
    os.chmod(jdir, 0o700)
    onion_dir = os.path.join(jdir, hostname)
    os.makedirs(onion_dir, exist_ok=True)
    with open(os.path.join(onion_dir, "hostname"), "wb") as f:
        f.write(kp["hostname"])
    with open(os.path.join(onion_dir, "hs_ed25519_secret_key"), "wb") as f:
        f.write(kp["secret_key_file"])
    with open(os.path.join(onion_dir, "hs_ed25519_public_key"), "wb") as f:
        f.write(kp["public_key_file"])
    build_tarball(jdir, onion_dir, "instant")
    qexec(
        "INSERT INTO jobs(token, filter, ip, status, created_at,"
        " started_at, finished_at, hostname, elapsed, kind)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)",
        (token, "instant", ip, "done", now(), now(), now(), hostname, 0.0,
         "instant"),
    )
    return token


# ---------------------------------------------------------------- hosting

_host_map = {}  # onion hostname -> hosting token
_host_map_lock = threading.Lock()


def hosting_pubdir(token):
    return os.path.join(HOSTING_DIR, token, "public")


def hosting_keysdir(token):
    return os.path.join(HOSTING_DIR, token, "keys")


def hosting_hsdir(token):
    return TOR_HSDIR_PREFIX + token


def refresh_host_map():
    rows = qexec("SELECT onion, token FROM hosting").fetchall()
    with _host_map_lock:
        _host_map.clear()
        for onion, token in rows:
            _host_map[onion.lower()] = token


def hosting_token_for_host(host):
    host = (host or "").split(":")[0].strip().lower()
    with _host_map_lock:
        return _host_map.get(host)


def safe_extract_zip(zip_bytes, dest):
    """Extract a zip into dest. Guards against zip-slip, bombs, junk."""
    count = 0
    total = 0
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        for info in z.infolist():
            count += 1
            if count > 500:
                raise ValueError("zip has too many files (max 500)")
            if info.file_size > 5 * 1024 * 1024:
                raise ValueError("a file inside the zip exceeds 5 MB")
            total += info.file_size
            if total > 50 * 1024 * 1024:
                raise ValueError("uncompressed size exceeds 50 MB")
            p = info.filename.replace("\\", "/").lstrip("/")
            parts = [x for x in p.split("/") if x not in ("", ".", "..")]
            if not parts:
                continue
            target = os.path.join(dest, *parts)
            if not os.path.abspath(target).startswith(
                    os.path.abspath(dest) + os.sep):
                raise ValueError("unsafe path inside zip")
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with z.open(info) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)
    # unwrap a single top-level folder (common when zipping a project dir)
    try:
        entries = [e for e in os.listdir(dest) if not e.startswith(".")]
    except OSError:
        entries = []
    if len(entries) == 1:
        single = os.path.join(dest, entries[0])
        if os.path.isdir(single):
            for e in os.listdir(single):
                shutil.move(os.path.join(single, e), os.path.join(dest, e))
            os.rmdir(single)


def _tor_reload():
    """Reload the real tor daemon (tor@default; tor.service is a dummy).
    Returns True if tor is active afterwards."""
    # validate our own key material first: derive pubkey from the secret
    # scalar of every deployed hosting key and compare with the public file.
    # (tor --verify-config does NOT check key validity; a bad key kills tor.)
    try:
        rows = qexec("SELECT token FROM hosting").fetchall()
        for (token,) in rows:
            hsdir = hosting_hsdir(token)
            skp = os.path.join(hsdir, "hs_ed25519_secret_key")
            pkp = os.path.join(hsdir, "hs_ed25519_public_key")
            if not (os.path.isfile(skp) and os.path.isfile(pkp)):
                continue
            with open(skp, "rb") as f:
                sk = f.read()
            with open(pkp, "rb") as f:
                pk = f.read()
            if len(sk) != 96 or len(pk) != 64:
                print("hosting key size invalid for %s, skip reload" % token)
                return False
            a = int.from_bytes(sk[32:64], "little")
            if ed25519_lib._encodepoint(
                    ed25519_lib._scalarmult(ed25519_lib._G, a)) != pk[32:64]:
                print("hosting key mismatch for %s, skip reload" % token)
                return False
    except Exception as e:  # noqa: BLE001 - never reload on validation error
        print("hosting key validation error: %s" % e)
        return False
    r = subprocess.run(["systemctl", "reload", "tor@default"],
                       capture_output=True, timeout=60)
    if r.returncode != 0:
        # reload on an inactive unit may fail; try a plain start
        subprocess.run(["systemctl", "reset-failed", "tor@default"],
                       capture_output=True, timeout=30)
        r = subprocess.run(["systemctl", "start", "tor@default"],
                           capture_output=True, timeout=120)
    time.sleep(3)
    r = subprocess.run(["systemctl", "is-active", "tor@default"],
                       capture_output=True, timeout=15, text=True)
    ok = r.stdout.strip() == "active"
    if not ok:
        print("tor@default not active after reload/start!")
    return ok


def sync_hosting_tor():
    """Deploy key material for every hosting project and regenerate the
    managed torrc block. Returns True if tor was reloaded."""
    try:
        rows = qexec("SELECT token FROM hosting").fetchall()
    except Exception:
        return False
    tokens = sorted(t for (t,) in rows if HOSTING_TOKEN_RE.fullmatch(t))
    # 1. key dirs under /var/lib/tor
    try:
        for token in tokens:
            hsdir = hosting_hsdir(token)
            os.makedirs(hsdir, exist_ok=True)
            for name in ("hostname", "hs_ed25519_secret_key",
                         "hs_ed25519_public_key"):
                src = os.path.join(hosting_keysdir(token), name)
                dst = os.path.join(hsdir, name)
                if os.path.isfile(src):
                    shutil.copyfile(src, dst)
            os.chmod(hsdir, 0o700)
            for name in ("hs_ed25519_secret_key", "hs_ed25519_public_key",
                         "hostname"):
                p = os.path.join(hsdir, name)
                if os.path.isfile(p):
                    os.chmod(p, 0o600)
            try:
                shutil.chown(hsdir, "debian-tor", "debian-tor")
                for name in ("hostname", "hs_ed25519_secret_key",
                             "hs_ed25519_public_key"):
                    p = os.path.join(hsdir, name)
                    if os.path.isfile(p):
                        shutil.chown(p, "debian-tor", "debian-tor")
            except (OSError, LookupError):
                pass
    except OSError:
        return False
    # 2. managed torrc block
    lines = [HOSTING_TORRC_BEGIN]
    for token in tokens:
        lines.append("HiddenServiceDir %s/" % hosting_hsdir(token))
        lines.append("HiddenServicePort 80 127.0.0.1:18093")
    lines.append(HOSTING_TORRC_END)
    block = "\n".join(lines) + "\n"
    try:
        with open(TORRC_PATH, "r", encoding="utf-8", errors="replace") as f:
            torrc = f.read()
    except OSError:
        return False
    if HOSTING_TORRC_BEGIN in torrc and HOSTING_TORRC_END in torrc:
        start = torrc.index(HOSTING_TORRC_BEGIN)
        end = torrc.index(HOSTING_TORRC_END) + len(HOSTING_TORRC_END)
        new_torrc = torrc[:start] + block + torrc[end:]
    else:
        new_torrc = torrc.rstrip("\n") + "\n\n" + block
    changed = new_torrc != torrc
    if changed:
        try:
            with open(TORRC_PATH, "w", encoding="utf-8") as f:
                f.write(new_torrc)
        except OSError:
            return False
        v = subprocess.run(["tor", "--verify-config", "-f", TORRC_PATH],
                           capture_output=True, timeout=30)
        if v.returncode != 0:
            print("tor config verify FAILED after hosting sync")
            return False
    # 3. reload tor so new/removed hidden services apply
    if changed:
        return _tor_reload()
    return False


def create_hosting_project(name, zip_bytes, ip):
    # 12 random bytes -> exactly 16 urlsafe chars (no padding)
    token = secrets.token_urlsafe(12)
    while qone("SELECT 1 FROM hosting WHERE token=?", (token,)):
        token = secrets.token_urlsafe(12)
    kp = ed25519_lib.generate_keypair()
    onion = kp["address"] + ".onion"
    base = os.path.join(HOSTING_DIR, token)
    pub = os.path.join(base, "public")
    keys = os.path.join(base, "keys")
    os.makedirs(pub, exist_ok=True)
    os.makedirs(keys, exist_ok=True)
    try:
        safe_extract_zip(zip_bytes, pub)
        with open(os.path.join(keys, "hostname"), "wb") as f:
            f.write(kp["hostname"])
        with open(os.path.join(keys, "hs_ed25519_secret_key"), "wb") as f:
            f.write(kp["secret_key_file"])
        with open(os.path.join(keys, "hs_ed25519_public_key"), "wb") as f:
            f.write(kp["public_key_file"])
        qexec(
            "INSERT INTO hosting(token, name, onion, ip, created_at)"
            " VALUES (?,?,?,?,?)",
            (token, name, onion, ip, now()),
        )
    except Exception:
        shutil.rmtree(base, ignore_errors=True)
        raise
    sync_hosting_tor()
    refresh_host_map()
    return token, onion


def delete_hosting_project(token):
    row = qone("SELECT token FROM hosting WHERE token=?", (token,))
    if not row:
        return False
    qexec("DELETE FROM hosting WHERE token=?", (token,))
    shutil.rmtree(os.path.join(HOSTING_DIR, token), ignore_errors=True)
    shutil.rmtree(hosting_hsdir(token), ignore_errors=True)
    sync_hosting_tor()
    refresh_host_map()
    return True


def get_hosting(token):
    row = qone("SELECT token, name, onion, created_at FROM hosting WHERE token=?",
               (token,))
    if not row:
        return None
    return {"token": row[0], "name": row[1], "onion": row[2],
            "created_at": row[3]}


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
        "<div><a href='/'>Domains</a> &nbsp;<a href='/hosting'>Hosting</a></div></header>"
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
<h2 style='margin-top:0'>Need a domain right now?</h2>
<p class='hint'>Skip the wait: generate a random v3 .onion address instantly.
No prefix, no bruteforce, keys ready to download immediately.</p>
<form method='post' action='/instant'>
<input type='hidden' name='csrf_token' value='{csrf}'>
<button type='submit'>Generate instant domain</button>
</form>
</div>
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
    kind = job.get("kind") or "bruteforce"
    badge = "<span class='badge b-%s'>%s</span>" % (
        status, esc(STATUS_ID.get(status, status)))
    created = fmt_ts(job["created_at"])
    started = fmt_ts(job["started_at"])
    finished = fmt_ts(job["finished_at"])
    elapsed = fmt_dur(job["elapsed"]) if job["elapsed"] else "-"
    if status in ("queued", "running") and job["started_at"]:
        elapsed = fmt_dur(time.time() - job["started_at"])
    if kind == "instant":
        est = "instant (no bruteforce)"
        flabel = "Type"
        fval = "Instant domain"
    else:
        est = estimate_for_filter(filt)
        flabel = "Prefix"
        fval = filt
    kv = (
        "<div class='kv'><span>%s</span><code>%s</code></div>"
        "<div class='kv'><span>Status</span>%s</div>"
        "<div class='kv'><span>Bruteforce estimate</span><span>%s</span></div>"
        "<div class='kv'><span>Created</span><span>%s</span></div>"
        "<div class='kv'><span>Started</span><span>%s</span></div>"
        "<div class='kv'><span>Finished</span><span>%s</span></div>"
        "<div class='kv'><span>Processing time</span><span>%s</span></div>"
    ) % (flabel, esc(fval), badge, esc(est), esc(created), esc(started),
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


def fmt_size(n):
    if n < 1024:
        return "%d B" % n
    if n < 1024 * 1024:
        return "%.1f KB" % (n / 1024.0)
    return "%.1f MB" % (n / 1048576.0)


def hosting_list_page(sid, csrf, error=None):
    err = "<div class='err'>%s</div>" % esc(error) if error else ""
    rows = qexec(
        "SELECT token, name, onion, created_at FROM hosting ORDER BY created_at DESC"
    ).fetchall()
    if rows:
        items = ""
        for token, name, onion, created_at in rows:
            items += ("<tr><td><a href='/hosting/%s'>%s</a></td>"
                      "<td class='mono' style='font-size:12px'>%s</td>"
                      "<td>%s</td></tr>"
                      % (esc(token), esc(name), esc(onion), esc(fmt_ts(created_at))))
        table = ("<table><tr><th>Project</th><th>Address</th><th>Created</th></tr>"
                 + items + "</table>")
    else:
        table = "<p class='hint'>No websites hosted yet.</p>"
    body = """
<h1>Onion hosting</h1>
<p>Upload a static website as a <span class='mono'>.zip</span> and Aeterra
hosts it on its own <span class='mono'>.onion</span> address. Each project
gets a fresh random v3 address, generated instantly.</p>
<p class='hint'>Static files only (HTML/CSS/JS/images). Max 10 MB zip,
500 files, 50 MB uncompressed.</p>
<div class='card'>
<h2 style='margin-top:0'>Host a new website</h2>
{err}
<form method='post' action='/hosting/create' enctype='multipart/form-data'>
<input type='hidden' name='csrf_token' value='{csrf}'>
<label for='pname'>Project name</label>
<input type='text' id='pname' name='name' maxlength='60' required
  placeholder='My site' autocomplete='off' style='letter-spacing:0;font-size:15px'>
<label for='pzip'>Website .zip file</label>
<input type='file' id='pzip' name='sitezip' accept='.zip,application/zip' required>
<button type='submit'>Upload &amp; host</button>
</form>
</div>
<h2>Hosted websites</h2>
{table}
""".format(err=err, csrf=esc(csrf), table=table)
    return page("Hosting", body)


def hosting_detail_page(sid, csrf, project):
    token = project["token"]
    pub = hosting_pubdir(token)
    files = []
    total = 0
    for root, _dirs, names in os.walk(pub):
        for n in names:
            if n.startswith("."):
                continue
            fp = os.path.join(root, n)
            rel = os.path.relpath(fp, pub)
            try:
                sz = os.path.getsize(fp)
            except OSError:
                sz = 0
            total += sz
            files.append((rel, sz))
    files.sort()
    if files:
        rows = "".join(
            "<tr><td class='mono' style='font-size:12px'>%s</td><td>%s</td></tr>"
            % (esc(rel), esc(fmt_size(sz))) for rel, sz in files[:200])
        ftable = ("<table><tr><th>File</th><th>Size</th></tr>%s</table>"
                  "<p class='hint'>%d files, %s total.</p>"
                  % (rows, len(files), fmt_size(total)))
    else:
        ftable = "<p class='hint'>No files yet.</p>"
    has_index = os.path.isfile(os.path.join(pub, "index.html")) or \
        os.path.isfile(os.path.join(pub, "index.htm"))
    warn = "" if has_index else \
        "<div class='err'>No <span class='mono'>index.html</span> at the zip root. " \
        "Visitors will see a 404 until you add one.</div>"
    body = """
<h1>{name}</h1>
<div class='card'>
<div class='kv'><span>Address</span><code>{onion}</code></div>
<div class='kv'><span>Created</span><span>{created}</span></div>
<div class='kv'><span>Manage</span><span><a href='/hosting/{token}'>this page</a></span></div>
</div>
{warn}
<p><a class='btn' href='http://{onion}/' target='_blank' rel='noopener'>Visit website</a></p>
<p class='hint'>Open this address in Tor Browser. It can take a minute for a
fresh hidden service to become reachable.</p>
<h2>Files</h2>
{ftable}
<form method='post' action='/hosting/{token}/delete' style='margin-top:16px'>
<input type='hidden' name='csrf_token' value='{csrf}'>
<button type='submit' class='danger'>Delete project &amp; address permanently</button>
</form>
""".format(name=esc(project["name"]), onion=esc(project["onion"]),
           created=esc(fmt_ts(project["created_at"])),
           token=esc(token), csrf=esc(csrf), warn=warn, ftable=ftable)
    return page(project["name"], body)


# ---------------------------------------------------------------- http handler


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "Aeterra/1.0"
    protocol_version = "HTTP/1.1"  # keep-alive: reuses one Tor circuit connection

    def log_message(self, fmt, *args):  # quieter logs
        pass

    # -- response helpers
    def _maybe_gzip(self, data, ctype):
        """Gzip-compress text responses when the client accepts it."""
        if not ctype.startswith("text/") and "javascript" not in ctype \
                and "json" not in ctype and "svg" not in ctype:
            return data, None
        if "gzip" not in self.headers.get("Accept-Encoding", ""):
            return data, None
        if len(data) < 512:
            return data, None
        import gzip as _gzip
        return _gzip.compress(data, compresslevel=6), "gzip"

    def send_html(self, code, html_body, extra_headers=()):
        data = html_body.encode("utf-8")
        data, encoding = self._maybe_gzip(data, "text/html; charset=utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if encoding:
            self.send_header("Content-Encoding", encoding)
            self.send_header("Vary", "Accept-Encoding")
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

    # -- multipart (hosting upload)
    def parse_multipart(self, max_size):
        ctype = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in ctype:
            return None
        m = re.search(r"boundary=([^\s;]+)", ctype)
        if not m:
            return None
        boundary = m.group(1).strip('"').encode("ascii", "ignore")
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            return None
        if length <= 0 or length > max_size:
            return None
        raw = self.rfile.read(length)
        if len(raw) != length:
            return None
        fields, files = {}, {}
        for part in raw.split(b"--" + boundary):
            if b"\r\n\r\n" not in part:
                continue
            head, body = part.split(b"\r\n\r\n", 1)
            if body.endswith(b"\r\n"):
                body = body[:-2]
            disp = ""
            for line in head.decode("latin1").split("\r\n"):
                if line.lower().startswith("content-disposition:"):
                    disp = line.split(":", 1)[1]
            nm = re.search(r'name="([^"]*)"', disp)
            fn = re.search(r'filename="([^"]*)"', disp)
            if not nm:
                continue
            if fn and fn.group(1):
                files[nm.group(1)] = {
                    "filename": os.path.basename(fn.group(1))[:120],
                    "data": body,
                }
            else:
                fields[nm.group(1)] = body.decode("utf-8", "replace")
        return fields, files

    # -- static file serving for hosted projects
    MIME = {
        ".html": "text/html; charset=utf-8", ".htm": "text/html; charset=utf-8",
        ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8",
        ".json": "application/json", ".txt": "text/plain; charset=utf-8",
        ".xml": "application/xml", ".svg": "image/svg+xml",
        ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".gif": "image/gif", ".webp": "image/webp", ".ico": "image/x-icon",
        ".woff": "font/woff", ".woff2": "font/woff2", ".ttf": "font/ttf",
        ".mp4": "video/mp4", ".webm": "video/webm", ".mp3": "audio/mpeg",
        ".pdf": "application/pdf",
    }

    def serve_hosted(self, token):
        pub = os.path.abspath(hosting_pubdir(token))
        upath = urllib.parse.urlparse(self.path).path
        rel = urllib.parse.unquote(upath).lstrip("/")
        target = os.path.abspath(os.path.join(pub, rel))
        if not target.startswith(pub + os.sep) and target != pub:
            self.send_html(404, page("404", "<h1>Not found</h1>"))
            return
        if os.path.basename(target).startswith("."):
            self.send_html(404, page("404", "<h1>Not found</h1>"))
            return
        if os.path.isdir(target):
            for idx in ("index.html", "index.htm"):
                cand = os.path.join(target, idx)
                if os.path.isfile(cand):
                    target = cand
                    break
            else:
                self.send_html(404, page("404", "<h1>Not found</h1>"))
                return
        if not os.path.isfile(target):
            self.send_html(404, page("404", "<h1>Not found</h1>"))
            return
        ext = os.path.splitext(target)[1].lower()
        ctype = self.MIME.get(ext, "application/octet-stream")
        try:
            with open(target, "rb") as f:
                data = f.read()
        except OSError:
            self.send_html(500, page("Error", "<div class='err'>Read failed.</div>"))
            return
        if len(data) > 20 * 1024 * 1024:
            self.send_html(500, page("Error", "<div class='err'>File too large.</div>"))
            return
        data, encoding = self._maybe_gzip(data, ctype)
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        # hosted files are content-addressed by project; cache for an hour
        # (project delete/replace changes the onion address anyway)
        self.send_header("Cache-Control", "public, max-age=3600")
        if encoding:
            self.send_header("Content-Encoding", encoding)
            self.send_header("Vary", "Accept-Encoding")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    # -- routing
    def do_GET(self):
        self._set_sid_cookie = None
        # hosted project? route by Host header before anything else
        htoken = hosting_token_for_host(self.headers.get("Host", ""))
        if htoken:
            self.serve_hosted(htoken)
            return
        sid, csrf = get_session(self)
        path = urllib.parse.urlparse(self.path).path
        if path == "/":
            done = qone("SELECT COUNT(*) FROM jobs WHERE status='done'")[0]
            self.send_html(200, home_page(sid, csrf, stats_done=done))
            return
        if path == "/hosting":
            self.send_html(200, hosting_list_page(sid, csrf))
            return
        m = re.fullmatch(r"/hosting/([A-Za-z0-9_-]+)", path)
        if m and HOSTING_TOKEN_RE.fullmatch(m.group(1)):
            proj = get_hosting(m.group(1))
            if not proj:
                self.send_html(404, page("404", "<h1>Not found</h1>"))
                return
            self.send_html(200, hosting_detail_page(sid, csrf, proj))
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
        # hosted projects are static: no POST handling on their hosts
        if hosting_token_for_host(self.headers.get("Host", "")):
            self.send_html(404, page("404", "<h1>Not found</h1>"))
            return
        sid, csrf = get_session(self)
        path = urllib.parse.urlparse(self.path).path
        if path == "/hosting/create":
            self.handle_hosting_create(sid, csrf)
            return
        m = re.fullmatch(r"/hosting/([A-Za-z0-9_-]+)/delete", path)
        if m and HOSTING_TOKEN_RE.fullmatch(m.group(1)):
            form = self.read_form()
            if form is None:
                self.send_html(413, page("Error", "<div class='err'>Body too large.</div>"))
                return
            if not self.check_csrf(form, csrf):
                self.send_html(403, self.csrf_error_page())
                return
            delete_hosting_project(m.group(1))
            self.redirect("/hosting")
            return
        if path == "/instant":
            form = self.read_form()
            if form is None:
                self.send_html(413, page("Error", "<div class='err'>Body too large.</div>"))
                return
            self.handle_instant(sid, csrf, form)
            return
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
            " hostname, elapsed, error, kind FROM jobs WHERE token=?",
            (token,),
        )
        if not row:
            return None
        keys = ("token", "filter", "status", "created_at", "started_at",
                "finished_at", "hostname", "elapsed", "error", "kind")
        return dict(zip(keys, row))

    def handle_instant(self, sid, csrf, form):
        if not self.check_csrf(form, csrf):
            self.send_html(403, self.csrf_error_page())
            return
        ip = client_ip(self)
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
        try:
            token = create_instant_job(ip)
        except Exception as e:  # noqa: BLE001 - show error, never crash
            self.send_html(
                500,
                page("Error",
                     "<div class='card'><div class='err'>Generation failed: %s</div>"
                     "<p><a href='/'>Back</a></p></div>" % esc(e)))
            return
        self.redirect("/job/" + token)

    def handle_hosting_create(self, sid, csrf):
        parsed = self.parse_multipart(MAX_UPLOAD)
        if parsed is None:
            self.send_html(
                400, hosting_list_page(
                    sid, csrf,
                    error="Upload failed: bad request or file larger than 10 MB."))
            return
        fields, files = parsed
        csrf_tok = fields.get("csrf_token", "")
        if not (csrf_tok and secrets.compare_digest(csrf_tok, csrf)):
            self.send_html(403, self.csrf_error_page())
            return
        name = (fields.get("name") or "").strip()[:60]
        up = files.get("sitezip")
        if not name:
            self.send_html(
                400, hosting_list_page(sid, csrf, error="Project name is required."))
            return
        if not up or not up["data"]:
            self.send_html(
                400, hosting_list_page(sid, csrf, error="No zip file received."))
            return
        if not up["filename"].lower().endswith(".zip"):
            self.send_html(
                400, hosting_list_page(
                    sid, csrf, error="Only .zip files are accepted."))
            return
        ip = client_ip(self)
        n = qone("SELECT COUNT(*) FROM hosting WHERE ip=?", (ip,))[0]
        if n >= MAX_HOSTING_PER_IP:
            self.send_html(
                429, hosting_list_page(
                    sid, csrf,
                    error="Project limit reached (%d per IP)." % MAX_HOSTING_PER_IP))
            return
        try:
            token, _onion = create_hosting_project(name, up["data"], ip)
        except ValueError as e:
            self.send_html(400, hosting_list_page(sid, csrf, error=str(e)))
            return
        except Exception as e:  # noqa: BLE001 - show error, never crash
            self.send_html(
                500, hosting_list_page(
                    sid, csrf, error="Hosting failed: %s" % e))
            return
        self.redirect("/hosting/" + token)

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
    os.makedirs(HOSTING_DIR, exist_ok=True)
    db()  # init schema
    recover_stale_jobs()
    refresh_host_map()
    try:
        if sync_hosting_tor():
            print("hosting hidden services synced, tor reloaded")
        else:
            print("hosting hidden services in sync")
    except Exception as e:  # noqa: BLE001 - never crash startup on this
        print("hosting sync failed: %s" % e)
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
