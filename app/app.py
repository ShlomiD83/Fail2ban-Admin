"""Fail2ban Admin - a small web UI to manage Fail2ban: jails, filters, actions, bans and unbans."""
import base64
import difflib
import glob
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from functools import wraps
from zoneinfo import ZoneInfo

from argon2 import PasswordHasher
from flask import (Flask, abort, flash, g, has_request_context, jsonify, make_response, redirect, render_template,
                   request, send_from_directory, session, url_for)

import f2b
import ipinfo
from f2b import F2BError

try:  # QR codes for TOTP setup; optional (the secret can always be typed in by hand)
    import segno
except ImportError:
    segno = None

try:  # passkeys (WebAuthn); the app still runs without the library, just without passkeys
    from webauthn import (base64url_to_bytes, generate_authentication_options,
                          generate_registration_options, verify_authentication_response,
                          verify_registration_response)
    from webauthn.helpers import bytes_to_base64url, options_to_json_dict
    from webauthn.helpers.structs import (AuthenticatorSelectionCriteria,
                                          PublicKeyCredentialDescriptor,
                                          ResidentKeyRequirement,
                                          UserVerificationRequirement)
    WEBAUTHN_OK = True
except ImportError:
    WEBAUTHN_OK = False

# ---------- settings ----------
# The Fail2ban configuration folder as this container sees it: for crazymax/fail2ban the /data folder
# (jail.d, filter.d, action.d, db), for linuxserver/fail2ban its fail2ban folder, or a whole /etc/fail2ban.
CONFIG_DIR = os.path.abspath(os.environ.get("FAIL2BAN_CONFIG_DIR", "/data"))
# This app's own files (backups, admin log, passkeys, settings), kept apart from Fail2ban's folder.
ADMIN_DIR = os.path.abspath(os.environ.get("ADMIN_DATA_DIR", "/admin"))
BACKUP_DIR = os.path.join(ADMIN_DIR, "backups")
MAX_BACKUPS = int(os.environ.get("MAX_BACKUPS", "30"))
# Fail2ban's stock configuration (bundled in the image) that the folder above is laid over for validation
BASE_CONFIG = os.environ.get("FAIL2BAN_BASE_CONFIG", "/opt/fail2ban/config")
# Where the Fail2ban container keeps its configuration (to check that a new filter or action is visible there)
F2B_ETC = os.environ.get("FAIL2BAN_ETC", "/etc/fail2ban").rstrip("/")
DB_FILE = os.environ.get("FAIL2BAN_DB_FILE") or os.path.join(CONFIG_DIR, "db", "fail2ban.sqlite3")
VALIDATOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "f2b_validate.py")
# Public IP shown on the dashboard. "off" turns the lookup off.
PUBLIC_IP_URL = os.environ.get("PUBLIC_IP_URL", "https://api.ipify.org").strip()

try:
    TZINFO = ZoneInfo(os.environ.get("TZ") or "UTC")
except Exception:
    print("WARNING: invalid TZ %r, using UTC" % os.environ.get("TZ"), flush=True)
    TZINFO = ZoneInfo("UTC")


def now():
    return datetime.now(TZINFO)


try:
    os.makedirs(ADMIN_DIR, exist_ok=True)
except OSError:
    print(f"WARNING: can't create the admin folder {ADMIN_DIR}", flush=True)

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")

# Passkeys: ADMIN_RP_ID is the site's domain (e.g. f2b.example.com) and ADMIN_ORIGIN its full https origin.
RP_ID = os.environ.get("ADMIN_RP_ID", "").strip()
RP_ORIGIN = os.environ.get("ADMIN_ORIGIN", "").strip().rstrip("/")
RP_NAME = os.environ.get("ADMIN_RP_NAME", "Fail2ban Admin")
PASSKEY_FILE = os.environ.get("PASSKEY_FILE") or os.path.join(ADMIN_DIR, "admin_passkeys.json")
PASSKEY_ONLY = os.environ.get("ADMIN_PASSKEY_ONLY", "false").lower() == "true"
PASSKEYS_ENABLED = WEBAUTHN_OK and bool(RP_ID and RP_ORIGIN)
ADMIN_HANDLE = hashlib.sha256(("fail2ban-admin:" + ADMIN_USER).encode()).digest()


# TOTP (RFC 6238, SHA-1, 6 digits, 30 s): a second step for PASSWORD sign-in. The secret lives in the
# environment. Passkey sign-in skips it, since a passkey already proves two factors.
def _norm_secret(s):
    return re.sub(r"[\s-]", "", s or "").upper()


def _b32(secret):
    return base64.b32decode(secret + "=" * (-len(secret) % 8))


def valid_totp_secret(secret):
    try:
        return len(secret) >= 16 and len(_b32(secret)) >= 10
    except Exception:
        return False


TOTP_SECRET = _norm_secret(os.environ.get("ADMIN_TOTP_SECRET", ""))
if TOTP_SECRET and not valid_totp_secret(TOTP_SECRET):
    raise SystemExit("ADMIN_TOTP_SECRET is not a valid base32 secret (at least 16 characters, A-Z and 2-7). "
                     "Generate one on the Security page, or remove the variable.")


def totp_at(secret, counter, digits=6):
    mac = hmac.new(_b32(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    return str((struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)).zfill(digits)


_totp_last = {}  # secret -> last accepted time step (replay guard; single worker process)


def totp_verify(secret, code, record=True, window=1):
    code = re.sub(r"\s", "", code or "")
    if not re.fullmatch(r"\d{6}", code):
        return False
    step_now = int(time.time() // 30)
    hit = None
    for step in range(step_now - window, step_now + window + 1):
        if hmac.compare_digest(totp_at(secret, step), code):
            hit = step
    if hit is None:
        return False
    if record:
        if hit <= _totp_last.get(secret, -1):
            return False  # this code was already used
        _totp_last[secret] = hit
    return True


def totp_uri(secret):
    issuer = urllib.parse.quote(RP_NAME)
    return (f"otpauth://totp/{issuer}:{urllib.parse.quote(ADMIN_USER)}?secret={secret}"
            f"&issuer={issuer}&algorithm=SHA1&digits=6&period=30")


ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "")
_hash_file = os.environ.get("ADMIN_PASSWORD_HASH_FILE", "")
if _hash_file:
    try:
        with open(_hash_file, encoding="utf-8") as _fh:
            ADMIN_PASSWORD_HASH = _fh.read().strip()
    except OSError as _e:
        raise SystemExit(f"Cannot read ADMIN_PASSWORD_HASH_FILE {_hash_file!r}: {_e}")
if ADMIN_PASSWORD_HASH and not ADMIN_PASSWORD_HASH.startswith("$argon2"):
    raise SystemExit("ADMIN_PASSWORD_HASH does not look like an argon2 hash "
                     "(did compose mangle the '$' signs? use ADMIN_PASSWORD_HASH_FILE).")
if not (ADMIN_PASSWORD or ADMIN_PASSWORD_HASH):
    raise SystemExit("Set ADMIN_PASSWORD or ADMIN_PASSWORD_HASH (argon2id) to protect this UI.")

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)

app = Flask(__name__)

# Behind a reverse proxy: TRUST_PROXY=<number of proxies> makes the app use X-Forwarded-For for the client
# address (login lockout, "your IP"). Only when the proxy is the ONLY way to reach this container.
_trust = int(os.environ.get("TRUST_PROXY", "0") or 0)
if _trust > 0:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=_trust)

try:
    IDLE_TIMEOUT = max(0, int(os.environ.get("ADMIN_IDLE_TIMEOUT", "30"))) * 60
except ValueError:
    IDLE_TIMEOUT = 30 * 60

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=max(3600, IDLE_TIMEOUT + 300),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)

_failed = {}  # ip -> (count, first_ts)


# ---------- helpers ----------
def check_admin_password(pw: str) -> bool:
    if ADMIN_PASSWORD_HASH:
        try:
            return ph.verify(ADMIN_PASSWORD_HASH, pw)
        except Exception:
            return False
    return hmac.compare_digest(pw.encode(), ADMIN_PASSWORD.encode())


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


def client_ip():
    return request.remote_addr or ""


app.jinja_env.globals.update(
    csrf_token=csrf_token, tzname=str(TZINFO), container_name=f2b.CONTAINER,
    uid_gid=f"{os.getuid()}:{os.getgid()}", audit_problem=lambda: audit_error,
    config_dir=CONFIG_DIR, admin_dir=ADMIN_DIR)

# One change at a time (single gunicorn worker process, so a thread lock is enough).
_change_lock = threading.Lock()

# Requests the browser makes on its own: they don't count as activity for the idle sign-out
PASSIVE_ENDPOINTS = {"dashboard_status", "f2b_status", "file_fingerprint", "session_status", "static", "healthz",
                     "ip_info"}
# POSTs that don't change anything (no lock needed)
_NO_LOCK = ("/passkeys/login", "/session/ping", "/files/test")


@app.before_request
def larger_uploads_for_import():
    if request.endpoint == "import_zip":
        request.max_content_length = 50 * 1024 * 1024


@app.errorhandler(413)
def too_large(e):
    flash("That upload is too large.", "error")
    return redirect(url_for("backups") if session.get("auth") else url_for("login"))


@app.before_request
def idle_sign_out():
    if not (IDLE_TIMEOUT and session.get("auth")):
        return None
    t = time.time()
    seen = session.get("seen") or t
    if t - seen >= IDLE_TIMEOUT:
        audit("Signed out (inactivity)", "", f"no activity for {IDLE_TIMEOUT // 60} minutes")
        session.clear()   # straight to the sign-in page, no message (the admin log records it)
        if request.endpoint in PASSIVE_ENDPOINTS or request.is_json or request.headers.get("X-CSRF-Token"):
            return jsonify(ok=False, signed_in=False, signed_out=True, error="Signed out after inactivity."), 401
        return redirect(url_for("login"))
    if request.endpoint not in PASSIVE_ENDPOINTS:
        session["seen"] = t
    return None


@app.route("/session/status")
def session_status():
    if not session.get("auth"):
        return jsonify(signed_in=False)
    left = IDLE_TIMEOUT - (time.time() - (session.get("seen") or time.time())) if IDLE_TIMEOUT else None
    resp = jsonify(signed_in=True, timeout=IDLE_TIMEOUT, left=None if left is None else max(0, math.ceil(left)))
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/session/ping", methods=["POST"])
def session_ping():
    if not session.get("auth"):
        return jsonify(signed_in=False), 401
    return jsonify(ok=True, left=IDLE_TIMEOUT)


@app.before_request
def one_change_at_a_time():
    if request.method == "POST" and not request.path.startswith(_NO_LOCK):
        _change_lock.acquire()
        g.holds_change_lock = True


@app.teardown_request
def release_change_lock(exc):
    if g.pop("holds_change_lock", False):
        _change_lock.release()


@app.before_request
def protect():
    if request.method == "POST":
        sent = request.form.get("csrf", "") or request.headers.get("X-CSRF-Token", "")
        if not hmac.compare_digest(sent, session.get("csrf", "x")):
            if request.is_json or request.headers.get("X-CSRF-Token"):
                return jsonify(ok=False, error="Your session expired. Reload the page and sign in again."), 400
            if not session.get("auth"):
                flash("Your session expired, so that action was not carried out. Sign in and try again "
                      "(unsaved edits are kept in this browser and can be restored).", "error")
                return redirect(url_for("login"))
            flash("The page was out of date, so that action was not carried out. Please try again.", "error")
            back = urllib.parse.urlparse(request.referrer or "").path
            if not back.startswith("/") or back.startswith("//"):
                back = url_for("dashboard")
            return redirect(back)


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("auth"):
            if request.is_json or request.headers.get("X-CSRF-Token") or request.endpoint in PASSIVE_ENDPOINTS:
                return jsonify(ok=False, signed_in=False, error="Not signed in."), 401
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper


def add_query(url, **params):
    """url with params set in its query string (replacing ones of the same name)."""
    p = urllib.parse.urlsplit(url)
    q = [(k, v) for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True) if k not in params]
    q += [(k, str(v)) for k, v in params.items() if v is not None]
    return urllib.parse.urlunsplit(("", "", p.path, urllib.parse.urlencode(q), ""))


def here():
    """The current page with its query string (e.g. /files/edit?path=jail.d/x.local), for "back" fields, without
    the one-off markers that shouldn't repeat when coming back."""
    if not has_request_context():
        return "/"
    return add_query(request.full_path.rstrip("?"), restarting=None, saved=None)


app.jinja_env.globals["here"] = here
app.jinja_env.globals["admin_user"] = ADMIN_USER
# An IP's public report on AbuseIPDB (opened in the browser; the panel itself sends nothing there)
app.jinja_env.globals["abuseipdb"] = lambda ip: "https://www.abuseipdb.com/check/" + urllib.parse.quote(str(ip), safe=":")
# Country (offline database) and AbuseIPDB score next to IPs; the score is filled in by the page (see /ipinfo)
app.jinja_env.globals["country"] = ipinfo.country
app.jinja_env.globals["abuse_on"] = lambda: bool(ipinfo.LOOKUP and ipinfo.api_key(CONFIG_DIR)[0])


def back_to(default):
    """A same-site path from the form's `back` field, else default."""
    back = request.form.get("back", "") or request.args.get("back", "")
    if not back.startswith("/") or back.startswith("//"):
        return default
    return back


# ---------- admin action log ----------
AUDIT_FILE = os.environ.get("AUDIT_LOG_FILE") or os.path.join(ADMIN_DIR, "admin_audit.log")
AUDIT_MAX_BYTES = 1_000_000
try:
    ACTIVITY_DAYS = max(1, int(os.environ.get("ACTIVITY_DAYS", "30")))
except ValueError:
    ACTIVITY_DAYS = 30
ACTIVITY_MAX_ROWS = 2000
audit_error = None


def audit(action, target="", detail=""):
    """Record an admin action. Never lets a logging problem break the action itself."""
    in_request = has_request_context()
    entry = {"time": now().isoformat(timespec="seconds"),
             "admin": (ADMIN_USER if session.get("auth") else "") if in_request else "automatic",
             "via": session.get("via", "") if in_request else "",
             "ip": client_ip() if in_request else "", "action": action,
             "target": str(target)[:200], "detail": str(detail)[:1000]}
    global audit_error
    try:
        if os.path.exists(AUDIT_FILE) and os.path.getsize(AUDIT_FILE) > AUDIT_MAX_BYTES:
            os.replace(AUDIT_FILE, AUDIT_FILE + ".1")
        with open(AUDIT_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        audit_error = None
    except OSError as e:
        audit_error = f"{e.strerror or e} ({e.filename or AUDIT_FILE})"
        app.logger.exception("Couldn't write the admin action log %s", AUDIT_FILE)


if os.path.exists(AUDIT_FILE) and not os.access(AUDIT_FILE, os.W_OK):
    audit_error = f"Permission denied ({AUDIT_FILE})"
elif not os.path.exists(AUDIT_FILE) and not os.access(os.path.dirname(AUDIT_FILE) or ".", os.W_OK):
    audit_error = f"Permission denied ({os.path.dirname(AUDIT_FILE)})"


def read_audit(limit=200, days=None):
    lines = []
    for path in (AUDIT_FILE, AUDIT_FILE + ".1"):
        try:
            with open(path, encoding="utf-8") as fh:
                lines += fh.readlines()[::-1]
        except OSError:
            continue
        if len(lines) >= limit:
            break
    cutoff = now() - timedelta(days=days) if days else None
    out = []
    for ln in lines:
        if len(out) >= limit:
            break
        try:
            e = json.loads(ln)
            e["when"] = datetime.fromisoformat(e["time"]) if e.get("time") else None
        except (ValueError, KeyError, TypeError):
            continue
        if cutoff and e["when"] and e["when"] < cutoff:
            continue
        out.append(e)
    return out


# ---------- settings file (this app's own small state) ----------
SETTINGS_FILE = os.path.join(ADMIN_DIR, "admin_settings.json")


def load_settings():
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_settings(data):
    fd, tmp = tempfile.mkstemp(dir=ADMIN_DIR, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, SETTINGS_FILE)
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def mark_applied():
    """Fail2ban has just loaded the configuration (reload or restart through this app)."""
    try:
        data = load_settings()
        data["applied_at"] = time.time()
        save_settings(data)
    except OSError:
        app.logger.exception("Couldn't save the settings file")


# ---------- the Fail2ban configuration folder ----------
SUBDIRS = ("jail.d", "filter.d", "action.d", "fail2ban.d")
KINDS = {"jail.d": "jail", "filter.d": "filter", "action.d": "action", "fail2ban.d": "main", "": "main"}
KIND_TITLES = [("jail", "Jails", "jail.d: which logs to watch, when to ban and what to do"),
               ("filter", "Filters", "filter.d: regular expressions that find failures in the logs"),
               ("action", "Actions", "action.d: what happens on a ban or unban"),
               ("main", "Main files", "jail.local, fail2ban.local and other top-level files")]
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,120}$")
EDIT_EXT = (".conf", ".local", ".py")
# Top-level files of a full /etc/fail2ban that Fail2ban owns: editable, but warn before overriding them
STOCK_TOP = {"jail.conf", "fail2ban.conf"}


def safe_rel(rel):
    """A path relative to CONFIG_DIR that this app may touch ('jail.d/x.local', 'jail.local'), or None."""
    rel = (rel or "").replace("\\", "/").strip().strip("/")
    parts = rel.split("/")
    if len(parts) == 1:
        sub, name = "", parts[0]
    elif len(parts) == 2 and parts[0] in SUBDIRS:
        sub, name = parts
    else:
        return None
    if not NAME_RE.match(name) or ".." in name:
        return None
    full = os.path.realpath(os.path.join(CONFIG_DIR, rel))
    base = os.path.realpath(os.path.join(CONFIG_DIR, sub)) if sub else os.path.realpath(CONFIG_DIR)
    if os.path.dirname(full) != base:
        return None
    return f"{sub}/{name}" if sub else name


def full_path(rel):
    return os.path.join(CONFIG_DIR, rel)


def kind_of(rel):
    return KINDS.get(rel.split("/")[0] if "/" in rel else "", "main")


def is_editable(rel):
    return rel.endswith(EDIT_EXT)


def read_text(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except (OSError, UnicodeDecodeError):
        return ""


def fingerprint(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


SECTION_RE = re.compile(r"^\[([^\]\r\n]+)\]", re.M)
NOT_JAILS = {"INCLUDES", "DEFAULT", "Definition", "Init", "Init?family=inet6", "KNOWN"}


def sections(text):
    return [s.strip() for s in SECTION_RE.findall(text or "") if s.strip() not in NOT_JAILS
            and not s.strip().startswith("Init?")]


def config_files():
    """All files in the folder this app manages, grouped by kind."""
    out = []
    for sub in ("",) + SUBDIRS:
        d = os.path.join(CONFIG_DIR, sub)
        try:
            names = sorted(os.listdir(d), key=str.lower)
        except OSError:
            continue
        for n in names:
            p = os.path.join(d, n)
            if not os.path.isfile(p) or n.startswith("."):
                continue
            rel = f"{sub}/{n}" if sub else n
            if safe_rel(rel) is None:
                continue
            st = os.stat(p)
            item = {"rel": rel, "name": n, "kind": KINDS[sub], "size": st.st_size,
                    "mtime": datetime.fromtimestamp(st.st_mtime, TZINFO), "editable": is_editable(rel),
                    "stock": not sub and n in STOCK_TOP}
            if item["kind"] == "jail" or rel == "jail.local":
                item["jails"] = sections(read_text(p)) if item["editable"] else []
            out.append(item)
    return out


def newest_change():
    times = [f["mtime"] for f in config_files() if f["editable"]]
    return max(times) if times else None


def overlay_names(text_dir):
    """The names jails use for the files in a folder (for completion and the editor's checks): 'iptables' for
    iptables.conf / iptables.local, but 'smtp.py' for smtp.py, since Fail2ban refers to Python actions with
    their extension (action = smtp.py[...])."""
    try:
        names = set()
        for n in os.listdir(text_dir):
            if n.startswith("."):
                continue
            if n.endswith(".py"):
                names.add(n)
            elif n.endswith((".conf", ".local")):
                names.add(os.path.splitext(n)[0])
        return sorted(names, key=str.lower)
    except OSError:
        return []


def known_names(kind):
    """Filter or action names available to jails: the stock ones plus the folder's own."""
    sub = f"{kind}.d"
    names = set(overlay_names(os.path.join(BASE_CONFIG, sub))) | set(overlay_names(os.path.join(CONFIG_DIR, sub)))
    return sorted(names, key=str.lower)


# ---------- validation: Fail2ban's own reader on (stock config + this folder + the edit) ----------
def build_tree(changes=None):
    """A temporary full configuration: the bundled stock config, this folder laid over it, then `changes`
    ({rel: text, or None to remove})."""
    tmp = tempfile.mkdtemp(prefix="f2b-check-")
    if os.path.isdir(BASE_CONFIG):
        shutil.copytree(BASE_CONFIG, tmp, dirs_exist_ok=True)
    for sub in ("",) + SUBDIRS:
        src = os.path.join(CONFIG_DIR, sub)
        if not os.path.isdir(src):
            continue
        os.makedirs(os.path.join(tmp, sub), exist_ok=True)
        for n in os.listdir(src):
            p = os.path.join(src, n)
            if os.path.isfile(p) and n.endswith(EDIT_EXT) and not n.startswith("."):
                shutil.copyfile(p, os.path.join(tmp, sub, n))
    for rel, text in (changes or {}).items():
        dest = os.path.join(tmp, rel)
        if text is None:
            if os.path.exists(dest):
                os.remove(dest)
        else:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
    return tmp


def child_env():
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(p for p in sys.path if p)
    for k in ("ADMIN_PASSWORD", "ADMIN_PASSWORD_HASH", "SECRET_KEY", "ADMIN_TOTP_SECRET"):
        env.pop(k, None)
    return env


def validate(changes=None):
    """{'ok': True/False/None, 'errors': [...], 'warnings': [...], 'jails': [...]}; ok None = couldn't check."""
    tmp = build_tree(changes)
    try:
        for rel, text in (changes or {}).items():   # Python actions: at least a syntax check
            if text is not None and rel.endswith(".py"):
                try:
                    compile(text, rel, "exec")
                except SyntaxError as e:
                    return {"ok": False, "errors": [f"Python syntax error in '{rel}' [line {e.lineno}]: {e.msg}"],
                            "warnings": [], "jails": []}
        r = subprocess.run([sys.executable, VALIDATOR, tmp], capture_output=True, text=True, timeout=60,
                           env=child_env(), cwd=tmp)
        try:
            res = json.loads(r.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return {"ok": None, "errors": [(r.stderr or r.stdout or "no output").strip()[-800:]], "warnings": [],
                    "jails": []}
        fix = lambda m: m.replace(tmp + os.sep, "").replace(tmp + "/", "").replace(tmp, CONFIG_DIR)
        res["errors"] = [fix(m) for m in res.get("errors", [])]
        res["warnings"] = [fix(m) for m in res.get("warnings", [])]
        if not os.path.isdir(BASE_CONFIG):
            res["warnings"].insert(0, f"The stock Fail2ban configuration isn't at {BASE_CONFIG}, so files from "
                                      "it (common.conf, iptables, ...) look missing.")
        return res
    except subprocess.TimeoutExpired:
        return {"ok": None, "errors": ["The check took longer than 60 seconds and was stopped."], "warnings": [],
                "jails": []}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


_validation_cache = {}


def folder_fingerprint():
    h = hashlib.sha256()
    for f in config_files():
        if f["editable"]:
            h.update(f["rel"].encode() + b"\0" + read_text(full_path(f["rel"])).encode() + b"\0")
    return h.hexdigest()


def validate_current():
    fp = folder_fingerprint()
    if fp not in _validation_cache:
        res = validate()
        _validation_cache.clear()
        _validation_cache[fp] = res
    return _validation_cache[fp]


# ---------- backups ----------
_BK_STAMP = re.compile(r"\.(\d{8}-\d{6})(?:-\d+)?$")


def backup_base(rel):
    """jail.d/x.local -> jail.d__x.local (backups live in one flat folder)"""
    return rel.replace("/", "__")


def rel_from_backup(name):
    base = _BK_STAMP.sub("", name)
    if "__" in base:
        sub, rest = base.split("__", 1)
        if sub in SUBDIRS:
            return f"{sub}/{rest}"
    return base


def backup_time(name):
    m = _BK_STAMP.search(name)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y%m%d-%H%M%S").replace(tzinfo=TZINFO)
    except ValueError:
        return None


def backup_name(base):
    stamp = now().strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(BACKUP_DIR, f"{base}.{stamp}")
    n = 2
    while os.path.exists(dest):
        dest = os.path.join(BACKUP_DIR, f"{base}.{stamp}-{n}")
        n += 1
    return dest


def backup_file(path, base):
    """Copy path into the backups folder as <base>.<time>; returns the backup's path or None."""
    if not os.path.exists(path):
        return None
    os.makedirs(BACKUP_DIR, exist_ok=True)
    dest = backup_name(base)
    shutil.copy2(path, dest)
    os.chmod(dest, 0o600)   # may contain API keys
    olds = sorted(glob.glob(os.path.join(BACKUP_DIR, glob.escape(base) + ".*")))
    olds = [o for o in olds if _BK_STAMP.search(o)]
    for old in olds[:-MAX_BACKUPS]:
        os.remove(old)
    return dest


def backup(rel):
    return backup_file(full_path(rel), backup_base(rel))


def atomic_write(rel, text):
    """Back up, then replace the file with text. Returns the backup's path (None for a new file)."""
    path = full_path(rel)
    bk = backup(rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        try:
            shutil.copymode(path, tmp)
            st = os.stat(path)
            try:
                os.chown(tmp, st.st_uid, st.st_gid)   # keep the owner when running as root
            except (PermissionError, AttributeError):
                pass
        except FileNotFoundError:
            os.chmod(tmp, 0o644)
        try:
            os.replace(tmp, path)
        except OSError:
            with open(path, "w", encoding="utf-8", newline="\n") as fh:   # single-file bind mount
                fh.write(text)
            os.remove(tmp)
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
    return bk


def make_diff(old, new, old_name, new_name):
    out = []
    for line in difflib.unified_diff(old.splitlines(), new.splitlines(), old_name, new_name, lineterm="", n=3):
        if line.startswith(("+++", "---")):
            cls = "hdr"
        elif line.startswith("@@"):
            cls = "hunk"
        elif line.startswith("+"):
            cls = "add"
        elif line.startswith("-"):
            cls = "del"
        else:
            cls = ""
        out.append((cls, line))
    return out


def change_summary(old, new):
    delta = [l for l in difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=0)
             if not l.startswith(("---", "+++", "@@"))]
    return f"+{sum(1 for l in delta if l.startswith('+'))} −{sum(1 for l in delta if l.startswith('-'))} lines"


# ---------- formatting ----------
def fmt_time(dt):
    if not dt:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=TZINFO)
    dt = dt.astimezone(TZINFO)
    if dt.date() == now().date():
        return dt.strftime("Today %H:%M:%S")
    return dt.strftime("%Y-%m-%d %H:%M")


def fmt_short(dt):
    if not dt:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=TZINFO)
    dt = dt.astimezone(TZINFO)
    return dt.strftime("%H:%M") if dt.date() == now().date() else dt.strftime("%d %b %H:%M")


def fmt_duration(seconds):
    if seconds is None:
        return ""
    try:
        s = int(seconds)
    except (TypeError, ValueError):
        return str(seconds)
    if s < 0:
        return "permanent"
    parts = []
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if s >= n:
            parts.append(f"{s // n}{unit}")
            s %= n
    if s or not parts:
        parts.append(f"{s}s")
    return " ".join(parts[:2])


app.jinja_env.filters["when"] = fmt_time
app.jinja_env.filters["short"] = fmt_short
app.jinja_env.filters["duration"] = fmt_duration


def log_files(files):
    """A jail's log paths as (shared folder, names under it), so a long list can say "34 files in /log/npm/"
    once instead of repeating the folder on every line. The folder is "" when the paths share none."""
    # natural order: proxy-host-2 before proxy-host-10
    files = sorted((str(f) for f in files or []),
                   key=lambda f: [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", f)])
    if not files:
        return "", []
    try:
        common = os.path.commonpath([os.path.dirname(f) for f in files])
    except ValueError:  # mixed absolute and relative paths
        common = ""
    if common in ("", "/"):
        return "", files
    return common.rstrip("/") + "/", [f[len(common):].lstrip("/") for f in files]


app.jinja_env.filters["log_files"] = log_files


# ---------- auth ----------
def load_passkeys():
    try:
        with open(PASSKEY_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def save_passkeys(items):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(PASSKEY_FILE), prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(items, fh, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, PASSKEY_FILE)
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


# Each passkey entry is signed with a key derived from SECRET_KEY (which lives in the compose file), so
# someone who can only write the admin folder can't add a passkey of their own.
PASSKEY_SIGNING = bool(os.environ.get("SECRET_KEY"))
_PK_KEY = hmac.new(app.config["SECRET_KEY"].encode(), b"fail2ban-admin passkey signing v1", hashlib.sha256).digest()
_PK_SIGNED_FIELDS = ("id", "public_key", "name", "created")


def pk_signature(p):
    msg = json.dumps({k: p.get(k) for k in _PK_SIGNED_FIELDS}, sort_keys=True, separators=(",", ":"))
    return hmac.new(_PK_KEY, msg.encode(), hashlib.sha256).hexdigest()


def pk_sign(p):
    if PASSKEY_SIGNING:
        p["sig"] = pk_signature(p)
    return p


def pk_trusted(p):
    if not PASSKEY_SIGNING:
        return True
    return isinstance(p.get("sig"), str) and hmac.compare_digest(p["sig"], pk_signature(p))


def trusted_passkeys():
    return [p for p in load_passkeys() if pk_trusted(p)]


def password_login_allowed():
    return not (PASSKEY_ONLY and PASSKEYS_ENABLED and trusted_passkeys())


def login_ctx():
    return dict(show_passkey=PASSKEYS_ENABLED and bool(trusted_passkeys()), password_ok=password_login_allowed())


def _limited(ip):
    count, first = _failed.get(ip, (0, time.time()))
    if time.time() - first > 900:
        count, first = 0, time.time()
    return count, first


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("auth") and request.method == "GET":
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        if not password_login_allowed():
            flash("Password sign-in is disabled. Use a passkey.", "error")
            return render_template("login.html", **login_ctx()), 403
        ip = client_ip()
        count, first = _limited(ip)
        if count >= 5:
            if count == 5:
                audit("Sign-in blocked", "", "too many failed attempts from this IP")
                _failed[ip] = (count + 1, first)
            flash("Too many failed attempts. Try again in 15 minutes.", "error")
            return render_template("login.html", **login_ctx()), 429
        u, p = request.form.get("username", ""), request.form.get("password", "")
        if hmac.compare_digest(u, ADMIN_USER) and check_admin_password(p):
            session.clear()
            if TOTP_SECRET:
                session["pw_ok"] = time.time()
                return redirect(url_for("login_totp"))
            _failed.pop(ip, None)
            session.update(auth=True, via="password")
            session.permanent = True
            audit("Signed in")
            return redirect(url_for("dashboard"))
        _failed[ip] = (count + 1, first)
        audit("Sign-in failed", u[:64], "wrong user name or password")
        flash("Invalid credentials.", "error")
    return render_template("login.html", **login_ctx())


@app.route("/login/totp", methods=["GET", "POST"])
def login_totp():
    if not TOTP_SECRET:
        return redirect(url_for("login"))
    t = session.get("pw_ok")
    if not t or time.time() - t > 300:
        session.clear()
        flash("Sign-in expired. Start again.", "error")
        return redirect(url_for("login"))
    if request.method == "POST":
        ip = client_ip()
        count, first = _limited(ip)
        if count >= 5:
            flash("Too many failed attempts. Try again in 15 minutes.", "error")
            return render_template("login_totp.html"), 429
        if totp_verify(TOTP_SECRET, request.form.get("code", "")):
            _failed.pop(ip, None)
            session.clear()
            session.update(auth=True, via="password + TOTP")
            session.permanent = True
            audit("Signed in")
            return redirect(url_for("dashboard"))
        _failed[ip] = (count + 1, first)
        audit("Sign-in failed", ADMIN_USER, "wrong TOTP code")
        flash("That code didn't work. Check the code and your phone's clock.", "error")
    return render_template("login_totp.html")


@app.route("/logout", methods=["POST"])
def logout():
    if session.get("auth"):
        audit("Signed out")
    session.clear()
    return redirect(url_for("login"))


@app.route("/healthz")
def healthz():
    if os.path.isdir(ADMIN_DIR) and os.access(ADMIN_DIR, os.W_OK) and os.path.isdir(CONFIG_DIR):
        return "ok", 200
    return "admin or config folder not accessible", 503


# ---------- passkeys (WebAuthn) and TOTP setup ----------
def _pk_error(msg, code=400):
    return jsonify(ok=False, error=msg), code


def security_page(new_secret=None, verified=None):
    qr = None
    if new_secret and segno:
        qr = segno.make(totp_uri(new_secret), error="m").svg_inline(
            scale=5, border=3, dark="#000000", light="#ffffff", omitsize=True, title="Authenticator setup QR code")
    resp = make_response(render_template(
        "security.html", page="security",
        passkeys=[dict(p, trusted=pk_trusted(p)) for p in load_passkeys()], signing=PASSKEY_SIGNING,
        enabled=PASSKEYS_ENABLED, lib_ok=WEBAUTHN_OK, rp_id=RP_ID, origin=RP_ORIGIN,
        passkey_only=PASSKEY_ONLY, totp_enabled=bool(TOTP_SECRET),
        new_secret=new_secret, verified=verified, qr=qr))
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/security")
@login_required
def security():
    return security_page()


@app.route("/security/totp/new", methods=["POST"])
@login_required
def totp_new():
    return security_page(new_secret=base64.b32encode(secrets.token_bytes(20)).decode())


@app.route("/security/totp/check", methods=["POST"])
@login_required
def totp_check():
    secret = _norm_secret(request.form.get("secret", ""))
    if not valid_totp_secret(secret):
        abort(400)
    ok = totp_verify(secret, request.form.get("code", ""), record=False)
    flash("Code is correct." if ok else "That code didn't work. Check the code and your phone's clock.",
          "ok" if ok else "error")
    return security_page(new_secret=secret, verified=ok)


@app.route("/passkeys/register/options", methods=["POST"])
@login_required
def pk_register_options():
    if not PASSKEYS_ENABLED:
        return _pk_error("Passkeys are not configured.", 404)
    existing = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(p["id"])) for p in load_passkeys()]
    opts = generate_registration_options(
        rp_id=RP_ID, rp_name=RP_NAME, user_name=ADMIN_USER, user_id=ADMIN_HANDLE,
        exclude_credentials=existing,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED))
    session["pk_reg"] = bytes_to_base64url(opts.challenge)
    return jsonify(options_to_json_dict(opts))


@app.route("/passkeys/register/verify", methods=["POST"])
@login_required
def pk_register_verify():
    if not PASSKEYS_ENABLED:
        return _pk_error("Passkeys are not configured.", 404)
    data = request.get_json(silent=True) or {}
    chal = session.pop("pk_reg", None)
    cred = data.get("credential")
    if not chal or not isinstance(cred, dict):
        return _pk_error("Registration expired. Try again.")
    try:
        v = verify_registration_response(
            credential=cred, expected_challenge=base64url_to_bytes(chal),
            expected_rp_id=RP_ID, expected_origin=RP_ORIGIN, require_user_verification=True)
    except Exception as e:
        return _pk_error(f"Registration failed: {e}")
    items = load_passkeys()
    cid = bytes_to_base64url(v.credential_id)
    if any(p.get("id") == cid for p in items):
        return _pk_error("That passkey is already registered.")
    transports = (cred.get("response") or {}).get("transports")
    items.append({
        "id": cid, "public_key": bytes_to_base64url(v.credential_public_key), "sign_count": v.sign_count,
        "name": (str(data.get("name") or "").strip()[:60] or "Passkey"),
        "created": now().isoformat(timespec="seconds"), "last_used": None,
        "synced": bool(v.credential_backed_up),
        "transports": [t for t in transports if isinstance(t, str)] if isinstance(transports, list) else [],
    })
    pk_sign(items[-1])
    save_passkeys(items)
    audit("Passkey added", items[-1]["name"])
    flash("Passkey added.", "ok")
    return jsonify(ok=True)


@app.route("/passkeys/<pid>/delete", methods=["POST"])
@login_required
def pk_delete(pid):
    items = load_passkeys()
    left = [p for p in items if p.get("id") != pid]
    if len(left) == len(items):
        abort(404)
    save_passkeys(left)
    audit("Passkey removed", next((p.get("name", "") for p in items if p.get("id") == pid), ""))
    flash("Passkey removed.", "ok")
    return redirect(url_for("security"))


@app.route("/passkeys/<pid>/trust", methods=["POST"])
@login_required
def pk_trust(pid):
    if not PASSKEY_SIGNING:
        abort(404)
    items = load_passkeys()
    p = next((x for x in items if x.get("id") == pid), None)
    if not p:
        abort(404)
    pk_sign(p)
    save_passkeys(items)
    audit("Passkey trusted", p.get("name", ""), "created " + str(p.get("created") or "unknown"))
    flash(f"Passkey '{p.get('name', 'Passkey')}' is trusted and can be used to sign in.", "ok")
    return redirect(url_for("security"))


@app.route("/passkeys/login/options", methods=["POST"])
def pk_login_options():
    if not (PASSKEYS_ENABLED and trusted_passkeys()):
        return _pk_error("Passkey sign-in is not available.", 404)
    opts = generate_authentication_options(rp_id=RP_ID, user_verification=UserVerificationRequirement.REQUIRED)
    session["pk_auth"] = bytes_to_base64url(opts.challenge)
    return jsonify(options_to_json_dict(opts))


@app.route("/passkeys/login/verify", methods=["POST"])
def pk_login_verify():
    if not (PASSKEYS_ENABLED and trusted_passkeys()):
        return _pk_error("Passkey sign-in is not available.", 404)
    ip = client_ip()
    count, first = _limited(ip)
    if count >= 5:
        return _pk_error("Too many failed attempts. Try again in 15 minutes.", 429)
    chal = session.pop("pk_auth", None)
    cred = (request.get_json(silent=True) or {}).get("credential")
    items = load_passkeys()
    pk = next((p for p in items if isinstance(cred, dict) and p.get("id") == cred.get("id") and pk_trusted(p)), None)
    verified = None
    if chal and pk:
        try:
            verified = verify_authentication_response(
                credential=cred, expected_challenge=base64url_to_bytes(chal),
                expected_rp_id=RP_ID, expected_origin=RP_ORIGIN,
                credential_public_key=base64url_to_bytes(pk["public_key"]),
                credential_current_sign_count=int(pk.get("sign_count") or 0),
                require_user_verification=True)
        except Exception:
            verified = None
    if not verified:
        _failed[ip] = (count + 1, first)
        audit("Sign-in failed", ADMIN_USER, "passkey not accepted")
        return _pk_error("Passkey sign-in failed.", 401)
    pk["sign_count"] = verified.new_sign_count
    pk["last_used"] = now().isoformat(timespec="seconds")
    save_passkeys(items)
    _failed.pop(ip, None)
    session.clear()
    session.update(auth=True, via="passkey: " + pk.get("name", "Passkey"))
    session.permanent = True
    audit("Signed in")
    return jsonify(ok=True, next=url_for("dashboard"))


# ---------- Fail2ban's database (read-only): ban history ----------
def f2b_db():
    if not os.path.isfile(DB_FILE):
        return None
    try:
        con = sqlite3.connect(f"file:{urllib.parse.quote(DB_FILE)}?mode=ro", uri=True, timeout=3)
        con.row_factory = sqlite3.Row
        con.execute("SELECT 1 FROM bans LIMIT 1")
        return con
    except sqlite3.Error:
        return None


def ban_history(days=None, ip=None, jail=None, limit=ACTIVITY_MAX_ROWS):
    """Newest first: [{'jail','ip','time','bantime','until','count','failures','matches'}]; None if no database."""
    con = f2b_db()
    if not con:
        return None
    where, args = [], []
    if days:
        where.append("timeofban >= ?")
        args.append(int(time.time() - days * 86400))
    if ip:
        where.append("ip = ?")
        args.append(ip)
    if jail:
        where.append("jail = ?")
        args.append(jail)
    sql = ("SELECT jail, ip, timeofban, bantime, bancount, data FROM bans"
           + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY timeofban DESC LIMIT ?")
    args.append(limit)
    out = []
    try:
        for r in con.execute(sql, args):
            try:
                data = json.loads(r["data"]) if r["data"] else {}
            except (ValueError, TypeError):
                data = {}
            t = datetime.fromtimestamp(r["timeofban"], TZINFO)
            bt = r["bantime"]
            matches = data.get("matches") or []
            out.append({"jail": r["jail"], "ip": r["ip"], "time": t, "bantime": bt,
                        "until": None if bt is None or bt < 0 else t + timedelta(seconds=bt),
                        "count": r["bancount"], "failures": data.get("failures"),
                        "matches": ["".join(m) if isinstance(m, list) else str(m) for m in matches][-10:]})
    except sqlite3.Error:
        app.logger.exception("Reading Fail2ban's database failed")
    finally:
        con.close()
    return out


# ---------- public IP ----------
# ---------- newest Fail2ban release (to tell whether the running one is up to date) ----------
UPDATE_CHECK = os.environ.get("UPDATE_CHECK", "on").strip().lower() not in ("off", "false", "0", "no")
_release = {"at": 0.0, "version": None}


def latest_f2b_release():
    """The newest Fail2ban release on GitHub ('1.1.1'), cached for 6 hours (1 hour after a failure); None if the
    check is off or GitHub can't be reached."""
    if not UPDATE_CHECK:
        return None
    if _release["at"] and time.time() - _release["at"] < (6 * 3600 if _release["version"] else 3600):
        return _release["version"]
    import urllib.request
    version = None
    try:
        req = urllib.request.Request("https://api.github.com/repos/fail2ban/fail2ban/releases/latest",
                                     headers={"Accept": "application/vnd.github+json", "User-Agent": "fail2ban-admin"})
        with urllib.request.urlopen(req, timeout=4) as r:
            m = re.match(r"v?(\d+\.\d+\.\d+)$", json.load(r).get("tag_name", ""))
            version = m.group(1) if m else None
    except Exception:
        version = None
    _release.update(at=time.time(), version=version)
    return version


def version_tuple(v):
    m = re.match(r"v?(\d+)\.(\d+)\.(\d+)", str(v or ""))
    return tuple(int(x) for x in m.groups()) if m else None


_public_ip = {"at": 0.0, "ip": None, "error": None}


def public_ip(force=False):
    if not PUBLIC_IP_URL or PUBLIC_IP_URL.lower() == "off":
        return None, "off"
    age = time.time() - _public_ip["at"]
    if not force and _public_ip["at"] and age < (600 if _public_ip["ip"] else 120):
        return _public_ip["ip"], _public_ip["error"]
    import urllib.request
    ip, err = None, None
    try:
        req = urllib.request.Request(PUBLIC_IP_URL, headers={"User-Agent": "fail2ban-admin"})
        with urllib.request.urlopen(req, timeout=4) as r:
            text = r.read(200).decode("ascii", "replace").strip()
        if text.startswith("{"):
            text = str(json.loads(text).get("ip", ""))
        ip = str(ipaddress.ip_address(text))
    except Exception as e:
        err = f"couldn't look it up ({type(e).__name__})"
    _public_ip.update(at=time.time(), ip=ip, error=err)
    return ip, err


# ---------- IP input ----------
def parse_ips(raw, allow_networks=True):
    """Split a text box into IPs/networks. Returns (valid list, invalid list)."""
    good, bad = [], []
    for token in re.split(r"[\s,;]+", raw or ""):
        token = token.strip()
        if not token:
            continue
        try:
            if "/" in token and allow_networks:
                net = ipaddress.ip_network(token, strict=False)
                value = str(net.network_address) if net.num_addresses == 1 else str(net)
            else:
                value = str(ipaddress.ip_address(token))
            if value not in good:
                good.append(value)
        except ValueError:
            bad.append(token)
    return good, bad


def ip_in(ip, entries):
    """Whether ip is covered by Fail2ban ignoreip-style entries (IPs, networks; host names are skipped)."""
    try:
        addr = ipaddress.ip_network(ip, strict=False)
    except ValueError:
        return None
    for e in entries or []:
        try:
            net = ipaddress.ip_network(str(e).strip(), strict=False)
        except ValueError:
            continue
        if addr.version == net.version and addr.subnet_of(net):
            return str(e)
    return None


def ignore_overlap(ip, entries):
    """The ignoreip entry that an address or network to ban overlaps (either way round), else None.
    Host names in ignoreip can't be checked here and are skipped."""
    try:
        target = ipaddress.ip_network(ip, strict=False)
    except ValueError:
        return None
    for e in entries or []:
        try:
            net = ipaddress.ip_network(str(e).strip(), strict=False)
        except ValueError:
            continue
        if target.version == net.version and target.overlaps(net):
            return str(e)
    return None


# ---------- Fail2ban state shared by several pages ----------
STARTUP_GRACE = 60   # seconds after a (re)start during which "not answering" means "still starting"
_restart_clicked = {"at": 0.0}   # when Restart was last used here (the old server is still stopping at first)
_silent_since = {"at": None}     # when the running container's Fail2ban server first stopped answering


def starting_since(info, not_answering=False):
    """Seconds Fail2ban has been (re)starting, while that's within the grace period; else None.
    Counts from the most recent of: a Restart click here, the container's start, and (when the container runs but
    the server inside doesn't answer, which is how a start or stop by anyone looks) the first time that was seen."""
    if info.get("state") == "restarting":
        return 0
    t = time.time()
    ages = [t - _restart_clicked["at"]]
    started = info.get("started")
    if info.get("state") == "running" and started:
        ages.append((datetime.now(timezone.utc) - started).total_seconds())
    if info.get("state") == "running" and not_answering:
        if _silent_since["at"] is None:
            _silent_since["at"] = t
        ages.append(t - _silent_since["at"])
    age = min(ages)
    return max(0, int(age)) if age < STARTUP_GRACE else None


def f2b_state(with_status=True):
    """{'info': container info, 'version', 'jails', 'status': {jail: ...}, 'error', 'starting'}
    'starting' (seconds since the start) is set instead of a plain error while Fail2ban is still starting up."""
    st = {"info": f2b.container_info(), "version": "", "jails": [], "status": {}, "error": None, "starting": None}
    if st["info"].get("error"):
        st["error"] = st["info"]["error"]
        return st
    try:
        ov = f2b.overview()
        st.update(version=ov["version"], jails=ov["jails"])
        if with_status:
            st["status"] = f2b.jail_status(ov["jails"])
        _silent_since["at"] = None
    except F2BError as e:
        st["error"] = str(e)
        since = starting_since(st["info"], getattr(e, "not_answering", False))
        if since is not None:
            st["starting"] = since
            st["error"] = (f"Fail2ban is restarting ({since} s so far). This page refreshes by itself until it "
                           "answers; bans are restored from its database.")
    return st


def apply_pending():
    """When the configuration changed after Fail2ban last loaded it: the newest change time, else None."""
    newest = newest_change()
    if not newest:
        return None
    info = f2b.container_info()
    started = info.get("started")
    applied = load_settings().get("applied_at")
    loaded = max([t for t in (started.timestamp() if started else None, applied) if t] or [0])
    return newest if newest.timestamp() > loaded + 2 else None


# ---------- dashboard ----------
def ago(dt):
    """'4 min ago', '3 h ago', '2 days ago'."""
    if not dt:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=TZINFO)
    s = max(0, int((now() - dt).total_seconds()))
    if s < 60:
        return "just now"
    for unit, n in (("day", 86400), ("h", 3600), ("min", 60)):
        if s >= n:
            v = s // n
            return f"{v} {unit}{'s' if unit == 'day' and v != 1 else ''} ago"
    return ""


def until(dt):
    """'in 18m' for a ban that ends later."""
    if not dt:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=TZINFO)
    s = int((dt - now()).total_seconds())
    if s <= 60:
        return "any moment"
    if s < 3600:
        return f"in {math.ceil(s / 60)} min"
    return "in " + fmt_duration(s - s % 60)


app.jinja_env.filters["ago"] = ago
app.jinja_env.filters["until"] = until


def ban_reason(h):
    """Why an IP was banned, from its database entry: '5 failures · <last log line>' or 'manual ban'."""
    if not h:
        return ""
    why = f"{h['failures']} failure{'s' if h['failures'] != 1 else ''}" if h.get("failures") else "manual ban"
    if h.get("count") and h["count"] > 1:
        why = f"ban #{h['count']} · " + why
    if h.get("matches"):
        why += " · " + h["matches"][-1].strip()[-110:]
    return why


def chart_series(hist):
    """Bans over time for the chart's three ranges: {key: {bars, ticks, total, ips, busiest}}, today, yesterday."""
    t = now()
    out = {}
    specs = (("24h", 24, timedelta(hours=1), "%H:00", 6), ("7d", 28, timedelta(hours=6), "%a", 7),
             ("30d", 30, timedelta(days=1), "%d %b", 6))
    for key, n, step, fmt, n_ticks in specs:
        if step >= timedelta(days=1):
            start = t.replace(hour=0, minute=0, second=0, microsecond=0) - step * (n - 1)
        elif step >= timedelta(hours=6):
            start = t.replace(hour=(t.hour // 6) * 6, minute=0, second=0, microsecond=0) - step * (n - 1)
        else:
            start = t.replace(minute=0, second=0, microsecond=0) - step * (n - 1)
        counts, ips = [0] * n, set()
        for h in hist or []:
            i = int((h["time"] - start) // step)
            if 0 <= i < n:
                counts[i] += 1
                ips.add(h["ip"])
        top = max(counts) or 1
        bars = []
        for i, c in enumerate(counts):
            b0 = start + step * i
            label = b0.strftime("%a %d %b %H:00") if step < timedelta(days=1) else b0.strftime("%a %d %b")
            bars.append({"n": c, "pct": round(c * 100 / top), "label": label, "hi": c == top and c > 0})
        every = max(1, n // n_ticks)
        ticks = []
        for i in range(0, n, every):
            b0 = start + step * i
            ticks.append("Today" if key != "24h" and b0.date() == t.date() else b0.strftime(fmt))
        busiest = max(range(n), key=lambda i: counts[i]) if any(counts) else None
        out[key] = {"bars": bars, "ticks": ticks, "total": sum(counts), "ips": len(ips),
                    "busiest": bars[busiest]["label"] if busiest is not None else None}
    today = sum(1 for h in hist or [] if h["time"].date() == t.date())
    yesterday = sum(1 for h in hist or [] if h["time"].date() == (t - timedelta(days=1)).date())
    return out, today, yesterday


@app.route("/")
@login_required
def dashboard():
    st = f2b_state()
    hist = ban_history(days=30, limit=50000)      # None when the database isn't readable
    latest_ban, last_in_jail = {}, {}             # (jail, ip) -> newest database entry; jail -> newest ban time
    for h in hist or []:
        latest_ban.setdefault((h["jail"], h["ip"]), h)
        last_in_jail.setdefault(h["jail"], h["time"])

    # jails: compact rows, with the ban time of each (one round trip)
    jails_info = []
    if not st["error"] and st["jails"]:
        try:
            bts = f2b.query(*[["get", j, "bantime"] for j in st["jails"]])
        except F2BError:
            bts = [(False, None)] * len(st["jails"])
        for j, (ok, bt) in zip(st["jails"], bts):
            s = st["status"].get(j, {})
            jails_info.append({"name": j, "banned": s.get("banned_now", 0), "failed": s.get("failed_now", 0),
                               "logs": len(s.get("files") or []), "error": s.get("error"),
                               "bantime": bt if ok else None, "last": last_in_jail.get(j)})

    # banned now, with when each ban ends and why (from the database)
    banned, banned_error = [], None
    for j in (st["jails"] if not st["error"] else []):
        if not st["status"].get(j, {}).get("banned_now"):
            continue
        try:
            for b in f2b.banned_with_time(j):
                b["jail"] = j
                b["why"] = ban_reason(latest_ban.get((j, b["ip"])))
                banned.append(b)
        except F2BError as e:
            banned_error = str(e)
    banned.sort(key=lambda b: b["start"].timestamp() if b["start"] else 0, reverse=True)

    # needs attention: only things to act on
    attention = []
    if not st["error"]:
        pending = apply_pending()
        if pending:
            attention.append(("reload", f"The configuration changed {ago(pending)}, after Fail2ban last loaded it."))
        for r in jails_info:
            if not r["error"] and r["logs"] == 0:
                attention.append(("jail", f"Jail {r['name']} watches no log files, so it can't ban anyone."))
    v = validate_current()
    if v.get("ok") is False:
        attention.append(("config", f"Fail2ban's configuration check finds {len(v.get('errors', []))} "
                                    "problem(s): the next reload or restart may fail."))

    chart, today, yesterday = chart_series(hist) if hist is not None else (None, 0, 0)
    offenders = []
    if hist:
        per_ip = {}
        for h in hist:
            per_ip[h["ip"]] = per_ip.get(h["ip"], 0) + 1
        top = sorted(per_ip.items(), key=lambda kv: kv[1], reverse=True)[:5]
        offenders = [{"ip": ip, "n": n} for ip, n in top]

    # recent activity: Fail2ban's bans and what admins did here
    feed = [{"time": h["time"], "kind": "ban", "ip": h["ip"], "jail": h["jail"], "text": ban_reason(h)}
            for h in (hist or [])[:8]]
    shown = {"Unbanned", "File saved", "File created", "File deleted", "Reloaded", "Reloaded (failed)", "Restarted",
             "Backup restored", "Imported"}
    audit_rows = read_audit(300)
    for a in audit_rows:
        if a.get("action") in shown and a.get("when"):
            feed.append({"time": a["when"], "kind": "admin", "action": a["action"], "target": a.get("target", ""),
                         "text": a.get("detail", "")[:110]})
    feed.sort(key=lambda e: e["time"], reverse=True)

    # configuration and backups
    files = [f for f in config_files() if f["editable"]]
    counts = {k: sum(1 for f in files if f["kind"] == k) for k, _, _ in KIND_TITLES}
    last_file = max(files, key=lambda f: f["mtime"]) if files else None
    last_by = None
    if last_file:
        for a in audit_rows:
            if (a.get("target") == last_file["rel"] and a.get("when")
                    and abs((a["when"] - last_file["mtime"]).total_seconds()) <= 5):
                last_by = a.get("admin") or "admin"
                break
    bk_count, bk_latest = 0, None
    for p in glob.glob(os.path.join(BACKUP_DIR, "*")):
        if os.path.isfile(p):
            bk_count += 1
            bt = backup_time(os.path.basename(p))
            if bt and (bk_latest is None or bt > bk_latest):
                bk_latest = bt

    return render_template(
        "dashboard.html", page="dashboard", st=st, jails_info=jails_info, banned=banned, banned_error=banned_error,
        attention=attention, chart=chart, chart_json=json.dumps(chart) if chart else "null", today=today,
        yesterday=yesterday, offenders=offenders, feed=feed[:6], db_ok=hist is not None, counts=counts,
        last_file=last_file, last_by=last_by, bk_count=bk_count, bk_latest=bk_latest,
        now_text=now().strftime("%A %d %B").replace(" 0", " "))


@app.route("/dashboard/status")
@login_required
def dashboard_status():
    """The slower checks, loaded by the dashboard after it opens (and refreshed while it's open)."""
    st = f2b_state()
    v = validate_current()
    pip, pip_err = public_ip()
    jails = []
    for j in st["jails"]:
        s = st["status"].get(j, {})
        jails.append({"name": j, "banned": s.get("banned_now", 0), "total": s.get("banned_total", 0),
                      "failed": s.get("failed_now", 0), "url": url_for("jail", name=j)})
    info = st["info"]
    pending = apply_pending() if not st["error"] else None
    banned_pip = None
    if pip and not st["error"]:
        banned_pip = [j for j in st["jails"] if pip in st["status"].get(j, {}).get("banned", [])]
    resp = jsonify(
        container=info.get("state"), container_error=info.get("error"), error=st["error"], starting=st["starting"],
        started=fmt_time(info["started"].astimezone(TZINFO)) if info.get("started") else None,
        uptime=fmt_duration((datetime.now(timezone.utc) - info["started"]).total_seconds())
        if info.get("started") and info.get("state") == "running" else None,
        version=st["version"], latest=latest_f2b_release() if st["version"] else None,
        jails=jails, banned_total=sum(j["banned"] for j in jails),
        config_ok=v.get("ok"), config_errors=len(v.get("errors", [])), config_warnings=len(v.get("warnings", [])),
        public_ip=pip, public_ip_error=pip_err, public_ip_banned=banned_pip,
        pending=fmt_time(pending) if pending else None, checked=now().strftime("%H:%M"))
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/fail2ban/status")
@login_required
def f2b_status():
    """Polled after a restart: is the container running and the server answering?"""
    info = f2b.container_info()
    up, version, jails = False, "", 0
    if info.get("state") == "running":
        try:
            ov = f2b.overview()
            up, version, jails = True, ov["version"], len(ov["jails"])
        except F2BError:
            up = False
    resp = jsonify(container=info.get("state"), error=info.get("error"), up=up, version=version, jails=jails)
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------- jails, bans and unbans ----------
@app.route("/jails")
@login_required
def jails():
    st = f2b_state()
    return render_template("jails.html", page="jails", st=st, your_ip=client_ip(),
                           pending=apply_pending() if not st["error"] else None)


@app.route("/jails/<name>")
@login_required
def jail(name):
    st = f2b_state(with_status=False)
    if st["error"]:
        return render_template("jail.html", page="jails", name=name, st=st, error=st["error"])
    if name not in st["jails"]:
        # during a reload a jail disappears for a moment while Fail2ban sets it up again: look once more
        time.sleep(1.5)
        st = f2b_state(with_status=False)
        if st["error"]:
            return render_template("jail.html", page="jails", name=name, st=st, error=st["error"])
    if name not in st["jails"]:
        flash(f"There's no running jail called '{name}'. It may be disabled, or Fail2ban hasn't been reloaded "
              "since it was added.", "error")
        return redirect(url_for("jails"))
    try:
        status = f2b.jail_status([name])[name]
        banned = f2b.banned_with_time(name)
        settings = f2b.jail_settings(name)
    except F2BError as e:
        return render_template("jail.html", page="jails", name=name, st=st, error=str(e))
    for b in banned:
        if b["end"]:
            end = b["end"] if b["end"].tzinfo else b["end"].replace(tzinfo=TZINFO)
            b["left"] = max(0, int((end - now()).total_seconds()))
    # which file defines the jail
    defined_in = [f["rel"] for f in config_files() if name in (f.get("jails") or [])]
    hist = ban_history(days=ACTIVITY_DAYS, jail=name, limit=200)
    return render_template("jail.html", page="jails", name=name, st=st, status=status, banned=banned,
                           settings=settings, defined_in=defined_in, hist=hist, days=ACTIVITY_DAYS,
                           your_ip=client_ip())


@app.route("/ban", methods=["POST"])
@login_required
def ban():
    jail_name = request.form.get("jail", "")
    back = back_to(url_for("jails"))
    ips, bad = parse_ips(request.form.get("ips", ""))
    if bad:
        flash("Not banned: these aren't IP addresses or networks: " + ", ".join(bad[:10]), "error")
        return redirect(back)
    if not ips:
        flash("Enter an IP address to ban.", "error")
        return redirect(back)
    if len(ips) > 200:
        flash("Ban at most 200 addresses at a time.", "error")
        return redirect(back)
    try:
        ov = f2b.overview()
        if jail_name not in ov["jails"]:
            flash(f"There's no running jail called '{jail_name}'.", "error")
            return redirect(back)
        # don't lock yourself out by accident
        mine = [ip for ip in ips if ip_in(client_ip(), [ip]) or (_public_ip["ip"] and ip_in(_public_ip["ip"], [ip]))]
        # Fail2ban's banip doesn't check ignoreip (that only stops automatic bans), so check it here:
        # an address or network that touches an ignoreip entry is only banned when confirmed.
        ignored = f2b.one("get", jail_name, "ignoreip") or []
        hits = [f"{ip} (ignoreip {ignore_overlap(ip, ignored)})" for ip in ips if ignore_overlap(ip, ignored)]
        ask_self = bool(mine) and request.form.get("confirm_self") != "on"
        ask_ignored = bool(hits) and request.form.get("confirm_ignored") != "on"
        if ask_self or ask_ignored:
            # nothing is banned yet: show why, with "Ban anyway" (the same request, confirmed) and "Cancel"
            return render_template("ban_confirm.html", page="jails", ips=ips, jail=jail_name, back=back,
                                   mine=mine if ask_self else [], hits=hits if ask_ignored else [],
                                   confirmed_self=not ask_self and bool(mine),
                                   confirmed_ignored=not ask_ignored and bool(hits))
        n = f2b.ban(jail_name, ips)
    except F2BError as e:
        flash(f"Ban failed: {e}", "error")
        return redirect(back)
    audit("Banned", ", ".join(ips)[:200], f"jail {jail_name}" + (f"; {n} newly banned" if isinstance(n, int) else "")
          + (f"; confirmed despite ignoreip: {'; '.join(hits)}" if hits else ""))
    already = len(ips) - n if isinstance(n, int) else 0
    msg = f"Banned {', '.join(ips[:5])}{' and %d more' % (len(ips) - 5) if len(ips) > 5 else ''} in jail {jail_name}."
    if already > 0:
        msg += f" {already} {'was' if already == 1 else 'were'} already banned."
    if hits:
        msg += " Banned although on the never-ban list: " + "; ".join(hits[:5]) + "."
    flash(msg, "ok")
    return redirect(back)


@app.route("/unban", methods=["POST"])
@login_required
def unban():
    jail_name = request.form.get("jail", "")
    back = back_to(url_for("jails"))
    ips, bad = parse_ips(request.form.get("ips", ""))
    if bad or not ips:
        flash("Enter valid IP addresses to unban." + (" Not valid: " + ", ".join(bad[:10]) if bad else ""), "error")
        return redirect(back)
    try:
        if jail_name in ("", "*"):
            n = f2b.unban_everywhere(ips)
            where = "all jails"
        else:
            if jail_name not in f2b.overview()["jails"]:
                flash(f"There's no running jail called '{jail_name}'.", "error")
                return redirect(back)
            n = f2b.unban(jail_name, ips)
            where = f"jail {jail_name}"
    except F2BError as e:
        flash(f"Unban failed: {e}", "error")
        return redirect(back)
    audit("Unbanned", ", ".join(ips)[:200], where + (f"; {n} unbanned" if isinstance(n, int) else ""))
    if isinstance(n, int) and n == 0:
        flash(f"{', '.join(ips[:5])} {'wasn' if len(ips) == 1 else 'weren'}'t banned in "
              f"{'any jail' if where == 'all jails' else where}.", "error")
    else:
        flash(f"Unbanned {', '.join(ips[:5])}{' and %d more' % (len(ips) - 5) if len(ips) > 5 else ''} "
              f"in {where}.", "ok")
    return redirect(back)


@app.route("/lookup")
@login_required
def lookup():
    raw = request.args.get("ip", "").strip()
    ips, bad = parse_ips(raw, allow_networks=False)
    result = None
    if raw and (bad or len(ips) != 1):
        flash("Enter one IP address to look up.", "error")
    elif ips:
        ip = ips[0]
        result = {"ip": ip, "jails": [], "ignored": [], "error": None}
        try:
            ov = f2b.overview()
            result["jails"] = f2b.jails_banning([ip]).get(ip, [])
            ign = f2b.query(*[["get", j, "ignoreip"] for j in ov["jails"]])
            for j, (ok, entries) in zip(ov["jails"], ign):
                hit = ip_in(ip, entries) if ok else None
                if hit:
                    result["ignored"].append((j, hit))
            result["all_jails"] = ov["jails"]
        except F2BError as e:
            result["error"] = str(e)
        result["history"] = ban_history(ip=ip, limit=200)
    return render_template("lookup.html", page="jails", q=raw, r=result, your_ip=client_ip())


_abuse_cache = ipinfo.Cache(os.path.join(ADMIN_DIR, "abuseipdb_cache.json"))


@app.route("/ipinfo")
@login_required
def ip_info():
    """Country and AbuseIPDB reputation for up to 50 IPs (?ip=...&ip=...), for the score next to each IP."""
    ips = []
    for raw in request.args.getlist("ip")[:50]:
        try:
            ip = str(ipaddress.ip_address(raw.strip()))
        except ValueError:
            continue
        if ip not in ips:
            ips.append(ip)
    data, status = ipinfo.lookup(ips, CONFIG_DIR, _abuse_cache)
    for ip in ips:
        c = ipinfo.country(ip)
        if c:
            data.setdefault(ip, {})
            data[ip] = dict(data[ip], country=c["name"], country_code=c["cc"])
    resp = jsonify(status=status, ips=data)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/reload", methods=["POST"])
@login_required
def reload():
    jail_name = request.form.get("jail", "").strip()
    back = back_to(url_for("jails"))
    args = ["reload"]
    if request.form.get("restart_jail") == "on" and jail_name:
        args.append("--restart")
    if jail_name:
        if not NAME_RE.match(jail_name):
            abort(400)
        args.append(jail_name)
    try:
        ok, out = f2b.client(*args)
    except F2BError as e:
        flash(f"Reload failed: {e}", "error")
        return redirect(back)
    target = f"jail {jail_name}" if jail_name else "all jails"
    audit("Reloaded" + ("" if ok else " (failed)"), target, out[-600:])
    if ok:
        if not jail_name:
            mark_applied()
        flash(f"Fail2ban reloaded {target}. Bans are kept." + (f" {out}" if out and out != "OK" else ""), "ok")
    else:
        flash(f"Reloading {target} failed: {out or 'no details'}. Check the configuration "
              f"(docker logs {f2b.CONTAINER}).", "error")
    return redirect(back)


@app.route("/restart", methods=["POST"])
@login_required
def restart():
    back = back_to(url_for("dashboard"))
    _restart_clicked["at"] = time.time()
    try:
        f2b.restart_container()
    except F2BError as e:
        _restart_clicked["at"] = 0.0
        flash(f"Restart failed: {e}", "error")
        return redirect(back)
    except Exception as e:
        _restart_clicked["at"] = 0.0
        flash(f"Restart failed: {f2b.docker_hint(e)}", "error")
        return redirect(back)
    mark_applied()
    audit("Restarted", f2b.CONTAINER, "container restart")
    return redirect(add_query(back, restarting=1))


# ---------- configuration files ----------
TEMPLATES = {
    "jail": """[{name}]
enabled  = true
filter   = {name}
logpath  = /path/to/the.log
maxretry = 5
findtime = 10m
bantime  = 1h
# action = %(action_)s
# ignoreip = 127.0.0.1/8 ::1 192.168.0.0/16
""",
    "filter": """[INCLUDES]
before = common.conf

[Definition]
# <HOST> matches the IP address to ban. One regular expression per line.
failregex = ^<HOST> - \\S+ \\[[^]]+\\] "[A-Z]+ [^"]*" 40[13]
ignoreregex =
""",
    "action": """[Definition]
# Commands run by Fail2ban. Tags: <ip>, <name> (jail), <failures>, <bantime>, <matches>
actionstart =
actionstop =
actioncheck =
actionban = echo "<name>: ban <ip>"
actionunban = echo "<name>: unban <ip>"

[Init]
""",
    "main": """# Settings here override jail.conf / fail2ban.conf
[DEFAULT]
""",
}


@app.route("/files")
@login_required
def files():
    items = config_files()
    groups = []
    for key, title, hint in KIND_TITLES:
        groups.append({"key": key, "title": title, "hint": hint,
                       "items": [f for f in items if f["kind"] == key]})
    return render_template("files.html", page="files", groups=groups, pending=apply_pending(),
                           layout_ok=any(os.path.isdir(os.path.join(CONFIG_DIR, s)) for s in SUBDIRS))


@app.route("/files/new", methods=["POST"])
@login_required
def file_new():
    kind = request.form.get("kind", "")
    name = request.form.get("name", "").strip()
    sub = {"jail": "jail.d", "filter": "filter.d", "action": "action.d", "main": ""}.get(kind)
    if sub is None:
        abort(400)
    if name and not name.endswith(EDIT_EXT):
        name += ".local" if kind in ("jail", "main") else ".conf"
    rel = safe_rel(f"{sub}/{name}" if sub else name) if name else None
    if not rel or not is_editable(rel):
        flash("Use a name of letters, digits, . _ - ending in .conf or .local (or .py for an action).", "error")
        return redirect(url_for("files"))
    if os.path.exists(full_path(rel)):
        flash(f"{rel} already exists; opened it instead.", "ok")
    return redirect(url_for("file_edit", path=rel))


def editor_page(rel, content, disk, exists, **kw):
    kind = kind_of(rel)
    data = {"kind": kind, "rel": rel, "filters": known_names("filter"), "actions": known_names("action"),
            "lang": "python" if rel.endswith(".py") else "ini"}
    return render_template("editor.html", page="files", rel=rel, kind=kind, content=content, disk=disk,
                           exists=exists, editor_data=json.dumps(data), logs=log_candidates() if kind == "filter" else [],
                           **kw)


@app.route("/files/edit", methods=["GET", "POST"])
@login_required
def file_edit():
    rel = safe_rel(request.values.get("path", ""))
    if not rel or not is_editable(rel):
        abort(404)
    path = full_path(rel)
    exists = os.path.isfile(path)
    disk = read_text(path) if exists else ""
    disk_fp = fingerprint(disk) if exists else "new"

    if request.method == "POST":
        text = request.form.get("content", "").replace("\r\n", "\n")
        if text and not text.endswith("\n"):
            text += "\n"
        action = request.form.get("action", "save")
        base = request.form.get("base") or disk_fp
        overwrote = action == "overwrite"
        if overwrote:
            base, action = disk_fp, "save"
        from_backup = os.path.basename(request.form.get("from_backup", ""))
        apply_mode = request.form.get("apply", "reload")

        def page(**kw):
            return editor_page(rel, text, disk, exists, base=base, from_backup=from_backup, apply_mode=apply_mode, **kw)

        if action == "diff":
            d = make_diff(disk, text, "current", "edited")
            if not d:
                flash("No changes compared to the current file.", "ok")
            return page(diff=d)
        if action == "save" and base != disk_fp:
            msg = ("Not saved: this file was created by someone else since you opened the page." if base == "new"
                   else "Not saved: the file was changed outside this page since you opened it. Review the "
                        "difference below, then load the current file or overwrite it.")
            flash(msg, "error")
            return page(conflict=True, diff=make_diff(disk, text, "on disk now", "your edits"))
        if not text.strip():
            flash("Not saved: the file is empty. To remove a file, use Delete on the Files page.", "error")
            return page()
        res = validate({rel: text})
        if action == "validate":
            if res["ok"] is None:
                flash("Couldn't check the configuration: " + "; ".join(res["errors"])[:500], "error")
            elif res["ok"]:
                flash("Fail2ban's check passed." + (f" {len(res['warnings'])} warning(s)." if res["warnings"] else ""),
                      "ok")
            else:
                flash(f"Fail2ban's check found {len(res['errors'])} problem(s).", "error")
            return page(check=res)
        if res["ok"] is False and request.form.get("force") != "on":
            flash("Not saved: Fail2ban's check found problems. Fix them, or tick 'Save anyway'.", "error")
            return page(check=res, failed=True)
        if text == disk and exists:
            flash("No changes to save.", "ok")
            return redirect(url_for("file_edit", path=rel))
        bk = atomic_write(rel, text)
        notes = [change_summary(disk, text) if exists else "new file"]
        if from_backup:
            notes.append("from backup " + from_backup)
        if overwrote:
            notes.append("overwrote a change made outside the editor")
        if res["ok"] is False:
            notes.append("saved although the check failed")
        if bk:
            notes.append("previous version backed up as " + os.path.basename(bk))
        audit("File saved" if exists else "File created", rel, "; ".join(notes))
        msg = f"{rel} saved" + (" (backup created)." if bk else ".")
        # new filters and actions in the crazymax image only appear in /etc/fail2ban after a restart
        needs_restart = False
        if not exists and kind_of(rel) in ("filter", "action"):
            needs_restart = f2b.visible(f"{F2B_ETC}/{rel}") is False
        if apply_mode == "reload" and not needs_restart:
            try:
                ok, out = f2b.client("reload")
                audit("Reloaded" + ("" if ok else " (failed)"), "all jails", f"after saving {rel}; {out[-400:]}")
                if ok:
                    mark_applied()
                    flash(msg + " Fail2ban reloaded it.", "ok")
                else:
                    flash(msg + f" But reloading Fail2ban failed: {out or 'no details'}", "error")
            except F2BError as e:
                flash(msg + f" Fail2ban wasn't reloaded: {e}", "error")
        elif needs_restart:
            flash(msg + " Fail2ban can't see this new file until its container restarts (the image links "
                  "filters and actions in at start). Restart Fail2ban to use it.", "ok")
        else:
            flash(msg + " Reload Fail2ban to apply it.", "ok")
        return redirect(url_for("file_edit", path=rel, saved=1))

    from_backup = request.args.get("from_backup", "")
    if from_backup:
        bpath = os.path.realpath(os.path.join(BACKUP_DIR, os.path.basename(from_backup)))
        if (os.path.dirname(bpath) != os.path.realpath(BACKUP_DIR) or not os.path.isfile(bpath)
                or rel_from_backup(os.path.basename(bpath)) != rel):
            abort(404)
        flash(f"Loaded {os.path.basename(bpath)} into the editor. It isn't saved yet: review it, then save.", "ok")
        return editor_page(rel, read_text(bpath), disk, exists, base=disk_fp, from_backup=os.path.basename(bpath),
                           apply_mode="reload")
    if not exists:
        name = os.path.splitext(os.path.basename(rel))[0]
        tpl = TEMPLATES[kind_of(rel)] if not rel.endswith(".py") else ""
        return editor_page(rel, tpl.replace("{name}", name), "", False, base="new", is_new=True, apply_mode="reload")
    saved = bool(request.args.get("saved"))
    return editor_page(rel, disk, disk, True, base=disk_fp, ondisk=True, saved=saved, apply_mode="reload",
                       pending=apply_pending() if saved else None)


@app.route("/files/fingerprint")
@login_required
def file_fingerprint():
    rel = safe_rel(request.args.get("path", ""))
    if not rel:
        abort(404)
    p = full_path(rel)
    resp = jsonify(fp=fingerprint(read_text(p)) if os.path.isfile(p) else "new")
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/files/delete", methods=["POST"])
@login_required
def file_delete():
    rel = safe_rel(request.form.get("path", ""))
    if not rel or not os.path.isfile(full_path(rel)):
        abort(404)
    if is_editable(rel) and request.form.get("force") != "on":
        res = validate({rel: None})
        if res["ok"] is False:
            flash(f"Not deleted: without {rel}, Fail2ban's configuration would have problems: "
                  + "; ".join(res["errors"][:3])[:600], "error")
            return redirect(url_for("files"))
    bk = backup(rel)
    os.remove(full_path(rel))
    audit("File deleted", rel, "backed up as " + os.path.basename(bk) if bk else "")
    flash(f"{rel} deleted (a backup was kept)." + (" Reload Fail2ban to apply it." if is_editable(rel) else ""), "ok")
    return redirect(url_for("files"))


# ---------- testing a filter against log lines (fail2ban-regex) ----------
LOG_ROOTS = [p for p in (os.environ.get("LOG_DIRS", "/log /var/log").split()) if p]


def log_candidates():
    """Log files this container can read: the ones Fail2ban watches (from its database) and files under
    LOG_DIRS, if they're mounted here too."""
    seen = []
    con = f2b_db()
    if con:
        try:
            for r in con.execute("SELECT DISTINCT path FROM logs ORDER BY path"):
                if r["path"] and os.path.isfile(r["path"]) and r["path"] not in seen:
                    seen.append(r["path"])
        except sqlite3.Error:
            pass
        finally:
            con.close()
    for root in LOG_ROOTS:
        for p in sorted(glob.glob(os.path.join(root, "**", "*.log"), recursive=True))[:200]:
            if os.path.isfile(p) and p not in seen:
                seen.append(p)
    return seen[:300]


@app.route("/files/test", methods=["POST"])
@login_required
def file_test():
    """Run fail2ban-regex with the edited filter (not saved) against pasted lines or a log file."""
    data = request.get_json(silent=True) or {}
    rel = safe_rel(str(data.get("path", "")))
    if not rel or kind_of(rel) != "filter":
        return jsonify(ok=False, error="Only filters can be tested."), 400
    text = str(data.get("content", ""))
    sample = str(data.get("sample", ""))
    logfile = str(data.get("logfile", ""))
    if logfile and logfile not in log_candidates():
        return jsonify(ok=False, error="That log file isn't available here."), 400
    if not logfile and not sample.strip():
        return jsonify(ok=False, error="Paste some log lines, or choose a log file."), 400
    tmp = build_tree({rel: text})
    try:
        target = logfile
        if not logfile:
            target = os.path.join(tmp, "sample.log")
            with open(target, "w", encoding="utf-8") as fh:
                fh.write(sample[:500_000])
        # by path, not by name: a jail with the same name as the filter would otherwise be used instead
        name = os.path.join(tmp, rel)
        args = [sys.executable, "-c",
                "import sys; from fail2ban.client.fail2banregex import exec_command_line; exec_command_line(sys.argv[1:])",
                "--config", tmp, "--print-no-missed" if logfile else "--print-all-matched"]
        if not logfile:
            args.append("--print-all-missed")
        args += [target, name]
        r = subprocess.run(args, capture_output=True, text=True, timeout=90, env=child_env(), cwd=tmp)
        out = (r.stdout + ("\n" + r.stderr if r.stderr.strip() else "")).replace(tmp + "/", "")
        m = re.search(r"Lines: (\d+) lines, (\d+) ignored, (\d+) matched, (\d+) missed", out)
        summary = None
        if m:
            summary = dict(zip(("lines", "ignored", "matched", "missed"), map(int, m.groups())))
        if len(out) > 60000:
            out = out[:60000] + "\n… (output cut)"
        return jsonify(ok=r.returncode == 0, output=out.strip(), summary=summary)
    except subprocess.TimeoutExpired:
        return jsonify(ok=False, error="The test took longer than 90 seconds and was stopped."), 200
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------- activity ----------
@app.route("/activity")
@login_required
def activity():
    audit_rows = read_audit(ACTIVITY_MAX_ROWS + 1, days=ACTIVITY_DAYS)
    hist = ban_history(days=ACTIVITY_DAYS)
    banned_now = {}
    try:
        st = f2b.jail_status(f2b.overview()["jails"])
        for j, s in st.items():
            for ip in s.get("banned", []):
                banned_now.setdefault(ip, []).append(j)
    except F2BError:
        banned_now = None
    jails, seen = [], set()
    for h in hist or []:      # newest first: only an IP's newest entry in a jail is the ban in force now
        h["why"] = ban_reason(h)
        key = (h["jail"], h["ip"])
        h["current"] = bool(banned_now) and key not in seen and h["jail"] in banned_now.get(h["ip"], [])
        seen.add(key)
        if h["jail"] not in jails:
            jails.append(h["jail"])
    return render_template("activity.html", page="activity", days=ACTIVITY_DAYS, cap=ACTIVITY_MAX_ROWS,
                           audit=audit_rows[:ACTIVITY_MAX_ROWS], audit_capped=len(audit_rows) > ACTIVITY_MAX_ROWS,
                           audit_file=AUDIT_FILE, hist=hist, jails=sorted(jails), banned_now=banned_now, db=DB_FILE)


# ---------- backups ----------
@app.route("/backups")
@login_required
def backups():
    files_ = sorted((f for f in glob.glob(os.path.join(BACKUP_DIR, "*")) if os.path.isfile(f)), reverse=True)
    by_kind = {k: [] for k, _, _ in KIND_TITLES}
    by_kind["admin"] = []
    for f in files_:
        n = os.path.basename(f)
        rel = rel_from_backup(n)
        kind = "admin" if rel == os.path.basename(PASSKEY_FILE) else kind_of(rel)
        by_kind.setdefault(kind, []).append({"name": n, "rel": rel, "size": os.path.getsize(f),
                                             "time": backup_time(n),
                                             "exists": os.path.isfile(full_path(rel)) if kind != "admin" else True})
    groups = [{"key": k, "title": t, "items": by_kind[k]} for k, t, _ in KIND_TITLES]
    if by_kind["admin"]:
        groups.append({"key": "admin", "title": "Admin passkeys", "items": by_kind["admin"]})
    return render_template("backups.html", page="backups", groups=groups, max_backups=MAX_BACKUPS,
                           backup_dir=BACKUP_DIR)


def safe_backup(name):
    path = os.path.realpath(os.path.join(BACKUP_DIR, os.path.basename(name)))
    if os.path.dirname(path) != os.path.realpath(BACKUP_DIR) or not os.path.isfile(path):
        abort(404)
    return path


@app.route("/backups/<name>/download")
@login_required
def backup_download(name):
    safe_backup(name)
    return send_from_directory(BACKUP_DIR, os.path.basename(name), as_attachment=True)


@app.route("/backups/<name>", methods=["GET", "POST"])
@login_required
def backup_view(name):
    path = safe_backup(name)
    content = read_text(path)
    rel = safe_rel(rel_from_backup(name))
    if not rel or not is_editable(rel):
        return redirect(url_for("backup_download", name=name))
    if request.method == "POST":
        if request.form.get("force") != "on":
            res = validate({rel: content})
            if res["ok"] is False:
                flash("Not restored: with this version Fail2ban's check finds problems: "
                      + "; ".join(res["errors"][:3])[:600] + " Open it in the editor to fix it first.", "error")
                return redirect(url_for("backup_view", name=name))
        atomic_write(rel, content)
        audit("Backup restored", rel, "from " + name)
        flash(f"Restored {rel} from {name}. Reload Fail2ban to apply it.", "ok")
        return redirect(url_for("files"))
    diff = make_diff(read_text(full_path(rel)), content, "current", name)
    return render_template("backup_view.html", page="backups", name=name, rel=rel, content=content, diff=diff,
                           exists=os.path.isfile(full_path(rel)))


@app.route("/backups/<name>/delete", methods=["POST"])
@login_required
def backup_delete(name):
    path = safe_backup(name)
    os.remove(path)
    audit("Backup deleted", os.path.basename(path))
    flash(f"Backup {os.path.basename(path)} deleted.", "ok")
    return redirect(url_for("backups"))


@app.route("/backups/export")
@login_required
def export_zip():
    import io
    import zipfile
    with_backups = request.args.get("backups") == "1"
    buf = io.BytesIO()
    names, skipped = [], []
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in config_files():
            try:
                with open(full_path(f["rel"]), "rb") as fh:
                    z.writestr("fail2ban/" + f["rel"], fh.read())
                names.append(f["rel"])
            except OSError as e:
                skipped.append(f"{f['rel']} ({e.strerror or e})")
        for p in (PASSKEY_FILE, SETTINGS_FILE, AUDIT_FILE, AUDIT_FILE + ".1"):
            if os.path.isfile(p):
                try:
                    with open(p, "rb") as fh:
                        z.writestr("admin/" + os.path.basename(p), fh.read())
                    names.append("admin/" + os.path.basename(p))
                except OSError as e:
                    skipped.append(f"{os.path.basename(p)} ({e.strerror or e})")
        if with_backups and os.path.isdir(BACKUP_DIR):
            for f in sorted(glob.glob(os.path.join(BACKUP_DIR, "*"))):
                if os.path.isfile(f):
                    with open(f, "rb") as fh:
                        z.writestr("backups/" + os.path.basename(f), fh.read())
        z.writestr("manifest.json", json.dumps({
            "app": "fail2ban-admin", "exported": now().isoformat(timespec="seconds"),
            "files": names, "skipped": skipped, "backups_included": with_backups}, indent=2))
    audit("Exported", "configuration", f"{len(names)} files" + (" + backups" if with_backups else ""))
    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"] = "application/zip"
    resp.headers["Content-Disposition"] = f'attachment; filename="fail2ban-export-{now().strftime("%Y%m%d-%H%M")}.zip"'
    return resp


@app.route("/backups/import", methods=["POST"])
@login_required
def import_zip():
    import zipfile
    up = request.files.get("archive")
    back = redirect(url_for("backups"))
    if not up or not up.filename:
        flash("Choose an export zip to import.", "error")
        return back
    try:
        z = zipfile.ZipFile(up.stream)
    except zipfile.BadZipFile:
        flash("That file isn't a zip archive.", "error")
        return back
    changes, passkeys = {}, None
    for info in z.infolist():
        n = info.filename.replace("\\", "/")
        if info.is_dir():
            continue
        if n.startswith("fail2ban/"):
            rel = safe_rel(n[len("fail2ban/"):])
            if rel and is_editable(rel) and info.file_size < 2_000_000:
                try:
                    changes[rel] = z.read(info).decode("utf-8").replace("\r\n", "\n")
                except UnicodeDecodeError:
                    pass
        elif n == "admin/" + os.path.basename(PASSKEY_FILE) and request.form.get("passkeys") == "on":
            try:
                passkeys = json.loads(z.read(info).decode("utf-8"))
                if not isinstance(passkeys, list):
                    raise ValueError
            except ValueError:
                flash("Not imported: the admin passkeys in the zip aren't valid.", "error")
                return back
    if not changes and passkeys is None:
        flash("The zip has no Fail2ban configuration files (expected a fail2ban/ folder from an export).", "error")
        return back
    if changes and request.form.get("force") != "on":
        res = validate(changes)
        if res["ok"] is False:
            flash("Not imported: with these files Fail2ban's check finds problems: "
                  + "; ".join(res["errors"][:3])[:600] + " Tick 'Import anyway' to import regardless.", "error")
            return back
    done = 0
    for rel, text in changes.items():
        if read_text(full_path(rel)) != text or not os.path.isfile(full_path(rel)):
            atomic_write(rel, text)
            done += 1
    if passkeys is not None:
        backup_file(PASSKEY_FILE, os.path.basename(PASSKEY_FILE))
        save_passkeys(passkeys)
    audit("Imported", up.filename[:100], f"{done} of {len(changes)} files changed"
          + ("; admin passkeys" if passkeys is not None else ""))
    flash(f"Imported: {done} file(s) changed, {len(changes) - done} already identical"
          + (", admin passkeys replaced" if passkeys is not None else "")
          + ". Every replaced file was backed up. Reload Fail2ban to apply.", "ok")
    return redirect(url_for("files"))


# ---------- errors and headers ----------
@app.errorhandler(OSError)
def file_error(e):
    app.logger.exception("File error on %s %s", request.method, request.path)
    where = getattr(e, "filename", None) or "a file"
    reason = e.strerror or str(e)
    hint = ""
    if isinstance(e, PermissionError):
        hint = (" This container runs as %s (PUID:PGID). That user or group needs write access to the folder: "
                "check it with ls -ldn, and see \"Running as a normal user\" in the README."
                % app.jinja_env.globals["uid_gid"])
    msg = f"Nothing was changed: couldn't access {where} ({reason}).{hint}"
    if request.is_json or request.headers.get("X-CSRF-Token"):
        return jsonify(ok=False, error=msg), 500
    if request.method == "GET":
        return render_template("error.html", message=msg, page=None), 500
    flash(msg, "error")
    back = urllib.parse.urlparse(request.referrer or "").path
    if not back.startswith("/") or back.startswith("//"):
        back = url_for("dashboard")
    return redirect(back)


@app.errorhandler(F2BError)
def f2b_error(e):
    msg = str(e)
    if request.is_json or request.headers.get("X-CSRF-Token") or request.endpoint in PASSIVE_ENDPOINTS:
        return jsonify(ok=False, error=msg), 503
    if request.method == "GET":
        return render_template("error.html", message=msg, page=None), 503
    flash(msg, "error")
    return redirect(url_for("dashboard"))


@app.after_request
def headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; style-src 'self' 'unsafe-inline'; "
                                               "script-src 'self'; img-src 'self' data:")
    return resp
