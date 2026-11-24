"""What we know about an IP address beyond Fail2ban: its country (offline) and its AbuseIPDB reputation.

Country: from the DB-IP "IP to Country Lite" database bundled in the image (CC BY 4.0, https://db-ip.com).
No network access, no quota.

AbuseIPDB: the /api/v2/check endpoint, with the API key from ABUSEIPDB_API_KEY or, if that isn't set, the
`abuseipdb_apikey` already in the Fail2ban configuration (the abuseipdb action). Only public addresses are sent.
Answers are cached on disk for ABUSEIPDB_CACHE_HOURS (24) and at most ABUSEIPDB_DAILY_LIMIT (900) checks are made
per day, below the free plan's 1,000. ABUSEIPDB_LOOKUP=off turns the whole thing off.
"""
import glob
import ipaddress
import json
import os
import re
import tempfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

GEOIP_DB = os.environ.get("GEOIP_DB", "/opt/geoip/dbip-country-lite.mmdb")
LOOKUP = os.environ.get("ABUSEIPDB_LOOKUP", "on").strip().lower() not in ("off", "false", "0", "no")
ENV_KEY = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
try:
    CACHE_SECONDS = max(1, int(os.environ.get("ABUSEIPDB_CACHE_HOURS", "24"))) * 3600
except ValueError:
    CACHE_SECONDS = 24 * 3600
try:
    DAILY_LIMIT = max(0, int(os.environ.get("ABUSEIPDB_DAILY_LIMIT", "900")))
except ValueError:
    DAILY_LIMIT = 900
MAX_AGE_DAYS = 90   # how far back AbuseIPDB counts reports
API_URL = os.environ.get("ABUSEIPDB_API_URL", "https://api.abuseipdb.com/api/v2/check")   # for tests

# ---------- country (offline) ----------
_reader = None
_reader_failed = False


def _geo_reader():
    global _reader, _reader_failed
    if _reader is None and not _reader_failed:
        try:
            import maxminddb
            _reader = maxminddb.open_database(GEOIP_DB)
        except Exception:
            _reader_failed = True
    return _reader


def country(ip):
    """{'cc': 'IL', 'name': 'Israel'} or None (private address, network, or no database)."""
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return None
    if not addr.is_global:
        return None
    r = _geo_reader()
    if not r:
        return None
    try:
        rec = r.get(str(addr)) or {}
    except Exception:
        return None
    c = rec.get("country") or {}
    if not c.get("iso_code"):
        return None
    return {"cc": c["iso_code"], "name": (c.get("names") or {}).get("en", c["iso_code"])}


def geo_available():
    return _geo_reader() is not None


# ---------- AbuseIPDB ----------
_KEY_RE = re.compile(r"abuseipdb_apikey\s*=\s*[\"']?([A-Za-z0-9]{32,})")
_key_cache = {"at": 0.0, "key": None, "source": None}


def api_key(config_dir):
    """(key, where it came from) or (None, None). The Fail2ban folder is re-read every 5 minutes."""
    if ENV_KEY:
        return ENV_KEY, "ABUSEIPDB_API_KEY"
    if time.time() - _key_cache["at"] < 300:
        return _key_cache["key"], _key_cache["source"]
    key = source = None
    for sub in ("jail.d", "action.d", ""):
        for p in sorted(glob.glob(os.path.join(config_dir, sub, "*.local")) + glob.glob(os.path.join(config_dir, sub, "*.conf"))):
            try:
                with open(p, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        if line.lstrip().startswith(("#", ";")):
                            continue
                        m = _KEY_RE.search(line)
                        if m:
                            key, source = m.group(1), os.path.relpath(p, config_dir).replace("\\", "/")
                            break
            except OSError:
                continue
            if key:
                break
        if key:
            break
    _key_cache.update(at=time.time(), key=key, source=source)
    return key, source


class Cache:
    """{ip: {'at': epoch, 'data': {...}}} plus {'_day': 'YYYY-MM-DD', '_used': n} in one small JSON file."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.data = None

    def _load(self):
        if self.data is None:
            try:
                with open(self.path, encoding="utf-8") as fh:
                    self.data = json.load(fh)
                if not isinstance(self.data, dict):
                    self.data = {}
            except (OSError, ValueError):
                self.data = {}
        return self.data

    def _save(self):
        d = self.data
        cutoff = time.time() - CACHE_SECONDS
        for k in [k for k, v in d.items() if not k.startswith("_") and v.get("at", 0) < cutoff]:
            del d[k]
        try:
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(self.path) or ".", prefix=".tmp-")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(d, fh)
            os.replace(tmp, self.path)
        except OSError:
            pass

    def get(self, ip):
        with self.lock:
            e = self._load().get(ip)
            if e and time.time() - e.get("at", 0) < CACHE_SECONDS:
                return e["data"]
        return None

    def put_many(self, items):
        with self.lock:
            d = self._load()
            for ip, data in items.items():
                d[ip] = {"at": time.time(), "data": data}
            self._save()

    def take_quota(self, n):
        """Reserve up to n checks from today's allowance; returns how many may be made."""
        with self.lock:
            d = self._load()
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            if d.get("_day") != today:
                d["_day"], d["_used"] = today, 0
            allowed = max(0, min(n, DAILY_LIMIT - d.get("_used", 0)))
            d["_used"] = d.get("_used", 0) + allowed
            self._save()
            return allowed

    def used_today(self):
        with self.lock:
            d = self._load()
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            return d.get("_used", 0) if d.get("_day") == today else 0


def _check(ip, key):
    req = urllib.request.Request(
        f"{API_URL}?ipAddress={ip}&maxAgeInDays={MAX_AGE_DAYS}",
        headers={"Key": key, "Accept": "application/json", "User-Agent": "fail2ban-admin"})
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            d = (json.load(r) or {}).get("data") or {}
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return {"error": "AbuseIPDB refused the API key", "retry": True}
        if e.code == 429:
            return {"error": "AbuseIPDB's daily limit is used up", "retry": True}
        return {"error": f"AbuseIPDB answered HTTP {e.code}", "retry": True}
    except Exception as e:
        return {"error": f"AbuseIPDB unreachable ({type(e).__name__})", "retry": True}
    return {"score": d.get("abuseConfidenceScore"), "reports": d.get("totalReports"),
            "users": d.get("numDistinctUsers"), "cc": d.get("countryCode"), "isp": d.get("isp"),
            "usage": d.get("usageType"), "domain": d.get("domain"), "tor": d.get("isTor"),
            "whitelisted": d.get("isWhitelisted"), "last": d.get("lastReportedAt")}


def lookup(ips, config_dir, cache):
    """{ip: info} for each IP: {'score', 'reports', ...} from AbuseIPDB (cached), {'private': True}, or
    {'error': ...}. Also returns a status dict: {'enabled', 'source', 'used', 'limit'}."""
    key, source = api_key(config_dir) if LOOKUP else (None, None)
    status = {"enabled": bool(key), "source": source, "limit": DAILY_LIMIT}
    out, todo = {}, []
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            out[ip] = {"error": "not an address"}
            continue
        if not addr.is_global:
            out[ip] = {"private": True}
            continue
        if not key:
            continue
        hit = cache.get(str(addr))
        if hit is not None:
            out[ip] = hit
        else:
            todo.append(str(addr))
    if key and todo:
        allowed = cache.take_quota(len(todo))
        for ip in todo[allowed:]:
            out[ip] = {"error": f"today's AbuseIPDB check limit ({DAILY_LIMIT}) is reached"}
        todo = todo[:allowed]
        if todo:
            with ThreadPoolExecutor(max_workers=4) as pool:
                results = dict(zip(todo, pool.map(lambda i: _check(i, key), todo)))
            cache.put_many({ip: r for ip, r in results.items() if not r.get("retry")})
            out.update(results)
    status["used"] = cache.used_today()
    return out, status
