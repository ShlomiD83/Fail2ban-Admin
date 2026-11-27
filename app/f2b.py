"""Talking to Fail2ban: through the Docker API, inside the Fail2ban container.

Queries (status, banned IPs, ban, unban) run a tiny Python snippet in the Fail2ban container with
`docker exec`. The snippet speaks Fail2ban's own socket protocol and prints JSON, so the answers are
structured data rather than text to parse. `reload` goes through `fail2ban-client`, because only the client
reads the configuration (and finds the log files) on the Fail2ban side. This is the same thing the
`docker exec <container> fail2ban-client ...` scripts do by hand.
"""
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone

CONTAINER = os.environ.get("FAIL2BAN_CONTAINER", "fail2ban").strip()
SOCKET = os.environ.get("FAIL2BAN_SOCKET", "/var/run/fail2ban/fail2ban.sock").strip()

# Runs inside the Fail2ban container (any image with Fail2ban's Python package: crazymax, linuxserver, ...)
_QUERY = r'''
import json, sys
from fail2ban.client.csocket import CSocket
def enc(o):
    if isinstance(o, BaseException): return {"__error__": str(o) or type(o).__name__, "type": type(o).__name__}
    if isinstance(o, (set, frozenset, tuple)): return list(o)
    return str(o)
s = CSocket(sys.argv[1], timeout=15)
out = []
try:
    for cmd in json.loads(sys.argv[2]):
        out.append(s.send(cmd))
finally:
    s.close()
sys.stdout.write(json.dumps(out, default=enc))
'''


class F2BError(Exception):
    """A problem reaching Fail2ban, worded for the page. `not_answering`: the container runs, but the Fail2ban
    server inside doesn't answer (yet), which is what a start or stop looks like."""

    def __init__(self, msg, not_answering=False):
        super().__init__(msg)
        self.not_answering = not_answering


_client = None


def docker_client():
    global _client
    if _client is None:
        try:
            import docker
            _client = docker.from_env(timeout=120)
        except Exception as e:
            raise F2BError(docker_hint(e))
    return _client


def docker_hint(e):
    s = str(e)
    proxy = os.environ.get("DOCKER_HOST", "")
    if proxy.startswith(("tcp://", "http://", "https://")):
        if "403" in s or "Forbidden" in s:
            return ("The Docker socket proxy refused the request. Its allow rules must name the Fail2ban "
                    f"container exactly as FAIL2BAN_CONTAINER does ('{CONTAINER}'); see the README.")
        if any(x in s for x in ("Connection refused", "Max retries", "Name or service not known",
                                "Failed to resolve", "Connection aborted", "timed out")):
            return (f"Can't reach the Docker socket proxy at {proxy}: is it running, on the same network, and "
                    "does its -allowfrom include this container?")
    if "No such file" in s or "FileNotFoundError" in s or "Connection aborted" in s:
        return ("Can't reach Docker: set DOCKER_HOST to the socket proxy (recommended, see README), or mount "
                "/var/run/docker.sock into this container.")
    if "Permission denied" in s or "PermissionError" in s:
        return ("Can't use the Docker socket: permission denied. Run this container as root (user: \"0:0\") "
                "or add the docker group's id with group_add.")
    return f"Docker error: {s}"


# Every call addresses the Fail2ban container by NAME (never by its id) and uses only these endpoints, so a
# socket proxy can allow exactly them, for this one container:
#   GET  /version                    GET  /containers/<name>/json        GET  /exec/<id>/json
#   POST /containers/<name>/exec     POST /exec/<id>/start               POST /containers/<name>/restart
def _api():
    if not CONTAINER:
        raise F2BError("FAIL2BAN_CONTAINER isn't set.")
    return docker_client().api


def inspect():
    try:
        return _api().inspect_container(CONTAINER)
    except F2BError:
        raise
    except Exception as e:
        if "404" in str(e) or "No such container" in str(e):
            raise F2BError(f"There's no container named '{CONTAINER}'. Set FAIL2BAN_CONTAINER to the name "
                           "shown by docker ps.")
        raise F2BError(docker_hint(e))


# Each Docker call is a round trip through the socket proxy, which is slow on small machines (a Raspberry Pi),
# so answers that several parts of one page ask for are reused for a moment. Anything that changes Fail2ban
# (ban, unban, reload, restart) forgets them at once.
_INFO_TTL = 2.0        # container state (docker inspect)
_OVERVIEW_TTL = 3.0    # version and jail list
_cache = {"info": (0.0, None), "overview": (0.0, None)}


def forget():
    """Drop the short-lived answers above (after anything that changes Fail2ban)."""
    _cache["info"] = (0.0, None)
    _cache["overview"] = (0.0, None)


def _cached(key, ttl):
    at, value = _cache[key]
    return value if value is not None and time.monotonic() - at < ttl else None


def container_info():
    """{'state': running|restarting|exited|..., 'started': datetime|None, 'image': str, 'health': str|None,
    'restarts': int} or {'error': message}. Reused for a couple of seconds."""
    hit = _cached("info", _INFO_TTL)
    if hit is not None:
        return dict(hit)
    try:
        attrs = inspect()
    except F2BError as e:
        info = {"error": str(e)}
    else:
        st = attrs.get("State", {})
        started = None
        m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", st.get("StartedAt") or "")
        if m and not st.get("StartedAt", "").startswith("0001"):
            started = datetime.fromisoformat(m.group(1) + "+00:00")
        info = {"state": st.get("Status", "unknown"), "started": started,
                "image": (attrs.get("Config") or {}).get("Image", ""),
                "health": (st.get("Health") or {}).get("Status"),
                "restarts": attrs.get("RestartCount", 0)}
    _cache["info"] = (time.monotonic(), info)
    return dict(info)


def _exec(cmd, what):
    # No "is it running?" check first: that would cost a round trip on every call. Only when Docker refuses the
    # exec is the container looked at, to say why (not running, no such container, proxy, ...).
    api = _api()
    try:
        ex = api.exec_create(CONTAINER, cmd, stdout=True, stderr=True)
    except Exception as e:
        state = (inspect().get("State") or {}).get("Status")   # raises a clear F2BError when it's missing
        forget()
        if state != "running":
            raise F2BError(f"The Fail2ban container '{CONTAINER}' isn't running ({state}).")
        raise F2BError(f"{what} failed: {docker_hint(e)}")
    try:
        out, err = api.exec_start(ex["Id"], demux=True)
        code = api.exec_inspect(ex["Id"]).get("ExitCode")
    except Exception as e:
        raise F2BError(f"{what} failed: {docker_hint(e)}")
    return code, (out or b"").decode("utf-8", "replace"), (err or b"").decode("utf-8", "replace")


# Everything a page about the jails needs, in ONE exec: version, jail list, and for every jail its status, ban
# time and banned IPs with their times, plus the container's UTC offset and (optionally) one jail's settings.
# Asking the socket is quick; it's each docker exec round trip that costs.
_SNAPSHOT = r'''
import json, sys, time
from fail2ban.client.csocket import CSocket
def enc(o):
    if isinstance(o, BaseException): return {"__error__": str(o) or type(o).__name__, "type": type(o).__name__}
    if isinstance(o, (set, frozenset, tuple)): return list(o)
    return str(o)
opts = json.loads(sys.argv[2])
s = CSocket(sys.argv[1], timeout=15)
out = {"tz": time.localtime().tm_gmtoff, "jails": {}}
try:
    out["version"] = s.send(["version"])
    out["status"] = s.send(["status"])
    jails = []
    if out["status"][0] == 0:
        for item in out["status"][1] or []:
            if isinstance(item, (list, tuple)) and len(item) == 2 and str(item[0]) == "Jail list":
                jails = [j.strip() for j in str(item[1]).split(",") if j.strip()]
    for j in jails:
        out["jails"][j] = [s.send(["status", j]), s.send(["get", j, "bantime"]),
                           s.send(["get", j, "banip", "--with-time"])]
    if opts.get("settings_for") in jails:
        out["settings"] = [s.send(["get", opts["settings_for"], k]) for k in opts.get("keys", [])]
finally:
    s.close()
sys.stdout.write(json.dumps(out, default=enc))
'''


def _run(snippet, args, what):
    """Run a Python snippet in the Fail2ban container and return its JSON output. Raises F2BError."""
    code, out, err = _exec(["python3", "-c", snippet, *args], what)
    if code != 0:
        low = err.lower()
        if any(x in low for x in ("no such file", "connectionrefused", "connection refused", "connectionreset",
                                  "connection reset", "broken pipe", "brokenpipe", "eoferror", "timed out")):
            raise F2BError("The Fail2ban server isn't answering: it may be starting, or stopped because of a "
                           "configuration error. Check: docker logs " + CONTAINER, not_answering=True)
        if "executable file not found" in low or "python3" in low and "not found" in low:
            raise F2BError(f"The container '{CONTAINER}' has no python3: is it really a Fail2ban container?")
        last = [l for l in err.strip().splitlines() if l.strip()]
        raise F2BError("Fail2ban query failed: " + (last[-1] if last else f"exit code {code}"))
    try:
        return json.loads(out)
    except ValueError:
        raise F2BError("Fail2ban sent an answer that isn't JSON: " + out[:200])


def _result(item):
    """One answer from the socket, [rc, value] -> (ok, value or error message)."""
    try:
        rc, value = item
    except (TypeError, ValueError):
        rc, value = 1, item
    if rc == 0:
        return True, value
    return False, (value.get("__error__") if isinstance(value, dict) else str(value))


_READ_ONLY = {"get", "status", "version", "banned", "ping"}


def query(*cmds):
    """Send commands to the Fail2ban server. Returns one result per command: (ok, value). A command the
    server rejects comes back as (False, message); not reaching the server at all raises F2BError."""
    changes = any(not c or str(c[0]) not in _READ_ONLY for c in cmds)
    if changes:
        forget()   # this changes Fail2ban: don't reuse answers from before it
    try:
        return [_result(item) for item in _run(_QUERY, [SOCKET, json.dumps(list(cmds))], "Asking Fail2ban")]
    finally:
        if changes:
            forget()


def one(*cmd):
    ok, value = query(list(cmd))[0]
    if not ok:
        raise F2BError(value)
    return value


def client(*args):
    """Run fail2ban-client in the container (used for reload). Returns (ok, output)."""
    forget()
    try:
        code, out, err = _exec(["fail2ban-client", *args], "fail2ban-client")
    finally:
        forget()
    text = "\n".join(l for l in (out + "\n" + err).splitlines() if l.strip())
    # its log lines carry a timestamp and the logger name: keep just the message
    text = re.sub(r"^\d{4}-\d\d-\d\d [\d:,]+ fail2ban\S*\s+\[\d+\]:\s+", "", text, flags=re.M)
    return code == 0, text.strip()


def restart_container():
    forget()
    try:
        _api().restart(CONTAINER, timeout=15)
    except F2BError:
        raise
    except Exception as e:
        raise F2BError(docker_hint(e))
    finally:
        forget()


# ---------- higher-level helpers ----------
def _pairs(value):
    """Fail2ban's status answers: [['Number of jail', 1], ['Jail list', 'a, b']] -> dict"""
    out = {}
    for item in value or []:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            out[str(item[0])] = item[1]
    return out


def _jail_list(ok, status):
    if not ok:
        return []
    lst = _pairs(status).get("Jail list", "")
    return [j.strip() for j in str(lst).split(",") if j.strip()]


def overview():
    """Server version and the jails. Reused for a few seconds. Raises F2BError."""
    hit = _cached("overview", _OVERVIEW_TTL)
    if hit is not None:
        return {"version": hit["version"], "jails": list(hit["jails"])}
    (ok1, version), (ok2, status) = query(["version"], ["status"])
    ov = {"version": version if ok1 else "", "jails": _jail_list(ok2, status)}
    _cache["overview"] = (time.monotonic(), ov)
    return {"version": ov["version"], "jails": list(ov["jails"])}


def _status(ok, value):
    """One jail's `status` answer -> {...} (or {'error'})."""
    if not ok:
        return {"error": value}
    p = _pairs(value)
    f, a = _pairs(p.get("Filter")), _pairs(p.get("Actions"))
    files = f.get("File list") or f.get("Journal matches") or []
    return {"failed_now": f.get("Currently failed", 0), "failed_total": f.get("Total failed", 0),
            "files": files if isinstance(files, list) else [files],
            "banned_now": a.get("Currently banned", 0), "banned_total": a.get("Total banned", 0),
            "banned": list(a.get("Banned IP list") or [])}


def jail_status(jails):
    """{jail: {...}} for the given jails, one round trip."""
    if not jails:
        return {}
    return {j: _status(ok, value) for j, (ok, value) in zip(jails, query(*[["status", j] for j in jails]))}


def snapshot(settings_for=None):
    """Everything about the jails in one round trip:
    {'version', 'jails', 'status': {jail: {...}}, 'bantime': {jail: seconds|None},
     'banned': {jail: [{'ip', 'start', 'bantime', 'end'}] or {'error': message}}, 'settings': {...} or None}
    `settings_for`: also that jail's settings (as jail_settings returns them). Raises F2BError."""
    data = _run(_SNAPSHOT, [SOCKET, json.dumps({"settings_for": settings_for, "keys": list(JAIL_SETTINGS)})],
                "Asking Fail2ban")
    try:
        tz = timezone(timedelta(seconds=int(data.get("tz") or 0)))
    except (TypeError, ValueError):
        tz = timezone.utc
    _offset_cache.update(at=time.time(), tz=tz)
    ok1, version = _result(data.get("version"))
    ok2, status = _result(data.get("status"))   # an error here means no jails, as overview() treats it
    jails, per = [], data.get("jails") or {}
    out = {"version": version if ok1 else "", "jails": jails, "status": {}, "bantime": {}, "banned": {},
           "settings": None}
    for j in _jail_list(ok2, status):    # Fail2ban's own order
        st_item, bt_item, ban_item = (per.get(j) or [None, None, None])[:3]
        jails.append(j)
        out["status"][j] = _status(*_result(st_item))
        ok, bt = _result(bt_item)
        out["bantime"][j] = bt if ok else None
        ok, lines = _result(ban_item)
        out["banned"][j] = _banned(lines, lambda: tz) if ok else {"error": lines}
    if settings_for in jails and data.get("settings"):
        out["settings"] = {k: (v if ok else None)
                           for k, (ok, v) in zip(JAIL_SETTINGS, (_result(i) for i in data["settings"]))}
    _cache["overview"] = (time.monotonic(), {"version": out["version"], "jails": list(jails)})
    return out


_BAN_LINE = re.compile(r"^(\S+)\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) \+ (-?\d+) = (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)")


_offset_cache = {"at": 0.0, "tz": None}


def container_tz():
    """The Fail2ban container's UTC offset as a tzinfo (its ban times are printed in its own local time, which
    may differ from this app's TZ). Cached for 10 minutes; UTC if it can't be read."""
    import time as _t
    if _offset_cache["tz"] is not None and _t.time() - _offset_cache["at"] < 600:
        return _offset_cache["tz"]
    tz = timezone.utc
    try:
        code, out, _ = _exec(["python3", "-c", "import time;print(time.localtime().tm_gmtoff)"], "Reading the time zone")
        if code == 0:
            tz = timezone(timedelta(seconds=int(out.strip())))
    except (F2BError, ValueError):
        pass
    _offset_cache.update(at=_t.time(), tz=tz)
    return tz


def _banned(lines, get_tz):
    """`get <jail> banip --with-time` lines -> [{'ip', 'start', 'bantime', 'end'}] with time-zone-aware times
    (end None for a permanent ban). get_tz is only called when a line has times."""
    out = []
    tz = None
    for line in lines or []:
        m = _BAN_LINE.match(str(line).strip())
        if not m:
            out.append({"ip": str(line).split()[0] if str(line).split() else str(line),
                        "start": None, "bantime": None, "end": None})
            continue
        tz = tz or get_tz()
        bt = int(m.group(3))
        start = datetime.strptime(m.group(2), "%Y-%m-%d %H:%M:%S").replace(tzinfo=tz)
        end = None if bt < 0 else datetime.strptime(m.group(4), "%Y-%m-%d %H:%M:%S").replace(tzinfo=tz)
        out.append({"ip": m.group(1), "start": start, "bantime": bt, "end": end})
    return out


def banned_with_time(jail):
    """[{'ip', 'start', 'bantime', 'end'}] with time-zone-aware times (end None for a permanent ban)."""
    return _banned(one("get", jail, "banip", "--with-time"), container_tz)


JAIL_SETTINGS = ("maxretry", "findtime", "bantime", "logpath", "actions", "ignoreip", "ignoreself",
                 "bantime.increment", "usedns", "logencoding", "datepattern", "maxlines")


def jail_settings(jail):
    res = query(*[["get", jail, k] for k in JAIL_SETTINGS])
    return {k: (v if ok else None) for k, (ok, v) in zip(JAIL_SETTINGS, res)}


def ban(jail, ips):
    return one("set", jail, "banip", *ips)


def unban(jail, ips):
    return one("set", jail, "unbanip", *ips)


def unban_everywhere(ips):
    return one("unban", *ips)


def jails_banning(ips):
    """{ip: [jails]} for IPs banned right now."""
    value = one("banned", *ips)
    out = {}
    for ip, jl in zip(ips, value or []):
        out[ip] = list(jl or [])
    return out


def visible(path):
    """Whether a file exists inside the Fail2ban container (new filters/actions in the crazymax image only
    become visible there after a restart)."""
    try:
        code, _, _ = _exec(["python3", "-c", "import os,sys;sys.exit(0 if os.path.exists(sys.argv[1]) else 1)",
                            path], "Checking a file")
        return code == 0
    except F2BError:
        return None
