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


def container_info():
    """{'state': running|restarting|exited|..., 'started': datetime|None, 'image': str, 'health': str|None,
    'restarts': int} or {'error': message}."""
    try:
        attrs = inspect()
    except F2BError as e:
        return {"error": str(e)}
    st = attrs.get("State", {})
    started = None
    m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", st.get("StartedAt") or "")
    if m and not st.get("StartedAt", "").startswith("0001"):
        started = datetime.fromisoformat(m.group(1) + "+00:00")
    return {"state": st.get("Status", "unknown"), "started": started,
            "image": (attrs.get("Config") or {}).get("Image", ""),
            "health": (st.get("Health") or {}).get("Status"),
            "restarts": attrs.get("RestartCount", 0)}


def _exec(cmd, what):
    state = (inspect().get("State") or {}).get("Status")
    if state != "running":
        raise F2BError(f"The Fail2ban container '{CONTAINER}' isn't running ({state}).")
    api = _api()
    try:
        ex = api.exec_create(CONTAINER, cmd, stdout=True, stderr=True)
        out, err = api.exec_start(ex["Id"], demux=True)
        code = api.exec_inspect(ex["Id"]).get("ExitCode")
    except Exception as e:
        raise F2BError(f"{what} failed: {docker_hint(e)}")
    return code, (out or b"").decode("utf-8", "replace"), (err or b"").decode("utf-8", "replace")


def query(*cmds):
    """Send commands to the Fail2ban server. Returns one result per command: (ok, value). A command the
    server rejects comes back as (False, message); not reaching the server at all raises F2BError."""
    code, out, err = _exec(["python3", "-c", _QUERY, SOCKET, json.dumps(list(cmds))], "Asking Fail2ban")
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
        res = json.loads(out)
    except ValueError:
        raise F2BError("Fail2ban sent an answer that isn't JSON: " + out[:200])
    results = []
    for item in res:
        try:
            rc, value = item
        except (TypeError, ValueError):
            rc, value = 1, item
        if rc == 0:
            results.append((True, value))
        else:
            msg = value.get("__error__") if isinstance(value, dict) else str(value)
            results.append((False, msg))
    return results


def one(*cmd):
    ok, value = query(list(cmd))[0]
    if not ok:
        raise F2BError(value)
    return value


def client(*args):
    """Run fail2ban-client in the container (used for reload). Returns (ok, output)."""
    code, out, err = _exec(["fail2ban-client", *args], "fail2ban-client")
    text = "\n".join(l for l in (out + "\n" + err).splitlines() if l.strip())
    # its log lines carry a timestamp and the logger name: keep just the message
    text = re.sub(r"^\d{4}-\d\d-\d\d [\d:,]+ fail2ban\S*\s+\[\d+\]:\s+", "", text, flags=re.M)
    return code == 0, text.strip()


def restart_container():
    try:
        _api().restart(CONTAINER, timeout=15)
    except F2BError:
        raise
    except Exception as e:
        raise F2BError(docker_hint(e))


# ---------- higher-level helpers ----------
def _pairs(value):
    """Fail2ban's status answers: [['Number of jail', 1], ['Jail list', 'a, b']] -> dict"""
    out = {}
    for item in value or []:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            out[str(item[0])] = item[1]
    return out


def overview():
    """Server version and the jails. Raises F2BError."""
    (ok1, version), (ok2, status) = query(["version"], ["status"])
    jails = []
    if ok2:
        lst = _pairs(status).get("Jail list", "")
        jails = [j.strip() for j in str(lst).split(",") if j.strip()]
    return {"version": version if ok1 else "", "jails": jails}


def jail_status(jails):
    """{jail: {...}} for the given jails, one round trip."""
    if not jails:
        return {}
    res = query(*[["status", j] for j in jails])
    out = {}
    for j, (ok, value) in zip(jails, res):
        if not ok:
            out[j] = {"error": value}
            continue
        p = _pairs(value)
        f, a = _pairs(p.get("Filter")), _pairs(p.get("Actions"))
        files = f.get("File list") or f.get("Journal matches") or []
        out[j] = {"failed_now": f.get("Currently failed", 0), "failed_total": f.get("Total failed", 0),
                  "files": files if isinstance(files, list) else [files],
                  "banned_now": a.get("Currently banned", 0), "banned_total": a.get("Total banned", 0),
                  "banned": list(a.get("Banned IP list") or [])}
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


def banned_with_time(jail):
    """[{'ip', 'start', 'bantime', 'end'}] with time-zone-aware times (end None for a permanent ban)."""
    out = []
    tz = None
    for line in one("get", jail, "banip", "--with-time") or []:
        m = _BAN_LINE.match(str(line).strip())
        if not m:
            out.append({"ip": str(line).split()[0] if str(line).split() else str(line),
                        "start": None, "bantime": None, "end": None})
            continue
        tz = tz or container_tz()
        bt = int(m.group(3))
        start = datetime.strptime(m.group(2), "%Y-%m-%d %H:%M:%S").replace(tzinfo=tz)
        end = None if bt < 0 else datetime.strptime(m.group(4), "%Y-%m-%d %H:%M:%S").replace(tzinfo=tz)
        out.append({"ip": m.group(1), "start": start, "bantime": bt, "end": end})
    return out


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
