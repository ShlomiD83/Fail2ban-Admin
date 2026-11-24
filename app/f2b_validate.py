"""Check a Fail2ban configuration folder with Fail2ban's own configuration reader.

    python f2b_validate.py <config dir>            -> JSON on stdout

Run as a separate process by the admin app (a broken config can't hang or crash the web app, and the
reader's global state starts fresh every time). It does what `fail2ban-client -t` does, plus two things
that command skips:
  * every failregex / ignoreregex / prefregex / datepattern is compiled the way the server would, so a
    broken regular expression is reported before the server rejects the jail at reload;
  * log files that don't exist here are a warning, not an error: the logs usually live in the Fail2ban
    container, not in this one.

Output: {"ok": bool, "errors": [msg...], "warnings": [msg...], "jails": [name...]}
Messages keep Fail2ban's wording, including "'<file>' [line  N]" references, so the editor can mark lines.
"""
import json
import logging
import sys


TIME_OPTS = {"bantime", "findtime", "bantime.maxtime", "bantime.rndtime"}
INT_OPTS = {"maxretry", "maxmatches", "maxlines"}


class Collect(logging.Handler):
    def __init__(self):
        super().__init__(logging.NOTSET)
        self.errors, self.warnings = [], []

    def emit(self, record):
        msg = record.getMessage().strip()
        if not msg:
            return
        if record.levelno >= logging.ERROR:
            self.errors.append(msg)
        elif record.levelno >= logging.WARNING or record.levelname == "NOTICE":
            self.warnings.append(msg)


def main(base):
    out = {"ok": False, "errors": [], "warnings": [], "jails": []}
    h = Collect()
    log = logging.getLogger("fail2ban")
    log.handlers[:] = [h]
    log.setLevel(25)   # Fail2ban's NOTICE level: warnings such as "No file(s) found for glob"
    log.propagate = False

    try:
        from fail2ban.client.configurator import Configurator
        from fail2ban.server.failregex import FailRegex, Regex, RegexException
        from fail2ban.server.datetemplate import DatePatternRegex
        from fail2ban.server.mytime import MyTime
    except Exception as e:   # pragma: no cover - image problem
        out["errors"].append(f"Fail2ban's Python package isn't available in this image: {e}")
        return out

    stream = []
    try:
        c = Configurator()
        c.setBaseDir(base)
        c.readAll()
        if not c.getOptions(None, ignoreWrong=False):
            if not h.errors:
                h.errors.append("The configuration has errors (no details from Fail2ban).")
        c.convertToProtocol(allow_no_files=True)
        stream = c.getConfigStream()
    except Exception as e:
        h.errors.append(str(e))

    # what the server would do with the stream: compile regexes, start jails
    prefregex = {}
    for cmd in stream:
        if not cmd:
            continue
        if cmd[0] == "config-error":
            h.errors.append(str(cmd[1]))
            continue
        if cmd[0] == "add" and len(cmd) > 1:
            out["jails"].append(cmd[1])
            continue
        if cmd[0] != "multi-set" and cmd[0] != "set" or len(cmd) < 4:
            continue
        jail, opt = cmd[1], cmd[2]
        values = cmd[3] if cmd[0] == "multi-set" else [cmd[3]]
        if not isinstance(values, (list, tuple)):
            values = [values]
        try:
            if opt == "prefregex":
                prefregex[jail] = Regex(values[0]) if values and values[0] else None
            elif opt == "addfailregex":
                for v in values:
                    FailRegex(v, prefRegex=prefregex.get(jail))
            elif opt == "addignoreregex":
                for v in values:
                    Regex(v)
            elif opt in TIME_OPTS:
                for v in values:
                    try:
                        bad = str(v).strip() and MyTime.str2seconds(str(v)) is None
                    except Exception:
                        bad = True
                    if bad:
                        raise ValueError(f"{v!r} is not a time (for example 600, 10m, 1h, 2d 3h, or -1 for permanent)")
            elif opt in INT_OPTS:
                for v in values:
                    if str(v) != "None":   # already reported by the reader as "Wrong value for ..."
                        int(str(v).strip())
            elif opt == "datepattern":
                for v in values:
                    if v and v.upper() not in ("EPOCH", "LEPOCH", "TAI64N", "ISO8601", "{NONE}", "{^LN-BEG}"):
                        DatePatternRegex(v)
        except RegexException as e:
            h.errors.append(f"Jail '{jail}': invalid {opt.replace('add', '')}: {e}")
        except Exception as e:
            h.errors.append(f"Jail '{jail}': invalid {opt}: {e}")

    # A wrong number makes Fail2ban quietly use its default instead: treat it as an error.
    for w in list(h.warnings):
        if w.startswith("Wrong value for"):
            h.warnings.remove(w)
            h.errors.append(w.replace(". Using default one: 'None'", "").rstrip(".") + ".")
    # de-duplicate, keep order
    out["errors"] = list(dict.fromkeys(h.errors))
    out["warnings"] = [w for w in dict.fromkeys(h.warnings) if w not in out["errors"]]
    out["ok"] = not out["errors"]
    return out


if __name__ == "__main__":
    print(json.dumps(main(sys.argv[1])))
