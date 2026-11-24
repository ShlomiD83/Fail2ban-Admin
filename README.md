<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/ShlomiD83/fail2ban-admin/main/docs/logo-dark.svg">
    <img src="https://raw.githubusercontent.com/ShlomiD83/fail2ban-admin/main/docs/logo-light.svg" alt="Fail2ban Admin" width="380">
  </picture>
</p>

A small, self-hosted web panel for [Fail2ban](https://github.com/fail2ban/fail2ban) running in Docker: edit jails,
filters and actions with validation and backups, ban and unban IPs, reload or restart Fail2ban, and see the ban
history, from your browser (phone included).

It talks to your Fail2ban container through the Docker API, the same way `docker exec <container> fail2ban-client …`
does, so it works with the common images (built and tested with [crazymax/fail2ban](https://github.com/crazy-max/docker-fail2ban)).
Runs as a single container on a distroless runtime image, for **amd64 and arm64**.

## Features

**Dashboard**
- Fail2ban up or down, version and uptime; jails with banned-now, total bans and failing addresses
- The server's **public IP** (with a warning if it's banned) and your own address
- Configuration check result, bans in the last 24 hours, recent admin actions and backups
- **Reload** and **Restart** buttons

**Jails and bans**
- **Ban** one or many IPs or CIDR networks in a jail; **unban** from one jail or all jails
- Guard against banning your own address by accident
- Bans and unbans run the jail's actions (firewall, Cloudflare, mail, AbuseIPDB…), exactly like `fail2ban-client set <jail> banip/unbanip`
- **Look up an IP**: where it's banned now, whether a jail's `ignoreip` covers it, its ban history with the log lines that triggered each ban
- Per-jail page: the settings in force (maxretry, findtime, bantime, actions, logs, ignoreip), banned IPs with time left, unban all, ban history
- **Reload** all jails or a single jail without restarting (bans are kept); **restart** the Fail2ban container with a live status until it answers again

**Configuration editor** (jail.d, filter.d, action.d and top-level files)
- CodeMirror editor with Fail2ban INI highlighting (sections, options, `<HOST>` tags, `%(interpolation)s`), Python for `.py` actions
- Autocomplete and hover docs for options; completion of filter and action names (stock and your own)
- Live problem markers: lines Fail2ban can't parse, duplicate options or sections, unknown filters or actions, regexes without `<HOST>`
- **Validated before every save** with Fail2ban's own configuration reader (the bundled stock config with your folder laid over it), plus every `failregex`/`ignoreregex`/`datepattern` and time value compiled the way the server does it, which `fail2ban-client -t` doesn't check. Problems are marked on their lines
- Optional **reload after save**; a notice when the configuration changed after Fail2ban last loaded it
- **Filter tester**: run `fail2ban-regex` with the edited (unsaved) filter against pasted lines or a mounted log file
- API keys and tokens blurred on screen, including inside action arguments like `abuseipdb[abuseipdb_apikey="…"]`
- Unsaved edits kept in the browser, "Leave site?" prompt, show changes (diff), and a conflict warning when the file was changed elsewhere (e.g. over SSH) while you edited
- New files from templates; delete with a check that no jail still needs the file

**Backups**
- Automatic timestamped backup before every save, delete, restore and import (the newest 30 per file)
- View a backup with the changes a restore would make; restore it, or open it in the editor
- **Export and import** the whole configuration (plus admin passkeys and log) as one zip

**IP details**
- Country next to every IP, from an offline database bundled in the image (DB-IP IP to Country Lite): no lookups, no quota
- AbuseIPDB abuse score (0–100%, coloured) next to every public IP, with reports, ISP and usage type on hover and in full on the lookup page; uses the API key already in your abuseipdb action, caches results for 24 hours and stays under the free daily limit. Private and LAN addresses are never sent
- "AbuseIPDB ↗" buttons that open an IP's public report

**Security**
- Admin login with password (argon2id hash supported), **TOTP** and **passkeys** (WebAuthn)
- CSRF protection, login rate limit, strict cookies and CSP, sign-out after inactivity
- Admin action log of every ban, unban, reload, restart, file change and sign-in

## Requirements

- Fail2ban running in a Docker container whose image has Python and `fail2ban-client` (crazymax/fail2ban, linuxserver/fail2ban, …)
- The Fail2ban configuration folder mounted into this container (for crazymax/fail2ban: the folder mounted as `/data`)
- Docker access for this container, through the included socket proxy (see [Docker access](#docker-access))
- HTTPS in front of the UI if you want passkeys

## Quick start

1. Clone the repository and copy `.env.example` to `.env`. Set:
   - `FAIL2BAN_CONTAINER`: your Fail2ban container's name (`docker ps`)
   - `FAIL2BAN_DATA`: its configuration folder on the host
   - `DOCKER_GID`: the Docker socket's group id (`getent group docker | cut -d: -f3`)
2. In `docker-compose.yml` set `ADMIN_USER`, the password and `SECRET_KEY` (`openssl rand -hex 32`)
3. `docker compose up -d --build`
4. Open `http://127.0.0.1:8081` (or your reverse proxy address) and sign in

## Docker access

The panel needs the Docker API for three things: running `fail2ban-client` and Fail2ban's socket protocol in the
Fail2ban container (`exec`), reading that container's state, and restarting it. Reload in particular must run
inside the Fail2ban container, because the client reads the configuration and finds the log files on its side.

The included compose file doesn't give the panel the Docker socket. A
[wollomatic/socket-proxy](https://github.com/wollomatic/socket-proxy) container holds it (read-only, non-root,
no capabilities, on an internal network that only the panel can reach) and lets through exactly these requests,
and only for the container named in `FAIL2BAN_CONTAINER`:

| Method | Path | Used for |
|---|---|---|
| GET | `/version` | API version negotiation |
| GET | `/containers/<name>/json` | is Fail2ban running, since when |
| POST | `/containers/<name>/exec`, `/exec/<id>/start`; GET `/exec/<id>/json` | status, ban, unban, reload |
| POST | `/containers/<name>/restart` | Restart button |

Everything else is refused with 403: listing or creating containers, any other container, images, volumes,
networks. The smoke test checks both sides: every feature works through the proxy, and those other requests
are refused.

Mounting `/var/run/docker.sock` into the panel directly (and leaving out `DOCKER_HOST`) also works, but then
the panel can do anything Docker can, which amounts to root on the host. Use the proxy.

## How it works

| What | How |
|---|---|
| Status, bans, unbans, lookups | A small Python snippet run in the Fail2ban container with `docker exec`, speaking Fail2ban's socket protocol (structured answers, no text parsing) |
| Reload | `fail2ban-client reload [jail]` in the Fail2ban container (bans are kept) |
| Restart | `docker restart` of the Fail2ban container through the Docker API and the socket proxy (no host service needed) |
| Validation and filter tests | Fail2ban's own Python package and stock configuration, bundled in this image from the latest Fail2ban release |
| Ban history | Fail2ban's SQLite database (`<config folder>/db/fail2ban.sqlite3`), read-only |

New filter and action files: the crazymax image links them into `/etc/fail2ban` when the container starts, so a
**new** filter or action needs a container restart before Fail2ban can use it (the editor tells you). Changes to
existing files and new jail files only need a reload.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `ADMIN_USER` | `admin` | Admin user name. |
| `ADMIN_PASSWORD` | – | Admin password in plain text. |
| `ADMIN_PASSWORD_HASH` | – | Admin password as an argon2id hash (takes precedence). In compose YAML write every `$` as `$$`. |
| `ADMIN_PASSWORD_HASH_FILE` | – | File containing the hash (no `$` escaping needed). |
| `ADMIN_TOTP_SECRET` | – | Base32 TOTP secret: password sign-in then asks for a 6-digit code. Generate it on the Security page. |
| `ADMIN_RP_ID` / `ADMIN_ORIGIN` | – | Passkeys: your domain and its https origin. |
| `ADMIN_PASSKEY_ONLY` | `false` | Turn password sign-in off while a trusted passkey exists. |
| `ADMIN_IDLE_TIMEOUT` | `30` | Minutes without activity before signing out; `0` turns it off. |
| `SECRET_KEY` | random per start | Signs the session cookie and the stored passkeys. **Set it.** |
| `COOKIE_SECURE` | `false` | `true` when served over HTTPS. |
| `TRUST_PROXY` | `0` | Number of reverse proxies in front, to use the real client address. Only when the proxy is the only way in. |
| `TZ` | `UTC` | Time zone for times and backup names. |
| `FAIL2BAN_CONTAINER` | `fail2ban` | Name of the Fail2ban container. Set in `.env`, so the proxy rules use the same name. |
| `DOCKER_HOST` | – | The socket proxy, `tcp://socket-proxy:2375` in the compose file. Without it, the panel uses `/var/run/docker.sock` if it's mounted. |
| `FAIL2BAN_SOCKET` | `/var/run/fail2ban/fail2ban.sock` | Fail2ban's socket inside its container. |
| `FAIL2BAN_CONFIG_DIR` | `/data` | Where the configuration folder is mounted in this container. |
| `FAIL2BAN_DB_FILE` | `<config dir>/db/fail2ban.sqlite3` | Fail2ban's database, for the ban history. |
| `FAIL2BAN_ETC` | `/etc/fail2ban` | Fail2ban's configuration folder inside its container. |
| `ADMIN_DATA_DIR` | `/admin` | This app's own files: backups, admin log, passkeys, settings. |
| `MAX_BACKUPS` | `30` | Backups kept per file. |
| `ACTIVITY_DAYS` | `30` | How far back the Activity page goes. |
| `LOG_DIRS` | `/log /var/log` | Where to look for log files for the filter tester. |
| `PUBLIC_IP_URL` | `https://api.ipify.org` | Service that returns the server's public IP for the dashboard; `off` turns it off. |
| `UPDATE_CHECK` | `on` | Ask GitHub for Fail2ban's newest release (every 6 hours) to show whether the running one is up to date; `off` turns it off. |
| `ABUSEIPDB_LOOKUP` | `on` | Show each IP's AbuseIPDB abuse score; `off` turns it off. |
| `ABUSEIPDB_API_KEY` | – | AbuseIPDB API key. If unset, the `abuseipdb_apikey` from your Fail2ban configuration (the abuseipdb action) is used. |
| `ABUSEIPDB_CACHE_HOURS` | `24` | How long a score is kept before it's checked again. |
| `ABUSEIPDB_DAILY_LIMIT` | `900` | Most checks per day (the free plan allows 1,000; the jail's own reports don't count against it). |
| `GEOIP_DB` | bundled | Country database (MaxMind format). The image includes DB-IP's free IP to Country Lite, refreshed at every build. |

## Security notes

- **Use the socket proxy** (see [Docker access](#docker-access)): the Docker socket itself is root on the host.
- Even through the proxy, `exec` into the Fail2ban container is powerful: that container runs as root with
  `NET_ADMIN` on the host network, and Fail2ban's own actions run shell commands. Keep the UI behind HTTPS and a
  strong login (TOTP or passkeys), and don't expose it to the internet directly.
- The Tecnativa docker-socket-proxy isn't a good fit: allowing `exec` there means allowing every POST, including
  creating containers. wollomatic/socket-proxy filters each request path by regex instead.
- Action files often hold API keys. They're blurred on screen; exports and backups contain them in clear text.
- Running as root (`user: "0:0"`) is the simple choice because Fail2ban's files belong to root. Files keep their
  owner and permissions when saved.

## Development

```bash
docker build -t fail2ban-admin:test .
bash tests/smoke-test.sh fail2ban-admin:test           # through the socket proxy, with crazymax/fail2ban next to it
bash tests/smoke-test.sh fail2ban-admin:test socket    # with the Docker socket mounted directly
```

## License

MIT

IP country data: [IP Geolocation by DB-IP](https://db-ip.com), CC BY 4.0.
