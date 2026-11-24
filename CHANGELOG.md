# Changelog

All notable changes to Fail2ban Admin. Images are tagged by build date and time (`YYYY.MM.DD-HHmm`), so
entries are headed by build date rather than by version.

## Unreleased

### Changed
- The panel runs as a normal user: `PUID` / `PGID` in `.env` set the user and group (root when unset). It only
  needs write access to Fail2ban's jail.d, filter.d and action.d folders; the README explains how to check them,
  and a "Permission denied" message now points there.
- `docker-compose.yml` pulls the published image (`romekd/fail2ban-admin`, or the GHCR one) instead of building it;
  the README says where the images are and how to build your own.

## 2026.11.24-1959

First published image (amd64 and arm64, Docker Hub and GHCR).

### Added
- First version, with a top-bar layout: section tabs, IP lookup, reload, restart and the user menu in the bar, and a status strip (Fail2ban running and up to date, configuration check, public IP) on every page.
- Dashboard: a "needs attention" bar (configuration changed since the last reload, a failing configuration
  check, a jail without log files); Banned now with the ban box, when each ban expires and why; bans over time
  (24 hours, 7 days, 30 days); jails with banned and failing counts, last ban, log files and ban time; top
  offenders; recent activity; configuration and backups. Cards fill two columns by height, so there are no gaps.
- Activity: the ban history filters by text, jail, time range and "banned now", shows why each IP was banned,
  and sums up what's shown.
- Country next to every IP from an offline database (DB-IP IP to Country Lite, bundled and refreshed at every build).
- AbuseIPDB score next to every public IP and in full on the lookup page (reports, ISP, usage, domain, last
  report), using the key from the abuseipdb action or ABUSEIPDB_API_KEY; cached for 24 hours, capped per day.
- Status strip: Fail2ban running, its version and whether it's the newest release (checked on GitHub every 6 hours).
- AbuseIPDB: an "AbuseIPDB ↗" button on every banned IP and history row, on the IP lookup page, and next to
  the lookup box on Jails & Bans, opening that IP's public report in a new tab.
- Jails and bans: ban one or many IPs or networks in a jail, unban in one jail or all of them, look up an IP
  (where it's banned, why, ignoreip matches, ban history with the log lines that triggered it), per-jail page
  with the settings in force, banned IPs with time left, unban all.
- Reload all jails or a single jail without restarting, and restart the Fail2ban container, with a live status
  until Fail2ban answers again.
- Configuration editor for jail, filter and action files (CodeMirror): Fail2ban INI highlighting, autocomplete
  and hover docs for options, filter and action names, live problem markers, blurred secrets (API keys and
  tokens, also inside action arguments), unsaved edits kept in the browser, conflict detection, diff.
- Validation with Fail2ban's own configuration reader before every save, plus compilation of every regular
  expression and time value (which `fail2ban-client -t` skips); a save can reload Fail2ban right away.
- Filter tester: run `fail2ban-regex` with the edited filter against pasted lines or a mounted log file.
- Backups of every file before each save, delete, restore and import; view, diff, restore or open a backup in
  the editor; export and import the whole configuration as a zip.
- Admin login with password (argon2id hash supported), TOTP and passkeys; CSRF protection, login rate limit,
  sign-out after inactivity, admin action log.
- Manual bans of an address or network that overlaps the jail's `ignoreip` are refused unless confirmed
  (Fail2ban itself applies `ignoreip` only to automatic bans); confirmed ones are noted in the admin log.
- Docker access through a socket proxy (wollomatic/socket-proxy) in the compose file, allowing only exec,
  inspect and restart of the Fail2ban container named in `.env`; all Docker calls address that container by
  name so the rules can pin it. The smoke test runs through the proxy and checks that other requests are refused.
