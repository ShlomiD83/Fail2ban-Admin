# Changelog

All notable changes to Fail2ban Admin. Images are tagged by build date and time (`YYYY.MM.DD-HHmm`), so
entries are headed by build date rather than by version.

## Unreleased

### Changed
- Dependabot updates are no longer merged or published automatically. Each pull request still gets a test
  build and smoke test, then a comment that mentions the repository owner (so GitHub notifies you) with the
  result; you review and merge it yourself (workflow renamed to dependabot-check.yml).

## 2026.11.25-1756

### Changed
- When the session ends after inactivity you land on the sign-in page with no message (the admin log still
  records it). The one-minute countdown before that is an amber heads-up instead of a red error.

### Fixed
- Phones: the status strip (Fail2ban, Config, Public IP) is centred, so the wrapped Public IP line lines up.
- The log excerpt in Recent activity and the ban history is cut at a word, marked with …, instead of
  mid-word (for example "sword mismatch").

### Added
- Screenshots in docs/screenshots, linked from the README (from a demo setup with documentation IP addresses).

## 2026.11.25-1432

### Changed
- Dashboard: the ban/unban box is its own slim card directly above Banned now, the same width, instead of
  sitting inside the Banned now card.

## 2026.11.25-1420

### Changed
- The "Ban even if it's my own address" and "Ban even if it's on the jail's ignore list" checkboxes are gone.
  A ban that hits one of those cases now opens a short "Ban anyway?" page explaining why, with Ban anyway
  and Cancel; other bans go through as before.

### Fixed
- Passkey sign-in works again after a failed attempt without reloading the page. A locked password
  manager (for example Bitwarden) could leave the first request hanging, which blocked every retry; each
  attempt now cancels the one before it, and the message suggests unlocking the password manager.

## 2026.11.25-1038

### Added
- Phones: a search button next to Reload and Restart opens the IP lookup field under the top bar, for the
  country, AbuseIPDB score and reports of any IP (desktop already has the field in the bar).

## 2026.11.25-0705

### Changed
- Top offenders lists each IP with its ban count, without the bar under it.

## 2026.11.25-0658

### Fixed
- Dashboard, Banned now: the country and AbuseIPDB score sit beside the IP instead of under it, the Why column
  is gone, and the table fits the card at every window width instead of scrolling sideways (the row buttons
  stack when the card is narrow). On phones each ban reads IP, then jail · since · expires, then the buttons,
  with nothing cut off or overlapping.
- The dashboard ban box keeps the address field, jail, Ban and Unban on one line in a narrower card.
- Top offenders: the bar under each IP (its ban count compared with the top offender) is a thin grey line
  instead of a thick crimson one.

## 2026.11.25-0622

### Added
- The sign-in pages have a Theme switch (Auto, Light, Dark) under the sign-in card, in place of the small
  corner button. Auto follows your device's setting again after you had picked one.

## 2026.11.25-0617

### Fixed
- The user menu's "Admin log" item, now called "Admin actions", opens the Activity page at the top of the admin
  actions card instead of partway down the list, with the heading and filter box in view below the top bar.

## 2026.11.25-0608

### Changed
- New colour scheme, "Charcoal and crimson", in light and dark: neutral greys, a near-black top bar and one
  crimson accent, replacing the teal "Harbor" theme. The README logos and social preview match.
- New icon and banner: a red BAN stamp on a log page, replacing the shield (apple-touch icon, README logos,
  social preview). The browser tab, top bar and sign-in pages use the stamp alone, on a transparent background.
- A jail's "Never ban" list folds like the log list: more than 3 entries show as "11 addresses", opening
  into a short scrolling list with a filter box when there are more than 10.
- The ban forms no longer show "Your address": behind the Docker network it showed the gateway, not you.

## 2026.11.25-0525

### Changed
- Phones: the six tabs fit across the screen as icons with a short name (Home, Bans, Config, Activity,
  Backups, Security) instead of a row that scrolled sideways and hid the current tab.
- A jail watching more than 3 logs shows one line, "25 files in /log/", that opens into a short scrolling
  list (in number order, with a filter box when there are more than 10) instead of every path on the page.
- The jail page drops the "Failing now" tile.

### Fixed
- Phones: page buttons sit in a row under the page title; ban, unban and lookup fields take the full width
  with their buttons sharing the row below (the lookup and new-file name fields were squeezed to a sliver).
- A jail's ban form lists both "Ban even if…" checkboxes under the Ban button.
- Dark mode: buttons that are links ("Open in editor" on a backup, "AbuseIPDB ↗", "Edit jail.d/…") had
  link-coloured text; "Open in editor" was barely readable on its teal background.

## 2026.11.24-2154

### Fixed
- The "Fail2ban is restarting" card counts the seconds live instead of staying at 0 s.

## 2026.11.24-2141

### Added
- While Fail2ban restarts, the dashboard and the jail pages show a "Fail2ban is restarting" card instead of a
  blank page, and refresh themselves; Reload and Restart show a "working" message as soon as they are clicked.
- The socket proxy in `docker-compose.yml` has a health check (healthy/unhealthy in Portainer and `docker ps`).

### Fixed
- Opening a jail's page during a reload no longer sends you back to the list with "no running jail".
- The editor no longer warns about Python actions (`action = smtp.py[...]`): they are known by their `.py` name,
  as Fail2ban refers to them, and autocomplete offers them that way.

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
