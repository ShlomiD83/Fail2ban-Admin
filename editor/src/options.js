// Fail2ban options with short descriptions, for autocomplete and hover docs.
// Grouped by where they are used: jail files (jail.d, jail.local), filters (filter.d), actions (action.d)
// and the server settings (fail2ban.local). Values: suggestions for the value side.

const TIME = "A time: seconds, or with units, e.g. 600, 10m, 1h, 1d, 1w; -1 means forever.";

export const JAIL = {
  enabled: { doc: "Whether the jail runs. Jails are off unless enabled = true.", values: ["true", "false"] },
  filter: { doc: "The filter (from filter.d) that finds failures in the logs. Can take arguments: name[mode=aggressive].", values: "filters" },
  action: { doc: "What to do on a ban: one or more actions from action.d, one per line, with optional arguments: name[arg=value]. Shortcuts: %(action_)s ban only, %(action_mw)s ban and mail, %(action_mwl)s ban, mail with log lines.", values: "actions" },
  banaction: { doc: "The default ban action used by %(action_)s and friends (e.g. iptables-multiport, nftables-multiport).", values: "actions" },
  banaction_allports: { doc: "The ban action used for all-ports bans.", values: "actions" },
  logpath: { doc: "Log file(s) to watch. Globs are allowed; one path per line. Paths are as seen inside the Fail2ban container." },
  backend: { doc: "How logs are watched: auto, pyinotify, polling, or systemd (journal; then use journalmatch instead of logpath).", values: ["auto", "pyinotify", "polling", "systemd"] },
  maxretry: { doc: "Failures from one address within findtime that trigger a ban." },
  findtime: { doc: "The window in which maxretry failures cause a ban. " + TIME },
  bantime: { doc: "How long a ban lasts. " + TIME },
  "bantime.increment": { doc: "Ban repeat offenders for longer each time (uses bantime.factor / bantime.formula / bantime.multipliers).", values: ["true", "false"] },
  "bantime.factor": { doc: "Growth factor for incremental ban times (default 1)." },
  "bantime.formula": { doc: "Python formula for incremental ban times." },
  "bantime.multipliers": { doc: "Ban time multipliers for repeat bans, e.g. 1 2 4 8 16 32 64." },
  "bantime.maxtime": { doc: "Upper limit for incremental ban times. " + TIME },
  "bantime.rndtime": { doc: "Random extra seconds added to ban times (makes botnets guess less)." },
  "bantime.overalljails": { doc: "Count previous bans of the address in all jails, not just this one.", values: ["true", "false"] },
  ignoreip: { doc: "Addresses never banned: IPs, CIDR networks or DNS names, separated by spaces (or one per line)." },
  ignoreself: { doc: "Never ban this host's own addresses.", values: ["true", "false"] },
  ignorecommand: { doc: "Command that decides whether to ignore an address (exit code 0 = ignore). Tag: <ip>." },
  ignorecache: { doc: "Cache for ignorecommand results, e.g. key=\"<ip>\", max-count=100, max-time=5m." },
  port: { doc: "Port(s) to block, e.g. ssh, http,https or 80,443 or 0:65535." },
  protocol: { doc: "Protocol for the ban action.", values: ["tcp", "udp", "icmp", "all"] },
  chain: { doc: "iptables chain the ban rules go into. For Docker containers use DOCKER-USER; INPUT for the host itself.", values: ["INPUT", "DOCKER-USER", "FORWARD"] },
  usedns: { doc: "Whether host names in logs are resolved: yes, warn, no, raw.", values: ["warn", "yes", "no", "raw"] },
  logencoding: { doc: "Encoding of the log files (auto uses the system locale).", values: ["auto", "utf-8", "ascii", "latin-1"] },
  journalmatch: { doc: "systemd journal filter for backend = systemd, e.g. _SYSTEMD_UNIT=sshd.service + _COMM=sshd." },
  datepattern: { doc: "How to find the time in a log line (overrides the filter's). Special values: {^LN-BEG}, EPOCH, ISO8601." },
  maxmatches: { doc: "How many matching log lines are kept per ticket (shown in mails as <matches>)." },
  maxlines: { doc: "Lines to buffer for multi-line regexes." },
  destemail: { doc: "Recipient of ban mails (for the mail actions)." },
  sender: { doc: "Sender address of ban mails." },
  sendername: { doc: "Sender name of ban mails." },
  mta: { doc: "Mail program for the mail actions.", values: ["sendmail", "mail"] },
  mode: { doc: "Filter mode (for filters that support it, like sshd): normal, ddos, extra, aggressive.", values: ["normal", "ddos", "extra", "aggressive"] },
  skip_if_nologs: { doc: "Skip the jail instead of failing when none of its log files exist.", values: ["true", "false"] },
  before: { doc: "[INCLUDES]: files read before this one." },
  after: { doc: "[INCLUDES]: files read after this one." },
};

export const FILTER = {
  failregex: { doc: "Regular expressions (one per line) that match a failure. Must contain <HOST> (or <ADDR>, <F-ID>…) for the address to ban. Continuation lines are indented." },
  ignoreregex: { doc: "Regular expressions for lines to ignore even if failregex matches." },
  prefregex: { doc: "Common prefix every line must match first; failregex then matches the part captured as <F-CONTENT>." },
  datepattern: { doc: "How to find the time in a log line. Special values: {^LN-BEG} (date at line start), EPOCH, ISO8601, {NONE}." },
  journalmatch: { doc: "systemd journal filter used when the jail's backend is systemd." },
  maxlines: { doc: "Lines to buffer for multi-line regexes." },
  mode: { doc: "Default mode for filters that have several (normal, ddos, aggressive…)." },
  _daemon: { doc: "Process name used by the common.conf prefix (__prefix_line)." },
  before: { doc: "[INCLUDES]: files read before this one, e.g. common.conf." },
  after: { doc: "[INCLUDES]: files read after this one." },
};

export const ACTION = {
  actionstart: { doc: "Command run once when the jail starts (e.g. create the firewall chain)." },
  actionstop: { doc: "Command run when the jail stops (e.g. remove the chain)." },
  actioncheck: { doc: "Command run before each ban to check the setup is intact." },
  actionban: { doc: "Command run on a ban. Tags: <ip>, <name> (jail), <failures>, <bantime>, <matches>, <time>, <F-*> groups." },
  actionunban: { doc: "Command run when a ban ends or the address is unbanned." },
  actionflush: { doc: "Command that removes all bans at once (used on stop/reload instead of unbanning one by one)." },
  actionrepair: { doc: "Command run when actioncheck fails." },
  actionstart_on_demand: { doc: "Run actionstart only before the first ban.", values: ["true", "false"] },
  norestored: { doc: "Don't run actionban for bans restored from the database at start (useful for reporting actions like AbuseIPDB).", values: ["1", "0", "true", "false"] },
  timeout: { doc: "Seconds a command may run before it is killed (default 60)." },
  name: { doc: "[Init]: the jail name, available as <name>." },
  before: { doc: "[INCLUDES]: files read before this one." },
  after: { doc: "[INCLUDES]: files read after this one." },
};

export const MAIN = {
  loglevel: { doc: "Server log level.", values: ["CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG"] },
  logtarget: { doc: "Where the server logs: a file, STDOUT, STDERR, SYSLOG or SYSOUT." },
  socket: { doc: "The server's control socket." },
  pidfile: { doc: "The server's PID file." },
  dbfile: { doc: "The database that keeps bans across restarts (:memory: or None to disable)." },
  dbpurgeage: { doc: "How long ban history is kept in the database. " + TIME },
  dbmaxmatches: { doc: "Matching log lines stored per ticket in the database." },
  allowipv6: { doc: "IPv6 support.", values: ["auto", "yes", "no"] },
  ...JAIL,
};

export const SECTIONS = {
  jail: ["DEFAULT", "INCLUDES"],
  filter: ["INCLUDES", "Definition", "Init"],
  action: ["INCLUDES", "Definition", "Init"],
  main: ["DEFAULT", "INCLUDES", "Definition", "Thread"],
};

export function optionsFor(kind, section) {
  if (kind === "filter") return section === "INCLUDES" ? { before: FILTER.before, after: FILTER.after } : FILTER;
  if (kind === "action") return section === "INCLUDES" ? { before: ACTION.before, after: ACTION.after } : ACTION;
  if (kind === "main") return MAIN;
  return section === "INCLUDES" ? { before: JAIL.before, after: JAIL.after } : JAIL;
}
