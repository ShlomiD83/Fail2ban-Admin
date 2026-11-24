#!/usr/bin/env bash
# Smoke test for a Fail2ban Admin image: starts a real Fail2ban container (crazymax/fail2ban) with the sample
# configuration in tests/fixtures, starts the admin image next to it, signs in, opens every page and tries the
# main actions (ban, unban, check, save + reload, filter test, delete protection, backups, restart).
# Exits non-zero if anything fails, so CI publishes only images that pass (see .github/workflows/docker.yml).
#
#   tests/smoke-test.sh <image> [proxy|socket]     e.g. tests/smoke-test.sh fail2ban-admin:test
#
# proxy (default): Docker access through wollomatic/socket-proxy with the allow rules from docker-compose.yml,
# and a check that anything else (listing containers, touching another container) is refused.
# socket: the Docker socket mounted directly.
#
# Needs docker, curl and openssl. Works on Linux and in Git Bash on Windows (Docker Desktop).
set -uo pipefail
docker() { MSYS_NO_PATHCONV=1 command docker "$@"; }   # Git Bash: keep container paths as they are
export -f docker 2>/dev/null || true

IMAGE="${1:?usage: tests/smoke-test.sh <image> [socket|proxy]}"
MODE="${2:-proxy}"           # proxy: through wollomatic/socket-proxy (the recommended setup); socket: direct
F2B_IMAGE="${F2B_IMAGE:-crazymax/fail2ban:latest}"
PROXY_IMAGE="${PROXY_IMAGE:-wollomatic/socket-proxy:1}"
PORT="${PORT:-18099}"
F2B="f2b-smoke-$$"
NAME="fa-smoke-$$"
PROXY="fa-proxy-$$"
NET="fa-net-$$"
HERE="$(cd "$(dirname "$0")" && pwd)"
DATA="$(mktemp -d)"          # Fail2ban's /data
LOGS="$(mktemp -d)"          # /log in both containers
ADMIN="$(mktemp -d)"         # the admin app's own folder
WORK="$(mktemp -d)"          # cookie jar and responses (not mounted)
B="http://127.0.0.1:${PORT}"
JAR="$WORK/cookies"
FAILED=0
PASSED=0

cp -r "$HERE"/fixtures/data/. "$DATA"/
cp -r "$HERE"/fixtures/log/. "$LOGS"/
chmod -R a+rwX "$DATA" "$LOGS" "$ADMIN"
ADMIN_PW="smoke-$(openssl rand -hex 8)"
# throwaway TOTP secret for this run only: 24 base32 characters (A-P from random hex, then fixed letters)
TOTP_SECRET="$(openssl rand -hex 8 | tr '0-9a-f' 'A-P')QRSTUVWX"
TOTP_SECRET="$(openssl rand -hex 10 | tr "0-9a-f" "A-P" | head -c 16)QRSTUVWX"   # throwaway base32 test secret

cleanup() {
  if [ "$FAILED" -gt 0 ]; then
    echo "---- admin container log (last 40 lines) ----"; docker logs "$NAME" 2>&1 | tail -40
    echo "---- fail2ban container log (last 20 lines) ----"; docker logs "$F2B" 2>&1 | tail -20
  fi
  if [ "$FAILED" -gt 0 ] && [ "$MODE" = proxy ]; then
    echo "---- proxy log (last 15 lines) ----"; docker logs "$PROXY" 2>&1 | tail -15
  fi
  docker rm -f "$NAME" "$F2B" "$PROXY" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
  # files the containers created belong to root: remove them from a container
  docker run --rm -v "$(winpath "$DATA"):/a" -v "$(winpath "$ADMIN"):/b" alpine:3 sh -c "rm -rf /a/* /b/*" >/dev/null 2>&1
  rm -rf "$DATA" "$LOGS" "$ADMIN" "$WORK" 2>/dev/null
}
trap cleanup EXIT

ok()   { PASSED=$((PASSED + 1)); echo "  ok    $1"; }
fail() { FAILED=$((FAILED + 1)); echo "  FAIL  $1"; }
check() { local name="$1"; shift; if "$@"; then ok "$name"; else fail "$name"; fi; }
winpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else echo "$1"; fi; }
f2b() { docker exec "$F2B" fail2ban-client "$@" 2>/dev/null; }

echo "Starting $F2B_IMAGE"
docker run -d --name "$F2B" --cap-add NET_ADMIN --cap-add NET_RAW -e TZ=Asia/Jerusalem \
  -v "$(winpath "$DATA"):/data" -v "$(winpath "$LOGS"):/log" "$F2B_IMAGE" >/dev/null || { echo "docker run (fail2ban) failed"; exit 1; }
up=0
for _ in $(seq 1 60); do
  if f2b ping | grep -q pong; then up=1; break; fi
  sleep 0.5
done
check "Fail2ban starts with the fixture configuration" [ "$up" = 1 ]
[ "$up" = 1 ] || exit 1

if [ "$MODE" = proxy ]; then
  # the same allow rules as in docker-compose.yml: only this one Fail2ban container, by name
  echo "Starting $PROXY_IMAGE (allowing only $F2B)"
  docker network create "$NET" >/dev/null
  docker run -d --name "$PROXY" --network "$NET" --user 0:0 --read-only --cap-drop ALL \
    -v /var/run/docker.sock:/var/run/docker.sock:ro "$PROXY_IMAGE" \
    -listenip=0.0.0.0 -allowfrom="$NAME" -loglevel=DEBUG \
    "-allowGET=/(v1\.[0-9]+/)?(version|containers/${F2B}/json|exec/[0-9a-f]+/json)" \
    "-allowPOST=/v1\.[0-9]+/(containers/${F2B}/(exec|restart)|exec/[0-9a-f]+/start)" >/dev/null \
    || { echo "docker run (proxy) failed"; exit 1; }
  DOCKER_ACCESS=(--network "$NET" -e DOCKER_HOST="tcp://$PROXY:2375")
else
  DOCKER_ACCESS=(-v /var/run/docker.sock:/var/run/docker.sock)
fi

echo "Starting $IMAGE ($MODE)"
docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:8080" --user 0:0 \
  -e ADMIN_USER=admin -e ADMIN_PASSWORD="$ADMIN_PW" -e ADMIN_TOTP_SECRET="$TOTP_SECRET" \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  -e TZ=Asia/Jerusalem -e FAIL2BAN_CONTAINER="$F2B" -e PUBLIC_IP_URL=off -e UPDATE_CHECK=off \
  "${DOCKER_ACCESS[@]}" \
  -v "$(winpath "$DATA"):/data" -v "$(winpath "$LOGS"):/log:ro" -v "$(winpath "$ADMIN"):/admin" \
  "$IMAGE" >/dev/null || { echo "docker run (admin) failed"; exit 1; }
up=0
for _ in $(seq 1 40); do
  if curl -fs "$B/healthz" >/dev/null 2>&1; then up=1; break; fi
  sleep 0.5
done
check "admin container starts and /healthz answers" [ "$up" = 1 ]
[ "$up" = 1 ] || exit 1

if [ "$MODE" = proxy ]; then
  echo "Proxy limits (from inside the admin container)"
  refused() {   # $1 = description, $2 = Python using the Docker client `c` (must raise a 403)
    docker exec "$NAME" /usr/bin/python -c "
import docker, sys
c = docker.from_env()
try:
    $2
except docker.errors.APIError as e:
    sys.exit(0 if e.status_code == 403 else 2)
sys.exit(1)" >/dev/null 2>&1
  }
  check "refused: listing containers" refused list "c.containers.list()"
  check "refused: creating a container" refused create "c.api.create_container('alpine:3', 'true')"
  check "refused: inspecting another container" refused inspect "c.api.inspect_container('$NAME')"
  check "refused: exec in another container" refused exec "c.api.exec_create('$NAME', ['true'])"
  check "refused: restarting another container" refused restart "c.api.restart('$PROXY')"
  check "refused: pulling an image" refused pull "c.api.pull('alpine', tag='3')"
fi

get()  { curl -s -L -b "$JAR" -c "$JAR" -o "$WORK/body" -w '%{url_effective} %{http_code}' "$B$1" > "$WORK/url"; }
post() { local path="$1"; shift; curl -s -L -b "$JAR" -c "$JAR" -o "$WORK/body" -w '%{url_effective} %{http_code}' "$@" "$B$path" > "$WORK/url"; }
csrf() { grep -o 'name="csrf" value="[^"]*"' "$WORK/body" | head -1 | sed 's/.*value="//; s/"$//'; }
base() { grep -o 'name="base" value="[^"]*"' "$WORK/body" | head -1 | sed 's/.*value="//; s/"$//'; }
body_has() { grep -q -- "$1" "$WORK/body"; }
status_is() { awk '{print $2}' "$WORK/url" | grep -qx -- "$1"; }
# the current TOTP code for TOTP_SECRET, computed like an authenticator app (RFC 6238, SHA-1, 6 digits, 30 s)
totp_now() {
  docker exec "$NAME" /usr/bin/python -c "import base64, hashlib, hmac, struct, time
k = base64.b32decode('$TOTP_SECRET')
h = hmac.new(k, struct.pack('>Q', int(time.time() // 30)), hashlib.sha1).digest()
o = h[-1] & 15
print('%06d' % ((struct.unpack('>I', h[o:o + 4])[0] & 0x7fffffff) % 1000000))"
}
totp_wrong() { local c; c="$(totp_now)"; printf '%06d' $(( (10#$c + 500000) % 1000000 )); }   # never the right one

echo "Sign-in"
get /jails
check "signed-out pages redirect to sign-in" body_has 'name="password"'
get /login; T="$(csrf)"
post /login --data-urlencode "csrf=$T" -d username=admin --data-urlencode "password=wrong-password"
check "wrong password is refused" body_has "Invalid credentials"
get /login; T="$(csrf)"
post /login --data-urlencode "csrf=$T" -d username=admin --data-urlencode "password=$ADMIN_PW"
check "TOTP: the right password alone leads to the code step" bash -c "grep -q 'Two-step check' '$WORK/body' && ! grep -q '<h1>Dashboard</h1>' '$WORK/body'"
T="$(csrf)"
post /login/totp --data-urlencode "csrf=$T" -d code="$(totp_wrong)"
check "TOTP: a wrong code is refused" body_has "didn&#39;t work"
CODE="$(totp_now)"
T="$(csrf)"
post /login/totp --data-urlencode "csrf=$T" -d code="$CODE"
check "TOTP: the right code signs in and lands on the dashboard" body_has "<h1>Dashboard</h1>"
# the same code once more, in a second browser session: it must not work twice
J2="$WORK/cookies2"
curl -s -b "$J2" -c "$J2" -o "$WORK/b2" "$B/login"
T2="$(grep -o 'name="csrf" value="[^"]*"' "$WORK/b2" | head -1 | sed 's/.*value="//; s/"$//')"
curl -s -L -b "$J2" -c "$J2" -o "$WORK/b2" --data-urlencode "csrf=$T2" -d username=admin --data-urlencode "password=$ADMIN_PW" "$B/login"
T2="$(grep -o 'name="csrf" value="[^"]*"' "$WORK/b2" | head -1 | sed 's/.*value="//; s/"$//')"
curl -s -L -b "$J2" -c "$J2" -o "$WORK/b2" --data-urlencode "csrf=$T2" -d code="$CODE" "$B/login/totp"
check "TOTP: a code that was already used is refused" bash -c "grep -q 'didn&#39;t work' '$WORK/b2' && ! grep -q '<h1>Dashboard</h1>' '$WORK/b2'"
post /reload -d csrf=wrong
check "a POST with a wrong CSRF token is refused" body_has "out of date"

echo "Pages"
for page in "/|Dashboard" "/jails|Ban IP addresses" "/jails/smoke|Settings in force" "/lookup?ip=203.0.113.9|Look up an IP" \
            "/files|New file" "/files/edit?path=jail.d/smoke.local|smoke.local" "/files/edit?path=filter.d/smoke.conf|Test this filter" \
            "/files/edit?path=action.d/new-one.conf|new file, not saved yet" "/activity|Admin actions" "/backups|Export and import" \
            "/security|Passkeys"; do
  path="${page%%|*}"; marker="${page#*|}"
  get "$path"
  check "$path opens" bash -c "awk '{print \$2}' '$WORK/url' | grep -qx 200 && grep -q -- '$marker' '$WORK/body'"
done
get /dashboard/status
check "dashboard status reports Fail2ban running with the jail" bash -c "grep -q '\"container\":\"running\"' '$WORK/body' && grep -q '\"name\":\"smoke\"' '$WORK/body' && grep -q '\"config_ok\":true' '$WORK/body'"
get "/ipinfo?ip=8.8.8.8&ip=192.168.1.10"
check "IP info: country from the bundled database, LAN address not sent anywhere" bash -c "grep -q '\"country_code\":\"US\"' '$WORK/body' && grep -q '\"private\":true' '$WORK/body'"

echo "Ban and unban"
get /jails; T="$(csrf)"
post /ban -d csrf="$T" -d jail=smoke --data-urlencode "ips=203.0.113.9 198.51.100.7"
check "ban: two addresses" bash -c "docker exec $F2B fail2ban-client get smoke banip | grep -q 203.0.113.9"
post /ban -d csrf="$T" -d jail=smoke --data-urlencode "ips=not-an-ip"
check "ban: an invalid address is refused" body_has "aren&#39;t IP addresses"
post /ban -d csrf="$T" -d jail=nosuchjail --data-urlencode "ips=192.0.2.1"
check "ban: an unknown jail is refused" body_has "no running jail"
banned() { docker exec "$F2B" fail2ban-client get smoke banip 2>/dev/null | grep -q -- "$1"; }
post /ban -d csrf="$T" -d jail=smoke --data-urlencode "ips=192.0.2.10"
check "ban: an address in ignoreip is refused" body_has "never-ban list"
check "ban: ...and Fail2ban didn't ban it" bash -c "! docker exec $F2B fail2ban-client get smoke banip | grep -q 192.0.2.10"
post /ban -d csrf="$T" -d jail=smoke --data-urlencode "ips=192.0.0.0/16"
check "ban: a network overlapping ignoreip is refused" body_has "never-ban list"
post /ban -d csrf="$T" -d jail=smoke -d confirm_ignored=on --data-urlencode "ips=192.0.2.10"
check "ban: an ignoreip address with confirmation" banned 192.0.2.10
get /activity
check "the confirmed ignoreip ban is in the admin log" body_has "confirmed despite ignoreip"
get /jails; T="$(csrf)"
post /unban -d csrf="$T" -d jail=smoke --data-urlencode "ips=192.0.2.10"
get "/lookup?ip=203.0.113.9"
check "lookup shows the ban" body_has 'banned</span> in'
get /jails; T="$(csrf)"
post /unban -d csrf="$T" -d jail=smoke --data-urlencode "ips=203.0.113.9"
check "unban in one jail" bash -c "! docker exec $F2B fail2ban-client get smoke banip | grep -q 203.0.113.9"
post /unban -d csrf="$T" -d "jail=*" --data-urlencode "ips=198.51.100.7"
check "unban in all jails" bash -c "! docker exec $F2B fail2ban-client get smoke banip | grep -q 198.51.100.7"

echo "Editor"
get "/files/edit?path=jail.d/smoke.local"; T="$(csrf)"; BASE="$(base)"
check "Python actions are known by their .py name (action = smtp.py[...])" bash -c "grep -q '\"smtp.py\"' '$WORK/body' && grep -q '\"iptables\"' '$WORK/body'"
BAD=$'[smoke]\nenabled = true\nfilter = no-such-filter\naction = dummy\nlogpath = /log/smoke.log\n'
post /files/edit -d csrf="$T" -d path=jail.d/smoke.local -d base="$BASE" -d action=save --data-urlencode "content=$BAD"
check "save with an unknown filter is refused" body_has "Not saved: Fail2ban"
check "the file on disk is unchanged" bash -c "grep -q 'filter = smoke' '$DATA/jail.d/smoke.local'"
BADRE=$'[Definition]\nfailregex = ^no host here\n'
get "/files/edit?path=filter.d/smoke.conf"; T="$(csrf)"; FB="$(base)"
post /files/edit -d csrf="$T" -d path=filter.d/smoke.conf -d base="$FB" -d action=validate --data-urlencode "content=$BADRE"
check "check finds a regex without <HOST>" body_has "No failure-id group"
get "/files/edit?path=jail.d/smoke.local"; T="$(csrf)"; BASE="$(base)"
GOOD=$'[smoke]\nenabled = true\nfilter = smoke\naction = dummy\nlogpath = /log/smoke.log\nmaxretry = 7\nbantime = 2h\n'
post /files/edit -d csrf="$T" -d path=jail.d/smoke.local -d base="$BASE" -d action=save -d apply=reload --data-urlencode "content=$GOOD"
check "a valid save reloads Fail2ban" body_has "Fail2ban reloaded it"
check "the new setting is live" bash -c "docker exec $F2B fail2ban-client get smoke maxretry | grep -qx 7"
check "a backup was made" bash -c "ls '$ADMIN/backups' | grep -q '^jail.d__smoke.local\.'"
post /files/edit -d csrf="$T" -d path=jail.d/smoke.local -d base="$BASE" -d action=save --data-urlencode "content=$GOOD# changed"
check "a stale save shows the conflict" body_has 'class="conflict"'
get /files; T="$(csrf)"
post /files/delete -d csrf="$T" -d path=filter.d/smoke.conf
check "deleting a filter a jail uses is refused" body_has "Not deleted"
curl -s -b "$JAR" -H "X-CSRF-Token: $T" -H "Content-Type: application/json" \
  -d '{"path":"filter.d/smoke.conf","content":"[Definition]\nfailregex = <HOST> login failed$\n","logfile":"/log/smoke.log"}' "$B/files/test" > "$WORK/test.json"
check "filter test against the log file" grep -q '"matched":3' "$WORK/test.json"
grep -q '"matched":3' "$WORK/test.json" || { head -c 800 "$WORK/test.json"; echo; }

echo "Reload, export, restart"
get /jails; T="$(csrf)"
post /reload -d csrf="$T" -d jail=smoke
check "reload one jail" body_has "reloaded jail smoke"
landed_on() { awk '{print $1}' "$WORK/url" | sed -E 's#^https?://[^/]+##' | grep -qxF -- "$1"; }
post /reload -d csrf="$T" --data-urlencode "back=/files/edit?path=jail.d/smoke.local"
check "reload from the editor returns to the same file" bash -c "awk '{print \$2}' '$WORK/url' | grep -qx 200 && awk '{print \$1}' '$WORK/url' | grep -Eq '/files/edit\?path=jail\.d(/|%2F)smoke\.local' && grep -q 'reloaded all jails' '$WORK/body'"
curl -s -b "$JAR" -o "$WORK/export.zip" "$B/backups/export"
check "export is a zip with the jail file" bash -c "head -c 2 '$WORK/export.zip' | grep -q PK && grep -aq 'fail2ban/jail.d/smoke.local' '$WORK/export.zip'"
post /restart -d csrf="$T" --data-urlencode "back=/files/edit?path=jail.d/smoke.local"
check "restart from the editor returns to the same file" bash -c "awk '{print \$2}' '$WORK/url' | grep -qx 200 && grep -q 'smoke.local' '$WORK/body' && awk '{print \$1}' '$WORK/url' | grep -q 'path=jail.d%2Fsmoke.local&restarting=1'"
up=0
for _ in $(seq 1 60); do
  sleep 1
  if curl -s -b "$JAR" "$B/fail2ban/status" | grep -q '"up":true'; then up=1; break; fi
done
check "restart: Fail2ban comes back" [ "$up" = 1 ]
get /activity
check "the admin log records the actions" bash -c "grep -q 'Banned' '$WORK/body' && grep -q 'File saved' '$WORK/body' && grep -q 'Restarted' '$WORK/body'"

echo
echo "$PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
