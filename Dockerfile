# ---------------------------------------------------------------------------
# Stage 1: Fail2ban's Python package and stock configuration, from the LATEST release tag.
# Only used to check configurations and test filters (fail2ban-regex) inside this image; bans, unbans and
# reloads run in your Fail2ban container. Pure Python, so it's copied as source (no pip, no setup.py).
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/wolfi-base:latest AS fail2ban-src
RUN apk add --no-cache git
# Changing this value (CI passes the date) forces a fresh clone, so scheduled builds pick up new releases.
ARG BUILD_STAMP=manual
RUN set -eux; \
    echo "Build stamp: ${BUILD_STAMP}"; \
    TAG="$(git ls-remote --tags --refs --sort=-v:refname https://github.com/fail2ban/fail2ban \
           | awk -F/ '{print $3}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | head -n1)"; \
    echo "Fail2ban ${TAG}"; \
    git clone --depth 1 --branch "${TAG}" https://github.com/fail2ban/fail2ban /src; \
    mkdir -p /out; \
    cp -r /src/fail2ban /out/fail2ban; \
    rm -rf /out/fail2ban/tests; \
    cp -r /src/config /out/config; \
    echo "${TAG}" > /out/VERSION

# ---------------------------------------------------------------------------
# Stage 1b: the free DB-IP "IP to Country Lite" database (CC BY 4.0, https://db-ip.com), so the panel can show
# each IP's country without asking any online service. This month's edition, or last month's early in a month.
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/wolfi-base:latest AS geoip
RUN apk add --no-cache curl gzip
ARG BUILD_STAMP=manual
RUN set -eux; \
    echo "Build stamp: ${BUILD_STAMP}"; \
    mkdir -p /out; \
    for m in "$(date -u +%Y-%m)" "$(date -u -d "$(date -u +%Y-%m-15) -1 month" +%Y-%m)"; do \
      if curl -fsSL --retry 3 -o /tmp/db.mmdb.gz "https://download.db-ip.com/free/dbip-country-lite-${m}.mmdb.gz"; then \
        gunzip -c /tmp/db.mmdb.gz > /out/dbip-country-lite.mmdb; echo "DB-IP country lite ${m}" > /out/GEOIP_VERSION; break; \
      fi; \
    done; \
    test -s /out/dbip-country-lite.mmdb

# ---------------------------------------------------------------------------
# Stage 2: Python dependencies into a plain directory (no venv, no pip in the final image).
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/python:latest-dev AS pybuild
USER root
RUN apk add --no-cache build-base libffi-dev
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --target /deps -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 3: the configuration editor (CodeMirror) as one static JS file. Node is only used here.
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/node:latest-dev AS editor-build
USER root
WORKDIR /editor
COPY editor/package.json editor/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY editor/src ./src
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 4: runtime. Distroless Wolfi Python: no shell, no package manager, no pip.
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/python:latest

ENV PYTHONPATH=/deps \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FAIL2BAN_CONFIG_DIR=/data \
    FAIL2BAN_BASE_CONFIG=/opt/fail2ban/config \
    ADMIN_DATA_DIR=/admin \
    GEOIP_DB=/opt/geoip/dbip-country-lite.mmdb

COPY --from=pybuild /deps /deps
COPY --from=fail2ban-src /out/fail2ban /deps/fail2ban
COPY --from=fail2ban-src /out/config /opt/fail2ban/config
COPY --from=fail2ban-src /out/VERSION /opt/fail2ban/VERSION
COPY --from=geoip /out/ /opt/geoip/
COPY --chmod=755 app/ /srv/app/
COPY --chmod=644 --from=editor-build /editor/dist/editor.js /srv/app/static/editor.js

# Smoke tests (exec form, no shell needed): fail the build if a piece is broken.
RUN ["/usr/bin/python", "-c", "import flask, argon2, docker, gunicorn, webauthn, segno, zoneinfo, maxminddb; print(maxminddb.open_database('/opt/geoip/dbip-country-lite.mmdb').get('8.8.8.8')['country']['iso_code']); zoneinfo.ZoneInfo('Asia/Jerusalem'); from fail2ban.client.configurator import Configurator; from fail2ban.client import fail2banregex; from fail2ban.server.failregex import FailRegex; print('deps OK')"]
RUN ["/usr/bin/python", "/srv/app/f2b_validate.py", "/opt/fail2ban/config"]

WORKDIR /srv/app
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/usr/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"]

# Usually run as root (user: "0:0" in compose): Fail2ban's files belong to root, and the Docker socket is
# needed for ban, unban, reload and restart.
ENTRYPOINT ["/usr/bin/python", "-m", "gunicorn", "-b", "0.0.0.0:8080", "-w", "1", "--threads", "4", "--timeout", "150", "--worker-tmp-dir", "/dev/shm", "--no-control-socket", "app:app"]
