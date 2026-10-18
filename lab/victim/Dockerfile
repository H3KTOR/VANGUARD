# lab/victim/Dockerfile
#
# Builds the real ~25MB VANGUARD Go binary (stage 1) and drops it into a
# minimal Debian runtime pre-configured with a real OpenSSH server and a
# real Nginx web server (stage 2), so every attack the lab fires produces
# genuine log traffic VANGUARD's log tailers parse exactly as they would
# on a real production host. Docker itself is used ONLY here, inside
# lab/ -- never in VANGUARD's own production deployment path, per the
# project's hard "zero external services in production" constraint.

# ---------------------------------------------------------------------------
# Stage 1: build the VANGUARD binary from the real source tree.
# ---------------------------------------------------------------------------
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY core/go.mod core/go.sum ./
RUN go mod download
COPY core/ ./
# The React dashboard's dist/ output is already checked into
# cmd/vanguard/dist (see frontend.go's go:embed all:dist), so no Node.js
# build step is needed here -- just compile the Go binary.
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/vanguard ./cmd/vanguard

# ---------------------------------------------------------------------------
# Stage 2: runtime image -- a realistic "victim" Linux host.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        nginx \
        rsyslog \
        curl \
    && rm -rf /var/lib/apt/lists/*

# --- SSH server: a deliberately weak account for the brute-force /
# attack-chain scenarios to target. This is an isolated, throwaway lab
# container with no real data -- never reachable from outside the lab's
# private Docker network. ---
RUN useradd -m -s /bin/bash testuser \
    && echo "testuser:password123" | chpasswd \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && ssh-keygen -A

# --- rsyslog: modern Debian/rsyslog defaults auth.log to the ISO8601
# "RSYSLOG_FileFormat" template (e.g. "2026-09-07T07:49:44+00:00 victim
# sshd[96]: ..."), NOT the traditional syslog timestamp
# ("Aug 23 14:02:11 ...") that a real production Linux host's auth.log
# has used for decades and that VANGUARD's AuthLogParser (see
# internal/detection/parser_auth.go) is written against. Force the
# traditional format here so this lab's auth.log is byte-for-byte
# representative of what VANGUARD parses in production -- this is a
# rsyslog *packaging default* quirk of the lab's base image, not a
# VANGUARD parser bug. ---
RUN printf '$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat\n' > /etc/rsyslog.d/00-traditional-format.conf

# --- Nginx: a couple of "sensitive" paths so the web-probing /
# path-traversal / SQLi scenarios have something realistic to request.
# The stock Debian nginx access-log format is Nginx's default "combined"
# format, which VANGUARD's WebLogParser already parses. ---
RUN mkdir -p /var/www/html/wp-admin /var/www/html/uploads /var/www/html/wp-content/uploads \
    && echo "<html><body>VANGUARD Lab Victim</body></html>" > /var/www/html/index.html \
    && echo "<?php /* not a real web shell -- static fixture file for the Web Shell Indicator lab scenario, VANGUARD only inspects the REQUEST PATH, never file contents */ ?>" > /var/www/html/uploads/shell.php

# --- Nginx log_format: append the Host header as VANGUARD's WebLogParser
# already optionally understands (see parser_web.go's trailing-quoted-
# field support) -- the stock "combined" format never logs Host at all,
# so without this override the Host Header / Virtual Host Abuse scenario
# (feature 10) would have nothing to detect. This is a realistic,
# common operator customization, not a VANGUARD-specific hack. ---
COPY lab/victim/nginx-vhost-log.conf /etc/nginx/conf.d/00-vhost-log-format.conf

COPY lab/victim/entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh

COPY --from=build /out/vanguard /usr/local/bin/vanguard

RUN mkdir -p /data

EXPOSE 22 80 8080 2222 21 23 3389 5432 6379 33060 8081

ENTRYPOINT ["/entrypoint.sh"]
