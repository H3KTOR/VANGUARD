#!/bin/bash
# entrypoint.sh brings up every service the "victim" host needs, in the
# correct dependency order, then hands off to VANGUARD itself:
#
#   1. rsyslogd  -- sshd only writes auth events via syslog(3); without a
#      syslog daemon running, /var/log/auth.log would never be created and
#      VANGUARD's auth-log tailer would have nothing to tail. This mirrors
#      exactly how a real bare-metal/VM Linux host is provisioned.
#   2. sshd      -- real OpenSSH server (password auth enabled for a
#      deliberately weak test account), so a genuine `hydra` SSH
#      brute-force against it produces real, unmodified auth.log lines --
#      not synthetic test fixtures.
#   3. nginx     -- real web server with its stock "combined" access-log
#      format (nginx's built-in default), so `curl`/`nmap` traffic against
#      it produces real access.log lines VANGUARD's WebLogParser already
#      knows how to read.
#   4. vanguard  -- the actual ~25MB Go binary under test, tailing both
#      real log files and listening on its honeypot decoy ports, exactly
#      as it would in production. This is the ONLY long-running foreground
#      process; the container's lifecycle is tied to it.
set -euo pipefail

echo "[victim] starting rsyslogd..."
# `service rsyslog start` requires a sysvinit/systemd service manager that
# isn't present in this minimal container -- start the daemon directly
# instead (the standard pattern for running sysvinit-style daemons in
# Docker). -n keeps it attached to a pid we can wait on if ever needed;
# here we just background it, mirroring how a real init system would.
mkdir -p /var/spool/rsyslog
rsyslogd
# Give rsyslogd a brief moment to create /var/log/auth.log before sshd's
# first syslog(3) write, so VANGUARD's tailer never races an ENOENT.
for i in $(seq 1 20); do
    [ -f /var/log/auth.log ] && break
    sleep 0.2
done
touch /var/log/auth.log

echo "[victim] starting sshd..."
mkdir -p /run/sshd
/usr/sbin/sshd

echo "[victim] starting nginx..."
nginx

# --- Phase 4 (System Posture & Drift) lab fixtures. Everything lives under
# /etc/vanguard-lab and /var/lib/vanguard-lab INSIDE this throwaway
# container: a posture/drift config pair for the scenarios to mutate, and
# a COPY of the real dpkg status database (so Package Drift scenarios edit
# metadata fixtures instead of installing real packages -- fast,
# deterministic, and the base image is never damaged). Created only if
# absent so a `docker restart` keeps the scenarios' state. ---
mkdir -p /etc/vanguard-lab /var/lib/vanguard-lab
[ -f /etc/vanguard-lab/posture.conf ] || { echo "lab posture fixture" > /etc/vanguard-lab/posture.conf; chmod 644 /etc/vanguard-lab/posture.conf; }
[ -f /etc/vanguard-lab/drift.conf ] || { echo "lab drift fixture" > /etc/vanguard-lab/drift.conf; chmod 644 /etc/vanguard-lab/drift.conf; }
[ -f /var/lib/vanguard-lab/dpkg-status ] || cp /var/lib/dpkg/status /var/lib/vanguard-lab/dpkg-status

echo "[victim] starting VANGUARD Core..."
exec /usr/local/bin/vanguard serve \
    -db=/data/vanguard.db \
    -http-addr=:8080 \
    -auth-log=/var/log/auth.log \
    -web-log=/var/log/nginx/access.log \
    -honeypot=true \
    -state-max-idle=10m \
    -reap-interval=30s \
    -posture-interval=3s \
    -posture-paths=/etc/vanguard-lab/posture.conf \
    -drift-paths=/etc/vanguard-lab/drift.conf \
    -listening-grace=10s \
    -dpkg-status=/var/lib/vanguard-lab/dpkg-status
