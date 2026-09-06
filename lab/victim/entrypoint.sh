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

echo "[victim] starting VANGUARD Core..."
exec /usr/local/bin/vanguard serve \
    -db=/data/vanguard.db \
    -http-addr=:8080 \
    -auth-log=/var/log/auth.log \
    -web-log=/var/log/nginx/access.log \
    -honeypot=true \
    -state-max-idle=10m \
    -reap-interval=30s
