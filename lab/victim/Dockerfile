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
FROM golang:1.25-bookworm AS build
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

# --- Nginx: a couple of "sensitive" paths so the web-probing /
# path-traversal / SQLi scenarios have something realistic to request.
# The stock Debian nginx access-log format is Nginx's default "combined"
# format, which VANGUARD's WebLogParser already parses. ---
RUN mkdir -p /var/www/html/wp-admin \
    && echo "<html><body>VANGUARD Lab Victim</body></html>" > /var/www/html/index.html

COPY lab/victim/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

COPY --from=build /out/vanguard /usr/local/bin/vanguard

RUN mkdir -p /data

EXPOSE 22 80 8080 2222 21 23 3389 5432 6379 33060 8081

ENTRYPOINT ["/entrypoint.sh"]
