#!/usr/bin/env bash
# deploy/release.sh - build release artifacts locally. Nothing is uploaded; nothing
# is signed unless you pass --sign-key.
#
#   deploy/release.sh [--version v1.2.3] [--out dist] [--targets "linux/amd64 linux/arm64"]
#                     [--sign-key FILE] [--check-repro] [--allow-old-toolchain]
#
# Produces, per target, a pure-Go binary (CGO_ENABLED=0, -trimpath), plus
#   <binary>.cdx.json      CycloneDX SBOM, ONLY if `cyclonedx-gomod` is on PATH
#                          (or $CYCLONEDX_GOMOD); structurally validated
#   RELEASE-MANIFEST.json  every artifact: os, arch, size, SHA-256, SBOM, build metadata
#   SHA256SUMS             checksums of everything shipped (verify: sha256sum -c SHA256SUMS)
#   SHA256SUMS.sig         detached ed25519 signature of SHA256SUMS, ONLY with --sign-key
#   BUILD-MANIFEST.txt     toolchain, commit, dirty flag, `go version -m` per binary
#
# Honest limits (see docs/PHASE17.md):
#  * a checksum detects corruption; it does not identify the publisher
#  * a signature identifies the holder of a PRIVATE key; its worth depends on how
#    users obtain the PUBLIC key. No key is generated or trusted by this script
#  * the SBOM lists Go modules known to the build, not the host, not npm packages
#  * "reproducible" is claimed only for what docs/PHASE17.md says was compared
#  * the dashboard must already be built (make build-frontend)
#  * the build refuses a Go toolchain older than deploy/MIN_GO_TOOLCHAIN (it has
#    known standard-library vulnerabilities) unless --allow-old-toolchain, which
#    is then recorded in the manifest
set -euo pipefail
umask 022

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
VERSION=""
OUT="$ROOT/dist"
TARGETS="linux/amd64 linux/arm64"
CHECK_REPRO=0
SIGN_KEY=""
ALLOW_OLD=0

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    --targets) TARGETS="${2:-}"; shift 2 ;;
    --sign-key) SIGN_KEY="${2:-}"; shift 2 ;;
    --check-repro) CHECK_REPRO=1; shift ;;
    --allow-old-toolchain) ALLOW_OLD=1; shift ;;
    -h|--help) sed -n '2,29p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

command -v go >/dev/null || { echo "go not found in PATH" >&2; exit 1; }
[ -f "$ROOT/core/cmd/vanguard/dist/index.html" ] || { echo "the dashboard is not built: run 'make build-frontend' first" >&2; exit 1; }
if [ -e "$ROOT/core/cmd/vanguard/dist/.gitkeep" ]; then
  echo "core/cmd/vanguard/dist/.gitkeep exists: it would be compiled into the binary (go:embed all:dist), making the artifact depend on a placeholder file. Run 'make build-frontend' (Vite empties the directory) and release from that state." >&2
  exit 1
fi
if [ -n "$SIGN_KEY" ]; then
  [ -f "$SIGN_KEY" ] || { echo "signing key not found: $SIGN_KEY" >&2; exit 1; }
  case "$SIGN_KEY" in "$ROOT"/*) echo "refusing to use a signing key inside the repository ($SIGN_KEY)" >&2; exit 1 ;; esac
fi

# --- toolchain gate -----------------------------------------------------------
MIN_GO="$(tr -d ' \r\n' < "$HERE/MIN_GO_TOOLCHAIN")"
HAVE_GO="$(go env GOVERSION | sed 's/^go//')"
ver_lt() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" != "$2" ]; } # $1 < $2
BELOW=0
if ver_lt "$HAVE_GO" "$MIN_GO"; then
  if [ "$ALLOW_OLD" = 1 ]; then
    BELOW=1; echo "WARNING: building with Go $HAVE_GO, older than the required $MIN_GO (recorded in the manifest)" >&2
  else
    echo "refusing to build releases with Go $HAVE_GO: deploy/MIN_GO_TOOLCHAIN requires $MIN_GO (older toolchains ship known standard-library vulnerabilities). Use a newer Go, or --allow-old-toolchain." >&2
    exit 1
  fi
fi

COMMIT="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
DIRTY="$(git -C "$ROOT" status --porcelain -- . ':!core/cmd/vanguard/dist/.gitkeep' 2>/dev/null | head -c1)"
[ -n "$DIRTY" ] && DIRTY=yes || DIRTY=no
[ -n "$VERSION" ] || VERSION="$(git -C "$ROOT" describe --tags --always 2>/dev/null || echo dev)"
# A fixed, commit-derived timestamp keeps the binary independent of build time.
EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || echo 0)}"
BUILD_DATE="$(date -u -d "@$EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"
CDX="${CYCLONEDX_GOMOD:-$(command -v cyclonedx-gomod || true)}"

relsign() { ( cd "$ROOT/core" && go run ./tools/relsign "$@" ); }

build_all() { # build_all outdir
  local dir="$1"; mkdir -p "$dir"
  for t in $TARGETS; do
    local os="${t%/*}" arch="${t#*/}"
    local name="vanguard-${VERSION}-${os}-${arch}"
    ( cd "$ROOT/core" && CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false \
        -ldflags "-s -w -X main.version=${VERSION} -X main.buildDate=${BUILD_DATE}" \
        -o "$dir/$name" ./cmd/vanguard )
  done
}

echo "building ${VERSION} (commit ${COMMIT}, dirty=${DIRTY}) with Go ${HAVE_GO} for: ${TARGETS}"
mkdir -p "$(dirname "$OUT")"
if [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then echo "output directory $OUT is not empty; refusing to mix releases (choose another --out or empty it yourself)" >&2; exit 1; fi
TMP="$(mktemp -d "${OUT}.build.XXXXXX")"
trap 'rm -rf "$TMP" "${TMP2:-}"' EXIT
build_all "$TMP"

if [ "$CHECK_REPRO" = 1 ]; then
  TMP2="$(mktemp -d "${OUT}.rebuild.XXXXXX")"
  build_all "$TMP2"
  if [ "$( cd "$TMP" && sha256sum vanguard-* )" = "$( cd "$TMP2" && sha256sum vanguard-* )" ]; then
    echo "same-machine rebuild produced identical SHA-256 values (this is NOT a cross-machine reproducibility claim)"
  else
    echo "WARNING: two builds on this machine produced different binaries" >&2; exit 1
  fi
fi

# --- SBOM (only when a real tool is present) ------------------------------------
if [ -n "$CDX" ]; then
  for t in $TARGETS; do
    os="${t%/*}"; arch="${t#*/}"
    ( cd "$ROOT/core" && GOOS="$os" GOARCH="$arch" "$CDX" app -json -main cmd/vanguard -std=false \
        -output "$TMP/vanguard-${VERSION}-${os}-${arch}.cdx.json" )
    relsign validate-sbom -in "$TMP/vanguard-${VERSION}-${os}-${arch}.cdx.json"
  done
  echo "SBOMs generated with $("$CDX" version 2>/dev/null | head -n1)"
else
  echo "NOTE: cyclonedx-gomod not found: NO SBOM generated (the manifest says so)"
fi

mkdir -p "$OUT"
cp -f "$TMP"/* "$OUT"/
cp -f "$HERE/vanguard.service" "$HERE/vanguard-monitor-only.conf" "$HERE/vanguard.env.example" "$HERE/install.sh" "$HERE/upgrade.sh" "$OUT"/

# --- manifest ---------------------------------------------------------------------
KEYID=""
[ -z "$SIGN_KEY" ] || KEYID="$(relsign pubkey -private "$SIGN_KEY")"
args=(manifest -dir "$OUT" -version "$VERSION" -commit "$COMMIT" -dirty "$DIRTY" -go "$(go version)" -build-date "$BUILD_DATE")
[ -z "$KEYID" ] || args+=(-sign-key-id "$KEYID")
[ "$BELOW" = 0 ] || args+=(-toolchain-below-min)
relsign "${args[@]}"

{
  echo "VANGUARD build manifest"
  echo "version:    $VERSION"
  echo "commit:     $COMMIT"
  echo "dirty tree: $DIRTY"
  echo "build date: $BUILD_DATE (derived from the commit time, not the wall clock)"
  echo "go:         $(go version)"
  echo "flags:      CGO_ENABLED=0 -trimpath -buildvcs=false -ldflags '-s -w -X main.version=... -X main.buildDate=...'"
  echo "signed:     $([ -n "$KEYID" ] && echo "yes, key id $KEYID (SHA256SUMS.sig)" || echo NO)"
  echo "sbom:       $([ -n "$CDX" ] && echo "CycloneDX, per binary (Go modules only)" || echo NO)"
  echo
  for f in "$OUT"/vanguard-"${VERSION}"-*; do
    case "$f" in *.cdx.json) continue ;; esac
    echo "---- $(basename "$f")"
    go version -m "$f" 2>&1 || true
  done
} > "$OUT/BUILD-MANIFEST.txt"

( cd "$OUT" && sha256sum "vanguard-${VERSION}"-* RELEASE-MANIFEST.json BUILD-MANIFEST.txt vanguard.service vanguard-monitor-only.conf vanguard.env.example install.sh upgrade.sh > SHA256SUMS )

if [ -n "$SIGN_KEY" ]; then
  relsign sign -private "$SIGN_KEY" -in "$OUT/SHA256SUMS" -out "$OUT/SHA256SUMS.sig"
  echo "signed SHA256SUMS with key id $KEYID. Publish the PUBLIC key through a channel users already trust."
fi

relsign manifest-check -dir "$OUT"
echo "artifacts in $OUT:"; ls -1 "$OUT"
echo "verify checksums:  (cd $OUT && sha256sum -c SHA256SUMS)"
[ -z "$SIGN_KEY" ] || echo "verify signature:  go run ./core/tools/relsign verify -public <publisher-key.pub> -in $OUT/SHA256SUMS -sig $OUT/SHA256SUMS.sig"
