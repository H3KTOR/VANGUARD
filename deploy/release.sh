#!/usr/bin/env bash
# deploy/release.sh - build release artifacts locally. Nothing is uploaded and
# nothing is signed.
#
#   deploy/release.sh [--version v1.2.3] [--out dist] [--targets "linux/amd64 linux/arm64"]
#
# Produces, per target, a pure-Go binary (CGO_ENABLED=0, -trimpath), plus:
#   SHA256SUMS         checksums of the artifacts (verify with: sha256sum -c SHA256SUMS)
#   BUILD-MANIFEST.txt toolchain, commit, dirty flag, and `go version -m` output
#                      (the module list embedded in each binary) for audit
#
# Honest limits:
#  * artifacts are UNSIGNED; a checksum detects accidental corruption, it does not
#    prove who built the file or that SHA256SUMS itself was not replaced
#  * BUILD-MANIFEST.txt is a dependency listing, NOT an SPDX/CycloneDX SBOM
#  * "reproducible" is only claimed after you rebuild on a second machine and the
#    SHA-256 values match; `--check-repro` rebuilds on THIS machine only
#  * the embedded dashboard must already be built (make build-frontend)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
VERSION=""
OUT="$ROOT/dist"
TARGETS="linux/amd64 linux/arm64"
CHECK_REPRO=0

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    --targets) TARGETS="${2:-}"; shift 2 ;;
    --check-repro) CHECK_REPRO=1; shift ;;
    -h|--help) sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[ -f "$ROOT/core/cmd/vanguard/dist/index.html" ] || { echo "the dashboard is not built: run 'make build-frontend' first" >&2; exit 1; }
command -v go >/dev/null || { echo "go not found in PATH" >&2; exit 1; }

COMMIT="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
DIRTY="$(git -C "$ROOT" status --porcelain 2>/dev/null | head -c1)"
[ -n "$DIRTY" ] && DIRTY=yes || DIRTY=no
[ -n "$VERSION" ] || VERSION="$(git -C "$ROOT" describe --tags --always 2>/dev/null || echo dev)"
# A fixed, commit-derived timestamp keeps the binary independent of build time.
EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || echo 0)}"
BUILD_DATE="$(date -u -d "@$EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"

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

echo "building ${VERSION} (commit ${COMMIT}, dirty=${DIRTY}) for: ${TARGETS}"
rm -rf "$OUT.tmp"
build_all "$OUT.tmp"

if [ "$CHECK_REPRO" = 1 ]; then
  build_all "$OUT.tmp2"
  if ( cd "$OUT.tmp" && sha256sum * ) > "$OUT.sums1" && ( cd "$OUT.tmp2" && sha256sum * ) > "$OUT.sums2" && cmp -s "$OUT.sums1" "$OUT.sums2"; then
    echo "same-machine rebuild produced identical SHA-256 values (this is NOT a cross-machine reproducibility claim)"
  else
    echo "WARNING: two builds on this machine produced different binaries" >&2
    rm -rf "$OUT.tmp2" "$OUT.sums1" "$OUT.sums2"; exit 1
  fi
  rm -rf "$OUT.tmp2" "$OUT.sums1" "$OUT.sums2"
fi

mkdir -p "$OUT"
cp -f "$OUT.tmp"/* "$OUT"/
rm -rf "$OUT.tmp"
cp -f "$HERE/vanguard.service" "$HERE/vanguard-monitor-only.conf" "$HERE/vanguard.env.example" "$HERE/install.sh" "$HERE/upgrade.sh" "$OUT"/

( cd "$OUT" && sha256sum "vanguard-${VERSION}"-* vanguard.service vanguard-monitor-only.conf vanguard.env.example install.sh upgrade.sh > SHA256SUMS )
{
  echo "VANGUARD build manifest"
  echo "version:    $VERSION"
  echo "commit:     $COMMIT"
  echo "dirty tree: $DIRTY"
  echo "build date: $BUILD_DATE (derived from the commit time, not the wall clock)"
  echo "go:         $(go version)"
  echo "flags:      CGO_ENABLED=0 -trimpath -buildvcs=false -ldflags '-s -w -X main.version=... -X main.buildDate=...'"
  echo "signed:     NO"
  echo "sbom:       NO (the module list below is a dependency listing, not an SBOM)"
  echo
  for f in "$OUT"/vanguard-"${VERSION}"-*; do
    echo "---- $(basename "$f")"
    go version -m "$f" 2>&1 || true
  done
} > "$OUT/BUILD-MANIFEST.txt"

echo "artifacts in $OUT:"; ls -1 "$OUT"
echo "verify: (cd $OUT && sha256sum -c SHA256SUMS)"
