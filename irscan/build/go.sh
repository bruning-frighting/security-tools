#!/usr/bin/env bash
# Build/test helper for use inside WSL2.
#
# The Go toolchain cannot run on the Windows host in this environment: Smart App Control
# blocks unsigned binaries (DECISIONS.md D-003 / B-001). Everything Go-related therefore runs
# in WSL2, including the cross-compile of the Windows binary.
set -uo pipefail

GO=${GO:-/home/kali/toolchain/go/bin/go}
REPO=${REPO:-/mnt/c/Users/thong/Downloads/irscan}
cd "$REPO" || exit 3

# Building on drvfs (/mnt/c) is slow; keep the build cache on the Linux filesystem.
export GOCACHE=${GOCACHE:-/home/kali/.cache/irscan-go-build}
export GOFLAGS=${GOFLAGS:--mod=mod}
export CGO_ENABLED=0

cmd=${1:-build}
shift || true

case "$cmd" in
  env)
    "$GO" version
    echo "GOCACHE=$GOCACHE"
    ;;
  build)
    echo "== go build ./... (host: linux/amd64) =="
    "$GO" build ./... || exit 1
    ;;
  vet)
    echo "== go vet ./... (linux) =="
    "$GO" vet ./... || exit 1
    echo "== go vet ./... (GOOS=windows) =="
    GOOS=windows GOARCH=amd64 "$GO" vet ./... || exit 1
    ;;
  test)
    echo "== go test ./... =="
    "$GO" test "$@" ./... || exit 1
    ;;
  crosscheck)
    # Compile-only verification of the Windows target. The resulting binary CANNOT be
    # executed in this environment (B-001); this proves it builds and type-checks, nothing
    # more, and every report that mentions the Windows binary states that limit.
    echo "== GOOS=windows go build =="
    GOOS=windows GOARCH=amd64 "$GO" build ./... || exit 1
    echo "windows build OK (compile + type check only; NOT executed)"
    ;;
  dist)
    mkdir -p dist
    VERSION=$(cat VERSION 2>/dev/null || echo "0.0.0-dev")
    COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
    LD="-s -w -X main.version=$VERSION -X main.commit=$COMMIT"
    # -buildvcs=false: Go's default VCS stamping embeds a vcs.modified flag read from
    # `git status`. dist/ was accidentally tracked in git in earlier phases (fixed by the
    # independent review pass), so every rebuild made the working tree look "dirty" to Go
    # relative to the previously committed binary, and three consecutive builds from
    # byte-identical source produced three different hashes. Disabling VCS stamping removes
    # that nondeterminism; version/commit are already stamped explicitly via -ldflags above.
    echo "== linux/amd64 =="
    GOOS=linux  GOARCH=amd64 "$GO" build -trimpath -buildvcs=false -ldflags "$LD" -o dist/irscan-linux-amd64 ./cmd/irscan || exit 1
    echo "== windows/amd64 =="
    GOOS=windows GOARCH=amd64 "$GO" build -trimpath -buildvcs=false -ldflags "$LD" -o dist/irscan-windows-amd64.exe ./cmd/irscan || exit 1
    ( cd dist && sha256sum irscan-linux-amd64 irscan-windows-amd64.exe > SHA256SUMS && cat SHA256SUMS )
    ;;
  *)
    echo "usage: go.sh {env|build|vet|test|crosscheck|dist}" >&2
    exit 2
    ;;
esac
