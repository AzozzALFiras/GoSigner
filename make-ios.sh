#!/bin/sh
# Build the iOS arm64 c-archive (libgosigner.a) for the Flutter FFI layer.
#
# The signing pepper is a SECRET: read from PEPPER.txt (gitignored) and injected
# via -ldflags at build time. It is never written into source or committed.
set -e
cd "$(dirname "$0")"

PEPPER=$(grep -E '^PEPPER=' PEPPER.txt 2>/dev/null | cut -d= -f2 | tr -d '[:space:]')
if [ ${#PEPPER} -ne 64 ]; then
  echo "error: PEPPER.txt missing/invalid (need 'PEPPER=<64 hex chars>')." >&2
  exit 1
fi

OUT="${1:-libgosigner.a}"
CC="$(pwd)/clangwrap.sh" \
CGO_ENABLED=1 GOOS=ios GOARCH=arm64 \
  go build -buildmode=c-archive -trimpath -buildvcs=false \
    -ldflags "-s -w -X main.pepperHex=$PEPPER" \
    -o "$OUT" ./mobile

echo "built $OUT ($(du -h "$OUT" | cut -f1))"
