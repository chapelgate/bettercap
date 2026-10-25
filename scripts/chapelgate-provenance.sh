#!/bin/sh
set -eu

UPSTREAM="${CHAPELGATE_UPSTREAM_COMMIT:-dfe56780bb342b6a6715c9557a2cefe1f13d805c}"
OUT="${CHAPELGATE_BUILD_OUT:-/tmp/chapelgate-bettercap-build}"
mkdir -p "$OUT"
BIN="$OUT/bettercap"

if ! git cat-file -e "${UPSTREAM}^{commit}" 2>/dev/null; then
  echo "pinned upstream commit is not in this clone: $UPSTREAM" >&2
  exit 1
fi

git merge-base --is-ancestor "$UPSTREAM" HEAD

rm -f "$BIN"
go build -o "$BIN" .
chmod 0644 "$BIN"
SHA="$(sha256sum "$BIN" | awk '{print $1}')"
{
  echo "upstream_commit=$UPSTREAM"
  echo "build_commit=$(git rev-parse HEAD)"
  echo "sha256=$SHA"
  echo "binary_executed=no"
  echo "upstream_signed=no"
} | tee "$OUT/provenance.txt"
rm -f "$BIN"
echo "deleted compile output after recording sha256"
