#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/logs}"
OUT_DIR="${OUT_DIR:-$LOG_DIR/hashes}"

if command -v sha256sum >/dev/null 2>&1; then
  HASH_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  HASH_CMD="shasum -a 256"
else
  echo "sha256sum or shasum is required" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

found=0
for log in "$LOG_DIR"/*.log; do
  [ -f "$log" ] || continue
  found=1
  base="$(basename "$log")"
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  size="$(stat -c %s "$log" 2>/dev/null || wc -c < "$log" | tr -d ' ')"
  hash="$($HASH_CMD "$log" | awk '{print $1}')"
  out="$OUT_DIR/$base.sha256.json"
  cat > "$out" <<JSON
{
  "filename": "$base",
  "path": "${log#$ROOT_DIR/}",
  "sha256": "$hash",
  "size": $size,
  "created_at": "$ts"
}
JSON
  echo "wrote $out"
done

if [ "$found" -eq 0 ]; then
  echo "no .log files found in $LOG_DIR" >&2
  exit 1
fi
