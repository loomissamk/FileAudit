#!/bin/sh
set -eu

INBOX_DIR="${INBOX_DIR:-/data/inbox}"
RECEIPTS_DIR="${RECEIPTS_DIR:-/data/receipts}"
LOG_DIR="${LOG_DIR:-/data/logs}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/inbox.log}"
POLL_SEC="${POLL_SEC:-2}"
STABLE_SEC="${STABLE_SEC:-2}"
INBOX_AUTOMANIFEST="${INBOX_AUTOMANIFEST:-1}"

mkdir -p "$INBOX_DIR" "$RECEIPTS_DIR" "$LOG_DIR"

PIPE="$(mktemp)"
rm -f "$PIPE"
mkfifo "$PIPE"
tee -a "$LOG_FILE" < "$PIPE" &
exec > "$PIPE" 2>&1

is_payload() {
  case "$1" in
    *.manifest.json|*.receipt.json|*.ready) return 1 ;;
  esac
  return 0
}

mark_ready_if_stable() {
  now="$(date +%s)"
  for p in "$INBOX_DIR"/*; do
    [ -f "$p" ] || continue
    is_payload "$p" || continue
    ready="${p}.ready"
    [ -f "$ready" ] && continue
    mtime="$(stat -c %Y "$p" 2>/dev/null || echo 0)"
    age=$((now - mtime))
    if [ "$age" -ge "$STABLE_SEC" ]; then
      : > "$ready"
      printf '{"event":"READY_CREATED","payload":"%s"}\n' "$(basename "$p")"
    fi
  done
}

ready_loop() {
  while :; do
    mark_ready_if_stable
    sleep "$POLL_SEC"
  done
}

ready_loop &

if [ "$INBOX_AUTOMANIFEST" != "0" ]; then
  /file_audit --mode sender --outbox "$INBOX_DIR" --poll-sec "$POLL_SEC" --require-ready 1 &
fi

exec /file_audit --mode receiver --inbox "$INBOX_DIR" --receipts-out "$RECEIPTS_DIR" --poll-sec "$POLL_SEC" --require-ready 1
