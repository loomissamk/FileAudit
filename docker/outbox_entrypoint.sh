#!/bin/sh
set -eu

OUTBOX_DIR="${OUTBOX_DIR:-/data/outbox}"
INBOX_DIR="${INBOX_DIR:-/data/inbox}"
RECEIPTS_DIR="${RECEIPTS_DIR:-/data/receipts}"
LOG_DIR="${LOG_DIR:-/data/logs}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/outbox.log}"
POLL_SEC="${POLL_SEC:-2}"
STABLE_SEC="${STABLE_SEC:-2}"
PAYLOAD_NAME="${PAYLOAD_NAME:-dummy.txt}"

PIPE=""
tee_pid=""
sender_pid=""

mkdir -p "$OUTBOX_DIR" "$INBOX_DIR" "$RECEIPTS_DIR" "$LOG_DIR" "$OUTBOX_DIR/.sent" "$OUTBOX_DIR/.acks"

PIPE="$(mktemp)"
rm -f "$PIPE"
mkfifo "$PIPE"
tee -a "$LOG_FILE" < "$PIPE" &
tee_pid=$!
exec > "$PIPE" 2>&1

is_payload() {
  case "$1" in
    *.manifest.json|*.receipt.json|*.ready) return 1 ;;
  esac
  return 0
}

mark_ready_if_stable() {
  now="$(date +%s)"
  for p in "$OUTBOX_DIR"/*; do
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

payload="$OUTBOX_DIR/$PAYLOAD_NAME"
if [ ! -f "$payload" ]; then
  head -c 2048 /dev/urandom | base64 > "$payload"
  : > "${payload}.ready"
fi

/file_audit --mode sender --outbox "$OUTBOX_DIR" --poll-sec "$POLL_SEC" --require-ready 1 &
sender_pid=$!

cleanup() {
  if [ -n "$sender_pid" ] && kill -0 "$sender_pid" 2>/dev/null; then
    kill "$sender_pid" 2>/dev/null || true
  fi
  if [ -n "$tee_pid" ] && kill -0 "$tee_pid" 2>/dev/null; then
    kill "$tee_pid" 2>/dev/null || true
  fi
  if [ -n "$PIPE" ]; then
    rm -f "$PIPE"
  fi
}
trap cleanup INT TERM EXIT

while :; do
  mark_ready_if_stable

  for payload in "$OUTBOX_DIR"/*; do
    [ -f "$payload" ] || continue
    case "$payload" in
      *.manifest.json|*.receipt.json|*.ready) continue;;
    esac
    manifest="${payload}.manifest.json"
    [ -f "$manifest" ] || continue

    base=$(basename "$payload")
    marker="$OUTBOX_DIR/.sent/$base.sent"
    [ -f "$marker" ] && continue

    cp "$payload" "$INBOX_DIR/$base.tmp"
    mv "$INBOX_DIR/$base.tmp" "$INBOX_DIR/$base"
    cp "$manifest" "$INBOX_DIR/$base.manifest.json.tmp"
    mv "$INBOX_DIR/$base.manifest.json.tmp" "$INBOX_DIR/$base.manifest.json"
    : > "$INBOX_DIR/$base.ready"

    : > "$marker"
    printf '{"event":"SENT","payload":"%s","inbox":"%s"}\n' "$base" "$INBOX_DIR/$base"
  done

  for receipt in "$RECEIPTS_DIR"/*.receipt.json; do
    [ -f "$receipt" ] || continue
    base=$(basename "$receipt")
    ack_marker="$OUTBOX_DIR/.acks/$base"
    [ -f "$ack_marker" ] && continue
    : > "$ack_marker"
    printf '{"event":"RECEIPT_RECEIVED","receipt":"%s"}\n' "$receipt"
  done

  sleep "$POLL_SEC"
done
