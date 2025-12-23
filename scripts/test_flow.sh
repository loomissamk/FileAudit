#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

COMPOSE="docker compose"
if ! $COMPOSE version >/dev/null 2>&1; then
  if command -v docker-compose >/dev/null 2>&1; then
    COMPOSE="docker-compose"
  else
    echo "docker compose or docker-compose is required" >&2
    exit 1
  fi
fi

KEEP=0
if [ "${1:-}" = "--keep" ]; then
  KEEP=1
fi

PROJECT_NAME="${PROJECT_NAME:-fileaudit_test}"
STARTED=0
HOST_UID="${HOST_UID:-${SUDO_UID:-$(id -u)}}"
HOST_GID="${HOST_GID:-${SUDO_GID:-$(id -g)}}"
export HOST_UID HOST_GID
PAYLOAD_NAME="${PAYLOAD_NAME:-dummy.txt}"

cleanup() {
  if [ "$KEEP" -eq 0 ] && [ "$STARTED" -eq 1 ]; then
    $COMPOSE -p "$PROJECT_NAME" down >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

wait_for_nonempty() {
  local path="$1"
  local timeout="${2:-30}"
  local i=0
  while [ "$i" -lt "$timeout" ]; do
    if [ -s "$path" ]; then
      return 0
    fi
    sleep 1
    i=$((i + 1))
  done
  echo "timeout waiting for $path" >&2
  return 1
}

wait_for_exists() {
  local path="$1"
  local timeout="${2:-30}"
  local i=0
  while [ "$i" -lt "$timeout" ]; do
    if [ -e "$path" ]; then
      return 0
    fi
    sleep 1
    i=$((i + 1))
  done
  echo "timeout waiting for $path" >&2
  return 1
}

mkdir -p outbox inbox receipts logs outbox/.sent outbox/.acks
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_UID:-}" ] && [ -n "${SUDO_GID:-}" ]; then
  chown -R "$SUDO_UID:$SUDO_GID" outbox inbox receipts logs || true
fi

PAYLOAD="outbox/$PAYLOAD_NAME"
MANIFEST="$PAYLOAD.manifest.json"
READY_OUT="outbox/$PAYLOAD_NAME.ready"
INBOX_PAYLOAD="inbox/$PAYLOAD_NAME"
READY_IN="inbox/$PAYLOAD_NAME.ready"

rm -f "$PAYLOAD" "$MANIFEST" "$READY_OUT" "outbox/.sent/$PAYLOAD_NAME.sent" \
  "$INBOX_PAYLOAD" "$INBOX_PAYLOAD.manifest.json" "$READY_IN" \
  "logs/outbox.log" "logs/inbox.log"

$COMPOSE -p "$PROJECT_NAME" down -v --remove-orphans >/dev/null 2>&1 || true

$COMPOSE -p "$PROJECT_NAME" build
STARTED=1

$COMPOSE -p "$PROJECT_NAME" run --rm outbox --mode outbox --once 1

READY="inbox/$PAYLOAD_NAME.ready"

wait_for_nonempty "$PAYLOAD" 40
wait_for_nonempty "$MANIFEST" 40
wait_for_nonempty "$INBOX_PAYLOAD" 40
wait_for_exists "$READY" 40

DOC_ID="$(sed -n 's/.*"doc_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$MANIFEST" | head -n 1)"
if [ -z "$DOC_ID" ]; then
  echo "failed to parse doc_id from $MANIFEST" >&2
  exit 1
fi

RECEIPT="receipts/$DOC_ID.receipt.json"
$COMPOSE -p "$PROJECT_NAME" run --rm inbox --mode inbox --once 1
wait_for_nonempty "$RECEIPT" 40

SHA_MAN="$(sed -n 's/.*"sha256"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$MANIFEST" | head -n 1)"
if [ -z "$SHA_MAN" ]; then
  echo "failed to parse sha256 from $MANIFEST" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  SHA_ACTUAL="$(sha256sum "$PAYLOAD" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  SHA_ACTUAL="$(shasum -a 256 "$PAYLOAD" | awk '{print $1}')"
else
  echo "sha256sum or shasum is required" >&2
  exit 1
fi

if [ "$(printf '%s' "$SHA_ACTUAL" | tr 'A-F' 'a-f')" != "$(printf '%s' "$SHA_MAN" | tr 'A-F' 'a-f')" ]; then
  echo "hash mismatch between payload and manifest" >&2
  exit 1
fi

wait_for_nonempty "logs/outbox.log" 20
wait_for_nonempty "logs/inbox.log" 20

echo "OK: payload, manifest, receipt, and logs verified"

if [ "$KEEP" -eq 1 ]; then
  echo "containers left running (use: $COMPOSE -p $PROJECT_NAME down)"
fi
