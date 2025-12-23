# FileAudit

FileAudit is a lightweight file integrity sidecar for filesystem or shared-drive workflows.
It watches an outbox/inbox pair, produces a JSON manifest (SHA-256 + size), ships payloads,
and writes receipts after verification. It supports optional HMAC signing and distroless
containers with hardened defaults.

## What It Does

- Outbox mode: create manifest + ship payload/manifest + create `.ready` + ack receipts.
- Inbox mode: optional auto-manifest + verify manifest + emit receipt.
- Optional HMAC signature on manifests (shared secret) for authenticity.
- Works on local folders, network shares, or mounted buckets.

## Directory Layout

```
/outbox
/inbox
/receipts
/logs
/scripts
```

## Quick Start (Docker)

```
sudo ./scripts/test_flow.sh
```

This builds the images and runs a one-shot outbox + inbox pass, verifying:
- payload
- manifest
- receipt
- logs

## Continuous Run (Docker Compose)

```
docker compose up --build
```

## Environment / Flags

Common env vars (also available as flags):

- `OUTBOX_DIR`, `INBOX_DIR`, `RECEIPTS_DIR`
- `POLL_SEC` (polling interval)
- `STABLE_SEC` (seconds a file must be unchanged before `.ready` is created)
- `REQUIRE_READY` (0/1)
- `INOTIFY` (0/1, Linux only)
- `LOG_DIR` or `LOG_FILE`
- `PAYLOAD_NAME`, `PAYLOAD_BYTES`
- `INBOX_AUTOMANIFEST` (0/1)
- `MANIFEST_HMAC_KEY` (shared secret for signing/verifying)
- `ONCE` (0/1)

Example HMAC run:

```
MANIFEST_HMAC_KEY=supersecret docker compose up --build
```

## Binary Usage

```
./file_audit --mode outbox --outbox ./outbox --inbox ./inbox --receipts-out ./receipts
./file_audit --mode inbox --inbox ./inbox --receipts-out ./receipts
```

One-shot mode:

```
./file_audit --mode outbox --once 1
./file_audit --mode inbox --once 1
```

## Security Notes

- Distroless runtime images
- Non-root user
- Read-only root filesystem
- All Linux caps dropped
- `no-new-privileges` enabled

## Logs

Logs are written to:

- `logs/outbox.log`
- `logs/inbox.log`

You can hash logs at end-of-day with:

```
./scripts/hash_logs.sh
```
