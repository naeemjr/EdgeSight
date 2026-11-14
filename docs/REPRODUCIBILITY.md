# EdgeSight — Reproducibility

## Prerequisites

- Go 1.22+ (validated on go1.26.0, linux/amd64, 2026-10-03).
- No CGO, no external services. Offline.

## Build + test (offline, deterministic)

```bash
cd edgesight
CGO_ENABLED=0 go build ./...
go test ./...
```

Expected: all packages build; `internal/api`, `internal/plugins`, and
`test/simulations` report `ok`. The API security behaviors are covered by
`internal/api/server_security_test.go`.

## Safe runtime evidence path (no capture, loopback only)

```bash
go build -o edgesight ./cmd/edgesight

# 1) Fail-closed: empty key + non-loopback bind must refuse to start.
./edgesight -listen 0.0.0.0:18080 -db /tmp/es.db        # exits with a refusal message

# 2) Loopback serve-only run answers the status endpoint.
./edgesight -listen 127.0.0.1:18080 -db /tmp/es.db &    # serve-only, no capture
curl -s http://127.0.0.1:18080/api/status               # -> {"listen_addr":...,"status":"running","total_events":0}
kill %1
```

Observed on 2026-10-03 (go1.26.0):

- Step 1 prints: `refusing to start: api_key is empty and listen_addr
  "0.0.0.0:18080" is not loopback ...`.
- Step 2 returns: `{"listen_addr":"127.0.0.1:18080","status":"running","total_events":0}`.

## What this demonstrates / does not demonstrate

- **Demonstrates:** the components build and link into one binary; the API
  serves over an existing DB on loopback; authentication fails closed.
- **Does NOT demonstrate:** live-capture correctness, throughput, or detection
  accuracy on real traffic. Those require an authorized local lab and are out
  of scope for this offline path.

## Determinism notes

- The offline path uses a fresh empty SQLite DB (deterministic empty result).
- No seeds/randomness are involved in the status/serve path.
