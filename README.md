# EdgeSight

A single-binary passive network detection tool written in Go.

**Maturity: research prototype.** The detector, storage, API, plugin, and
syslog components are implemented and exercised by the `test/simulations`
suite; the integrated `cmd/edgesight` binary wires them together with safe
defaults. Live-capture throughput, long-run stability, and real-traffic
detection quality are **not** independently benchmarked here — see
[Limitations](#limitations). This is a research artifact, not a
production-ready product.

## Features (implemented)

- **Pure-Go AF_PACKET capture** on Linux via `mdlayher/packet` — no CGO.
- **SQLite storage** via `modernc.org/sqlite` (WAL mode).
- **Behavioral baselining** with Welford online mean/stddev + z-score anomaly
  detection (`internal/analytics`).
- **MITRE ATT&CK mapping** for generated alerts (`internal/mitre`).
- **Embedded web dashboard** + REST API, served from the binary.
- **RFC 5424 syslog** output (`internal/syslog`).
- **Plugin architecture**: webhook, CSV export, IP enrichment
  (Shodan/VirusTotal/Censys/AbuseIPDB), syslog — all **disabled by default**;
  see [docs/SECURITY_BOUNDARIES.md](docs/SECURITY_BOUNDARIES.md).
- **Bubble Tea TUI** component (`internal/tui`).

## Build

```bash
cd edgesight
CGO_ENABLED=0 go build -o edgesight ./cmd/edgesight
```

No external runtime dependencies; the binary is static.

## Quick start (safe default: no capture, loopback only)

```bash
# Serve the dashboard/API over an existing SQLite DB on loopback. No capture,
# no root required. This is the default mode.
./edgesight -db edgesight.db -listen 127.0.0.1:8080

# Opt in to live AF_PACKET capture (authorized local lab only; needs CAP_NET_RAW):
sudo ./edgesight -capture -config edgesight.json
```

Flags: `-config`, `-db`, `-listen`, `-capture`. Run `./edgesight -help`.

> There are also two focused helper binaries: `cmd/afprobe` (raw AF_PACKET
> probe) and `cmd/pcapcal` (calibration helper).

## Security model (fail-closed)

- Authentication is a **single mechanism**: the `X-API-Key` HTTP header,
  compared in constant time. **URL query-string credentials are rejected**
  (they leak into logs/proxies/history).
- If `api_key` is **empty**, the server **refuses to bind to any non-loopback
  address** and prints a warning; empty-key mode is loopback-only local
  development. Set `api_key` before exposing the API.
- `/api/query` is **SELECT-only**, but note that read-only SQL still exposes
  captured network metadata; treat the API as sensitive and keep it
  authenticated and bound to trusted interfaces.

## Configuration

```json
{
  "interface": "eth0",
  "promiscuous": true,
  "database_path": "edgesight.db",
  "listen_addr": "127.0.0.1:8080",
  "api_key": "",
  "plugins_enabled": [],
  "baseline_window": "5m",
  "anomaly_z_score": 3.0
}
```

With `api_key: ""` and a loopback `listen_addr`, the server runs in local mode.
No enrichment plugins are enabled by default, so no external calls are made.

## REST API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/events` | GET | List events (`?kind=&limit=50&offset=0`) |
| `/api/metrics` | GET | Current metrics snapshot |
| `/api/query` | POST | Read-only `SELECT` query (`{"q":"SELECT ..."}`) |
| `/api/status` | GET | Status and event count |
| `/` | GET | Embedded dashboard |

Authenticate with the `X-API-Key` header when `api_key` is set.

## Test

```bash
go test ./...
```

Simulation tests live in `test/simulations/`; API security tests in
`internal/api/server_security_test.go`. A deterministic offline evidence path
is documented in [docs/REPRODUCIBILITY.md](docs/REPRODUCIBILITY.md).

## Limitations

- **No performance benchmark.** Earlier "1 Gbps+ / line-rate" wording was
  removed; throughput and drop behavior under load are not measured in this
  repository.
- **Integrated binary is minimal.** `cmd/edgesight` serves the API and
  optionally drives capture; it does not wire every plugin/TUI permutation.
- **Capture is untested in CI** (needs privileges); CI covers build + the
  offline component tests only.
- Detection quality on real traffic is out of scope for this prototype.

## License

MIT
