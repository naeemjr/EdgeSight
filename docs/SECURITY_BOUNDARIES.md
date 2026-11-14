# EdgeSight — Security & Privacy Boundaries

EdgeSight is a passive network detection research prototype. This document
states its trust boundaries, network egress, and safe defaults.

## Authentication (fail-closed)

- Single mechanism: `X-API-Key` request header, constant-time compared.
- URL query-string credentials are **rejected** by design.
- Empty `api_key` ⇒ server refuses any non-loopback bind (`internal/api.bindGuard`).
- Unauthorized requests get a generic `401` with no key material echoed.

## Data sensitivity

- The SQLite database holds captured network metadata (addresses, ports,
  timings, derived baselines). Treat it as sensitive.
- `/api/query` is restricted to `SELECT`. This prevents writes but **does not**
  prevent read exposure of the metadata above. Keep the API authenticated and
  bound to a trusted interface.

## Enrichment plugins — external egress (OFF by default)

`plugins_enabled` is empty by default. No plugin performs external calls unless
explicitly enabled and given credentials.

| Plugin | Egress when enabled | Data sent |
|--------|--------------------|-----------|
| `enrich` (Shodan/VirusTotal/Censys/AbuseIPDB) | Third-party APIs over the network | Observed IP addresses + your API keys |
| `webhook` | Your configured `webhook_url` | Event JSON |
| `syslog` | Your configured `syslog_target` | RFC 5424 event lines |
| `csv` | Local file only | Event rows |

Enabling `enrich` transmits observed IP addresses to third parties; enable it
only with authorization and awareness of the privacy implication.

## Capture

- Live AF_PACKET capture is **opt-in** (`-capture`) and requires `CAP_NET_RAW`.
- Capture only traffic on networks you are authorized to monitor.
- Default mode performs **no** capture and serves an existing database.

## Out of scope / not claimed

- No performance/line-rate guarantee.
- No production hardening (rate limiting, TLS termination, audit logging).
- No detection-accuracy claim on real-world traffic.
