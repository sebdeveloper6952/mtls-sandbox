# mTLS Sandbox

A zero-config Go server that enforces mutual TLS, designed for developers who need to validate their mTLS stack before connecting to a real third party (banks, payment processors, partner APIs). It auto-generates a full PKI (CA, server cert, client cert), starts an HTTPS server requiring client certificates, and gives structured diagnostic feedback on every connection attempt — telling you *why* the handshake failed, not just *that* it failed.

## Why

Setting up mTLS is hard to debug. When your TLS handshake fails against a production endpoint, you get a cryptic error and no way to inspect what went wrong. mTLS Sandbox gives you a local server that behaves like a strict third party but returns structured `InspectionReport`s with failure codes and actionable hints for every connection.

## Public Testing Service

**[mtls.apps.sebdev.io](https://mtls.apps.sebdev.io)** is a hosted instance of mTLS Sandbox. Use it to validate that your server correctly enforces inbound mutual TLS — no installation required.

The flow: you get a session with a unique client certificate issued by the sandbox CA. You configure your server to trust that CA and require client certificates. The sandbox calls your server and tells you whether the handshake succeeded or failed, and why.

### How it works

```
  Your server                    mtls.apps.sebdev.io
      │                                  │
      │  1. Trust sandbox CA             │
      │◄────────────────────────────────►│  POST /api/sessions
      │                                  │  ← session ID + CA cert
      │  2. Require client certs         │
      │     from that CA                 │
      │                                  │
      │  3. Set your callback URL        │
      │ ────────────────────────────────►│  PATCH /api/sessions/{id}
      │                                  │
      │  4. Sandbox calls you            │
      │ ◄────────────────────────────────│  POST /api/sessions/{id}/test
      │     presents session client cert │
      │                                  │
      │  5. View result                  │
      │◄────────────────────────────────►│  GET /api/sessions/{id}/calls
```

### Step-by-step

**1. Create a session**

Open [mtls.apps.sebdev.io](https://mtls.apps.sebdev.io) in your browser and click **New Session**, or via curl:

```bash
SESSION=$(curl -s -X POST https://mtls.apps.sebdev.io/api/sessions)
SESSION_ID=$(echo "$SESSION" | jq -r '.id')
echo "$SESSION" | jq -r '.ca_cert_pem' > sandbox-ca.crt
```

Each session gets a unique client certificate (`cert_cn: session-<id>`) valid for 24 hours.

**2. Configure your server to trust the sandbox CA**

Your server needs to trust `sandbox-ca.crt` for incoming client certificates and require client authentication.

nginx:
```nginx
ssl_client_certificate /etc/nginx/sandbox-ca.crt;
ssl_verify_client on;
```

Go:
```go
caPool := x509.NewCertPool()
caPool.AppendCertsFromPEM(sandboxCAPEM)
tlsCfg := &tls.Config{
    ClientCAs:  caPool,
    ClientAuth: tls.RequireAndVerifyClientCert,
}
```

**3. Set your callback URL**

```bash
curl -s -X PATCH https://mtls.apps.sebdev.io/api/sessions/$SESSION_ID \
  -H "Content-Type: application/json" \
  -d '{"callback_url": "https://your-server.example.com"}'
```

The callback URL must be `https` and publicly reachable. Private/internal IPs are blocked.

**4. Trigger a test**

```bash
curl -s -X POST https://mtls.apps.sebdev.io/api/sessions/$SESSION_ID/test | jq .
```

The sandbox makes an outbound HTTPS request to your server using the session's client certificate and returns a full inspection report:

```json
{
  "call_id": 1,
  "test_mode": "normal",
  "status_code": 200,
  "duration_ms": 143,
  "inspection": {
    "handshake_ok": true,
    "presented": { "cert_chain": [{"cn": "session-abc123"}], "tls_version": "TLS 1.3" }
  }
}
```

**5. Run negative tests**

Verify your server correctly *rejects* connections it shouldn't accept:

```bash
# No client cert — server should return a TLS handshake error
curl -s -X POST https://mtls.apps.sebdev.io/api/sessions/$SESSION_ID/test \
  -H "Content-Type: application/json" \
  -d '{"test_mode": "no_cert"}'

# Client cert from a different, untrusted CA — server should reject
curl -s -X POST https://mtls.apps.sebdev.io/api/sessions/$SESSION_ID/test \
  -H "Content-Type: application/json" \
  -d '{"test_mode": "wrong_ca"}'
```

| `test_mode` | What the sandbox sends | Expected result |
|---|---|---|
| `normal` | Session client cert (trusted CA) | Server accepts — HTTP 2xx |
| `no_cert` | No client certificate | Server rejects — TLS handshake error |
| `wrong_ca` | Client cert from a different CA | Server rejects — TLS handshake error |

**6. View call history**

```bash
curl -s "https://mtls.apps.sebdev.io/api/sessions/$SESSION_ID/calls" | jq .
```

Or open the session page in the dashboard: `https://mtls.apps.sebdev.io/#/session/<id>`

### Limits

- Sessions expire after **24 hours**
- Test calls are rate-limited to **10 per 60 seconds** per session
- Callback URL must be `https` and must not resolve to a private/internal IP
- No authentication — keep your session ID private

---

## Self-Hosting

### Docker

```bash
docker run -d \
  -p 8443:8443 \
  -p 8080:8080 \
  -v $(pwd)/data:/data \
  -e MTLS_TLS_PERSIST_PATH=/data/certs \
  -e MTLS_SESSION_DB_PATH=/data/sessions.db \
  -e MTLS_HOSTNAMES=your-domain.example.com \
  ghcr.io/sebdeveloper6952/mtls-sandbox:latest
```

On first boot, the CA and server certificates are generated and written to `/data/certs`. They reload automatically on subsequent starts.

### Docker Compose

```bash
git clone https://github.com/sebdeveloper6952/mtls-sandbox.git
cd mtls-sandbox
docker compose up
```

To use a custom domain, update `MTLS_HOSTNAMES` in `docker-compose.yml`:

```yaml
environment:
  - MTLS_HOSTNAMES=your-domain.example.com,localhost
  - MTLS_TLS_PERSIST_PATH=/data/certs
  - MTLS_SESSION_DB_PATH=/data/sessions.db
```

### Kubernetes

For Kubernetes deployments you need:
- A `Deployment` with `strategy: Recreate` (SQLite doesn't support concurrent writers)
- A `ReadWriteOnce` PVC mounted at `/data` for certs and the session database
- Two ingress routes on the same domain: TLS termination on port 443 for the dashboard, and TLS passthrough on port 8443 for the mTLS endpoint (the app manages its own CA)

Set the data paths via env vars:

```yaml
env:
  - name: MTLS_TLS_PERSIST_PATH
    value: /data/certs
  - name: MTLS_SESSION_DB_PATH
    value: /data/sessions.db
  - name: MTLS_HOSTNAMES
    value: your-domain.example.com
```

### Session service configuration

| Variable | Description | Default |
|---|---|---|
| `MTLS_SESSION_ENABLED` | Enable the session testing API | `true` |
| `MTLS_SESSION_DB_PATH` | SQLite database file path | `sessions.db` |
| `MTLS_SESSION_MAX_AGE` | Session TTL (e.g. `24h`) | `24h` |
| `MTLS_SESSION_RATE_LIMIT` | Max test calls per window per session | `10` |
| `MTLS_SESSION_RATE_WINDOW` | Rate limit window (e.g. `60s`) | `60s` |

To run as a pure mTLS sandbox without the public session API:

```bash
MTLS_SESSION_ENABLED=false mtls-sandbox
```

---

## Quick Start

### From source

```bash
go install github.com/sebdeveloper6952/mtls-sandbox/cmd/mtls-sandbox@latest
mtls-sandbox
```

### Build and run locally

```bash
git clone https://github.com/sebdeveloper6952/mtls-sandbox.git
cd mtls-sandbox
go run ./cmd/mtls-sandbox
```

On first boot, the server will:

1. Generate a self-signed root CA (ECDSA P-256)
2. Issue a server certificate (SANs: `localhost`, `127.0.0.1`)
3. Issue a client certificate for you to use
4. Write all certs to `./certs/`
5. Print the full certificate bundle to stdout
6. Start the mTLS server on `:8443` and a health endpoint on `:8080`

### Test it with curl

```bash
# This will be rejected — returns 401 with diagnostic report
curl -sk https://localhost:8443/ | jq .
# {
#   "handshake_ok": false,
#   "failure_code": "no_client_cert",
#   "failure_reason": "client certificate not presented",
#   "expected": { "client_auth": "strict", "trusted_ca": "mtls-sandbox-ca" },
#   "presented": { "cert_chain": [], "tls_version": "TLS 1.3", ... },
#   "hints": [
#     "Your client did not present a certificate during the TLS handshake.",
#     "If using curl, add: --cert client.crt --key client.key --cacert ca.crt",
#     ...
#   ]
# }

# This will succeed (using the generated client cert)
curl -s \
  --cert ./certs/client.crt \
  --key ./certs/client.key \
  --cacert ./certs/ca.crt \
  https://localhost:8443/ | jq .
# {"client":{"cn":"mtls-sandbox-client","expires":"...","issuer":"mtls-sandbox-ca"},"message":"mTLS handshake successful","status":"ok"}

# Health check (plain HTTP, always accessible)
curl http://localhost:8080/health
# {"status":"ok"}
```

## Server Modes

The server supports three modes that control how it handles client certificate validation. Set the mode via config file, environment variable, or flag.

### `strict` (default)

Behaves like a real production mTLS endpoint. Connections without a valid client certificate receive an HTTP 401 response with a structured `InspectionReport` containing failure details and actionable hints.

```bash
# Rejected with diagnostic feedback
curl -sk https://localhost:8443/
# HTTP 401 — InspectionReport with failure_code, failure_reason, and hints

# Accepted
curl --cert ./certs/client.crt --key ./certs/client.key --cacert ./certs/ca.crt https://localhost:8443/
# {"status":"ok","message":"mTLS handshake successful","client":{"cn":"mtls-sandbox-client",...}}
```

### `lenient`

Accepts connections with or without a client certificate. Always returns HTTP 200 with an inspection report. When no cert is presented, the response includes a warning header.

```bash
MTLS_MODE=lenient mtls-sandbox
```

```bash
# Accepted with warning
curl -sk https://localhost:8443/
# HTTP 200
# Header: X-MTLS-Warning: client certificate not presented
# Body: {"status":"ok","inspection":{"handshake_ok":false,"failure_code":"no_client_cert",...}}

# Accepted with full success
curl --cert ./certs/client.crt --key ./certs/client.key --cacert ./certs/ca.crt https://localhost:8443/
# {"status":"ok","inspection":{"handshake_ok":true,...}}
```

### `inspect`

Accepts all connections and returns the full `InspectionReport` as the response body. Use this to debug your TLS configuration.

```bash
MTLS_MODE=inspect mtls-sandbox
```

```bash
curl -sk https://localhost:8443/ | jq .
# {
#   "handshake_ok": false,
#   "failure_code": "no_client_cert",
#   "failure_reason": "client certificate not presented",
#   "expected": { "client_auth": "inspect", "trusted_ca": "mtls-sandbox-ca" },
#   "presented": { "cert_chain": [], "tls_version": "TLS 1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256", "server_name": "localhost" },
#   "hints": ["Your client did not present a certificate...", "If using curl..."],
#   "timestamp": "2026-03-18T20:27:40-06:00"
# }
```

When a client certificate is provided, the response includes full cert details (subject, issuer, serial, validity period, SANs, key type and strength).

## Inspection Report

Every connection to the mTLS server is analyzed by the inspector and produces a structured `InspectionReport`. The report identifies the specific failure and provides actionable hints to fix it.

### Failure Codes

| Failure Code | Meaning | Example Hint |
|---|---|---|
| `no_client_cert` | Client did not present a certificate | "If using curl, add: --cert client.crt --key client.key --cacert ca.crt" |
| `wrong_ca` | Certificate was signed by an untrusted CA | "Your cert was signed by 'Other CA', but this server trusts only 'mtls-sandbox-ca'" |
| `cert_expired` | Certificate has expired | "Your certificate expired on 2025-01-15T00:00:00Z" |
| `cert_not_yet_valid` | Certificate's NotBefore is in the future | "Your certificate is not valid until 2027-01-01. Check your system clock." |
| `weak_key` | RSA key is less than 2048 bits | "Your certificate uses a RSA 1024-bit key, which is below the minimum accepted strength." |
| `no_client_auth_eku` | Certificate lacks ClientAuth extended key usage | "Your certificate does not include the ClientAuth EKU. This usually means a server certificate is being used as a client certificate." |

### `/debug` Endpoint

The `/debug` endpoint always returns the full `InspectionReport` regardless of server mode. Use it when you want diagnostics without changing the server mode.

```bash
curl -sk https://localhost:8443/debug | jq .
```

## Configuration

### Config file (YAML)

```yaml
mode: strict              # strict | lenient | inspect
port: 8443
health_port: 8080
tls:
  ca_cert: ""             # path to CA cert PEM (empty = auto-generate)
  ca_key: ""              # path to CA key PEM
  server_cert: ""         # path to server cert PEM
  server_key: ""          # path to server key PEM
  client_cert: ""         # path to client cert PEM
  client_key: ""          # path to client key PEM
  persist_path: "./certs" # where to write generated certs
hostnames:
  - localhost
  - 127.0.0.1
log:
  level: info             # debug | info | warn | error
  format: json            # json | text
  file: ""                # log file path (empty = stdout)
```

Pass the config file path with `-config`:

```bash
mtls-sandbox -config config.yaml
```

### Environment variables

Every config field can be overridden with an environment variable. Environment variables take precedence over the config file.

| Variable | Description | Default |
|---|---|---|
| `MTLS_MODE` | Server mode (`strict`, `lenient`, `inspect`) | `strict` |
| `MTLS_PORT` | mTLS server port | `8443` |
| `MTLS_HEALTH_PORT` | Health endpoint port | `8080` |
| `MTLS_TLS_CA_CERT` | Path to CA certificate PEM | (auto-generate) |
| `MTLS_TLS_CA_KEY` | Path to CA key PEM | (auto-generate) |
| `MTLS_TLS_SERVER_CERT` | Path to server certificate PEM | (auto-generate) |
| `MTLS_TLS_SERVER_KEY` | Path to server key PEM | (auto-generate) |
| `MTLS_TLS_CLIENT_CERT` | Path to client certificate PEM | (auto-generate) |
| `MTLS_TLS_CLIENT_KEY` | Path to client key PEM | (auto-generate) |
| `MTLS_TLS_PERSIST_PATH` | Directory for generated certs | `./certs` |
| `MTLS_HOSTNAMES` | Comma-separated SANs for server cert | `localhost,127.0.0.1` |
| `MTLS_LOG_LEVEL` | Log level | `info` |
| `MTLS_LOG_FORMAT` | Log format (`json`, `text`) | `json` |
| `MTLS_LOG_FILE` | Log file path (empty = stdout) | (stdout) |

### CLI flags

```
mtls-sandbox [flags]

  -config string
        Path to config YAML file
  -ephemeral
        Do not persist generated certificates to disk
```

## Certificate Management

### Auto-generation (default)

On first boot with no existing certs, the server generates:

| File | Description |
|---|---|
| `certs/ca.crt` | Root CA certificate (ECDSA P-256, valid 10 years) |
| `certs/ca.key` | Root CA private key |
| `certs/server.crt` | Server certificate (valid 1 year, SANs from config) |
| `certs/server.key` | Server private key |
| `certs/client.crt` | Client certificate (valid 1 year) |
| `certs/client.key` | Client private key |

On subsequent boots, existing certs at `persist_path` are reloaded automatically.

### Ephemeral mode

Generate fresh certs on every boot without writing to disk. Useful for CI and testing:

```bash
mtls-sandbox -ephemeral
```

### Bring your own CA

Supply your own CA to match a specific third party's PKI structure:

```bash
MTLS_TLS_CA_CERT=/path/to/ca.crt MTLS_TLS_CA_KEY=/path/to/ca.key mtls-sandbox
```

The server will use your CA to issue server and client certificates.

## Request Logging

Every request to the mTLS server is logged as structured JSON with the following fields:

```json
{
  "time": "2026-03-18T20:27:40.006037-06:00",
  "level": "INFO",
  "msg": "request",
  "client_ip": "[::1]:50098",
  "method": "GET",
  "path": "/",
  "status": 200,
  "latency": 26916,
  "tls_version": "TLS 1.3",
  "cert_cn": "mtls-sandbox-client",
  "cert_sans": ["localhost"],
  "cert_expiry": "2027-03-19T02:27:38Z"
}
```

Switch to human-readable text logging with:

```bash
MTLS_LOG_FORMAT=text mtls-sandbox
```

## Architecture

```
mtls-sandbox/
├── cmd/mtls-sandbox/
│   └── main.go              # Entry point, subcommand dispatch (serve/ping/probe)
├── config/
│   └── config.go            # Config struct, YAML loading, env overrides
├── internal/
│   ├── ca/
│   │   └── ca.go            # CA generation, cert issuance, persistence
│   ├── client/
│   │   └── client.go        # Outbound mTLS client (ping/probe)
│   ├── inspector/
│   │   ├── inspector.go     # InspectionReport, TLS analysis, failure detection
│   │   └── hints.go         # Actionable hint generation per failure code
│   ├── mock/
│   │   ├── router.go        # Path matching, template expansion, delay simulation
│   │   ├── loader.go        # YAML mock route loading
│   │   └── mock.go          # Types: Route, Response, compiledRoute
│   ├── ratelimit/
│   │   └── limiter.go       # Fixed-window rate limiter (per session)
│   ├── safedial/
│   │   └── safedial.go      # SSRF-safe dialer (blocks private IPs)
│   ├── server/
│   │   ├── server.go        # mTLS server + health/API server + session handlers
│   │   └── middleware.go    # Mode handlers, recording middleware, request logging
│   ├── session/
│   │   ├── store.go         # SQLite session store + call history
│   │   └── migrations/      # sql-migrate SQL migration files
│   ├── store/
│   │   └── store.go         # In-memory ring buffer for inbound request log
│   └── ui/
│       ├── dashboard.go     # go:embed handler
│       └── static/          # Dashboard SPA (HTML/CSS/JS)
├── go.mod
└── go.sum
```

The mTLS server and health server run on separate ports. The health endpoint is always plain HTTP so it remains accessible even when your TLS configuration is broken.

All three server modes use `tls.RequestClientCert` at the TLS layer, which means the HTTP handler always runs. Certificate verification is performed in the handler by the inspector package, allowing every connection to receive structured diagnostic feedback.

## Development

### Prerequisites

- Go 1.22+

### Run from source

```bash
go run ./cmd/mtls-sandbox
```

### Run tests

```bash
go test ./...
```

Tests cover:
- Config loading, defaults, YAML parsing, env overrides, and validation
- CA generation (ECDSA P-256 and RSA 4096), cert issuance, chain verification, persistence round-trip
- Inspector: all failure modes (no cert, wrong CA, expired, not yet valid, weak key, missing EKU), hint generation, cert info extraction
- All three server modes with and without client certificates, wrong-CA rejection, `/debug` endpoint, health endpoint, and graceful shutdown

### Build

```bash
go build -o mtls-sandbox ./cmd/mtls-sandbox
```

## License

Apache 2.0
