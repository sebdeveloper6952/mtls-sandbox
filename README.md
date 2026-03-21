# mTLS Sandbox

A zero-config Go server that enforces mutual TLS, designed for developers who need to validate their mTLS stack before connecting to a real third party (banks, payment processors, partner APIs). It auto-generates a full PKI (CA, server cert, client cert), starts an HTTPS server requiring client certificates, and gives structured diagnostic feedback on every connection attempt — telling you *why* the handshake failed, not just *that* it failed.

## Why

Setting up mTLS is hard to debug. When your TLS handshake fails against a production endpoint, you get a cryptic error and no way to inspect what went wrong. mTLS Sandbox gives you a local server that behaves like a strict third party but returns structured `InspectionReport`s with failure codes and actionable hints for every connection.

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
│   └── main.go             # Entry point, flag parsing, wiring
├── config/
│   └── config.go           # Config struct, YAML loading, env overrides
├── internal/
│   ├── ca/
│   │   └── ca.go           # CA generation, cert issuance, persistence
│   ├── inspector/
│   │   ├── inspector.go    # InspectionReport, TLS analysis, failure detection
│   │   └── hints.go        # Actionable hint generation per failure code
│   └── server/
│       ├── server.go       # mTLS HTTPS server + health server
│       └── middleware.go   # Inspector-based mode handlers + request logging
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
