# mTLS Sandbox — Implementation Plan

## Project Vision

A self-hostable, zero-config Go service that acts as a realistic third-party enforcing mutual TLS.
Developers run it locally or in CI to fully validate their mTLS stack — certificates, TLS termination,
client auth, and app logic — before ever contacting the real third party.

---

## Guiding Principles

- **Zero config to start.** `docker run` produces a working server with generated certs on stdout.
- **Educational first.** Error messages explain *why* the handshake failed, not just *that* it failed.
- **Realistic strictness.** Behaves like an actual bank/payment processor, not a lenient dev server.
- **Single binary.** No external dependencies at runtime. Embed everything.
- **CI-friendly.** Works headlessly. Health endpoint. Deterministic exit codes.

---

## Repository Structure

```
mtls-sandbox/
├── cmd/
│   └── mtls-sandbox/
│       └── main.go               # Entrypoint, flag parsing, wiring
├── internal/
│   ├── ca/
│   │   ├── ca.go                 # CA creation, cert signing, persistence
│   │   └── ca_test.go
│   ├── server/
│   │   ├── server.go             # mTLS HTTPS listener
│   │   ├── middleware.go         # Cert validation, logging, mode enforcement
│   │   └── server_test.go
│   ├── client/
│   │   ├── client.go             # Outbound mTLS client (for callback/ping mode)
│   │   └── client_test.go
│   ├── inspector/
│   │   ├── inspector.go          # Cert chain analysis and human-readable diagnostics
│   │   └── inspector_test.go
│   ├── mock/
│   │   ├── router.go             # Configurable mock API routes
│   │   ├── loader.go             # Load mock responses from YAML
│   │   └── mock_test.go
│   ├── store/
│   │   └── log.go                # In-memory + optional file request log
│   └── ui/
│       ├── dashboard.go          # HTTP handler for web dashboard
│       └── static/               # Embedded HTML/CSS/JS (go:embed)
│           ├── index.html
│           └── style.css
├── config/
│   └── config.go                 # Config struct, YAML loading, env var override
├── examples/
│   ├── nginx/
│   ├── envoy/
│   ├── spring-boot/
│   └── node/
├── testdata/
│   └── mocks/
│       └── example.yaml          # Example mock route definitions
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── go.mod
├── go.sum
└── README.md
```

---

## Milestones

### Milestone 1 — Core mTLS Server (Week 1–2)

The minimum useful thing: a server that enforces mTLS and gives good error feedback.

**CA Package (`internal/ca`)**
- Generate a self-signed root CA (RSA 4096 or ECDSA P-256, configurable)
- Issue server certificate signed by the CA (SAN: localhost + configurable hostnames)
- Issue client certificate signed by the CA
- Persist CA + certs to disk (configurable path) OR operate ephemeral (in-memory only)
- Print cert bundle to stdout on first boot for easy copy-paste

**Server Package (`internal/server`)**
- `tls.Config` with `ClientAuth: tls.RequireAndVerifyClientCert`
- Three modes controlled by config:
  - `strict` — hard reject, 400/TLS alert, detailed log entry
  - `lenient` — accept without client cert, log a warning in response headers
  - `inspect` — accept all, return full handshake diagnostic in JSON body
- Structured JSON request logging (timestamp, client IP, TLS version, cert CN/SANs/expiry, HTTP method/path, response code)
- `/health` endpoint (no mTLS required — on separate port)
- Graceful shutdown

**Config (`config/config.go`)**
```yaml
mode: strict              # strict | lenient | inspect
port: 8443
health_port: 8080
tls:
  ca_cert: ""             # leave empty = auto-generate
  ca_key: ""
  server_cert: ""
  server_key: ""
  client_cert: ""         # issued to the developer to configure their stack
  client_key: ""
  persist_path: "./certs" # where to write generated certs
hostnames:
  - localhost
  - 127.0.0.1
log:
  level: info
  format: json            # json | text
  file: ""                # empty = stdout
```

**Deliverable:** `docker run ghcr.io/yourorg/mtls-sandbox` → server starts, certs printed, curl with cert works, curl without cert rejected with a clear message.

---

### Milestone 2 — Inspector & Diagnostics (Week 3)

The feedback loop that makes this tool unique.

**Inspector Package (`internal/inspector`)**

Every request gets an `InspectionReport`:
```json
{
  "handshake_ok": false,
  "failure_reason": "client certificate not presented",
  "expected": {
    "client_auth": "RequireAndVerifyClientCert",
    "trusted_ca": "CN=mtls-sandbox-ca"
  },
  "presented": {
    "cert_chain": [],
    "tls_version": "TLS 1.3"
  },
  "hints": [
    "Your client did not present a certificate during the TLS handshake.",
    "If using curl, add: --cert client.crt --key client.key",
    "If using nginx, set: proxy_ssl_certificate and proxy_ssl_certificate_key"
  ]
}
```

Hints are keyed to specific failure modes:
| Failure | Hint |
|---|---|
| No client cert | How to add one in curl, nginx, envoy, Spring, Node |
| Cert from wrong CA | "Your cert was signed by X, but I trust only Y. Re-issue from the sandbox CA." |
| Cert expired | "Your cert expired on DATE. Regenerate with: `mtls-sandbox certs renew`" |
| CN mismatch | "I expected CN=X, got CN=Y. Check your CSR subject." |
| Weak key | "RSA 1024-bit keys are rejected. Use RSA 2048+ or ECDSA P-256." |

**`/debug` Endpoint**
- Returns `InspectionReport` as JSON for any request regardless of mode
- Available even when handshake fails (TLS alert is suppressed for this path in inspect mode)
- Powers the dashboard

---

### Milestone 3 — Mock API + Request Log (Week 4)

Make it useful beyond the handshake.

**Mock Routes (`internal/mock`)**

YAML-defined mock responses loaded at startup (hot-reload optional):
```yaml
routes:
  - path: /api/v1/payments
    method: POST
    response:
      status: 200
      body: |
        {"transaction_id": "txn_abc123", "status": "ACCEPTED"}
      headers:
        Content-Type: application/json
        X-Request-Id: "{{uuid}}"   # simple templating

  - path: /api/v1/accounts/:id
    method: GET
    response:
      status: 200
      body_file: ./testdata/account_response.json
```

Supports: static body, body from file, simple template variables (`{{uuid}}`, `{{timestamp}}`), per-route delay simulation.

**Request Store (`internal/store`)**
- Ring buffer of last N requests (configurable, default 500)
- Each entry: timestamp, cert info, path, method, status, latency, inspection report
- Queryable via `GET /api/requests` (JSON) and `GET /api/requests/:id`
- Optional append-only NDJSON log file

---

### Milestone 4 — Web Dashboard (Week 5)

**Dashboard (`internal/ui`)**

Single-page, no framework, embedded via `go:embed`. Sections:

1. **Status bar** — mode badge, server uptime, cert expiry countdown
2. **Certificate panel** — shows the CA cert, server cert, and client cert. One-click copy PEM. Download buttons.
3. **Request log** — live-updating table (polling `/api/requests`). Columns: time, path, cert CN, result (✅/❌), latency. Clickable for full inspection report.
4. **Inspection detail** — when you click a failed request, shows the full report with hints rendered nicely.
5. **Quick test panel** — shows copy-pasteable curl commands pre-filled with the right cert paths.

Dashboard is served on the health port (no mTLS required) so it's always accessible even when your mTLS setup is broken.

---

### Milestone 5 — Outbound Client Mode (Week 6)

For teams that need the bank to call *them* back (webhooks, push notifications).

**Client Package (`internal/client`)**
- `mtls-sandbox ping <url>` — makes a single mTLS request to your service using the sandbox client cert, reports result
- `mtls-sandbox probe <url>` — like ping but runs the full inspection: did your server request a client cert? did it validate it? what cert did your server present?
- Configurable as a scheduled "keepalive" — useful in CI to assert your infra stays valid

---

### Milestone 6 — CLI & DX Polish (Week 7)

**CLI (`cmd/mtls-sandbox`)**
```
mtls-sandbox serve              # Start the server
mtls-sandbox certs show         # Print all cert details
mtls-sandbox certs renew        # Regenerate all certs
mtls-sandbox certs export       # Bundle certs as a zip
mtls-sandbox ping <url>         # Test outbound mTLS to your service
mtls-sandbox probe <url>        # Full diagnostic of your server's mTLS config
mtls-sandbox validate           # Check config file for errors
```

**Docker UX**
```bash
# Simplest possible start
docker run -p 8443:8443 -p 8080:8080 ghcr.io/yourorg/mtls-sandbox

# Persist certs across restarts
docker run -v $(pwd)/certs:/certs -p 8443:8443 ghcr.io/yourorg/mtls-sandbox

# Custom mocks
docker run -v $(pwd)/mocks:/mocks -p 8443:8443 ghcr.io/yourorg/mtls-sandbox

# Bring your own CA (e.g., to match the real bank's CA structure)
docker run \
  -e TLS_CA_CERT=/certs/bank-ca.crt \
  -e TLS_CA_KEY=/certs/bank-ca.key \
  ghcr.io/yourorg/mtls-sandbox
```

---

### Milestone 7 — CI Integration & Examples (Week 8)

**GitHub Actions example:**
```yaml
services:
  mtls-sandbox:
    image: ghcr.io/yourorg/mtls-sandbox
    ports:
      - 8443:8443
      - 8080:8080

steps:
  - name: Wait for sandbox
    run: curl --retry 5 http://localhost:8080/health

  - name: Export certs
    run: |
      curl http://localhost:8080/api/certs/client > client.crt
      curl http://localhost:8080/api/certs/client-key > client.key
      curl http://localhost:8080/api/certs/ca > ca.crt

  - name: Run integration tests
    run: go test ./... -tags=integration
```

**Integration guides (one per popular stack):**
- `examples/nginx/` — nginx reverse proxy as mTLS client
- `examples/envoy/` — Envoy as mTLS egress proxy
- `examples/spring-boot/` — RestTemplate + SSLContext config
- `examples/node/` — Node.js `https.Agent` config
- `examples/curl/` — reference curl commands

---

## Key Technical Decisions

### Why Go stdlib TLS (not a wrapper)?
`crypto/tls` exposes `tls.ConnectionState` on every request, giving us the full verified cert chain, negotiated version, cipher suite, etc. This is what powers the inspector. Third-party wrappers often hide this.

### Why ECDSA P-256 as default (not RSA)?
Smaller keys, faster handshakes, still accepted by all modern TLS stacks. RSA available as an option for legacy compatibility testing.

### Why separate health port?
If your mTLS config is broken, you still need to reach the dashboard and health endpoint. Mixing them on the same port means a broken TLS setup locks you out of diagnostics.

### Why go:embed for the UI?
Single binary deployment. `docker cp` not needed. The dashboard is always at the right version.

### Cert persistence strategy
- Default: write to `./certs/` on first boot, reload on restart (stable across restarts)
- `--ephemeral` flag: in-memory only, new certs every boot (good for CI)
- `--ca-cert` / `--ca-key`: bring your own CA (good for matching a specific third party's PKI structure)

---

## Testing Strategy

| Layer | Approach |
|---|---|
| CA package | Unit tests: generate CA, sign cert, verify chain |
| Server | Integration tests using `net/http/httptest` with custom TLS configs |
| Inspector | Table-driven tests for each failure mode and hint |
| Mock router | Unit tests for route matching and response templating |
| End-to-end | Docker Compose test: spin up sandbox + test client, assert handshake outcomes |
| CI | GitHub Actions matrix: Linux/macOS, Go 1.21+ |

---

## Open Source Setup

- **License:** Apache 2.0
- **Repo name suggestion:** `mtls-sandbox` (simple, searchable)
- **GitHub topics:** `mtls`, `tls`, `developer-tools`, `testing`, `security`, `golang`, `banking`, `pki`
- **CONTRIBUTING.md** with local dev setup (just `go run ./cmd/mtls-sandbox`)
- **Issue templates:** bug report, new integration guide request, new hint request

---

## Phase Summary

| Milestone | What you can do after it | Est. Time |
|---|---|---|
| 1 — Core mTLS Server | Run it, hit it with curl, see rejections | Week 1–2 |
| 2 — Inspector | Get human-readable feedback on failures | Week 3 |
| 3 — Mock API + Log | Test app logic, not just the handshake | Week 4 |
| 4 — Dashboard | Visual request history and cert management | Week 5 |
| 5 — Outbound Client | Test your server's mTLS config too | Week 6 |
| 6 — CLI & DX | Polished developer experience, full Docker UX | Week 7 |
| 7 — CI + Examples | Drop into any team's pipeline immediately | Week 8 |

**Milestone 1 alone is already useful and shippable.** Each milestone after that adds a layer of value without breaking anything from the previous one.
