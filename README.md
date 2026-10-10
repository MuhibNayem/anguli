# anguli (অঙ্গুলি — "finger")

A fingerprint access-control platform: MCC cylinder-code matching, four Go
services, SIA OSDP v2.2 hardware integration, and a 3,000-case chaos suite.

> **Note on naming.** The codebase, packages and image names still say
> `aegis-*` in places. The repository is `anguli`; renaming the internal
> identifiers is mechanical follow-up work and has not been done, so expect
> the two names to coexist for now.

---

## What is here

| Area | Where |
|---|---|
| Biometric pipeline | `pkg/biometrics/` — image, minutiae, MCC, quality, crypto |
| Interop | `pkg/biometrics/iso19794/` — ISO/IEC 19794-4 image records; `pkg/biometrics/iso19794b/` — ISO/IEC 19794-2 minutiae records |
| Hardware | `pkg/hardware/` — OSDP v2.2 framing, turnstile driver |
| Security | `pkg/security/` — TLS, rate limiting; `pkg/resilience/` — admission control, circuit breakers |
| Storage | `pkg/store/` — SQLite (default) and PostgreSQL drivers behind one interface |
| Services | `services/` — biometric, access-policy, edge-gateway, api-gateway |
| Chaos suite | `test/chaos/` — 2,728 cases across 42 dimensions behind a hard gate |

## Requirements

Go 1.26. Docker and Docker Compose for the containerised path; Helm 3 for
Kubernetes. No CGO anywhere — the runtime images are Alpine.

## Quickstart

```bash
# Bring up the full stack. Every service declares a healthcheck and dependents
# wait on service_healthy, so a cold start no longer races the backends.
MASTER_KEY=$(openssl rand -hex 32) \
API_GATEWAY_KEY=$(openssl rand -hex 32) \
docker compose -f deploy/docker-compose.yml up --build
```

For Kubernetes, the chart refuses to render without an explicit Secret:

```bash
kubectl create secret generic anguli-secrets \
  --from-literal=MASTER_KEY="$(openssl rand -hex 32)" \
  --from-literal=API_GATEWAY_KEY="$(openssl rand -hex 32)"

helm upgrade --install anguli deploy/helm \
  --set existingSecret.name=anguli-secrets
```

## Configuration

Every secret is read from the environment with no insecure default. Compose
uses `${VAR:?message}`, so a missing key fails the deployment rather than
starting a service with an empty one.

| Variable | Default | Meaning |
|---|---|---|
| `MASTER_KEY` | — (required) | 64-char hex key for the template vault |
| `API_GATEWAY_KEY` | — (required) | REST API credential |
| `STORAGE_DRIVER` | `sqlite` | `sqlite` or `postgres` |
| `STORAGE_DSN` | — | Postgres URL; ignored for SQLite |
| `STORAGE_DATA_DIR` | `data` | Where the SQLite file lives |
| `MAX_CONCURRENT_REQUESTS` | `64` | Gateway admission ceiling |
| `ADMISSION_GRACE_MS` | `250` | How long a request may queue before being shed |
| `PORT` | per-service | `50051` / `50052` / `50053` / `8080` |

### Why overload protection is on by default

Measured on this platform, verify latency grew from 140 ms at one concurrent
request to 4.4 s at 128, and 300 concurrent verifies averaged 6.3 s (max 8.3 s).
Above capacity the gateway used to accept work it could never finish. It now
bounds concurrency and sheds the excess with `503` plus `Retry-After`, which is
faster for the user and visible to a load balancer.

`/metrics` publishes the limiter and circuit-breaker series. Shedding without
visibility would be a guess.

## Testing

```bash
go test ./pkg/... ./services/... ./api/...     # unit
go test ./test/chaos/ -v -count=1             # chaos suite + coverage gate
go test -race ./pkg/... ./services/...        # race detector
go test ./test/chaos/ -run XXX -fuzz '^FuzzVaultDecrypt$' -fuzztime 30s
```

Use `-v` on the chaos suite. Go suppresses stdout and stderr from a passing test
binary, so the gate report is invisible without it.

The chaos suite has its own gate in `TestMain`: it fails below 1,000 cases, on
any dimension that registered zero, and on ledger inconsistency. It also fails
deliberately on an isolated `-run`, because a partial run is exactly what it
exists to catch — fuzz runs pass `-short` to opt out. See
[`test/chaos/README.md`](test/chaos/README.md).

## CI

`.github/workflows/ci.yml` runs on every push and pull request:

- **verify** — tidy check, build, vet, gofmt, unit tests with a coverage floor
- **chaos** — both chaos suites with their gates, plus a race-detector pass
- **fuzz** — a 30 s smoke run per fuzz target
- **build** — matrix build of all four service images

## Known limitations

These are real and worth stating plainly:

- **`pkg/security/tls` is not wired into any service yet.** The package fails
  closed when misconfigured and is well tested, but no gRPC server currently
  uses mTLS. Inter-service traffic is still plaintext.
- **MINEX III is not implemented.** It is a certified template format and a much
  larger standard. What exists is ISO/IEC 19794-4 *image* records
  (`pkg/biometrics/iso19794`) and ISO/IEC 19794-2:2005 *minutiae* records
  (`pkg/biometrics/iso19794b`).
  - Only uncompressed 8-bit images; no WSQ.
  - The 19794-2 extended data area (ridge counts, core/delta, zonal quality) is
    preserved byte-for-byte but **not decoded**, and `Build` does not write one.
    The Appendix D certification block is flagged but not parsed.
  - The 2011 edition is rejected, not misread — it restructures the record.
  - Every field offset is pinned against the standard's normative text and
    byte-offset tables in `TestRecordHeaderMatchesTheStandard`,
    `TestFingerHeaderMatchesTheStandard` and `TestMinutiaRecordMatchesTheStandard`.
    Worth knowing: **the 19794-2 header is not laid out like the 19794-4
    header** despite both being 24 bytes. 19794-2 puts a certification flag and
    12-bit capture device ID at `[12:14]` where 19794-4 puts image height, and
    its width is at `[14:16]`. Reading one with the other's offsets yields a
    plausible-looking but wrong record rather than an error.
- **Composite (multi-finger) recognition is out of scope.** No.
- **The edge cache defaults its WAL to a fixed path** in the system temp
  directory. Two edge nodes sharing a host would write the same file. Make it
  per-instance before running more than one.
- **Synthetic corpora only.** Accuracy figures in the chaos ledger come from a
  loop-print generator, not real finger data. They exercise the pipeline; they
  are not a claim about match rates on real prints.