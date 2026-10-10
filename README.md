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
| Hardware | `pkg/hardware/` — OSDP v2.2 framing, turnstile driver, `fprintd/` attestation driver |
| Security | `pkg/security/` — TLS, rate limiting; `pkg/resilience/` — admission control, circuit breakers |
| Storage | `pkg/store/` — SQLite (default) and PostgreSQL drivers behind one interface |
| Evaluation | `pkg/biometrics/dataset/` + `cmd/anguli-eval` — matcher accuracy on real fingerprint records |
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
| `MASTER_KEY` | — (required) | 64-char hex key for the template vault (primary) |
| `MASTER_KEY_ID` | `1` | Key id assigned to `MASTER_KEY` |
| `MASTER_KEY_PREVIOUS` | — | `kid:hex,kid:hex,…` kept for decryption only during a rotation |
| `API_GATEWAY_KEY` | — (required) | Administrator credential for REST |
| `READER_KEY` | — (required) | Credential a turnstile presents; must differ from `API_GATEWAY_KEY` |
| `RATE_LIMIT_RPS` | `10` | Sustained biometric requests per second per caller |
| `RATE_LIMIT_BURST` | `20` | Instantaneous burst per caller |
| `FACILITY_ID` | `default` | Which site this deployment serves. Recorded in the database on first boot; the service **refuses to start** if the database already belongs to another facility. One deployment serves one site — see below. |
| `EDGE_WAL_PATH` | `<EDGE_DATA_DIR>/edge-offline.wal` | Durable offline audit log on the edge node |
| `OFFLINE_REPLAY_INTERVAL` | `30s` | How often an edge flushes buffered door decisions centrally. A non-positive or malformed value falls back to the default; it never disables the flush. |
| `STORAGE_DRIVER` | `sqlite` | `sqlite` or `postgres` |
| `STORAGE_DSN` | — | Postgres URL; ignored for SQLite |
| `STORAGE_DATA_DIR` | `data` | Where the SQLite file lives |
| `MAX_CONCURRENT_REQUESTS` | `64` | Gateway admission ceiling |
| `ADMISSION_GRACE_MS` | `250` | How long a request may queue before being shed |
| `ENABLE_TLS` | `false` | Set `true` to encrypt all inter-service gRPC |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | — | Server key pair; required when TLS is on |
| `TLS_CA_FILE` | — | CA bundle; required for mTLS, or for a private CA |
| `TLS_SERVER_NAME` | — | SNI name the client validates the server against |
| `TLS_REQUIRE_MTLS` | `false` | Set `true` to demand and verify a client certificate |
| `PORT` | per-service | `50051` / `50052` / `50053` / `8080` |

### Credentials and privilege separation

Two credentials, and they are not interchangeable:

| Credential | Presented by | May do |
|---|---|---|
| `API_GATEWAY_KEY` | HR system, admin tooling | Everything: enroll, revoke, reset anti-passback, and door scans |
| `READER_KEY` | Every turnstile in the building | Door scans only: `verify` and `doors/scan` |

The reader key lives on hardware in a corridor, so anything that **grants**
access (`enroll`), **revokes** access (`revoke`), or **resets** access state
(`reset-apb`) requires the administrator key. Resetting anti-passback in
particular is a direct bypass of the tail-entry control — a reader that could
call it would let anyone defeat it for anyone.

A reader credential against an administrative route returns **403**, not 401:
the caller authenticated successfully and still is not allowed, so a 401 would
invite a pointless retry loop.

**The gateway refuses to start** if either credential is missing outside
development, or if the two are equal. There are no built-in production
credentials. The published `aegis-*-2026` values are used only when
`ENVIRONMENT` is `development` or `dev`, and doing so logs a warning that says
in plain terms that the values are in the source repository and grant
administrative access.

> **Rotating these is not automatic.** Both values are read once at startup.
> Changing `API_GATEWAY_KEY` or `READER_KEY` requires a restart, and there is
> no dual-key acceptance window, so roll it with a coordinated restart or
> brief 503s will reach whichever turnstiles are still using the old value.

### Interoperability: ISO/IEC standards

| Package | Standard | What it is |
|---|---|---|
| `pkg/biometrics/iso19794b` | ISO/IEC 19794-2:2005 | Finger minutiae record. Field layouts transcribed from the primary text. |
| `pkg/biometrics/iso19794` | ISO/IEC 19794-4 | Finger image record. |
| `pkg/biometrics/cbeff` | ISO/IEC 19785-1 | CBEFF Biometric Information Record container, so either of the above can be exchanged with a third-party PACS. |
| `pkg/biometrics/dataset` | — | Loader and evaluator for real fingerprint datasets (FAR/FRR/EER/ROC). |

`pkg/biometrics/cbeff` also implements the **PIV patron format** header from
NIST SP 800-76-2: the fixed 88-byte header, all 14 mandatory fields, and the
INCITS fingerprint modality values. Fingerprint data under PIV uses format
owner `0x001B` (INCITS M1) — **not** the `0x0101` (ISO/IEC JTC 1/SC 37) owner
used by the ISO/IEC 19794-x records above; they are different registries and a
reader will reject the wrong one. The CBEFF signature block is not yet
implemented, so records produced this way are not yet PIV-conformant — see
`docs/production-status.md`.

CBEFF wraps a data block and identifies it: format owner `0x0101` (ISO/IEC JTC
1/SC 37), format type `0x0001` for a 19794-2 minutiae record and `0x0007` for
a 19794-4 image, biometric type `0x08` for finger. Those identifiers are
asserted in tests against values the standards state, not merely round-tripped
against this encoder.

### Current production status

[`docs/production-status.md`](docs/production-status.md) is the authoritative
statement of what this platform can and cannot do in production, with measured
numbers. The older `docs/parity.md` and `docs/findings-audit-2026-10-09.md`
contradict each other and are marked superseded.

### Rotating the template encryption key

`MASTER_KEY` protects every enrolled fingerprint. A leaked key exposes every
person in the facility, so rotating it is not optional in any real deployment.
The ciphertext envelope carries a key id, and the vault can hold several keys,
so rotation does **not** require re-enrolling anyone:

```sh
# 1. Add the new key as decrypt-only alongside the current one.
export MASTER_KEY=<new-64-hex>
export MASTER_KEY_ID=2
export MASTER_KEY_PREVIOUS=1:<old-64-hex>

# 2. See how many templates still sit on the old key. Writes nothing.
go run ./services/biometric-service/cmd/keyrotate -dry-run

# 3. Migrate them. Every payload is decrypted, re-encrypted, verified by
#    decrypting it back, and only then written.
go run ./services/biometric-service/cmd/keyrotate -apply

# 4. Re-run -dry-run until it reports nothing left.
go run ./services/biometric-service/cmd/keyrotate -dry-run

# 5. Only then drop MASTER_KEY_PREVIOUS.
```

Step 5 must be last. Removing a key while templates still reference it makes
those templates permanently unreadable — the encrypted data is the only copy,
so there is no recovery path.

### Inter-service gRPC transport

Every service-to-service gRPC hop — gateway to biometric, policy and edge, and
edge to central policy — uses `pkg/security/tls`. Set `ENABLE_TLS=true` and
supply a key pair to turn it on; `TLS_REQUIRE_MTLS=true` additionally demands a
client certificate signed by `TLS_CA_FILE`.

The transport is **fail-closed**. Once TLS is requested, a missing, unreadable
or insufficiently configured certificate stops the process rather than
downgrading to plaintext. An operator who sets `ENABLE_TLS=true` and mistypes a
path gets a service that refuses to start, not one that quietly serves
biometric templates and door decisions in cleartext.

It is off by default because a single-host `docker compose up` has no
certificate authority. That is a development convenience, not a production
posture: in any real deployment this should be on.

### Offboarding: revoking a fingerprint

```sh
curl -X POST http://localhost:8080/api/v1/biometrics/revoke \
  -H "X-API-Key: $API_GATEWAY_KEY" \
  -H "Content-Type: application/json" \
  -d '{"employee_id":"EMP-1042","position":1,"reason":"OFFBOARDED"}'
```

```json
{"employee_id":"EMP-1042","revoked":true,"reason":"OFFBOARDED","edge_synced":true,"already_gone":false}
```

`DELETE` is accepted as well. **Check `edge_synced`** — it is `false` when the
edge could not be reached, and that is a partial offboarding: the employee is
denied centrally but a cached edge copy may still match. Retry until it is true.

Revocation is not deletion. The template row is flagged out of every read path,
its encrypted payload is archived into `revocation_records` with the reason, and
the 1:N gallery cache is invalidated immediately — waiting out its 30-second TTL
would leave a revoked template matchable for another half minute, which is
exactly the window someone already on site would use.

The operation is **idempotent**. Revoking an employee with no live template
returns `"revoked": false` with HTTP 200 and `"already_gone": true`, so a
bulk HR offboarding job can be retried without special-casing partial failures.

### One deployment, one facility

Every table is keyed **without** a facility: policies by `zone_id`, roles by
`employee_id`, templates by `(employee_id, position)`, anti-passback by
`(employee_id, zone_id)`. That is correct for a single site. For two it fails
silently — a London and a Dublin lobby both named `zone-main-gate` share one
policy row, so tightening one changes the other, with no error anywhere.

So a deployment serves exactly one facility, and says so rather than leaving it
to be discovered:

```sh
FACILITY_ID=london-hq STORAGE_DATA_DIR=/data ...
```

The service records `FACILITY_ID` in the database on first boot. Starting again
against that database with a different value **refuses to start**, naming both
facilities:

```
store: database belongs to a different facility: this database holds access
policies, templates and anti-passback history for facility "london-hq", but it is
configured as "dublin-office". Every table here is keyed without a facility, so
pointing one database at two facilities merges their zone policies and employee
roles silently. Give each facility its own STORAGE_DATA_DIR, or set FACILITY_ID
back to "london-hq"
```

Multi-site therefore means **one deployment and one database per site**, which is
what the guard enforces. `facility_id` does travel on the wire — the gateway
stamps it on edge roster syncs — but it identifies the deployment rather than
partitioning its data.

### Reading the access audit trail

Every door decision made at an edge node is buffered to that node's durable WAL
and flushed to central storage on a timer (`OFFLINE_REPLAY_INTERVAL`, 30s
default). The trail is admin-only and rate limited:

```sh
curl -G http://localhost:8080/api/v1/audit/access-events \
  -H "X-API-Key: $API_GATEWAY_KEY" \
  --data-urlencode 'employee_id=EMP-1042' \
  --data-urlencode 'zone_id=zone-main-gate' \
  --data-urlencode 'from_unix=1700000000' \
  --data-urlencode 'outcome=granted' \
  --data-urlencode 'limit=100'
```

```json
{"events":[{"event_id":"...","turnstile_id":"turnstile-01","employee_id":"EMP-1042",
  "zone_id":"zone-main-gate","decision":"granted offline","access_granted":true,
  "processed_offline":true,"occurred_unix":1700000000}],
 "next_page_token":"eyJ1IjoxNzAwMDAwMDAwLCJlIjoiZXZ0LTEifQ"}
```

Filters (`employee_id`, `zone_id`, `turnstile_id`, `from_unix`, `to_unix`,
`outcome=granted|denied`) combine with AND; empty means "any". Pass
`next_page_token` back to continue.

Paging is **keyset**, not offset. The trail is append-only and a replay lands
mid-scan as a matter of routine, so an offset cursor would shift every later page
and silently skip events — which during an investigation looks exactly like the
person never having entered. Each row carries `processed_offline`, because a
decision the edge made from cached policy during an outage is materially
different from one taken against live central policy, and only the flag
distinguishes them.

Recording is idempotent on `event_id`, so a retried replay never double-counts a
door entry. The edge keeps its copy until the forward is confirmed; if the
forward fails, the events stay on the edge and the failure is logged rather than
swallowed.

### Rate limiting the biometric endpoints

`/api/v1/biometrics/enroll`, `/api/v1/biometrics/verify` and `/api/v1/doors/scan`
are rate limited per caller, returning `429` with `Retry-After`.

The reason is specific to biometrics rather than to web services generally. The
1:N identification path answers *"who does this print belong to"* across the
whole gallery, so an unthrottled caller can walk a building's roster out of the
system one scan at a time. The enrolled population of a site is exactly what an
access system should not disclose, and fingerprint templates cannot be reissued
if they leak, so the disclosure they cause is permanent.

Buckets are keyed on the strongest credential the caller presents —
`X-Reader-ID`, then `X-Reader-Token`, then `X-API-Key`, then the remote address —
and credential values are hashed to a short tag, so process memory never holds a
raw API key. One noisy door cannot consume another door's budget, which matters
because every turnstile currently shares a single API key.

| Variable | Default | Meaning |
|---|---:|---|
| `RATE_LIMIT_RPS` | `10` | Sustained requests per second per caller |
| `RATE_LIMIT_BURST` | `20` | Instantaneous burst per caller |
| `RATE_LIMIT_MAX_KEYS` | `10000` | Cap on tracked callers before they share an overflow bucket |

Defaults assume a main gate peaking near 2 scans/second, leaving ~5× headroom.
Rejections are visible as `anguli_ratelimit_rejected_total`; a sustained
non-zero rate is either a misconfigured limit or an enumeration attempt.

**What this does not do.** It raises the cost of enumeration from minutes to
hours and makes the attempt observable. It does not stop a caller who already
holds valid credentials and is willing to be slow — that requires per-reader
credentials, which is a deployment property rather than middleware behaviour.
Setting the limit too low rejects real employees at a door, so it is set
deliberately and monitored, never quietly disabled.

### Storage and replica count

Anti-passback is shared state. With one SQLite file per pod, an ENTRY recorded
by the pod serving one lane is invisible to the pod serving the next, and the
second swipe is allowed — a silent authorisation bypass that no log line
reports. The Helm chart therefore **rejects** more than one replica on the
sqlite driver at `helm template` time, and names PostgreSQL as the fix.

### Known limitation: anti-passback is not atomic across replicas

*Resolved.* The repository port now exposes `WithPassEventLock`, and the
service runs its check and its commit inside it: a `pg_advisory_xact_lock` on
Postgres, a keyed mutex plus transaction on SQLite. The read and the write are
one atomic unit rather than two operations bracketed by a lock. Two
simultaneous swipes now produce exactly one grant.

### Known limitation: 1:N search is still linear in enrolled fingers

**Read this before sizing a gallery.** Walk-up 1:N identification remains
O(number of enrolled fingers). The per-scan cost is dominated by the matcher,
not by I/O.

What was fixed: 1:N used to call `ListAll` and then decrypt, JSON-parse and
match every enrolled record on the request path — tens of thousands of AES-GCM
operations per swipe. It now runs against a cached, pre-decrypted gallery
(`services/biometric-service/internal/service/gallery.go`), invalidated on local
enrollment and refreshed on a 30s TTL, with candidates verified across a worker
pool. Enrollment records are read once per TTL rather than once per scan.

What that did **not** fix: the matcher itself. It compares every probe cylinder
against every gallery cylinder for each candidate — about a thousand pair
comparisons per candidate, times the whole gallery. CPU profiling puts 85% of
search time in `Cylinder.SimilarityWithShift`. A worker pool divides that by
the core count; it does not change the order.

Measured on the development machine, warm cache, 32 minutiae per finger:

| Enrolled fingers | Per walk-up | Before the matcher fixes |
|---:|---:|---:|
| 100 | 8.2 ms | 165 ms |
| 200 | 14.6 ms | 319 ms |
| 400 | 26.5 ms | 628 ms |
| 800 | 50.0 ms | 1.24 s |
| 1600 | 94.8 ms | 2.47 s |
| 3200 | 184 ms | — |
| 6400 | 381 ms | — |

The matcher itself was rewritten twice, each time after profiling rather than
guessing, and each time with the output proven bit-identical to the previous
implementation against randomised cylinders:

1. **Bit-at-a-time to cell-at-a-time (5.1x).** `Cylinder.SimilarityWithShift`
   profiled at **85% of search CPU** walking all 1536 cylinder bits one at a
   time. A directional shift only permutes slices *within* a spatial cell, so
   the whole comparison can be done cell by cell on small integers with
   popcount and the inclusion-exclusion identity, never materialising the
   rotated operand.
2. **Loop scaffolding and redundancy (2.9x).** Re-profiling showed the popcounts
   were no longer the cost. Four things were: the rotation index was recomputed
   with two integer modulos for every cell when it takes at most six values; the
   accumulators were heap-allocated twice per pair; a branch for the identity
   rotation sat in the innermost loop; and because rotation is a permutation,
   the rotated operand's popcount is the *same number* for every rotation yet
   was recomputed once per rotation. Dropping empty cells and replacing the
   remaining popcount with a 6×64×64 lookup table finished the job.

Taken together the supported 1:N gallery grew from roughly 100 fingers to
**roughly 3400** inside the 200 ms turnstile SLA.

The growth is still linear, and that is the remaining problem. Constant-factor
work divides the cost; it does not change the order. **1:1 verification and
enrollment are unaffected and remain production-ready; 1:N walk-up
identification is now viable for a small-to-medium site, not a Fortune 500
campus.**

Further scale needs a change to the algorithm, not more constant factors: a
single global MCC bitstring compared by Hamming distance is O(words) per pair
instead of O(cylinders²), at some cost in rotation tolerance. That is not
implemented. `TestSearchScalingIsReported` records the current growth rate so
the day it changes, this section gets revisited.

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

## Measuring the matcher on real data

Every accuracy number this project has produced came from synthetic images.
That proves a pipeline does not crash and a codec round-trips; it says nothing
about whether the matcher recognises a finger it has seen once.

`cmd/anguli-eval` runs the platform's actual pipeline — normalise, binarise,
thin, extract minutiae, build MCC templates, match — over records on disk and
reports the standard open-set measures.

```bash
go run ./cmd/anguli-eval -dir ./mydataset -roc
```

`mydataset` holds ISO/IEC 19794-4 image records and/or 19794-2 minutiae
records. Subject and finger come from `manifest.tsv` if present:

```
# file<TAB>subject<TAB>finger
s01_left-index_01.iso	s01	left-index
```

or from a `<subject>_<finger>_<n>` file name otherwise. A **genuine** trial is
two impressions of the same finger; an **impostor** trial is two different
people. Trials are seeded, so the same dataset and seed always produce the same
comparison set and a score change between runs is a real change.

Two things to know before trusting its output:

- The MCC score is **not** normalised to 0..1. Production compares it against
  60, and the flag defaults to that. Feeding it a 0..1 threshold accepts nearly
  everything and reports a false accept rate of 1.0 while looking healthy.
- Trials that fail to score are **excluded** and reported separately, because
  a dataset with many unreadable prints biases the measured rates optimistically.

It does not download datasets. FVC and NIST SD4 carry their own licences.

## Hardware note: laptop fingerprint sensors

macOS Touch ID never releases the fingerprint image from the Secure Enclave, so
no application can read pixels — nothing to feed the pipeline. Most Linux
laptop sensors are **match-on-sensor** (for example Synaptics `06cb:00f9`): the
chip has its own MCU, matches in its own firmware, and returns only a verdict.
That is why `pkg/hardware/fprintd` is an **attestation** driver, not a capture
one — it answers "did the enrolled owner just touch the sensor?" and cannot
produce an image. It talks D-Bus to `fprintd` in pure Go, so Alpine and CGO-off
builds are unaffected.

`fprintd` is a per-session service, so it suits a kiosk or per-terminal
deployment. It does not suit a headless door-controller daemon running as a
system service. For real door hardware use `pkg/hardware/osdp`, which returns
pixels from a reader that exposes them.

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