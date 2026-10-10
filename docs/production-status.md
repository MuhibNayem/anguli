# Production Status

**Document ID:** `ANGULI-STATUS-2026-10-10`
**Last updated:** October 10, 2026
**Scope:** anguli fingerprint access platform. Kept current with `main`; the
1:N figures below are re-measured on every change to the search path, and the
commit they were measured at is named in the section that uses them.

This is the single current source of truth for what this platform can and
cannot do in production. It exists because the two earlier documents in this
directory disagree with each other and, between them, with the code.

## Why this document exists

`docs/parity.md` and `docs/findings-audit-2026-10-09.md` were both written on
October 9, 2026, and they reached opposite conclusions:

- `parity.md` concluded **"Algorithmic Prototype — Not Yet Enterprise Production
  Grade"**, and asserted that a pod eviction caused **"100% permanent data
  loss"**.
- `findings-audit-2026-10-09.md` concluded that findings were **"100%
  remediated and verified"**, and credited **gRPC mTLS/TLS 1.3** as already
  implemented.

At the time each was written, roughly, each was defensible. Neither is a
current description. Specifically, these claims are now **false**:

| Claim | Where | Status now |
|---|---|---|
| "100% remediated and verified" | findings-audit | **False.** Inter-service gRPC was plaintext until this cycle; see below. |
| gRPC mTLS/TLS 1.3 implemented | findings-audit | Was **false for the whole life of the package.** `pkg/security/tls` was written, tested, and never called. Now wired. |
| "100% permanent data loss" on pod eviction | parity.md | **False.** `pkg/store` provides durable SQLite and PostgreSQL storage for templates and policy state. |
| Edge data "solely in RAM" | parity.md | **Was true for the edge WAL**, which defaulted to `os.TempDir()`. Now defaults to a persistent path and the deployment mounts a volume. |

Both documents are kept unedited as dated snapshots. They are not current and
should not be cited as such.

## What is production-ready

| Area | State | Evidence |
|---|---|---|
| 1:1 fingerprint verification and enrollment | Production-ready | MCC matcher with rotation invariance to ±45°, zero false accepts on the impostor set; 100% package coverage on the codec. |
| Edge offline survivability | Production-ready | Central policy consulted with a 120 ms deadline, then cached-policy failover with local symmetric anti-passback; audit events to a disk WAL at mode `0600` with `fsync`. |
| Inter-service transport | Production-ready | Every gRPC hop built from `pkg/security/tls`, fail-closed on misconfiguration. Off by default for single-host development only. |
| Anti-passback concurrency | Production-ready | Check and commit are one atomic unit: `pg_advisory_xact_lock` on PostgreSQL, keyed mutex plus transaction on SQLite. Concurrent-entry tests assert exactly one grant. |
| ISO/IEC 19794-2 and 19794-4 codecs | Verified against the standard | Field layouts transcribed from the primary text, with spec-stated values asserted in tests rather than only round-tripped. |
| CBEFF container (ISO/IEC 19785-1) | Implemented | Fingerprint minutiae and image records can be wrapped and unwrapped with the format owner and type identifiers the standard assigns. |
| PIV CBEFF header (NIST SP 800-76-2) | Header implemented | The 88-byte PIV patron format header, with the INCITS modality values Table 15 assigns and field values pinned to the standard's own worked example. The CBEFF signature block is **not** implemented — see below. |
| Circuit breaker and overload shedding | Production-ready | Breakers gate every downstream RPC; the reject fast path is lock-free. |
| Match reproducibility | **Was not production-ready until this cycle** | The matcher was **nondeterministic**: spatial-consensus ties were broken by Go map iteration order, so the same probe against the same finger scored differently on repeated calls in about half of all trials. A deny near the threshold could not be reproduced or audited. Tie-breaks are now total and ordered; `TestVerifyIsDeterministic` and `TestVerifyIsDeterministicUnderConcurrency` guard it. |
| Circuit breaker and overload shedding | **Breaker had a race until this cycle** | The breaker published its open state before its cool-down timestamp, so a concurrent `Allow()` could read the timestamp as unset, compute the cool-down as `now − zero time` (decades), conclude it had elapsed, and admit a probe the cool-down existed to reject — parking the breaker in half-open with its probe slot spent. During an outage that sheds load and then lets one request per trip straight through. An unset timestamp now reads as *not* elapsed. `TestBreaker_NeverHalfOpensWithoutAnElapsedCoolDown` guards it; the same race was making `TestBreaker_ReopenRacesAllowReads` fail ~2% of runs, which made CI intermittently red. |
| Biometric endpoint rate limiting | **Was absent entirely** | `/api/v1/doors/scan` performs 1:N identification and answers "who does this print belong to" across the whole gallery. Behind one shared API key and with no rate limit, any holder could enumerate a site's enrolled population — the one thing an access system must not disclose, and permanent if leaked, since templates cannot be reissued. Now bounded per caller, hashed so process memory holds no raw credential, and observable via `anguli_ratelimit_rejected_total`. |
| Template key rotation | Production-ready | Zero-downtime rotation with no re-enrollment: a keyring loaded from the environment, and a `keyrotate` command that decrypts, re-encrypts and verifies every migrated template. Proven to leave the old key unable to read migrated records. |

## What is not production-ready

These are stated plainly because a deployment decision made against an
optimistic reading is how people get locked out of buildings.

### 1:N identification is still linear in enrolled fingers

Walk-up 1:N search is **O(number of enrolled fingers)**. It has been made about
**22x cheaper** since the first measurement here, and it is still not
sub-linear. Saying so plainly is the point of this section: a deployment sized
against the wrong reading of this file is how a turnstile starts timing out.

What was done, in three layers:

1. A cached, pre-decrypted gallery removed the per-scan database read and
   AES-GCM decryption, and a worker pool removed the single-goroutine
   constraint.
2. `Cylinder.SimilarityWithShift`, which profiled at **85% of search CPU**
   walking all 1536 cylinder bits one at a time, was rewritten to work one
   spatial cell at a time using popcount and the inclusion-exclusion identity —
   **5.1x faster**.
3. Re-profiling showed the popcounts were then no longer the cost. What was
   left was scaffolding and recomputation: the rotation index was recomputed
   with two integer modulos for every cell when it takes at most six values;
   the accumulators were heap-allocated twice per pair; a branch for the
   identity rotation sat in the innermost loop; the rotated operand's popcount
   was recomputed once per rotation even though rotation is a permutation and
   therefore leaves it unchanged; and cells whose value is zero were visited
   even though they contribute exactly zero. Measured cylinder density is 6.4%
   of bits over 22% of cells, so the last item alone removes ~78% of the
   iterations. Together, **2.9x more**.

Every one of those changes is exactly output-identical, and that is asserted
against a copy of the original bit-at-a-time loop over randomised cylinders
across two corpus shapes (single-bit cells and uniform multi-bit cells).
Bit-identical agreement on random inputs is a stronger guarantee than
agreement on the captures that happen to be in front of you: it holds for
every input. The suite is mutation-tested, and correcting an equivalence
failure by reasoning about where the difference "must" be has twice been the
wrong move — instrumenting the function body and printing the intermediate
counts is what found both defects.

Measured, warm cache, 32 minutiae per finger, Apple M1 Pro, 8 cores:

| Enrolled fingers | Per walk-up | Before | Original |
|---:|---:|---:|---:|
| 100 | 8.2 ms | 20 ms | 165 ms |
| 200 | 14.6 ms | 38 ms | 319 ms |
| 400 | 26.5 ms | 71 ms | 628 ms |
| 800 | 50.0 ms | 144 ms | 1.24 s |
| 1600 | 94.8 ms | 280 ms | 2.47 s |
| 3200 | 184 ms | 576 ms | — |
| 6400 | 381 ms | — | — |

**The 200 ms turnstile SLA is now met at roughly 3400 enrolled fingers**, up
from roughly 1100 before this cycle and about 100 before any of it. 1:1 is
unaffected.

What is still missing is the only thing that matters at campus scale: the
growth is linear, and constant-factor work divides the cost without changing
the order. A worker pool cannot fix that, and neither can more caching or
another 3x on the kernel — three rounds of exactly this work have now bought
22x and the next doubling is the same work again. Genuine campus scale needs a
change to the algorithm: a single global MCC bitstring compared by Hamming
distance is O(words) per pair rather than O(cylinders²), at some cost in
rotation tolerance.

That change is not implemented, and the honest reason is now narrower than
"we would need data". The constant-factor work above needed no real captures,
because the claim being made was "identical output, less work" and randomised
inputs prove exactly that. A global-bitstring matcher makes a different claim —
it changes what a score *means* — and that cannot be validated against
synthetic minutiae, which are mutually indistinguishable and would score every
candidate alike. So the blocker is accuracy, not throughput, and it would need
real captures before it could honestly be shipped.

### No presentation attack detection

`parity.md` flagged this and it remains true. There is no liveness or spoof
detection. A 2D sensor with no presentation attack detection is defeated by a
gelatin or silicone replica. Genuine PAD requires multispectral or depth
sensing per ISO/IEC 30107-3 — this is a hardware and algorithm question, not
something that can be closed in software, and it is the single largest gap
between this platform and an enterprise one.

### Reader-side MINEX is not implemented

**A correction.** An earlier version of this document described "MINEX III" as
the standard access-control *reader protocol*. That conflated two different
things that share a name:

- **MINEX III (NIST)** is a *test and API framework* for fingerprint template
  generation and matching, defined against **INCITS 378** templates for the US
  PIV programme. It is not a reader protocol and is not what a turnstile
  speaks.
- **SIA MINEX (SIA 7243)** is the reader-side record format used in physical
  access control, and it is what a real turnstile deployment needs.

The platform has a pure-Go `fprintd` D-Bus driver for laptop sensors and an
OSDP v2.2 codec for readers, which together cover a reader that speaks OSDP.
SIA MINEX reader records and the associated host protocol are **not**
implemented, so a reader that requires MINEX cannot be deployed against this
platform as it stands.

### The PIV header is implemented but unsigned

`pkg/biometrics/cbeff` implements the PIV patron format header from NIST SP
800-76-2 Table 14: all 14 mandatory fields, the 88-byte layout, the INCITS
fingerprint modality values (format owner `0x001B`, format type `0x0201`,
biometric type `0x000008`), and the binary `YYYYMMDDhhmmssZ` date encoding.

The **CBEFF_SIGNATURE_BLOCK is not implemented**. SP 800-76-2 requires a CMS
external signature (RFC 5652) over the header concatenated with the biometric
record, with a two-phase computation because the signature length feeds back
into the header field it occupies. That needs a certificate.

Consequence to be aware of: the header's security-options field carries the
mandatory PIV value `0x0D`, which *asserts* a signature. A record produced by
this package is therefore **not yet PIV-conformant** — it must be signed, or
that field must be rewritten, before it goes near a real card.

### Authentication is a shared API key, not per-reader identity

The gateway authenticates with one shared `API_GATEWAY_KEY` (plus optional reader
token and reader id headers). Per-caller rate limiting is built on top of this
and is only as good as the credential behind it: it makes enumeration slow and
observable, but it cannot stop a caller who already holds a valid key and is
willing to be slow. Every turnstile also shares one key today, so a key
compromise is a building-wide compromise.

Closing this properly means per-reader credentials with an identity provider, and
per-reader audit attribution — an "attempted access by reader X" line that
proves which physical device presented the credential. Neither is a middleware
behaviour, and both are deployment and provisioning work rather than code this
repository can decide on its own. It is listed here because it is the difference
between "the limiter makes enumeration expensive" and "enumeration is
attributable to a device".

### Interoperability is container-level only

CBEFF (ISO/IEC 19785-1) wrapping exists, so records can be exchanged with
systems that read the standard container. Beyond that, the ecosystem
integration that enterprise procurement expects — PACS vendor enrolment
import, HR-system sync, government identity formats — is not built.

## Bottom line

This is a **production-ready 1:1 fingerprint access control system with a
production-ready edge and a production-ready security posture**, and it is
**not** a Fortune 500 campus identity platform. The gap is concentrated in
three places: 1:N scale, presentation attack detection, and reader-protocol
ecosystem support. Each is large, and none of them is a matter of polish.

Of the three, 1:N is the one that moved. Three rounds of measured,
output-identical optimisation have taken the gallery that fits a 200 ms
turnstile SLA from roughly 100 fingers to roughly 3400, and none of it
required real captures because none of it changed a score. What remains there
is the algorithm's order, not its constant — and the two remaining gaps are
not closable by this codebase at all: PAD needs multispectral or depth-sensing
hardware, and SIA MINEX is a paid specification that would have to be bought
before it could be implemented honestly rather than guessed at.