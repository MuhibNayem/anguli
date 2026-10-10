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
| Offboarding / template revocation | **The control existed but was unreachable** | The platform could add people but never remove them. `enrolled_templates.revoked`, the `revocation_records` audit table, the domain type and `RecordRevocation`/`RevocationHistory` were all present and tested — but no port method, service operation, gRPC method or HTTP route could reach any of it, and `ListAll` ignored the flag, so a revoked template would still have been matched in 1:N. A terminated employee's finger kept opening doors centrally and at every edge node, indefinitely. Now end to end: `POST/DELETE /api/v1/biometrics/revoke`, idempotent, archives the payload for audit, invalidates the warm gallery cache, and pushes `IsActive: false` to the edge — with edge failure **reported**, never silently swallowed. |
| Authentication and privilege separation | **Was a complete bypass in the default deployment** | The reader credential defaulted to a constant published in this repository, set by *no* deployment configuration, and fell back **silently** — no warning at all. `RequireAuth` then accepted that reader credential on *every* route, including enrollment, revocation and anti-passback reset. Anyone who had read the source could authenticate to any anguli deployment, clear anti-passback for anyone (a direct bypass of the tail-entry control), enroll their own fingerprint, or lock real employees out. Now: two distinct credentials, administrative routes require the admin key and answer 403 to a reader key, and the gateway **refuses to start** if either is missing outside development or if the two are equal. |
| Anti-passback could be skipped entirely | **An unset door direction disabled the rule** | The APB evaluation branched on `direction == 1` for entry and `direction == 2` for exit. Anything else matched neither branch, fell through to the grant, and recorded a pass event. proto3 defaults an unset enum field to zero and `DOOR_DIRECTION_UNSPECIFIED` is zero, so a caller that simply omitted `direction` sent exactly the value that disables anti-passback — and the turnstile controller passed the enum straight through. It was worse than a bypass: the bogus event was persisted, so the next legitimate scan was judged against a movement that never happened. Now rejected at the gRPC boundary, denied again in both the online and offline evaluators, and recorded nowhere. Separately, a roster item whose template bytes cannot be decoded now reports the loss instead of answering `synchronized successfully` - such an employee is cached but unverifiable at that node, a silent lockout. The item is still forwarded rather than dropped, because the revocation path sends `IsActive: false` with no template bytes at all and dropping-by-default would have silently discarded exactly the deactivation it exists to deliver. |
| Role clearance enforcement | **A misspelled role opened the zone to everyone** | Clearance was `roleRank(employee) < roleRank(required)` on both the online and offline paths, and an unrecognised *required* role scores 0 - so the test became `1 < 0`, never fired, and the grant proceeded. A zone configured with `allowed_role: "ADMINISTRATOR"` - a plausible name that is simply not in the hierarchy - admitted every employee and contractor on the roster, with nothing logged. The employee side was already fail-closed (an unknown employee role scores 0 and fails `0 < 1`); only the required side was fail-open, and the asymmetry is invisible at the call site. Clearance now fails closed on both sides, and `Configure` refuses to store a role it cannot evaluate so the mistake is reported to whoever typed it. |
| Credential rotation | **Was a building-wide lockout** | Both credentials are read once at startup, so switching to a new key returned `401` to every door still holding the old one - and a turnstile is bolted to a wall, so the rollout is physical and the gateway cannot be told the new key is live until it finishes. A retiring credential can now be kept valid via `API_GATEWAY_KEY_PREVIOUS` / `READER_KEY_PREVIOUS` for the duration. The overlap is refused if it would escalate privilege (a retiring admin key equal to the live reader key, or the reverse, or the two retiring keys matching), and neither generation of reader credential is accepted on an admin route. Verified against the running gateway. |
| Match reproducibility | **Was not production-ready until this cycle** | The matcher was **nondeterministic**: spatial-consensus ties were broken by Go map iteration order, so the same probe against the same finger scored differently on repeated calls in about half of all trials. A deny near the threshold could not be reproduced or audited. Tie-breaks are now total and ordered; `TestVerifyIsDeterministic` and `TestVerifyIsDeterministicUnderConcurrency` guard it. |
| Circuit breaker and overload shedding | **Breaker had a race until this cycle** | The breaker published its open state before its cool-down timestamp, so a concurrent `Allow()` could read the timestamp as unset, compute the cool-down as `now − zero time` (decades), conclude it had elapsed, and admit a probe the cool-down existed to reject — parking the breaker in half-open with its probe slot spent. During an outage that sheds load and then lets one request per trip straight through. An unset timestamp now reads as *not* elapsed. `TestBreaker_NeverHalfOpensWithoutAnElapsedCoolDown` guards it; the same race was making `TestBreaker_ReopenRacesAllowReads` fail ~2% of runs, which made CI intermittently red. |
| Biometric endpoint rate limiting | **Was absent entirely** | `/api/v1/doors/scan` performs 1:N identification and answers "who does this print belong to" across the whole gallery. Behind one shared API key and with no rate limit, any holder could enumerate a site's enrolled population — the one thing an access system must not disclose, and permanent if leaked, since templates cannot be reissued. Now bounded per caller, hashed so process memory holds no raw credential, and observable via `anguli_ratelimit_rejected_total`. |
| Facility isolation | **Single-facility per deployment, and now enforced** | Every table is keyed without a facility, so two sites sharing one database would silently merge their zone policies, employee roles and templates — `facility_id` existed in the API and was discarded as a hardcoded literal. Rather than half-scope the schema, `FACILITY_ID` is real configuration, the database records which facility claimed it, and both stateful services **refuse to start** against a database claimed by another. Verified by running the built binary. Multi-site still means one deployment per site — see below. |
| Template key rotation | Production-ready | Zero-downtime rotation with no re-enrollment: a keyring loaded from the environment, and a `keyrotate` command that decrypts, re-encrypts and verifies every migrated template. Proven to leave the old key unable to read migrated records. |
| Central access audit trail | **Did not exist, though every layer of it was "done"** | Replaying the edge's offline WAL **destroyed** it: `DrainOfflineEvents` truncated the durable log as part of the read, handed the events to a handler that discarded them, and the `access_events` table it was meant to feed was never written by any code path. Nothing triggered a replay at all, so during an outage every door decision was written to one edge machine's disk and never left. "Who entered which door, and when" had no central answer. Now: take → forward → acknowledge, with the WAL retired only after a confirmed forward — and retired by rewriting it from the live queue rather than truncating, because a door scan that lands mid-forward is still only on disk, and a truncate would destroy it while the node still held a copy in memory that looked fine until it restarted; a new `RecordAccessEvents` RPC; a real `access_audit_events` table keyed on a generated `event_id` so a retried batch cannot duplicate a door entry; and a background loop that flushes on a timer. The trail is also **readable**: `GET /api/v1/audit/access-events` (admin-only, rate limited), filtered by employee, zone, turnstile, time window and outcome, paginated by a keyset cursor so a replay landing mid-scan cannot make an operator skip events. Recording without a read path would have left the same gap in a new form — data no application can query answers none of the questions an audit trail exists to answer. |

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

One consequence of a shared reader key is that it must be rotated in place, and
that rotation now has an overlap window: `API_GATEWAY_KEY_PREVIOUS` and
`READER_KEY_PREVIOUS` keep a retiring credential valid while readers are updated
one at a time. **Nothing expires them.** A forgotten previous key is a live
credential that nobody is tracking, and the only safeguard is the startup warning
naming both variables. That trade is deliberate - the alternative is that a
routine rotation locks every door in the building until the last turnstile is
physically visited - but it means the overlap is a process obligation, not a
mechanism.

### The audit trail is only as durable as the edge disk that buffers it

Central storage now receives every door decision, and the flush runs on a timer
(`OFFLINE_REPLAY_INTERVAL`). But the path from decision to record still passes
through **one edge node's disk**. If that node's storage fails during an outage,
the events buffered on it are gone, and no replay can recover them because they
never left. A second edge node does not help; the WAL is per-node, not shared.

Bounding that needs host-owned infrastructure this library does not ship: an
edge-to-edge or edge-to-central replication for the WAL, so a node's loss costs
nothing, rather than a local disk holding the only copy until the next flush. The
`Take` → `forward` → `Acknowledge` sequence makes the *flush* safe, and the
replay loop makes it automatic; neither makes the *buffer* redundant.

Two smaller consequences worth stating:

- The trail records **decisions**, not the imagery behind them. A fingerprint
  template is not re-derivable from an event row, so the log answers "who was
  let through, when, and by what rule" but not "this print matched that finger".
- `recorded_at_unix` is stamped when central storage receives the event, not when
  the door opened. Both timestamps are stored, and `occurred_unix` is the one to
  filter on, but an outage makes the gap between them large and visible.

### A deployment serves exactly one facility, and multi-site is not supported

`facility_id` appears in three protobuf messages and was, until recently,
hardcoded to the literal `"facility-primary"` in the gateway and stored nowhere.
Worse, the schema behind it has no facility anywhere: policies are keyed by
`zone_id`, employee roles by `employee_id`, templates by
`(employee_id, position)`, anti-passback by `(employee_id, zone_id)`.

For one site that is correct. For two it fails **silently**: a company with
buildings in London and Dublin that names both lobbies `zone-main-gate` has one
policy row between them, so tightening the London lobby threshold quietly
changes the Dublin lobby, and 1:N search at one building matches against the
other's enrolled fingers. Nothing errors. Nothing logs. It is simply wrong.

The fix chosen was **not** to add a `facility_id` column to some tables. Half a
migration is worse than none — a schema where policies are scoped but templates
and anti-passback are not reads as isolated while still merging sites, and
reviewing it is far harder than reviewing a schema with an honest boundary. So:

- `FACILITY_ID` is real configuration (default `default`), used by the gateway
  and stamped on edge roster syncs, replacing the hardcoded literal.
- The database records the facility that claimed it, on first boot, and both
  stateful services **refuse to start** if it is claimed by another. The routine
  way to hit this — reusing a database image or a volume for a second site —
  now fails loudly with a message naming both facilities.
- The refusal was verified by running the built binary: the first start claims
  and serves, the second against the same directory exits.

What this does **not** do is let one deployment serve several facilities. That
needs `facility_id` on every table, in every primary key and every query, plus
per-facility caching at the edge and 1:N search restricted to one site — a
schema migration across the whole system, not a patch. For a multi-site operator
today the answer is **one deployment and one database per site**, which the guard
now makes explicit rather than leaving to be discovered.

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