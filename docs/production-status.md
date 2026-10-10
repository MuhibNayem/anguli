# Production Status

**Document ID:** `ANGULI-STATUS-2026-10-10`
**Last updated:** October 10, 2026
**Scope:** anguli fingerprint access platform, at commit `b6ad0c3` and the work committed alongside it.

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

## What is not production-ready

These are stated plainly because a deployment decision made against an
optimistic reading is how people get locked out of buildings.

### 1:N identification does not scale past roughly 100 enrolled fingers

Walk-up 1:N search is **O(number of enrolled fingers)**. A cached pre-decrypted
gallery and a worker pool removed the per-scan database read and AES-GCM
decryption, but CPU profiling puts **85% of search time in
`Cylinder.SimilarityWithShift`**, which runs once per probe/gallery cylinder
pair — about a thousand pairs per candidate, times the whole gallery. A worker
pool divides that by the core count and does not change the order.

Measured, warm cache, 32 minutiae per finger:

| Enrolled fingers | Per walk-up |
|---:|---:|
| 50 | 83 ms |
| 100 | 165 ms |
| 200 | 319 ms |
| 400 | 628 ms |
| 800 | 1.24 s |
| 1600 | 2.47 s |

A 4x larger gallery costs 4.25x more. **The 200 ms turnstile SLA is met at
roughly 100 enrolments on development hardware.** 1:1 is unaffected.

Closing this requires a change to the matcher — a single global MCC bitstring
compared by Hamming distance is O(words) per pair rather than O(cylinders²),
at some cost in rotation tolerance. Not implemented, and not implementable
responsibly without real fingerprint captures to tune and validate against;
the synthetic minutiae available in-tree are mutually indistinguishable and
cannot serve that purpose.

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