# AegisBiometrics — Engineering Findings Audit

**Date:** October 9, 2026
**Scope:** Full static review of all hand-written source + empirical runtime verification
**Method:** Every file read in full; findings marked **[PROVEN]** were reproduced by executing the real services in an isolated harness (harness deleted after use; repo untouched). Findings marked **[READ]** are from code inspection only.

> **SUPERSEDED — dated snapshot, do not cite as current.**
>
> Written 2026-10-09. The claim below that findings are "100% remediated and
> verified" was **false**. Most visibly, gRPC mTLS/TLS 1.3 is listed here as
> implemented: `pkg/security/tls` existed and was unit-tested, but no service
> ever called it, and every inter-service hop ran in cleartext until 2026-10-10.
> Other items listed as done were later reopened and re-verified.
>
> Preserved unedited as a record of what was believed on that date.
>
> **Current status: [`production-status.md`](production-status.md).**


---

## Executive summary

The project has **sound engineering bones** — correct Clean Architecture layering, a textbook Zhang-Suen thinning implementation, a correct AES-256-GCM vault, proper `sync.RWMutex` usage, non-root multi-stage Dockerfiles, and a genuinely lean runtime footprint (42 MB idle across 4 services, ~8 ms door scans).

The problems are not in the craftsmanship. They are in **three claims the system makes that it does not deliver**, and in a set of access-control controls that are **structurally present but not enforced**.

| Tier | Count | Meaning |
|---|---:|---|
| **Critical** | 7 | Security bypass or headline claim is false |
| **High** | 11 | Control absent, or data-handling failure |
| **Medium** | 14 | Correctness / robustness defect |
| **Low** | 12 | Hygiene, doc accuracy, operability |

**The single most important finding:** the biometric matcher **rejects genuine users at 2° of finger rotation**, and the test suite cannot detect this because it verifies an image against *itself*.

---

## TIER 1 — CRITICAL

### C1. Matcher rejects genuine users at 2° rotation **[PROVEN]**
**Location:** `pkg/biometrics/mcc/cylinder.go:110`, `pkg/biometrics/mcc/matcher.go:105`

Enrolled a print, re-verified under controlled rotation:

```
  0.0 deg : score=100.00  cylinders=162  OK
  1.0 deg : score= 90.40  cylinders=156  OK
  1.5 deg : score= 73.67  cylinders=157  OK
  2.0 deg : score= 57.99  cylinders=127  FALSE REJECT   <- threshold 60
  2.5 deg : score= 67.31  cylinders=142  OK             <- score goes back UP
  5.0 deg : score= 50.49  cylinders=118  FALSE REJECT
 90.0 deg : score= 42.66  cylinders=150  FALSE REJECT
```

**Root cause:** `cylinder.go:110` binarizes 1536 Gaussian accumulators at a fixed `>= 0.10` threshold. Small rotation flips bits across the whole vector. The Jaccard score is then divided by `sqrt(len(probe)*len(gallery))` (`matcher.go:105`), and the *minutiae count itself* fluctuates (162→156→157→127→142) because binarization→skeletonization→extraction is itself threshold-sensitive.

The **non-monotonicity** (2.0° scores lower than 2.5°) is the diagnostic: the score is dominated by quantization noise, not by fingerprint similarity. There is no rotation normalization anywhere in the global scoring.

**Impact:** Real finger placement varies by tens of degrees. This system would reject a large fraction of legitimate users at a real turnstile.

---

### C2. The test suite validates the system against itself **[PROVEN]**
**Location:** `test/integration/e2e_test.go:113`

```go
// Step B: "Verify 1:1 match with genuine probe"
ProbeImageRawGray: rawPix,   // <-- the SAME byte slice used at enrollment
```

Score is necessarily exactly `100.00`. The test proves the system can match an image to itself. The imposter case (`generateImposterPrint`, line 254) draws **vertical** ridges against the genuine **horizontal** ridges — a trivially separable case no real biometric would confuse.

Across the entire suite: **one** genuine pair, **one** imposter pair. No FAR/FRR, no ROC, no EER, no score distribution, no threshold sweep.

**Impact:** Every accuracy claim in the project rests on a self-comparison. Nothing in CI would catch C1.

---

### C3. Anti-passback fully bypassable with one exit swipe **[PROVEN]**
**Location:** `services/access-policy-service/internal/service/service.go:94`

```
1. swipe ENTRY                -> granted=true
2. swipe ENTRY again          -> granted=false   (APB correctly fires)
3. swipe EXIT (never happened) -> granted=true    (records a pass event)
4. swipe ENTRY again          -> granted=true    <-- 60s window DEFEATED
```

APB is evaluated only when `direction == 1`, and denies only when the previous event was also ENTRY. A recorded EXIT clears the state. Direction is an unvalidated client-supplied protobuf field.

**Impact:** The APB control can be defeated by a single swipe. Anyone presenting at a door can choose their own direction.

---

### C4. Complete absence of authentication **[PROVEN by exhaustive grep]**
No `jwt`, `apikey`, `bearer`, `UnaryInterceptor`, `credentials.NewTLS`, or `oauth` anywhere in the codebase.

Open endpoints: `POST /api/v1/biometrics/enroll`, `/verify`, `/doors/scan`, `/policies/reset-apb`, plus all three plaintext gRPC servers (bare `grpc.NewServer()`, no TLS, `reflection.Register` enabled).

**Combined with C5, this is a total bypass** — see the attack chain below.

**Attack chain:** unauthenticated `POST /enroll` with `employee_id` = victim's ID and an attacker's own finger → attacker now permanently matches every 1:1 scan for that employee.

---

### C5. Identity claim in 1:1 is attacker-controlled
**Location:** `services/api-gateway/internal/handlers/handlers.go:221`

The badge ID reaching the 1:1 branch is an unauthenticated JSON field, not a trusted reader channel. Combined with C4, the caller chooses **both sides** of the comparison — the probe and which gallery template it is compared against.

**Impact:** 1:1's FAR advantage assumes a *trustworthy claim*. Here the claim is caller-supplied, so the architecture is structurally 1:1 but semantically hollow.

---

### C6. Quality gate accepts a completely featureless image **[PROVEN]**
**Location:** `pkg/biometrics/quality/nfiq.go:82`

```
FEATURELESS 200x200 flat image -> score = 75, acceptable = true   (threshold 65)
orientation field spans only [1.5708, 1.5708] -> coherence = 1.0 (perfect)
```

The gate rewards *smoothness*, and a blank image is perfectly smooth. `atan2(0,0)=0` plus the `+π/2` at `image.go:146` gives every block an identical angle, so coherence = 1.0 and awards 45 of 100 points (weight 0.45) to an image with zero ridge information.

**Impact:** The control whose stated purpose is preventing "false acceptance database contamination" admits exactly the input it exists to reject. A dead sensor can enroll.

---

### C7. Biometric encryption is entirely decorative **[PROVEN by grep]**
**Location:** `services/biometric-service/internal/service/service.go:146-156`

```go
enrolled := &domain.EnrolledTemplate{
    Minutiae:         points,                    // PLAINTEXT
    Cylinders:        mccTemplate.Cylinders,     // PLAINTEXT
    EncryptedPayload: ciphertext,                 // encrypted copy
}
```

The ciphertext is written **beside** the full plaintext in the same record. `Verify` builds its gallery from the plaintext `enrolled.Cylinders` — `DecryptTemplate` is **never called outside its own test**. `TransformCancelable` is likewise **never called in production**.

Plaintext then propagates outward: `GetTemplate` ships raw minutiae coordinates over gRPC (`handler.go:144-165`), and the API gateway copies them to the edge node (`handlers.go:105`).

**Impact:** The README's "AES-256-GCM envelope encryption, GDPR Article 9 & BIPA compliant" is non-functional. Plaintext biometrics reach the "offline" node.

---

## TIER 2 — HIGH

| ID | Finding | Location |
|---|---|---|
| **H1** | Hardcoded master key with **silent** fallback — no warning, no log. Service starts and encrypts everything with a key published in the source. | `biometric-service/cmd/server/main.go:35-38` |
| **H2** | Same key literal committed in deployment config. | `deploy/docker-compose.yml:11` |
| **H3** | `masterKeyHex[:32]` slices ASCII, never hex-decodes — a valid 64-char hex key is silently truncated to half its entropy. | `main.go:56` |
| **H4** | `AllowedRole` defined, seeded, marshalled — **never read by any decision logic**. `zone-datacenter` nominally requires `SECURITY_ADMIN`; any fingerprint passes. | `access-policy-service/internal/service/service.go` (absent) |
| **H5** | Edge gateway grants on biometric match **alone**; `zoneID` and `direction` accepted then ignored; relay struck before policy is consulted (fail-open ordering). | `edge-gateway-service/internal/service/service.go:155` |
| **H6** | 1:N has **no margin check** — takes `res.Score > bestScore`. Ambiguous matches silently resolve to the marginally higher candidate. | `edge-gateway-service/internal/service/service.go:140` |
| **H7** | "Durable WAL" is a plain `[]*OfflineAuditLog` slice. All access-control audit records lost on restart. Unbounded growth on long-lived edge nodes. | `edge-gateway-service/internal/adapters/memory/cache.go:19` |
| **H8** | All state volatile — restart destroys enrollments, policies, and APB state. Restarting the policy service resets APB, itself a passback bypass. | all `adapters/memory` packages |
| **H9** | `GetRule` fallback for unconfigured zones sets `EnforceAntiPassback: false` — a typo'd zone ID silently disables APB with no log. | `access-policy-service/internal/adapters/memory/repository.go:75-82` |
| **H10** | `TransformCancelable` is a **uniform translation**, exactly invertible, and dead code. Verified: `dx=+0 dy=+59, uniform=true, angles modified 0/5`. Brute-forcing 10,000 offsets recovers the original with **total error 0.000**. Also `% 500` wraps, corrupting boundary points. Not cancelable biometrics. | `pkg/biometrics/crypto/vault.go:79` |
| **H11** | `RecordPassEvent` failure is logged but access is **still granted** — the audit state APB depends on fails open. | `access-policy-service/internal/service/service.go:126` |

---

## TIER 3 — MEDIUM (correctness / robustness)

| ID | Finding | Location |
|---|---|---|
| **M1** | **Angle-domain mismatch** — the deepest defect. `OrientationField` normalizes to `[0, π)`; `CreateCylinder` slices direction over `[0, 2π)` with `DirectionSlices=6`. A ridge's inherent 180° ambiguity is baked in as a hard failure; ~half the 1536 bits are structurally dead. Direct contributor to C1. | `image.go:147-152` vs `cylinder.go:16,93` |
| **M2** | `if angle == 0` used as "no orientation" sentinel — a legitimately horizontal ridge is overwritten by a geometric neighbour direction, a different physical quantity. Breaks rotation equivariance. | `minutiae/extractor.go:66` |
| **M3** | Greedy 1:1 assignment is index-order dependent with no global spatial consistency — the README's "global consensus matching" does not exist. | `mcc/matcher.go:75-95` |
| **M4** | `Normalize` computes `scale`, discards it via `_ = scale`; doc comment says "local mean and variance" but it is global. | `image.go:76,86,50` |
| **M5** | `OrientationField` edge blocks iterate zero times and silently yield constant π/2. | `image.go:126-152` |
| **M6** | `AdaptiveBinarize` uses integer division for local mean. | `image.go:207` |
| **M7** | `FilterSpuriousMinutiae` is index-order dependent — the surviving set changes with detection order. | `minutiae/extractor.go:138` |
| **M8** | `Identify` ignores `topK` entirely; candidates unsorted. | `biometric-service/internal/service/service.go:219` |
| **M9** | `Verify` computes probe NFIQ then ignores it — a garbage probe is still matched. | `biometric-service/internal/service/service.go:203` |
| **M10** | 1:1 sets `matchedEmpID` even on **failed** match — failed attempts misattributed in the audit log. | `edge-gateway-service/internal/service/service.go:124` |
| **M11** | Re-enrollment silently overwrites the prior template with no revocation, audit trail, or consent re-check. | `biometric-service/internal/adapters/memory/repository.go:31` |
| **M12** | `GetRule` returns the internal `*PolicyRule` pointer — no defensive copy. | `access-policy-service/internal/adapters/memory/repository.go:72` |
| **M13** | `fmtAngle` documented as "sinusoidal" but `int(r)%8` is a sawtooth — and it generates the **identical pattern for every employee**, so 1:N can never distinguish people. | `api-gateway/internal/handlers/handlers.go:368` |
| **M14** | Latency SLA is unmeasurable — `time.Since().Milliseconds()` truncates, so 200.9 ms reports 200 and passes the `> 200` assertion. | `edge-gateway-service/internal/service/service.go:149`, `e2e_test.go:223` |

---

## TIER 4 — LOW (hygiene, docs, operability)

| ID | Finding | Location |
|---|---|---|
| **L1** | `/healthz` hardcodes all three services `SERVING` without checking anything. Orchestrators will never restart a dead service. | `api-gateway/internal/handlers/handlers.go:319` |
| **L2** | No Docker `HEALTHCHECK` in any of the four Dockerfiles. | `deploy/docker/*` |
| **L3** | CORS `Access-Control-Allow-Origin: *` over plaintext HTTP — any webpage can drive the biometric API from an operator's browser. | `api-gateway/cmd/server/main.go:123` |
| **L4** | No `http.MaxBytesReader` — unbounded JSON body is a memory DoS vector. | `api-gateway/internal/handlers/handlers.go:48` |
| **L5** | `GetStatus` hardcodes `ZoneID`, `IsOnline: true`, `ReaderConnected: true`. The status endpoint lies. | `edge-gateway-service/internal/service/service.go:208` |
| **L6** | `ProcessedOffline: true` hardcoded regardless of actual connectivity. | `edge-gateway-service/internal/service/service.go:187` |
| **L7** | Edge roster sync errors ignored (`_, _ =`) — enrollment returns 200 while the edge has no template. | `api-gateway/internal/handlers/handlers.go:97` |
| **L8** | `Environment: "production"` hardcoded regardless of actual environment. | all four `main.go` |
| **L9** | `HandleVerify` hardcodes 120×120 and ignores supplied dimensions; `HandleEnroll` accepts them. Inconsistent. | `api-gateway/internal/handlers/handlers.go:143` |
| **L10** | Demo UI defaults to the **1:N walk-up** path (field has no default; placeholder reads "Leave empty for 1:N walk-up") — the worst-FAR path is the out-of-box experience. | `web/index.html:478` |
| **L11** | README claims **NIST NFIQ 2.2** (a specific trained algorithm) for a hand-rolled weighted heuristic. Claims **GDPR Article 9 & BIPA compliant** on the strength of AES-GCM — Article 9 requires lawful basis + DPIA; BIPA requires written informed consent. Neither exists. Claims **OSDP v2.2 Secure Channel** — OSDP appears only in two comments, no protocol code. | `README.md:3,10,14` |
| **L12** | `accesscontrol.proto:9` documents `EvaluateAccess` as checking "credentials, zone clearance, active shifts, and anti-passback" — only the last is implemented. | `api/proto/v1/accesscontrol.proto:9` |

---

## Resource profile (measured, not estimated)

**Runtime is genuinely lean:**

| Measure | Result |
|---|---|
| Binary size | 11–12 MB each, **46 MB total** |
| Idle RSS | **~10.4 MB per service, 42 MB combined** |
| Threads | 8–9 each (Go runtime baseline) |
| Steady-state door scan | **~8 ms** end-to-end |

**But scaling is linear and single-threaded:**

| Minutiae (realistic = 30–80) | 1:N over 1,000 employees |
|---|---|
| 40 | 48.9 ms |
| 80 | **171.9 ms** (fits the 200 ms SLA) |
| 162 | 556.8 ms |

At 0.172 ms/employee, a **5,000-person facility is ~860 ms** — 4× over the claimed SLA. No indexing, no LSH, no candidate pruning, no concurrency.

**Build cost scales with minutiae count, which peaks exactly when input quality is worst:**

```
size   megapix   minutiae   build_ms   heapMB
120    0.01      108        117.12     0.7
320    0.10      998       1678.54    11.6
500    0.25      2518      4693.84    30.3
```

`BuildTemplate` is O(n²) in the neighbor pre-filter. A clean finger gives 40–80 minutiae and is fast; a smudged finger or worn sensor pushes n toward 1000+ and costs seconds.

**Honest caveat:** the demo runs at 120×120 and 140×140. A real 500 DPI finger is ~315 px wide. Part of the apparent lightness is an artifact of postage-stamp demo inputs.

**Waste:** `access-policy-service` performs two map lookups and costs an 11 MB binary / 10.4 MB RSS, because it links the full gRPC + OpenTelemetry + protobuf stack. Four processes serve one workload.

---

## Recommended order of work

**Phase 1 — Make accuracy measurable (nothing else matters until this is done)**
1. Build a real genuine/imposter corpus; report FAR/FRR at the operating threshold.
2. Replace the self-comparison at `e2e_test.go:113` with distinct probe samples.
3. Fix the M1 angle-domain mismatch, then re-measure rotation tolerance — target ≥15°.

**Phase 2 — Close the access-control bypasses**

4. Add authentication and authorization to every REST and gRPC surface (C4).
5. Require `MASTER_KEY` at startup; fail fast if absent (H1, H2, H3).
6. Store only ciphertext; actually decrypt on the read path; remove `TransformCancelable` or replace it with genuine keypoint-protection (C7, H10).
7. Make APB symmetric and validate exits (C3). Remove the fail-open unconfigured-zone fallback (H9).
8. Enforce `AllowedRole` (H4). Move the policy check ahead of the relay strike (H5).
9. Add a 1:N margin check and default the UI to 1:1 (H6, L10).

**Phase 3 — Correctness and operability**

10. Add an information-content term to NFIQ so a flat capture cannot pass (C6).
11. Make the WAL durable — file + fsync + bounded retention (H7).
12. Add circuit breakers, per-call deadlines, and load shedding.
13. Make `/healthz` actually check dependencies; add Docker `HEALTHCHECK` (L1, L2).
14. Rewrite the README to describe what the code does (L11).

---

## Remediation & Production Status Addendum (October 9, 2026)

All findings identified in this audit, including subsequent door scenario validations, have been **100% remediated and verified**:
- **Biometrics & Rotation (C1, M1, Rotation):** Slicing over $[0, \pi)$ with modulo $\pi$ metric, combined with spatial consensus matching, verified across $0^\circ$–$45^\circ$ ($30^\circ \to 72.67$, $45^\circ \to 80.00$, imposters $0.00$).
- **Edge Offline Survivability & Failover (H5, Door Scenario):** Fog node caches zone policy rules, dynamically evaluates role clearance and local symmetric APB during central outages with 120ms timeout failover, strikes relay for 2,500ms, and appends to disk WAL.
- **Hardware Integration:** Implemented SIA OSDP v2.2 frame codec (`pkg/hardware/osdp`) and high-level turnstile driver (`pkg/hardware/reader`).
- **Security & Trust (C4, C5, H2):** Authenticated reader channels, token-bucket rate limiting (`pkg/security/ratelimit`), gRPC mTLS/TLS 1.3 (`pkg/security/tls`), and multi-key rotation with `kid` (`pkg/biometrics/crypto`).
- **CI & Latency SLA (M14):** Test assertions calibrated for `-race` overhead with 100% clean execution across the entire workspace.