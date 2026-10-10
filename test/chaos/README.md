# Chaos Test Suite — AegisBiometrics

Robustness (chaos) testing for the platform. These tests deliberately abuse the
system: malformed images, degraded fingerprints, hostile inputs, dependency
outages, extreme concurrency and resource pressure.

## Running

```bash
# Full chaos suite (runs the coverage gate)
go test ./test/chaos/ -v -count=1

# Auth/CORS chaos (lives with the internal middleware package)
go test ./services/api-gateway/internal/middleware/ -v -count=1

# Concurrency dimensions under the race detector
go test ./test/chaos/ -race -run 'TestChaos_(Concurrent|DeepFanout)' -count=1

# Extend a fuzz target beyond its seed corpus
go test ./test/chaos/ -run XXX -fuzz FuzzVaultDecrypt -fuzztime 60s
```

Everything is in-process: no ports are bound beyond ephemeral loopback
listeners, no services need to be running first, and no state leaks between
tests.

## Design philosophy

These tests do **not** assert that the system behaves ideally on every input.
They assert five invariants that must never break:

| Invariant | Meaning |
|---|---|
| `INV-NOPANIC` | No RPC or algorithm may panic on any input. |
| `INV-BOUNDED` | No unbounded memory or time consumption. |
| `INV-NOSECRET` | Templates must never be returned in plaintext. |
| `INV-NOBYPASS` | No input may produce an unauthorized grant. |
| `INV-CORRECT` | Malformed input must be rejected, not silently accepted. |
| `INV-DETERMINISM` | Identical probes against an unchanged gallery must agree. |

Accuracy characteristics — monotonicity of match scores, FAR/FRR behaviour,
NFIQ scoring quirks — are **measured and reported** through the findings
ledger rather than asserted, because several are known to be imperfect and are
tracked separately. Asserting them would produce a permanently red suite, and
a suite that is always red gets ignored.

## The findings ledger

Every case registers itself with `record(dim, name)`. Observations that are
characterised rather than asserted go through `observe(dim, msg)`. At the end
of the run, `TestMain` prints a per-dimension breakdown:

```
=========================================================
  CHAOS COVERAGE: 2041 / 1000 cases across 38 dimensions
=========================================================
```

The gate **fails the build** if the suite drops below its contractual minimum,
and also fails if any required dimension reports zero cases — so a suite that
meets the number by silently losing coverage cannot pass.

### Why the gate lives in `TestMain`, not a test function

Go executes fuzz targets in a **separate phase after** all regular tests. A gate
implemented as an ordinary `func TestZZCoverageGate(t *testing.T)` therefore
always evaluates *before* the fuzz seed corpus has run, and reports those
dimensions as empty. `TestMain` wraps `m.Run()`, so its post-run checks execute
after everything — tests and fuzz seeds alike.

An isolated run (`-run TestChaos_ImageDegradation`) will deliberately fail the
gate: it is the point of the gate, since it catches a suite that silently
stopped covering things.

Two flags skip the gate, and both are detected by **prefix** matching against
the test binary's own arguments:

- `-short`
- `-fuzz=<target>`, because a fuzzing run is isolated by construction

The prefix matters more than it looks. `go test -short` hands the binary
`-test.short=true`, never a bare `-test.short`, so an exact string comparison
silently never matched and `-short` skipped nothing — while the README claimed
it did. And under `-fuzz`, `go test` re-executes the binary once per fuzzing
worker with its own argument set, so `-test.short` is not carried across at
all and fuzzing has to be detected from `-test.fuzz` directly.

## Dimensions

| Dimension | What it attacks |
|---|---|
| `image-degradation` | blur, oily, wet, dry, partial, rotation, translation, motion blur, noise |
| `combined-degradation` | pairwise and randomised-triple cross products of the above |
| `malformed-image` | nil/short/long buffers, extreme dimensions, degenerate pixel patterns |
| `boundary-dimensions` | 8×8 up to 360×360, plus non-square aspect ratios |
| `degenerate-patterns` | periodic inputs that carry no local variation |
| `identification-cohort` | 1:N search across a 12-person cohort, plus strangers |
| `lookup-abuse` | hostile identifiers against an empty store |
| `enroll-abuse` | hostile identifiers written into the store |
| `policy-edge-abuse` | hostile zone/turnstile/employee values through policy and edge |
| `enum-boundaries` | finger position, direction, DPI, score and timestamp extremes |
| `apb-sequences` | every swipe sequence up to length 6 (126 sequences) |
| `apb-exit-gating` | exit without a prior entry |
| `apb-zones` | zone × role matrix |
| `apb-verify-flag` | `BiometricVerified` × score × zone matrix |
| `apb-window-recovery` | entry/exit cycles that must recover |
| `crypto-key-length` | vault key length validation |
| `crypto-tamper` | bit flips, truncation, extension, wrong key |
| `crypto-cancelable` | cancelable-transform recoverability |
| `crypto-rotation` | key rotation must not orphan existing payloads |
| `serialization` | cylinder wire format, truncation, mutation |
| `matcher-invariants` | empty/duplicate/extreme templates |
| `concurrency-*` | duplicate enrol, parallel verify, APB contention, scan vs sync |
| `deep-fanout` | 200-way simultaneous load |
| `dependency-*` | policy down, standalone mode, dead endpoints, context cancellation |
| `resource-*` | roster scaling, large images, sustained load, audit volume |
| `fuzz-*` | Go native fuzz targets: deserialise, vault, pipeline, APB |
| `security-tls` | TLS config matrices, silent downgrade, invalid CA material |
| `security-ratelimit` | token-bucket boundaries, negative consumption, concurrent bursts |
| `security-osdp` | frame corruption/truncation, CRC, hostile transport, relay bounds |
| `security-reader` | turnstile driver against dead, silent and garbage peripherals |
| `auth-credentials` | 10 header channels × 26 credential shapes (middleware pkg) |
| `auth-cors` | origin reflection and wildcard+credentials (middleware pkg) |

## Fixed defects

Chaos testing found real defects, not flaky tests. All three were tracked as
skips via a `knownDefect(...)` helper so CI stayed green while the finding
remained visible in the ledger, and **all three are now fixed** — the skips are
gone and the assertions underneath run as hard `INV-BOUNDED` failures.

| ID | Defect | Impact | Status |
|---|---|---|---|
| `OSDP-001` | `osdp.Driver.SendCommand` blocked in `io.ReadFull` with no `ctx` check | A peripheral returning `(0, nil)` wedged `Poll` and `StrikeRelay` forever | **Fixed** |
| `OSDP-002` | The bus lock was held across that blocking read | After one wedged transport every later OSDP call deadlocked; the door could not recover without a process restart | **Fixed** |
| `OSDP-003` | `reader.PollEvent` / `StrikeRelay` inherited the above | The turnstile could not be commanded open or closed after a reader fault | **Fixed** |

The fix, in `pkg/hardware/osdp/driver.go` and `pkg/hardware/reader/reader.go`:

- **Every read and write is bounded by the caller's context.** Transports that
  support deadlines (`net.Conn`, `os.File`) get `SetReadDeadline`/`SetWriteDeadline`
  from the context; everything else runs behind a watchdog goroutine.
- **The bus lock is a channel, not a `sync.Mutex`,** so a queued caller abandons
  the wait when its own context expires instead of inheriting someone else's timeline.
- **Status reporting is on a separate `RWMutex` that is never held across I/O.**
  Previously `IsOnline()` took the same mutex as the blocking read, so a single
  silent peripheral also froze the health check.
- **An abandoned transaction poisons the transport.** OSDP is strict
  request/response on a shared bus, so once a reply has been partially consumed
  frame boundaries can no longer be trusted; later calls fail fast with
  `ErrTransportPoisoned` rather than misparsing the stream.
- **An unbounded caller still gets a 2s backstop** (`defaultIOTimeout`), so
  forgetting a deadline cannot reintroduce OSDP-001 through the back door.

Regression coverage lives in `pkg/hardware/osdp/driver_resilience_test.go`
(`TestOSDP001_*`, `TestOSDP002*`) and in the `security-osdp` / `security-reader`
chaos dimensions.

## A note on the test corpus

A naive "uniform parallel ridges" fingerprint generator is **degenerate**: every
local neighbourhood looks identical, so every MCC cylinder is near-identical
and the matcher saturates — reporting ~100% matched pairs and scores of 93-99
for structurally different inputs. That produces false alarms that teach people
to ignore the suite.

`LoopPrint` in the harness generates prints with a core, radiating ridge flow,
angular radius modulation and a per-angle phase offset, so minutiae land in
characteristic positions and a rejected probe actually means something. With a
realistic corpus the matcher discriminates correctly; the degenerate behaviour
is captured separately and explicitly in `degenerate-patterns` rather than
being allowed to masquerade as a vulnerability elsewhere.