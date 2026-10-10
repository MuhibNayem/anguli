package chaos

import (
	"fmt"
	"os"
	"sort"
	"testing"
)

// This file sorts last alphabetically so the report runs after every other
// chaos test. The AUTHORITATIVE coverage gate lives in TestMain at the bottom
// of this file, because Go executes fuzz targets in a separate phase *after*
// all regular tests — a gate that ran as an ordinary test function would
// always evaluate before the fuzz seed corpus had registered its cases.

const TargetCoverage = 1000

// requiredDimensions must each report at least one case. This stops a suite
// from meeting the numeric target by silently losing an area of coverage.
var requiredDimensions = []string{
	"image-degradation",
	"malformed-image",
	"boundary-dimensions",
	"degenerate-patterns",
	"lookup-abuse",
	"enroll-abuse",
	"policy-edge-abuse",
	"enum-boundaries",
	"apb-sequences",
	"apb-exit-gating",
	"apb-zones",
	"apb-verify-flag",
	"apb-window-recovery",
	"crypto-key-length",
	"crypto-tamper",
	"crypto-cancelable",
	"crypto-rotation",
	"serialization",
	"matcher-invariants",
	"concurrency-duplicate-enroll",
	"concurrency-verify",
	"concurrency-policy",
	"concurrency-edge",
	"deep-fanout",
	"dependency-policy-down",
	"dependency-standalone",
	"dependency-dead",
	"dependency-context",
	"resource-roster",
	"resource-large-image",
	"resource-sustained",
	"resource-audit",
	"combined-degradation",
	"identification-cohort",
	"fuzz-deserialize",
	"fuzz-vault",
	"fuzz-pipeline",
	"fuzz-apb",
	"security-tls",
	"security-ratelimit",
	"security-osdp",
	"security-reader",
}

// TestZZCoverageReport prints the full breakdown. It does not itself gate —
// TestMain does that after the fuzz phase has completed.
func TestZZCoverageReport(t *testing.T) {
	if testing.Short() {
		t.Skip("coverage report skipped in -short mode")
	}
	dumpLedger(t)
	t.Logf("interim count (fuzz targets run later): %d", CaseCount())
}

// TestZZLedgerSanity keeps the ledger internally consistent.
func TestZZLedgerSanity(t *testing.T) {
	dims := dimensionCounts()
	sum := 0
	for _, v := range dims {
		sum += v
	}
	if sum != CaseCount() {
		t.Errorf("ledger inconsistency: dimension sums to %d but total is %d", sum, CaseCount())
	}
	t.Logf("ledger consistent: %d cases / %d dimensions", sum, len(dims))
}

// TestMain is the authoritative coverage gate. It runs after m.Run() has
// executed every test INCLUDING the fuzz seed corpus phase, which Go schedules
// after the regular tests.
//
//	go test ./test/chaos/          # full suite, gate enforced
//	go test ./test/chaos/ -short   # gate skipped
//	go test ./test/chaos/ -run XXX # isolated run, gate intentionally fails
func TestMain(m *testing.M) {
	short := false
	for _, a := range os.Args {
		if a == "-test.short" || a == "-short" {
			short = true
		}
	}
	isolated := false
	for _, a := range os.Args {
		if a == "-test.run" || a == "-run" {
			isolated = true
		}
	}

	code := m.Run()
	if short {
		os.Exit(code)
	}

	fmt.Fprintln(os.Stderr)
	dumpLedgerW(os.Stderr)

	total := CaseCount()
	dims := dimensionCounts()
	keys := make([]string, 0, len(dims))
	for k := range dims {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	fmt.Fprintln(os.Stderr, "=========================================================")
	fmt.Fprintf(os.Stderr, "  CHAOS COVERAGE: %d / %d cases across %d dimensions\n", total, TargetCoverage, len(dims))
	fmt.Fprintln(os.Stderr, "=========================================================")

	failed := code != 0
	if isolated {
		fmt.Println("NOTE: isolated run (-run) detected; the coverage gate is expected to")
		fmt.Println("      fail because most dimensions were skipped. Run the full suite.")
		if !failed {
			failed = true
		}
	}

	if total < TargetCoverage {
		fmt.Fprintf(os.Stderr, "FAIL: chaos coverage %d is below the contractual minimum of %d\n", total, TargetCoverage)
		failed = true
	}

	missing := []string{}
	for _, r := range requiredDimensions {
		if dims[r] == 0 {
			missing = append(missing, r)
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "FAIL: chaos dimensions with zero cases: %v\n", missing)
		failed = true
	}

	sum := 0
	for _, v := range dims {
		sum += v
	}
	if sum != total {
		fmt.Fprintf(os.Stderr, "FAIL: ledger inconsistency: dimensions sum to %d but total is %d\n", sum, total)
		failed = true
	}

	if failed {
		os.Exit(1)
	}
	os.Exit(0)
}
