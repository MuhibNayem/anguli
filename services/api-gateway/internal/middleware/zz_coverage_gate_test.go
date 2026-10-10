package middleware

import "testing"

// This file sorts last so the gate runs after every other chaos test in this
// package has had the chance to register its cases.

// TestZZAuthCoverageGate runs last (alphabetical ordering) and asserts this
// package executed its contractual number of cases.
func TestZZAuthCoverageGate(t *testing.T) {
	if testing.Short() {
		t.Skip("auth coverage gate skipped in -short mode")
	}
	t.Log("---- AUTH CHAOS DIMENSION BREAKDOWN ----")
	total := 0
	for dim, n := range dimCounts {
		t.Logf("  %-24s %5d cases", dim, n)
		total += n
	}
	t.Logf("  %-24s %5d TOTAL", "ALL", total)
	if caseCount != total {
		t.Errorf("auth ledger inconsistency: dimensions sum to %d but counter is %d", total, caseCount)
	}
	if caseCount < ChaosTargetCoverage {
		t.Errorf("auth chaos coverage %d is below the contractual minimum of %d", caseCount, ChaosTargetCoverage)
	}
	for _, required := range []string{"auth-credentials", "auth-cors"} {
		if dimCounts[required] == 0 {
			t.Errorf("auth chaos dimension %q has zero cases", required)
		}
	}
}
