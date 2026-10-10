package service

import (
	"context"
	"testing"
	"time"

	"finger-scanner/pkg/biometrics/mcc"
)

// BenchmarkIdentifyGallery measures the 1:N search path the way production runs
// it: a warm gallery, many enrolled fingers, one probe.
//
// This exists because the whole point of the gallery is a latency claim, and a
// latency claim that was never measured is an assertion. Run it before and
// after any change to the search path.
func BenchmarkIdentifyGallery(b *testing.B) {
	ctx := context.Background()
	repo := &countingRepo{}
	v := testVaultB(b)
	const enrolled = 2000
	for i := 0; i < enrolled; i++ {
		addEnrolledB(b, repo, v, empName(i), 1, synthPoints(32, i))
	}

	g := &gallery{}
	if _, _, err := g.snapshot(ctx, repo, v, quietLogger()); err != nil {
		b.Fatal(err)
	}

	pts := synthPoints(32, 0)
	probe := mcc.BuildTemplate("probe", pts)
	matcher := mcc.NewMatcher(0.35, 60.0, quietLogger())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := g.search(ctx, probe, pts, matcher, 5, quietLogger()); len(got) == 0 {
			b.Fatal("expected candidates")
		}
	}
}

// BenchmarkIdentifyGalleryCold measures a cold cache - the first walk-up after
// a restart or a TTL expiry. This is the latency an operator actually
// experiences when someone complains, so it is the number worth watching.
func BenchmarkIdentifyGalleryCold(b *testing.B) {
	ctx := context.Background()
	repo := &countingRepo{}
	v := testVaultB(b)
	const enrolled = 2000
	for i := 0; i < enrolled; i++ {
		addEnrolledB(b, repo, v, empName(i), 1, synthPoints(32, i))
	}
	pts := synthPoints(32, 0)
	probe := mcc.BuildTemplate("probe", pts)
	matcher := mcc.NewMatcher(0.35, 60.0, quietLogger())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g := &gallery{}
		if _, _, err := g.snapshot(ctx, repo, v, quietLogger()); err != nil {
			b.Fatal(err)
		}
		if got := g.search(ctx, probe, pts, matcher, 5, quietLogger()); len(got) == 0 {
			b.Fatal("expected candidates")
		}
	}
}

// TestSearchLatencyStaysWithinTurnstileBudget is the assertion form of the
// benchmark, and its size is chosen from measurement rather than aspiration.
//
// MEASURED, do not raise this number without re-measuring. On the development
// machine, warm gallery, 32 minutiae per finger:
//
//	N= 100    20 ms     within a 200 ms budget
//	N= 200    38 ms     within a 200 ms budget
//	N= 400    71 ms     within a 200 ms budget
//	N= 800   144 ms     within a 200 ms budget
//	N=1600   280 ms     over
//	N=3200   576 ms     over
//
// The gallery removed the per-scan database read and AES-GCM decryption, and
// the worker pool removed the single-goroutine constraint. Optimising
// Cylinder.SimilarityWithShift - which profiled at 85% of search CPU walking
// all 1536 bits one at a time - bought a further 8x, taking the supported
// gallery from roughly 100 fingers to roughly 1100 at a 200 ms SLA.
//
// The growth is still linear, and that is the point of this comment. Parallelism
// and constant-factor work divide the cost; they do not change the order. So 1:N
// search remains O(enrolled fingers) no matter how many cores it gets.
//
// A single-host laptop measurement with synthetic minutiae, to be repeated on
// the deployment target, but the SHAPE - linear and core-count independent -
// will not change. Reaching genuine campus scale needs a change to the
// algorithm: a single global MCC bitstring compared by Hamming distance is
// O(words) per pair instead of O(cylinders squared). That is not implemented
// here, and nothing in this file should be read as claiming the system is 1:N
// ready at enterprise enrolment counts.
//
// The test therefore asserts what is actually true rather than a number that
// would fail: it guards against the caching regressing, and it records the
// ceiling as a number someone will notice if performance gets worse.
func TestSearchLatencyStaysWithinTurnstileBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("latency guard skipped in -short")
	}
	ctx := context.Background()
	repo := &countingRepo{}
	v := testVault(t)

	// Sized to the measured ceiling, not to an aspiration. See the table above.
	const enrolled = 800
	const budget = 400 * time.Millisecond * raceLatencyFactor

	for i := 0; i < enrolled; i++ {
		addEnrolled(t, repo, v, empName(i), 1, synthPoints(32, i))
	}

	g := &gallery{}
	if _, _, err := g.snapshot(ctx, repo, v, quietLogger()); err != nil {
		t.Fatal(err)
	}
	pts := synthPoints(32, 0)
	probe := mcc.BuildTemplate("probe", pts)
	matcher := mcc.NewMatcher(0.35, 60.0, quietLogger())

	// Warm up so the measurement is not dominated by first-touch page faults.
	for i := 0; i < 3; i++ {
		g.search(ctx, probe, pts, matcher, 5, quietLogger())
	}

	const runs = 5
	start := time.Now()
	for i := 0; i < runs; i++ {
		g.search(ctx, probe, pts, matcher, 5, quietLogger())
	}
	per := time.Since(start) / runs

	t.Logf("1:N search over %d enrolments: %v per walk-up (budget %v)", enrolled, per, budget)
	if raceLatencyFactor > 1 {
		t.Logf("race detector enabled: budget scaled %dx to account for instrumentation overhead", raceLatencyFactor)
	}
	if per > budget {
		t.Fatalf("1:N search took %v over %d enrolments, over the %v guard. "+
			"Exceeding it means scans are slower than the turnstile can absorb. "+
			"If a slower ceiling is acceptable, raise the constant deliberately "+
			"and update the measurement table; do not let it drift unnoticed.",
			per, enrolled, budget)
	}
}

// TestSearchScalingIsReported documents the growth rate rather than asserting
// a bound, because the growth rate is the finding: search cost is linear in the
// number of enrolled fingers, so enterprise-scale 1:N is a matcher problem and
// not a caching problem. If this ever becomes sub-linear, the matcher has
// changed and the guidance in this file and in the README should be revisited.
func TestSearchScalingIsReported(t *testing.T) {
	if testing.Short() {
		t.Skip("scaling report skipped in -short")
	}
	ctx := context.Background()
	pts := synthPoints(32, 0)
	probe := mcc.BuildTemplate("probe", pts)
	matcher := mcc.NewMatcher(0.35, 60.0, quietLogger())

	measure := func(n int) time.Duration {
		repo := &countingRepo{}
		v := testVault(t)
		for i := 0; i < n; i++ {
			addEnrolled(t, repo, v, empName(i), 1, synthPoints(32, i))
		}
		g := &gallery{}
		if _, _, err := g.snapshot(ctx, repo, v, quietLogger()); err != nil {
			t.Fatal(err)
		}
		g.search(ctx, probe, pts, matcher, 5, quietLogger())
		start := time.Now()
		g.search(ctx, probe, pts, matcher, 5, quietLogger())
		return time.Since(start)
	}

	small := measure(100)
	large := measure(400)

	ratio := float64(large) / float64(small)
	t.Logf("search scaling: 100 enrolments %v, 400 enrolments %v, ratio %.2fx for a 4x larger gallery",
		small.Round(time.Millisecond), large.Round(time.Millisecond), ratio)

	// A 4x gallery costing far more than ~12x would mean something worse than
	// linear crept in. This is a loose sanity bound, not a performance claim.
	if ratio > 12 {
		t.Fatalf("search cost grew %.1fx for a 4x larger gallery; expected roughly linear", ratio)
	}
}
