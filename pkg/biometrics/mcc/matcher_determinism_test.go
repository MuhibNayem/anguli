package mcc

import (
	"context"
	"io"
	"log/slog"
	"math/rand"
	"testing"

	"finger-scanner/pkg/biometrics/minutiae"
)

func detPoints(n, seed int) []minutiae.Minutia {
	r := rand.New(rand.NewSource(int64(seed)))
	out := make([]minutiae.Minutia, n)
	for i := range out {
		out[i] = minutiae.Minutia{
			X:     uint16(r.Intn(512)),
			Y:     uint16(r.Intn(512)),
			Angle: r.Float64(),
		}
	}
	return out
}

func quietMatcher() *Matcher {
	return NewMatcher(0.35, 60.0, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// TestVerifyIsDeterministic is a regression test for a defect found while
// optimising the search path.
//
// Step 3 picks the spatial-consensus cluster with the most inliers by ranging
// over a Go map. Go randomises map iteration order, and the original comparison
// kept the first cluster of maximum size, so the winner depended on runtime
// iteration order rather than on the inputs.
//
// On random templates the same probe matched against the same finger returned a
// DIFFERENT score on repeated calls in roughly half of all trials - matched
// pair counts and scores both moved, and in some cases a pair count changed.
//
// For access control that is not cosmetic. A score near the 60-point threshold
// decides admit or deny; if the same finger, same finger placement and same
// template can score differently across attempts, then a deny can be
// unreproducible from the captured data, an incident cannot be reconstructed,
// and a test that fails intermittently cannot be told apart from a regression.
//
// Asserting the invariant, rather than one known-good score, is what makes this
// a regression test: any future change that reintroduces an order-dependent
// tie-break fails here regardless of which score it lands on.
func TestVerifyIsDeterministic(t *testing.T) {
	m := quietMatcher()
	ctx := context.Background()

	for seed := 0; seed < 120; seed++ {
		probe := BuildTemplate("probe", detPoints(32, seed))
		gallery := BuildTemplate("gallery", detPoints(32, seed+1000))

		first, err := m.Verify(ctx, probe, gallery)
		if err != nil {
			t.Fatalf("seed=%d: %v", seed, err)
		}

		for repeat := 0; repeat < 15; repeat++ {
			again, err := m.Verify(ctx, probe, gallery)
			if err != nil {
				t.Fatalf("seed=%d repeat=%d: %v", seed, repeat, err)
			}
			if again.Score != first.Score ||
				again.MatchedPairs != first.MatchedPairs ||
				again.IsMatch != first.IsMatch {
				t.Fatalf("seed=%d repeat=%d: Verify is not deterministic\n"+
					"  first  score=%.17g matched_pairs=%d is_match=%v\n"+
					"  again  score=%.17g matched_pairs=%d is_match=%v",
					seed, repeat,
					first.Score, first.MatchedPairs, first.IsMatch,
					again.Score, again.MatchedPairs, again.IsMatch)
			}
		}
	}
}

// TestVerifyIsDeterministicUnderConcurrency checks the same invariant when
// several searches run at once. The matcher is documented as pure and shared
// across a worker pool, and a determinism bug that only appears under
// concurrency would slip past the sequential test above.
func TestVerifyIsDeterministicUnderConcurrency(t *testing.T) {
	m := quietMatcher()
	ctx := context.Background()

	const n = 40
	pairs := make([][2]*Template, n)
	for i := 0; i < n; i++ {
		pairs[i] = [2]*Template{
			BuildTemplate("probe", detPoints(32, i)),
			BuildTemplate("gallery", detPoints(32, i+500)),
		}
	}

	want := make([]MatchVerificationResult, n)
	for i, p := range pairs {
		r, err := m.Verify(ctx, p[0], p[1])
		if err != nil {
			t.Fatal(err)
		}
		want[i] = r
	}

	for round := 0; round < 8; round++ {
		// Every goroutine reports exactly once, pass or fail, so the reader below
		// always receives n values. Reporting only on failure would leave the
		// success path blocked forever.
		reports := make(chan string, n)
		for i := 0; i < n; i++ {
			go func(i int) {
				r, err := m.Verify(ctx, pairs[i][0], pairs[i][1])
				switch {
				case err != nil:
					reports <- err.Error()
				case r.Score != want[i].Score || r.MatchedPairs != want[i].MatchedPairs:
					reports <- "result differs from the sequential run"
				default:
					reports <- ""
				}
			}(i)
		}
		for i := 0; i < n; i++ {
			if msg := <-reports; msg != "" {
				t.Fatalf("round=%d: %s", round, msg)
			}
		}
	}
}
