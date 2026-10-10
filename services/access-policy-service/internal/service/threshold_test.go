package service_test

import (
	"context"
	"strings"
	"testing"

	"finger-scanner/services/access-policy-service/internal/domain"
)

// The match score is a percentage, so a threshold outside 0-100 is nonsense, and
// the low side is the dangerous one: `score < threshold` with a negative
// threshold is never true, so every verified print passes regardless of how poor
// the match. A configured control switched off by a value that still looks like
// a number.
func TestConfigureRejectsAnImpossibleBiometricThreshold(t *testing.T) {
	for _, bad := range []float64{-1, -0.01, -100, 100.01, 1000} {
		ctx := context.Background()
		svc, _ := policyService(t)

		err := svc.Configure(ctx, &domain.PolicyRule{
			ZoneID: "zone-test", AllowedRole: "EMPLOYEE",
			RequireBiometrics: true, MinBiometricScore: bad,
		})
		if err == nil {
			t.Fatalf("a threshold of %v was accepted; below 0 admits every print", bad)
		}
		// The message has to give the operator the valid range.
		for _, want := range []string{"0-100", "zone-test"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error does not mention %q: %v", want, err)
			}
		}
	}
}

// Every legitimate threshold must still be configurable, or the guard above is
// just a locked building.
func TestConfigureAcceptsThresholdsInRange(t *testing.T) {
	for _, good := range []float64{0, 1, 42.5, 60, 99.9, 100} {
		ctx := context.Background()
		svc, _ := policyService(t)

		if err := svc.Configure(ctx, &domain.PolicyRule{
			ZoneID: "zone-test", AllowedRole: "EMPLOYEE",
			RequireBiometrics: true, MinBiometricScore: good,
		}); err != nil {
			t.Fatalf("threshold %v was rejected: %v", good, err)
		}
	}
}

// The guard that matters is the runtime one: a rule stored before this check
// existed must not admit every print either. This writes the bad threshold
// behind the service's back and evaluates against it.
func TestAStoredNegativeThresholdDoesNotAdmitEveryPrint(t *testing.T) {
	ctx := context.Background()
	svc, repo := policyService(t)

	if err := repo.SaveRule(ctx, &domain.PolicyRule{
		ZoneID: "zone-test", AllowedRole: "EMPLOYEE",
		RequireBiometrics:     true,
		MinBiometricScore:     -1,
		EnforceAntiPassback:   true,
		AntiPassbackWindowSec: 60,
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetEmployeeRole(ctx, "EMP-1", "EMPLOYEE"); err != nil {
		t.Fatal(err)
	}

	// A verification that scored far below any sensible threshold. With the
	// stored threshold of -1 it would pass, which is the defect.
	res, err := svc.Evaluate(ctx, "EMP-1", "zone-test", "turnstile-1", 1, true, 5)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.IsGranted {
		t.Fatalf("a print scoring %.0f was admitted by a zone whose stored threshold is -1", 5.0)
	}
}
