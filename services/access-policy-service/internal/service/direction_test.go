package service_test

import (
	"context"
	"testing"

	"finger-scanner/services/access-policy-service/internal/domain"
)

// An unspecified or unknown direction must not skip anti-passback.
//
// The APB evaluation branched on `direction == 1` for entry and `direction == 2`
// for exit. Anything else matched neither branch, fell straight through to the
// grant, and recorded a pass event - so anti-passback was silently skipped for
// every request that did not name a direction.
//
// That is not a hypothetical. proto3 defaults an unset enum field to zero, and
// DOOR_DIRECTION_UNSPECIFIED is zero, so a caller that simply omits `direction`
// sends exactly the value that disables the rule. The turnstile controller
// passing an unset enum straight through is what makes it reachable in
// production.
//
// The trade is not symmetric. Reading the direction wrong could strand someone
// inside a zone with no recorded exit; granting it bypasses a physical access
// control entirely and leaves no trace beyond a pass event nobody can explain.
func TestUnspecifiedDirectionDoesNotBypassAntiPassback(t *testing.T) {
	for _, direction := range []int32{0, 3, -1, 99} {
		ctx := context.Background()
		svc, repo := policyService(t)

		if err := repo.SaveRule(ctx, &domain.PolicyRule{
			ZoneID:                "zone-test",
			AllowedRole:           "EMPLOYEE",
			RequireBiometrics:     true,
			MinBiometricScore:     40.0,
			EnforceAntiPassback:   true,
			AntiPassbackWindowSec: 300,
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.SetEmployeeRole(ctx, "EMP-1", "EMPLOYEE"); err != nil {
			t.Fatal(err)
		}

		res, err := svc.Evaluate(ctx, "EMP-1", "zone-test", "turnstile-1", direction, true, 85)
		if err != nil {
			t.Fatalf("Evaluate(direction=%d): %v", direction, err)
		}
		if res.IsGranted {
			t.Fatalf("direction %d was granted access with anti-passback enforced; "+
				"an unrecognised direction must not silently skip the rule", direction)
		}
		if res.RelayOpenDurationMs != 0 {
			t.Errorf("direction %d struck the relay (%dms) despite the denial",
				direction, res.RelayOpenDurationMs)
		}
	}
}

// A rejected direction must not leave a pass event behind. If it did, the next
// legitimate scan would be evaluated against a movement that never happened.
func TestUnspecifiedDirectionRecordsNoPassEvent(t *testing.T) {
	ctx := context.Background()
	svc, repo := policyService(t)

	if err := repo.SaveRule(ctx, &domain.PolicyRule{
		ZoneID: "zone-test", AllowedRole: "EMPLOYEE",
		RequireBiometrics: true, MinBiometricScore: 40.0,
		EnforceAntiPassback: true, AntiPassbackWindowSec: 300,
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetEmployeeRole(ctx, "EMP-1", "EMPLOYEE"); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.Evaluate(ctx, "EMP-1", "zone-test", "turnstile-1", 0, true, 85); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if ev, err := repo.GetLastPassEvent(ctx, "EMP-1", "zone-test"); err == nil && ev != nil {
		t.Fatalf("a denied, unrecognised direction recorded a pass event: %+v", ev)
	}
}

// The two real directions must be unaffected.
func TestRecognisedDirectionsStillWork(t *testing.T) {
	t.Run("entry then immediate re-entry is denied", func(t *testing.T) {
		ctx := context.Background()
		svc, repo := policyService(t)
		if err := repo.SaveRule(ctx, &domain.PolicyRule{
			ZoneID: "zone-test", AllowedRole: "EMPLOYEE",
			RequireBiometrics: true, MinBiometricScore: 40.0,
			EnforceAntiPassback: true, AntiPassbackWindowSec: 300,
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.SetEmployeeRole(ctx, "EMP-1", "EMPLOYEE"); err != nil {
			t.Fatal(err)
		}

		first, err := svc.Evaluate(ctx, "EMP-1", "zone-test", "turnstile-1", 1, true, 85)
		if err != nil {
			t.Fatal(err)
		}
		if !first.IsGranted {
			t.Fatalf("first entry was denied: %q", first.Reason)
		}

		second, err := svc.Evaluate(ctx, "EMP-1", "zone-test", "turnstile-1", 1, true, 85)
		if err != nil {
			t.Fatal(err)
		}
		if second.IsGranted {
			t.Fatal("re-entry inside the anti-passback window was granted")
		}
	})

	t.Run("entry then exit is allowed", func(t *testing.T) {
		ctx := context.Background()
		svc, repo := policyService(t)
		if err := repo.SaveRule(ctx, &domain.PolicyRule{
			ZoneID: "zone-test", AllowedRole: "EMPLOYEE",
			RequireBiometrics: true, MinBiometricScore: 40.0,
			EnforceAntiPassback: true, AntiPassbackWindowSec: 300,
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.SetEmployeeRole(ctx, "EMP-1", "EMPLOYEE"); err != nil {
			t.Fatal(err)
		}

		if _, err := svc.Evaluate(ctx, "EMP-1", "zone-test", "turnstile-1", 1, true, 85); err != nil {
			t.Fatal(err)
		}
		out, err := svc.Evaluate(ctx, "EMP-1", "zone-test", "turnstile-1", 2, true, 85)
		if err != nil {
			t.Fatal(err)
		}
		if !out.IsGranted {
			t.Fatalf("exit after entry was denied: %q", out.Reason)
		}
	})
}
