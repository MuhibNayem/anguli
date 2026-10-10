package service_test

import (
	"context"
	"strings"
	"testing"

	"finger-scanner/services/edge-gateway-service/internal/adapters/memory"
	"finger-scanner/services/edge-gateway-service/internal/domain"
	"finger-scanner/services/edge-gateway-service/internal/service"
)

// A zone whose required role is a name the system does not recognise must not
// become an open door.
//
// roleRank scores an unknown role 0, and the clearance test is
// `roleRank(employee) < roleRank(required)`. With an unknown required role that
// comparison is `1 < 0`, which is false, so nothing is denied and the grant
// proceeds. The employee side is fail-closed - an unknown employee role scores
// 0 and is refused - but the required side was fail-open, and the asymmetry is
// invisible at the call site.
//
// This is not a theoretical typo. "ADMINISTRATOR" is a perfectly plausible name
// for a role that is not in the switch, and configuring a server room with it
// hands the room to every employee and contractor on the roster, silently.
//
// This exercises the offline path, which is the one that matters most: it is
// what runs when the WAN is down, which is exactly when nobody is watching the
// logs.
func TestOfflineRefusesAnUnrecognisedRequiredRole(t *testing.T) {
	ctx := context.Background()
	cache := memory.NewMemoryEdgeCache()
	// No policy client: every evaluation runs the cached offline path.
	svc := service.NewEdgeService(cache, quietLogger())

	rawPix, cyls := generateTestPrint(120, 120)
	if err := cache.UpsertEmployee(ctx, &domain.CachedEmployee{
		EmployeeID: "EMP-CONTRACTOR",
		FullName:   "Contractor",
		Role:       "EMPLOYEE",
		IsActive:   true,
		Cylinders:  cyls,
	}); err != nil {
		t.Fatal(err)
	}
	if err := cache.UpsertPolicyRule(ctx, &domain.PolicyRule{
		ZoneID:                "zone-datacenter",
		AllowedRole:           "ADMINISTRATOR", // not a role the system knows
		RequireBiometrics:     true,
		MinBiometricScore:     40.0,
		EnforceAntiPassback:   true,
		AntiPassbackWindowSec: 60,
	}); err != nil {
		t.Fatal(err)
	}

	res, err := svc.ProcessScan(ctx, "turnstile-dc", "zone-datacenter", 1, "EMP-CONTRACTOR", rawPix, 120, 120)
	if err != nil {
		t.Fatalf("ProcessScan: %v", err)
	}
	if res.IsAccessGranted {
		t.Fatalf("an unrecognised required role granted access to a plain EMPLOYEE "+
			"(decision=%d, reason=%q); an unknown requirement must deny, not admit everyone",
			res.Decision, res.Reason)
	}
	if res.RelayStrikeDurationMs != 0 {
		t.Errorf("relay struck (%dms) despite the denial", res.RelayStrikeDurationMs)
	}
	// The operator needs to be told why, or the correct fix looks like a mystery.
	if !strings.Contains(strings.ToLower(res.Reason), "role") {
		t.Errorf("denial reason does not mention the role requirement: %q", res.Reason)
	}
}

// The ordinary, recognised hierarchy must keep working. A fix that simply denies
// whenever it cannot compare would lock out legitimate staff.
func TestOfflineStillHonoursTheRecognisedHierarchy(t *testing.T) {
	cases := []struct {
		required  string
		employee  string
		wantGrant bool
	}{
		{"EMPLOYEE", "EMPLOYEE", true},
		{"OPERATOR", "OPERATOR", true},
		{"SECURITY_ADMIN", "SECURITY_ADMIN", true},
		// Rank hierarchy: a higher rank satisfies a lower requirement.
		{"EMPLOYEE", "SECURITY_ADMIN", true},
		{"OPERATOR", "SECURITY_ADMIN", true},
		// And not the reverse.
		{"SECURITY_ADMIN", "OPERATOR", false},
		{"OPERATOR", "EMPLOYEE", false},
		{"SECURITY_ADMIN", "EMPLOYEE", false},
		// An empty requirement means "no clearance requirement".
		{"", "EMPLOYEE", true},
	}

	for _, tc := range cases {
		t.Run(tc.required+"<-requires-<-emp-"+tc.employee, func(t *testing.T) {
			ctx := context.Background()
			cache := memory.NewMemoryEdgeCache()
			svc := service.NewEdgeService(cache, quietLogger())

			rawPix, cyls := generateTestPrint(120, 120)
			if err := cache.UpsertEmployee(ctx, &domain.CachedEmployee{
				EmployeeID: "EMP-1", Role: tc.employee, IsActive: true, Cylinders: cyls,
			}); err != nil {
				t.Fatal(err)
			}
			if err := cache.UpsertPolicyRule(ctx, &domain.PolicyRule{
				ZoneID:                "zone-test",
				AllowedRole:           tc.required,
				RequireBiometrics:     true,
				MinBiometricScore:     40.0,
				EnforceAntiPassback:   true,
				AntiPassbackWindowSec: 60,
			}); err != nil {
				t.Fatal(err)
			}

			res, err := svc.ProcessScan(ctx, "turnstile-1", "zone-test", 1, "EMP-1", rawPix, 120, 120)
			if err != nil {
				t.Fatal(err)
			}
			if res.IsAccessGranted != tc.wantGrant {
				t.Fatalf("required %q, employee %q: granted=%v (decision=%d, reason=%q), want granted=%v",
					tc.required, tc.employee, res.IsAccessGranted, res.Decision, res.Reason, tc.wantGrant)
			}
		})
	}
}

// An unrecognised *employee* role must still be refused, which is the direction
// that was already correct. Both directions have to fail closed, and fixing
// only the required-role side would be an incomplete change.
func TestOfflineRefusesAnUnrecognisedEmployeeRole(t *testing.T) {
	ctx := context.Background()
	cache := memory.NewMemoryEdgeCache()
	svc := service.NewEdgeService(cache, quietLogger())

	rawPix, cyls := generateTestPrint(120, 120)
	if err := cache.UpsertEmployee(ctx, &domain.CachedEmployee{
		EmployeeID: "EMP-1", Role: "SUPERUSER", IsActive: true, Cylinders: cyls,
	}); err != nil {
		t.Fatal(err)
	}
	if err := cache.UpsertPolicyRule(ctx, &domain.PolicyRule{
		ZoneID: "zone-test", AllowedRole: "EMPLOYEE",
		RequireBiometrics: true, MinBiometricScore: 40.0,
	}); err != nil {
		t.Fatal(err)
	}

	res, err := svc.ProcessScan(ctx, "turnstile-1", "zone-test", 1, "EMP-1", rawPix, 120, 120)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsAccessGranted {
		t.Fatalf("an unrecognised employee role (%q) was granted access to a zone requiring EMPLOYEE", "SUPERUSER")
	}
}

// The offline path carries the same shape as the online one: anti-passback
// branched on entry and exit explicitly, so an unrecognised direction matched
// neither branch and the grant proceeded. On the edge this is the only path
// that runs when the WAN is down.
//
// An unspecified direction is not hypothetical here either - proto3 defaults an
// unset enum to zero, and the turnstile controller passes it straight through.
func TestOfflineDeniesAnUnrecognisedDirection(t *testing.T) {
	for _, direction := range []int32{0, 3, -1, 99} {
		ctx := context.Background()
		cache := memory.NewMemoryEdgeCache()
		svc := service.NewEdgeService(cache, quietLogger())

		rawPix, cyls := generateTestPrint(120, 120)
		if err := cache.UpsertEmployee(ctx, &domain.CachedEmployee{
			EmployeeID: "EMP-1", Role: "EMPLOYEE", IsActive: true, Cylinders: cyls,
		}); err != nil {
			t.Fatal(err)
		}
		if err := cache.UpsertPolicyRule(ctx, &domain.PolicyRule{
			ZoneID: "zone-test", AllowedRole: "EMPLOYEE",
			RequireBiometrics: true, MinBiometricScore: 40.0,
			EnforceAntiPassback: true, AntiPassbackWindowSec: 300,
		}); err != nil {
			t.Fatal(err)
		}

		res, err := svc.ProcessScan(ctx, "turnstile-1", "zone-test", direction, "EMP-1", rawPix, 120, 120)
		if err != nil {
			t.Fatalf("ProcessScan(direction=%d): %v", direction, err)
		}
		if res.IsAccessGranted {
			t.Fatalf("offline scan with direction %d was granted with anti-passback enforced; "+
				"an unrecognised direction must not silently skip the rule", direction)
		}
		if res.RelayStrikeDurationMs != 0 {
			t.Errorf("direction %d struck the relay (%dms) despite the denial",
				direction, res.RelayStrikeDurationMs)
		}
	}
}

// A negative biometric threshold must not become "no threshold" offline.
//
// The comparison was `bestScore < rule.MinBiometricScore`, and a negative
// threshold makes that never true - so a control configured as a floor became no
// floor at all. Central now rejects such a rule when it is written, but this
// node caches what it is given and may hold one stored before that check
// existed. When the WAN is down, this is the only evaluation that runs.
func TestOfflineDeniesAnUnusableBiometricThreshold(t *testing.T) {
	ctx := context.Background()
	cache := memory.NewMemoryEdgeCache()
	svc := service.NewEdgeService(cache, quietLogger())

	rawPix, cyls := generateTestPrint(120, 120)
	if err := cache.UpsertEmployee(ctx, &domain.CachedEmployee{
		EmployeeID: "EMP-1", Role: "EMPLOYEE", IsActive: true, Cylinders: cyls,
	}); err != nil {
		t.Fatal(err)
	}
	if err := cache.UpsertPolicyRule(ctx, &domain.PolicyRule{
		ZoneID: "zone-test", AllowedRole: "EMPLOYEE",
		RequireBiometrics:     true,
		MinBiometricScore:     -1, // unusable: admits every print
		EnforceAntiPassback:   true,
		AntiPassbackWindowSec: 60,
	}); err != nil {
		t.Fatal(err)
	}

	res, err := svc.ProcessScan(ctx, "turnstile-1", "zone-test", 1, "EMP-1", rawPix, 120, 120)
	if err != nil {
		t.Fatalf("ProcessScan: %v", err)
	}
	if res.IsAccessGranted {
		t.Fatalf("a zone whose cached threshold is -1 admitted a print; the configured "+
			"biometric floor was silently switched off (score %.1f)", res.MatchScore)
	}
}

// The ordinary thresholds must still work in both directions.
func TestOfflineStillHonoursNormalBiometricThresholds(t *testing.T) {
	for _, tc := range []struct {
		threshold float64
		wantGrant bool
	}{
		// The probe is the print that was enrolled, so it matches itself and
		// scores 100. A realistic floor therefore has to admit it - asserting
		// otherwise would be asserting a score this matcher does not produce.
		{0, true},  // no floor configured
		{1, true},  // any real match passes
		{60, true}, // a realistic floor, still satisfied by a perfect match
		{100, true},
		{101, false}, // above any achievable score: refuses
	} {
		ctx := context.Background()
		cache := memory.NewMemoryEdgeCache()
		svc := service.NewEdgeService(cache, quietLogger())

		rawPix, cyls := generateTestPrint(120, 120)
		if err := cache.UpsertEmployee(ctx, &domain.CachedEmployee{
			EmployeeID: "EMP-1", Role: "EMPLOYEE", IsActive: true, Cylinders: cyls,
		}); err != nil {
			t.Fatal(err)
		}
		if err := cache.UpsertPolicyRule(ctx, &domain.PolicyRule{
			ZoneID: "zone-test", AllowedRole: "EMPLOYEE",
			RequireBiometrics:     true,
			MinBiometricScore:     tc.threshold,
			EnforceAntiPassback:   true,
			AntiPassbackWindowSec: 60,
		}); err != nil {
			t.Fatal(err)
		}

		res, err := svc.ProcessScan(ctx, "turnstile-1", "zone-test", 1, "EMP-1", rawPix, 120, 120)
		if err != nil {
			t.Fatal(err)
		}
		if res.IsAccessGranted != tc.wantGrant {
			t.Fatalf("threshold %.0f: granted=%v (score %.1f), want granted=%v",
				tc.threshold, res.IsAccessGranted, res.MatchScore, tc.wantGrant)
		}
	}
}
