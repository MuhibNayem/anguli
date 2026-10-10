package service_test

import (
	"context"
	"strings"
	"testing"

	"finger-scanner/services/access-policy-service/internal/adapters/memory"
	"finger-scanner/services/access-policy-service/internal/domain"
	"finger-scanner/services/access-policy-service/internal/ports"
	"finger-scanner/services/access-policy-service/internal/service"
)

// The repository is returned alongside the service so a test can store a rule
// behind the service's back. That is the case that matters for the runtime
// guard: a policy written before validation existed, or by a tool that bypassed
// it, must still fail closed.
func policyService(t *testing.T) (service.PolicyUseCase, ports.PolicyRepository) {
	t.Helper()
	repo := memory.NewMemoryPolicyRepository()
	return service.NewPolicyService(repo, nil), repo
}

// The online path carried the same fail-open as the offline one: clearance was
// `roleRank(employee) < roleRank(required)`, so an unrecognised required role
// scored 0 and the comparison `1 < 0` never denied.
//
// This drives the service directly with a rule stored behind its back, because
// that is the case that matters: a policy written before validation existed, or
// written by a tool that bypassed it, must still fail closed.
func TestOnlineRefusesAnUnrecognisedRequiredRole(t *testing.T) {
	ctx := context.Background()
	svc, repo := policyService(t)

	rule := &domain.PolicyRule{
		ZoneID:                "zone-datacenter",
		AllowedRole:           "ADMINISTRATOR", // not a role this system knows
		RequireBiometrics:     true,
		MinBiometricScore:     40.0,
		EnforceAntiPassback:   true,
		AntiPassbackWindowSec: 60,
	}
	// Stored directly, so the runtime guard is what is under test.
	if err := repo.SaveRule(ctx, rule); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetEmployeeRole(ctx, "EMP-CONTRACTOR", "EMPLOYEE"); err != nil {
		t.Fatal(err)
	}

	res, err := svc.Evaluate(ctx, "EMP-CONTRACTOR", "zone-datacenter", "turnstile-dc", 1, true, 85)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.IsGranted {
		t.Fatalf("an unrecognised required role granted access to a plain EMPLOYEE "+
			"(decision=%d, reason=%q); an unknown requirement must deny, not admit everyone",
			res.Decision, res.Reason)
	}
	if res.Decision != 2 {
		t.Errorf("decision = %d, want 2 (DENIED_INVALID_ZONE)", res.Decision)
	}
	if !strings.Contains(strings.ToLower(res.Reason), "role") {
		t.Errorf("denial reason does not mention the role requirement: %q", res.Reason)
	}
}

// The recognised hierarchy must keep working after the change. A fix that
// simply denies whenever it cannot compare would lock out legitimate staff.
func TestOnlineStillHonoursTheRecognisedHierarchy(t *testing.T) {
	cases := []struct {
		required  string
		employee  string
		wantGrant bool
	}{
		{"EMPLOYEE", "EMPLOYEE", true},
		{"OPERATOR", "OPERATOR", true},
		{"SECURITY_ADMIN", "SECURITY_ADMIN", true},
		{"EMPLOYEE", "SECURITY_ADMIN", true},
		{"OPERATOR", "SECURITY_ADMIN", true},
		{"SECURITY_ADMIN", "OPERATOR", false},
		{"OPERATOR", "EMPLOYEE", false},
		{"SECURITY_ADMIN", "EMPLOYEE", false},
		{"", "EMPLOYEE", true},
		// Aliases the hierarchy has always accepted must keep working.
		{"ADMIN", "ADMIN", true},
		{"SECURITY_OPERATOR", "SECURITY_OPERATOR", true},
	}

	for _, tc := range cases {
		t.Run(tc.required+"-vs-"+tc.employee, func(t *testing.T) {
			ctx := context.Background()
			svc, repo := policyService(t)

			if err := repo.SaveRule(ctx, &domain.PolicyRule{
				ZoneID:                "zone-test",
				AllowedRole:           tc.required,
				RequireBiometrics:     true,
				MinBiometricScore:     40.0,
				EnforceAntiPassback:   true,
				AntiPassbackWindowSec: 60,
			}); err != nil {
				t.Fatal(err)
			}
			if err := repo.SetEmployeeRole(ctx, "EMP-1", tc.employee); err != nil {
				t.Fatal(err)
			}

			res, err := svc.Evaluate(ctx, "EMP-1", "zone-test", "turnstile-1", 1, true, 85)
			if err != nil {
				t.Fatal(err)
			}
			if res.IsGranted != tc.wantGrant {
				t.Fatalf("required %q, employee %q: granted=%v (reason=%q), want granted=%v",
					tc.required, tc.employee, res.IsGranted, res.Reason, tc.wantGrant)
			}
		})
	}
}

// Configure refuses to store a requirement it cannot evaluate, so the mistake is
// reported to whoever typed it rather than surfacing later as a zone that
// stopped admitting anyone.
func TestConfigureRejectsAnUnrecognisedRole(t *testing.T) {
	ctx := context.Background()
	svc, _ := policyService(t)

	for _, bad := range []string{"ADMINISTRATOR", "superuser", "SÉCURITÉ_ADMIN", "SUPERVISOR", "engineering"} {
		t.Run(bad, func(t *testing.T) {
			err := svc.Configure(ctx, &domain.PolicyRule{
				ZoneID: "zone-test", AllowedRole: bad,
			})
			if err == nil {
				t.Fatalf("role %q was accepted as a clearance requirement", bad)
			}
			// The operator must be told which value is wrong and what is valid.
			for _, want := range []string{bad, "SECURITY_ADMIN"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error does not mention %q: %v", want, err)
				}
			}
		})
	}
}

// The valid roles must still be configurable, or the guard above is useless.
func TestConfigureAcceptsKnownRoles(t *testing.T) {
	ctx := context.Background()
	for _, good := range []string{"", "EMPLOYEE", "AGENT", "STAFF", "OPERATOR",
		"SECURITY_OPERATOR", "SECURITY_ADMIN", "ADMIN", "SUPERADMIN", " employee ",
		// Surrounding whitespace is normalised rather than treated as an
		// unknown role, so a stray space in a config file is not a locked zone.
		" admin "} {
		t.Run(good, func(t *testing.T) {
			svc, _ := policyService(t)
			if err := svc.Configure(ctx, &domain.PolicyRule{
				ZoneID: "zone-test", AllowedRole: good,
			}); err != nil {
				t.Fatalf("role %q was rejected: %v", good, err)
			}
		})
	}
}
