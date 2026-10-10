package handlers_test

import (
	"net/http"
	"testing"

	"finger-scanner/pkg/store"
	"finger-scanner/services/api-gateway/internal/clients"
	"finger-scanner/services/api-gateway/internal/handlers"
)

// TestGatewayStampsTheConfiguredFacilityNotALiteral covers the identity the
// gateway sends to the edge.
//
// Both edge syncs used to hardcode "facility-primary". That literal was never
// compared against anything, so every deployment stamped the same value and
// nothing distinguished two sites - which matters because the facility is what
// the stateful services use to claim their database.
func TestGatewayStampsTheConfiguredFacilityNotALiteral(t *testing.T) {
	t.Setenv("FACILITY_ID", "warehouse-annex")

	edge := &stubRevokeEdge{}
	bio := &stubRevokeBiometrics{}
	h := handlers.NewGatewayHandler(&clients.ServiceClients{
		BiometricsClient:  bio,
		EdgeGatewayClient: edge,
	}, nil)

	rec := do(t, h.HandleRevokeTemplate, http.MethodPost, "/api/v1/biometrics/revoke",
		`{"employee_id":"EMP-1","position":1,"reason":"OFFBOARDED"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if edge.calls == 0 {
		t.Fatal("the edge was never synced")
	}
	if got := edge.last.GetFacilityId(); got != "warehouse-annex" {
		t.Fatalf("edge was told facility %q, want the configured warehouse-annex; the value is "+
			"still a constant rather than this deployment's identity", got)
	}
}

// TestGatewayFacilityFallsBackToTheDocumentedDefault keeps an unset FACILITY_ID
// working, since single-site deployments should not have to configure one.
func TestGatewayFacilityFallsBackToTheDocumentedDefault(t *testing.T) {
	t.Setenv("FACILITY_ID", "")

	// Constructing the handler is the point: it must not fail or panic when no
	// facility is configured, so single-site deployments need no configuration.
	handlers.NewGatewayHandler(&clients.ServiceClients{}, nil)

	if got := store.FacilityIDFromEnv(); got != store.DefaultFacilityID {
		t.Fatalf("with FACILITY_ID unset the deployment resolves to %q, want %q",
			got, store.DefaultFacilityID)
	}
}

// TestFacilityIDIsTrimmed guards an easy operator mistake: trailing whitespace
// in a .env file would otherwise produce a second identity for the same site,
// which ClaimFacility then refuses as though it were a different facility.
func TestFacilityIDIsTrimmed(t *testing.T) {
	for raw, want := range map[string]string{
		"  hq-lobby  ": "hq-lobby",
		"\thq-lobby\n": "hq-lobby",
		"   ":          store.DefaultFacilityID,
		"":             store.DefaultFacilityID,
		"hq-lobby":     "hq-lobby",
	} {
		t.Setenv("FACILITY_ID", raw)
		if got := store.FacilityIDFromEnv(); got != want {
			t.Fatalf("FACILITY_ID=%q resolved to %q, want %q", raw, got, want)
		}
	}
}
