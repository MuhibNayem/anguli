package grpc_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	edgegatewayv1 "finger-scanner/pkg/api/v1/edgegateway"
	grpedge "finger-scanner/services/edge-gateway-service/internal/adapters/grpc"
	"finger-scanner/services/edge-gateway-service/internal/domain"
	"finger-scanner/services/edge-gateway-service/internal/service"
)

// stubEdge records what each handler forwarded, and can be made to fail.
type stubEdge struct {
	service.EdgeUseCase
	rosterCalls   int
	roster        []*domain.CachedEmployee
	policyCalls   int
	policies      []*domain.PolicyRule
	statusCalls   int
	statusErr     error
	replayCalls   int
	replayErr     error
	replayedCount int
}

func (s *stubEdge) SyncRoster(_ context.Context, items []*domain.CachedEmployee) (uint32, error) {
	s.rosterCalls++
	s.roster = items
	return uint32(len(items)), nil
}

func (s *stubEdge) SyncPolicies(_ context.Context, rules []*domain.PolicyRule) error {
	s.policyCalls++
	s.policies = rules
	return nil
}

func (s *stubEdge) GetStatus(_ context.Context, turnstileID string) (*domain.TurnstileState, error) {
	s.statusCalls++
	if s.statusErr != nil {
		return nil, s.statusErr
	}
	return &domain.TurnstileState{
		TurnstileID:          turnstileID,
		ZoneID:               "zone-main-gate",
		IsOnline:             true,
		ReaderConnected:      true,
		LocalRosterCount:     42,
		OfflinePendingEvents: 7,
		StartTimeUnix:        1700000000,
	}, nil
}

func (s *stubEdge) ReplayEvents(_ context.Context) ([]*domain.OfflineAuditLog, error) {
	s.replayCalls++
	if s.replayErr != nil {
		return nil, s.replayErr
	}
	return make([]*domain.OfflineAuditLog, s.replayedCount), nil
}

// TestSyncFacilityRosterForwardsDeactivationsWithoutCylinders guards the
// offboarding path.
//
// The gateway revokes by sending a roster item with IsActive false and no
// template bytes at all. A handler that rejected items it could not build
// cylinders for would silently discard exactly the deactivation it is meant to
// deliver - and the employee would stay cached and matchable at the edge.
func TestSyncFacilityRosterForwardsDeactivationsWithoutCylinders(t *testing.T) {
	edge := &stubEdge{}
	srv := newServer(edge)

	resp, err := srv.SyncFacilityRoster(context.Background(), &edgegatewayv1.SyncFacilityRosterRequest{
		FacilityId: "london-hq",
		Items: []*edgegatewayv1.SyncEmployeeItem{{
			EmployeeId: "EMP-1042",
			Position:   1,
			IsActive:   false, // revoked; no template bytes by design
		}},
	})
	if err != nil {
		t.Fatalf("SyncFacilityRoster: %v", err)
	}
	if !resp.GetSuccess() || resp.GetSyncedCount() != 1 {
		t.Fatalf("response = success:%v count:%d, want true and 1", resp.GetSuccess(), resp.GetSyncedCount())
	}
	if edge.rosterCalls != 1 || len(edge.roster) != 1 {
		t.Fatalf("the deactivation reached the service %d times with %d items", edge.rosterCalls, len(edge.roster))
	}
	got := edge.roster[0]
	if got.EmployeeID != "EMP-1042" || got.IsActive {
		t.Fatalf("forwarded item = %+v; a revocation must arrive as IsActive=false", got)
	}
}

func TestSyncFacilityRosterForwardsPolicies(t *testing.T) {
	edge := &stubEdge{}
	srv := newServer(edge)

	_, err := srv.SyncFacilityRoster(context.Background(), &edgegatewayv1.SyncFacilityRosterRequest{
		Items: []*edgegatewayv1.SyncEmployeeItem{{EmployeeId: "EMP-1", IsActive: true}},
		Policies: []*accesscontrolv1.PolicyRule{{
			ZoneId:                "zone-datacenter",
			AllowedRole:           "SECURITY_ADMIN",
			RequireBiometrics:     true,
			MinBiometricScore:     70,
			EnforceAntiPassback:   true,
			AntiPassbackWindowSec: 300,
		}},
	})
	if err != nil {
		t.Fatalf("SyncFacilityRoster: %v", err)
	}
	if edge.policyCalls != 1 || len(edge.policies) != 1 {
		t.Fatalf("policies reached the service %d times with %d rules", edge.policyCalls, len(edge.policies))
	}
	p := edge.policies[0]
	if p.ZoneID != "zone-datacenter" || p.AllowedRole != "SECURITY_ADMIN" || p.AntiPassbackWindowSec != 300 {
		t.Fatalf("policy was not forwarded faithfully: %+v", p)
	}
}

func TestSyncFacilityRosterWithoutPoliciesSkipsThePolicyCall(t *testing.T) {
	edge := &stubEdge{}
	srv := newServer(edge)

	if _, err := srv.SyncFacilityRoster(context.Background(), &edgegatewayv1.SyncFacilityRosterRequest{
		Items: []*edgegatewayv1.SyncEmployeeItem{{EmployeeId: "EMP-1", IsActive: true}},
	}); err != nil {
		t.Fatal(err)
	}
	if edge.policyCalls != 0 {
		t.Fatalf("an empty policy list still called SyncPolicies %d times", edge.policyCalls)
	}
}

func TestGetTurnstileStatusMapsEveryField(t *testing.T) {
	edge := &stubEdge{}
	srv := newServer(edge)

	resp, err := srv.GetTurnstileStatus(context.Background(), &edgegatewayv1.GetTurnstileStatusRequest{
		TurnstileId: "turnstile-01",
	})
	if err != nil {
		t.Fatalf("GetTurnstileStatus: %v", err)
	}
	st := resp.GetStatus()
	if st.GetTurnstileId() != "turnstile-01" || st.GetZoneId() != "zone-main-gate" {
		t.Fatalf("identity not mapped: %+v", st)
	}
	if !st.GetIsOnline() || !st.GetReaderConnected() {
		t.Fatalf("health flags not mapped: %+v", st)
	}
	if st.GetLocalRosterCount() != 42 {
		t.Errorf("roster count = %d, want 42", st.GetLocalRosterCount())
	}
	if st.GetOfflinePendingEvents() != 7 {
		t.Errorf("pending events = %d, want 7; the operator needs this to see a backlog building",
			st.GetOfflinePendingEvents())
	}
	if st.GetUptimeSeconds() != 1700000000 {
		t.Errorf("uptime = %d", st.GetUptimeSeconds())
	}
}

// A failing dependency must be reported, not reported as a healthy node.
func TestGetTurnstileStatusPropagatesFailure(t *testing.T) {
	edge := &stubEdge{statusErr: errors.New("sensor bus unavailable")}
	srv := newServer(edge)

	_, err := srv.GetTurnstileStatus(context.Background(), &edgegatewayv1.GetTurnstileStatusRequest{
		TurnstileId: "turnstile-01",
	})
	if err == nil {
		t.Fatal("a failing status read returned success")
	}
	if code := status.Code(err); code != codes.Internal {
		t.Fatalf("code = %s, want Internal", code)
	}
	if !strings.Contains(err.Error(), "sensor bus unavailable") {
		t.Errorf("error does not carry the cause: %v", err)
	}
}

func TestReplayOfflineEventsReportsTheCount(t *testing.T) {
	edge := &stubEdge{replayedCount: 5}
	srv := newServer(edge)

	resp, err := srv.ReplayOfflineEvents(context.Background(), &edgegatewayv1.ReplayOfflineEventsRequest{
		FacilityId: "london-hq",
	})
	if err != nil {
		t.Fatalf("ReplayOfflineEvents: %v", err)
	}
	if !resp.GetSuccess() || resp.GetReplayedCount() != 5 {
		t.Fatalf("response = success:%v count:%d, want true and 5", resp.GetSuccess(), resp.GetReplayedCount())
	}
}

// A failed replay must not be reported as a successful one. This is the call
// that used to discard the offline audit WAL.
func TestReplayOfflineEventsPropagatesFailure(t *testing.T) {
	edge := &stubEdge{replayErr: errors.New("policy service unreachable")}
	srv := newServer(edge)

	_, err := srv.ReplayOfflineEvents(context.Background(), &edgegatewayv1.ReplayOfflineEventsRequest{})
	if err == nil {
		t.Fatal("a failed replay reported success")
	}
	if code := status.Code(err); code != codes.Internal {
		t.Fatalf("code = %s, want Internal", code)
	}
	if !strings.Contains(err.Error(), "unreachable") {
		t.Errorf("error does not carry the cause: %v", err)
	}
}

// newServer is the shared constructor used across this package's tests.
func newServer(edge service.EdgeUseCase) *grpedge.Server { return grpedge.NewServer(edge) }

// A roster item whose template bytes cannot be decoded is forwarded, because
// dropping it would be worse - but the loss must be reported.
//
// The item reaching the edge with no cylinders is an employee who is cached and
// can never be verified: a silent lockout. Reporting "synchronized successfully"
// for that is how an operator finds out from someone standing at the door.
func TestSyncFacilityRosterReportsUndecodableTemplates(t *testing.T) {
	edge := &stubEdge{}
	srv := newServer(edge)

	resp, err := srv.SyncFacilityRoster(context.Background(), &edgegatewayv1.SyncFacilityRosterRequest{
		Items: []*edgegatewayv1.SyncEmployeeItem{
			{EmployeeId: "EMP-OK", IsActive: true},
			// Not valid MCC cylinder encoding.
			{EmployeeId: "EMP-CORRUPT", IsActive: true, MccCylinderBytes: []byte{0xFF, 0xFE, 0xFD}},
		},
	})
	if err != nil {
		t.Fatalf("SyncFacilityRoster: %v", err)
	}
	if len(edge.roster) != 2 {
		t.Fatalf("the corrupt item was dropped; it must still be forwarded so a "+
			"deactivation in the same batch is not lost too (forwarded %d)", len(edge.roster))
	}
	if !strings.Contains(resp.GetMessage(), "could not be decoded") {
		t.Fatalf("degradation was not reported: %q", resp.GetMessage())
	}
}

// The happy path must not gain a scary message.
func TestSyncFacilityRosterCleanSyncSaysSo(t *testing.T) {
	edge := &stubEdge{}
	srv := newServer(edge)

	resp, err := srv.SyncFacilityRoster(context.Background(), &edgegatewayv1.SyncFacilityRosterRequest{
		Items: []*edgegatewayv1.SyncEmployeeItem{{EmployeeId: "EMP-1", IsActive: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(resp.GetMessage(), "could not be decoded") {
		t.Fatalf("a clean sync reported degradation: %q", resp.GetMessage())
	}
}
