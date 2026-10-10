package grpc_test

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	edgegatewayv1 "finger-scanner/pkg/api/v1/edgegateway"
	"finger-scanner/services/edge-gateway-service/internal/service"
)

// countingEdge records what reached the service, so the boundary can be shown to
// reject a malformed request before any decision is made.
type countingEdge struct {
	service.EdgeUseCase
	calls int
}

func (c *countingEdge) ProcessScan(
	ctx context.Context, turnstileID, zoneID string, direction int32, employeeID string,
	probePix []byte, width, height uint32,
) (*service.ScanResult, error) {
	c.calls++
	return &service.ScanResult{Decision: 1, IsAccessGranted: true}, nil
}

// An unset direction must be refused at the boundary. proto3 defaults an unset
// enum to zero, and zero used to travel all the way into the anti-passback
// evaluation, match neither the entry nor the exit branch, and skip the rule.
func TestProcessTurnstileScanRejectsAnUnsetDirection(t *testing.T) {
	for _, d := range []accesscontrolv1.DoorDirection{
		accesscontrolv1.DoorDirection_DOOR_DIRECTION_UNSPECIFIED,
		accesscontrolv1.DoorDirection(3),
		accesscontrolv1.DoorDirection(-1),
		accesscontrolv1.DoorDirection(99),
	} {
		edge := &countingEdge{}
		srv := newServer(edge)

		_, err := srv.ProcessTurnstileScan(context.Background(), &edgegatewayv1.ProcessTurnstileScanRequest{
			TurnstileId: "turnstile-01",
			ZoneId:      "zone-test",
			Direction:   d,
			EmployeeId:  "EMP-1",
		})
		if err == nil {
			t.Fatalf("direction %d was accepted at the boundary", d)
		}
		if code := status.Code(err); code != codes.InvalidArgument {
			t.Fatalf("direction %d: code is %s, want InvalidArgument", d, code)
		}
		if edge.calls != 0 {
			t.Fatalf("direction %d reached the service %d times; the malformed request was not stopped at the boundary", d, edge.calls)
		}
	}
}

// The two real directions must pass through untouched.
func TestProcessTurnstileScanAcceptsRealDirections(t *testing.T) {
	for _, d := range []accesscontrolv1.DoorDirection{
		accesscontrolv1.DoorDirection_DOOR_DIRECTION_ENTRY,
		accesscontrolv1.DoorDirection_DOOR_DIRECTION_EXIT,
	} {
		edge := &countingEdge{}
		srv := newServer(edge)

		if _, err := srv.ProcessTurnstileScan(context.Background(), &edgegatewayv1.ProcessTurnstileScanRequest{
			TurnstileId: "turnstile-01",
			ZoneId:      "zone-test",
			Direction:   d,
			EmployeeId:  "EMP-1",
		}); err != nil {
			t.Fatalf("direction %d was rejected: %v", d, err)
		}
		if edge.calls != 1 {
			t.Fatalf("direction %d reached the service %d times, want 1", d, edge.calls)
		}
	}
}

// The existing turnstile_id guard must keep working alongside the new one.
func TestProcessTurnstileScanStillRequiresATurnstile(t *testing.T) {
	edge := &countingEdge{}
	srv := newServer(edge)
	_, err := srv.ProcessTurnstileScan(context.Background(), &edgegatewayv1.ProcessTurnstileScanRequest{
		Direction:  accesscontrolv1.DoorDirection_DOOR_DIRECTION_ENTRY,
		EmployeeId: "EMP-1",
	})
	if err == nil {
		t.Fatal("a request with no turnstile_id was accepted")
	}
	if edge.calls != 0 {
		t.Fatalf("the service was called %d times", edge.calls)
	}
}
