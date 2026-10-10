package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	"finger-scanner/services/api-gateway/internal/clients"
	"finger-scanner/services/api-gateway/internal/handlers"
)

// stubAuditPolicy records the query the gateway forwarded and returns a fixed
// page, so the handler's parameter mapping is observable.
type stubAuditPolicy struct {
	accesscontrolv1.AccessPolicyServiceClient
	last  *accesscontrolv1.QueryAccessEventsRequest
	calls int
	page  []*accesscontrolv1.AccessAuditEvent
	token string
	err   error
}

func (s *stubAuditPolicy) QueryAccessEvents(
	_ context.Context, in *accesscontrolv1.QueryAccessEventsRequest, _ ...grpc.CallOption,
) (*accesscontrolv1.QueryAccessEventsResponse, error) {
	s.calls++
	s.last = in
	if s.err != nil {
		return nil, s.err
	}
	return &accesscontrolv1.QueryAccessEventsResponse{Events: s.page, NextPageToken: s.token}, nil
}

func newAuditFixture(pol *stubAuditPolicy) *handlers.GatewayHandler {
	return handlers.NewGatewayHandler(&clients.ServiceClients{AccessPolicyClient: pol}, nil)
}

// TestHandleQueryAccessEvents_MapsEveryFilter is what makes the route usable at
// all: an operator asking "was EMP-7 let into the server room after hours" has
// to be able to express it, and every filter has to survive the HTTP-to-gRPC
// mapping rather than silently defaulting to "everything".
func TestHandleQueryAccessEvents_MapsEveryFilter(t *testing.T) {
	pol := &stubAuditPolicy{page: []*accesscontrolv1.AccessAuditEvent{{
		EventId:          "e1",
		TurnstileId:      "t-1",
		EmployeeId:       "EMP-7",
		ZoneId:           "zone-server-room",
		Decision:         "granted offline",
		AccessGranted:    true,
		ProcessedOffline: true,
		OccurredUnix:     1700000000,
	}}}
	h := newAuditFixture(pol)

	rec := do(t, h.HandleQueryAccessEvents, http.MethodGet,
		"/api/v1/audit/access-events?employee_id=EMP-7&zone_id=zone-server-room"+
			"&turnstile_id=t-1&from_unix=1700000000&to_unix=1700009999&outcome=granted"+
			"&limit=25&page_token=abc123", "", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rec.Code, rec.Body.String())
	}
	got := pol.last
	if got.GetEmployeeId() != "EMP-7" || got.GetZoneId() != "zone-server-room" || got.GetTurnstileId() != "t-1" {
		t.Fatalf("identity filters were not forwarded: %+v", got)
	}
	if got.GetFromUnix() != 1700000000 || got.GetToUnix() != 1700009999 {
		t.Fatalf("time window was not forwarded: from=%d to=%d", got.GetFromUnix(), got.GetToUnix())
	}
	if got.GetOutcome() != accesscontrolv1.AccessEventOutcome_ACCESS_EVENT_OUTCOME_GRANTED {
		t.Fatalf("outcome filter was not forwarded: %v", got.GetOutcome())
	}
	if got.GetLimit() != 25 || got.GetPageToken() != "abc123" {
		t.Fatalf("pagination was not forwarded: limit=%d token=%q", got.GetLimit(), got.GetPageToken())
	}

	var body struct {
		Events []struct {
			EventID       string `json:"event_id"`
			EmployeeID    string `json:"employee_id"`
			ZoneID        string `json:"zone_id"`
			AccessGranted bool   `json:"access_granted"`
			Offline       bool   `json:"processed_offline"`
		} `json:"events"`
		NextPageToken string `json:"next_page_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not the documented JSON shape: %v", err)
	}
	if len(body.Events) != 1 || body.Events[0].EventID != "e1" {
		t.Fatalf("response lost the events: %+v", body.Events)
	}
	if !body.Events[0].AccessGranted || !body.Events[0].Offline {
		t.Fatalf("response lost the outcome fields: %+v", body.Events[0])
	}
}

// TestHandleQueryAccessEvents_DeniedOutcome checks the other half of the filter.
// An audit log that can only be asked about grants answers half the questions.
func TestHandleQueryAccessEvents_DeniedOutcome(t *testing.T) {
	pol := &stubAuditPolicy{}
	h := newAuditFixture(pol)

	rec := do(t, h.HandleQueryAccessEvents, http.MethodGet, "/api/v1/audit/access-events?outcome=denied", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if pol.last.GetOutcome() != accesscontrolv1.AccessEventOutcome_ACCESS_EVENT_OUTCOME_DENIED {
		t.Fatalf("denied filter was not forwarded: %v", pol.last.GetOutcome())
	}
}

// TestHandleQueryAccessEvents_RejectsBadInput keeps a mistyped filter from
// silently becoming "no filter". An operator who types outcome=grnated and gets
// every event back would draw the wrong conclusion from the answer.
func TestHandleQueryAccessEvents_RejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"unknown outcome":   "?outcome=grnated",
		"non-numeric time":  "?from_unix=yesterday",
		"negative time":     "?to_unix=-5",
		"negative from":     "?from_unix=-1",
		"negative limit":    "?limit=-3",
		"non-numeric limit": "?limit=lots",
	}
	for name, query := range cases {
		t.Run(name, func(t *testing.T) {
			pol := &stubAuditPolicy{}
			h := newAuditFixture(pol)
			rec := do(t, h.HandleQueryAccessEvents, http.MethodGet, "/api/v1/audit/access-events"+query, "", nil)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400 for %q: %s", rec.Code, query, rec.Body.String())
			}
		})
	}
}

// TestHandleQueryAccessEvents_PassesThroughCursor makes sure paging through the
// whole trail is possible: the handler must hand the caller's token onward and
// return the next one untouched.
// A page token is opaque: its encoding is the access-policy service's contract,
// not the gateway's, so the gateway forwards it untouched. The service rejects a
// forged or truncated one, which is asserted in the service package - duplicating
// that decode here would create two places that have to agree about the format.
func TestHandleQueryAccessEvents_PassesThroughCursor(t *testing.T) {
	pol := &stubAuditPolicy{token: "next-token-xyz"}
	h := newAuditFixture(pol)

	rec := do(t, h.HandleQueryAccessEvents, http.MethodGet,
		"/api/v1/audit/access-events?page_token=first-token", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if pol.last.GetPageToken() != "first-token" {
		t.Fatalf("cursor was not forwarded: %q", pol.last.GetPageToken())
	}
	if !strings.Contains(rec.Body.String(), "next-token-xyz") {
		t.Fatalf("next page token was not returned: %s", rec.Body.String())
	}
}

// TestHandleQueryAccessEvents_RejectsWriteMethods keeps this a read endpoint.
func TestHandleQueryAccessEvents_RejectsWriteMethods(t *testing.T) {
	pol := &stubAuditPolicy{}
	h := newAuditFixture(pol)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		rec := do(t, h.HandleQueryAccessEvents, method, "/api/v1/audit/access-events", "", nil)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s returned %d, want 405", method, rec.Code)
		}
	}
	if pol.calls != 0 {
		t.Fatalf("a write method reached the policy service %d times", pol.calls)
	}
}

// TestHandleQueryAccessEvents_ReportsDownstreamFailure: a failing policy service
// must not be reported as an empty trail. "No events" and "could not ask" are
// completely different answers during an investigation.
func TestHandleQueryAccessEvents_ReportsDownstreamFailure(t *testing.T) {
	pol := &stubAuditPolicy{err: status.Error(codes.Unavailable, "policy service unreachable")}
	h := newAuditFixture(pol)

	rec := do(t, h.HandleQueryAccessEvents, http.MethodGet, "/api/v1/audit/access-events", "", nil)
	if rec.Code == http.StatusOK {
		t.Fatalf("a failed query returned 200 with an empty-looking body: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"events":[]`) {
		t.Fatalf("a failure was rendered as an empty audit trail: %s", rec.Body.String())
	}
}
