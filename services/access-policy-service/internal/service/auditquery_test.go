package service_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"finger-scanner/services/access-policy-service/internal/adapters/memory"
	"finger-scanner/services/access-policy-service/internal/domain"
	"finger-scanner/services/access-policy-service/internal/service"
)

func auditService(t *testing.T) service.PolicyUseCase {
	t.Helper()
	repo := memory.NewMemoryPolicyRepository()
	svc := service.NewPolicyService(repo, nil)
	ctx := context.Background()
	for i := 0; i < 6; i++ {
		e := &domain.AccessAuditEvent{
			EventID:       fmt.Sprintf("e%d", i),
			TurnstileID:   "t-1",
			EmployeeID:    "EMP-1",
			ZoneID:        "zone-main-gate",
			Decision:      fmt.Sprintf("decision %d", i),
			AccessGranted: i%2 == 0,
			OccurredUnix:  1700000000 + int64(i),
		}
		if _, _, err := svc.RecordAccessEvents(ctx, []*domain.AccessAuditEvent{e}); err != nil {
			t.Fatal(err)
		}
	}
	return svc
}

// TestQueryAccessEventsRejectsForgedPageTokens is the security property of the
// cursor. The token is client-supplied base64 JSON, so it is attacker-controlled
// input, not a trusted position.
//
// The important half is what happens on rejection: it must be an error. Silently
// resetting to the first page would look to an operator like the trail ended,
// which during an investigation is the most dangerous answer this endpoint can
// give.
//
// Note what this is not: an authorisation check. The token is a pagination
// position, not a capability - every call is authorised on its own and the caller
// supplies its own filters - so a forged token buys a caller nothing it could not
// get by varying its query. What is being tested is that an unusable cursor is
// refused rather than silently reinterpreted.
func TestQueryAccessEventsRejectsForgedPageTokens(t *testing.T) {
	svc := auditService(t)
	ctx := context.Background()

	cases := map[string]string{
		"not base64":           "!!!not-a-token!!!",
		"base64 but not json":  base64.RawURLEncoding.EncodeToString([]byte("this is not json")),
		"json but wrong shape": base64.RawURLEncoding.EncodeToString([]byte(`{"nope":1}`)),
		"missing event id":     base64.RawURLEncoding.EncodeToString([]byte(`{"u":1700000003}`)),
		"empty json object":    base64.RawURLEncoding.EncodeToString([]byte(`{}`)),
		"wrong types":          base64.RawURLEncoding.EncodeToString([]byte(`{"u":"soon","e":"e1"}`)),
		"unknown field":        base64.RawURLEncoding.EncodeToString([]byte(`{"u":1700000003,"e":"e1","extra":true}`)),
	}

	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			events, next, err := svc.QueryAccessEvents(ctx,
				domain.AccessEventFilter{Limit: 10}, token)
			if err == nil {
				t.Fatalf("forged token was accepted and returned %d events with next=%q; a client can read any page it likes",
					len(events), next)
			}
			if code := status.Code(err); code != codes.InvalidArgument {
				t.Fatalf("error code is %s, want InvalidArgument: %v", code, err)
			}
			if len(events) != 0 {
				t.Fatalf("a rejected token still returned %d events", len(events))
			}
		})
	}
}

// TestQueryAccessEventsAcceptsItsOwnToken is the other half: the happy path must
// still work, or the endpoint is useless.
func TestQueryAccessEventsAcceptsItsOwnToken(t *testing.T) {
	svc := auditService(t)
	ctx := context.Background()

	first, next, err := svc.QueryAccessEvents(ctx, domain.AccessEventFilter{Limit: 2}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || next == "" {
		t.Fatalf("first page returned %d events with next=%q", len(first), next)
	}

	second, _, err := svc.QueryAccessEvents(ctx, domain.AccessEventFilter{Limit: 2}, next)
	if err != nil {
		t.Fatalf("continuing with the returned token: %v", err)
	}
	for _, e := range second {
		for _, p := range first {
			if e.EventID == p.EventID {
				t.Fatalf("event %s appears on both pages", e.EventID)
			}
		}
	}
}

// TestQueryAccessEventsRejectsInvertedWindow stops a mistyped range from reading
// as unbounded, which would return the entire trail and look like a filter that
// matched everything.
func TestQueryAccessEventsRejectsInvertedWindow(t *testing.T) {
	svc := auditService(t)

	_, _, err := svc.QueryAccessEvents(context.Background(), domain.AccessEventFilter{
		FromUnix: 1700000100, ToUnix: 1700000000,
	}, "")
	if err == nil {
		t.Fatal("an inverted time window was accepted")
	}
	if code := status.Code(err); code != codes.InvalidArgument {
		t.Fatalf("error code is %s, want InvalidArgument: %v", code, err)
	}
}

// TestQueryAccessEventsReadsBackWhatWasRecorded is the smallest end-to-end
// statement of what this whole change is for: a door decision recorded at the
// edge can be found again afterwards.
func TestQueryAccessEventsReadsBackWhatWasRecorded(t *testing.T) {
	svc := auditService(t)
	ctx := context.Background()

	got, _, err := svc.QueryAccessEvents(ctx, domain.AccessEventFilter{
		Limit: 100, EmployeeID: "EMP-1", Outcome: domain.OutcomeGranted,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("returned %d granted events, want 3", len(got))
	}
	if got[0].Decision == "" {
		t.Fatal("the newest event has no decision text; an operator could not tell why access was allowed")
	}
	if !strings.Contains(got[0].Decision, "decision") {
		t.Fatalf("decision text looks wrong: %q", got[0].Decision)
	}
}
