package integration_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	"finger-scanner/pkg/store"
	accesspolicyservice "finger-scanner/services/access-policy-service"
	edgegatewayservice "finger-scanner/services/edge-gateway-service"
)

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// centralAuditStore is a real SQLite-backed access-policy service on an ephemeral
// port, using the same migrations and repository the daemon uses.
func centralAuditStore(t *testing.T, ctx context.Context) (*store.Store, accesscontrolv1.AccessPolicyServiceClient) {
	t.Helper()

	st, err := store.Open(ctx, store.Config{
		Driver:  store.DriverSQLite,
		DSN:     "file:" + filepath.Join(t.TempDir(), "policy.db") + "?_pragma=busy_timeout(5000)",
		DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("open central store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	srv := grpc.NewServer()
	if err := accesspolicyservice.RegisterServiceWithStorage(srv, st, silentLogger()); err != nil {
		t.Fatalf("mount policy service over SQL storage: %v", err)
	}
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("connect to policy service: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return st, accesscontrolv1.NewAccessPolicyServiceClient(conn)
}

// TestOfflineAuditReachesCentralStorage is the end-to-end proof that the audit
// trail leaves the edge.
//
// Every layer of this was individually correct while the feature did not work.
// The edge buffered door decisions to a durable WAL; ReplayEvents forwarded them;
// a gRPC endpoint exposed it; central storage had a table to receive them. But
// no running edge process ever called ReplayEvents, so central storage never
// received anything, and "who entered which door, and when" had no answer outside
// one edge machine's disk.
//
// The unit tests could not catch this: they call ReplayEvents directly. Only
// driving the replay the way the daemon does shows whether the chain closes.
func TestOfflineAuditReachesCentralStorage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	st, policyClient := centralAuditStore(t, ctx)
	node := edgegatewayservice.NewNode("", policyClient, silentLogger())

	// An outage: door decisions pile up on the edge while central is unreachable.
	const events = 25
	for i := 0; i < events; i++ {
		if err := node.BufferOfflineEvent(ctx, edgeAuditEvent(i)); err != nil {
			t.Fatalf("buffer offline event: %v", err)
		}
	}
	if n := countAuditRows(t, st); n != 0 {
		t.Fatalf("central storage already holds %d rows during the outage", n)
	}

	// WAN returns. Nothing calls the replay RPC; the daemon's loop must.
	go node.RunOfflineReplayLoop(ctx, 50*time.Millisecond, silentLogger())

	waitForAuditRows(t, st, events)

	// Spot-check that rows carry what an investigation needs. Both outcomes are
	// checked: an audit log that only records grants is half an answer, and the
	// expected values come from the helper so the assertion cannot drift from it.
	for _, i := range []int{2, 3} {
		want := edgeAuditEvent(i)
		var employee, zone, decision string
		var granted, offline int
		err := st.DB().QueryRowContext(ctx, `
			SELECT employee_id, zone_id, decision, access_granted, processed_offline
			FROM access_audit_events WHERE event_id = ?`, want.EventID,
		).Scan(&employee, &zone, &decision, &granted, &offline)
		if err != nil {
			t.Fatalf("read replayed audit row %s: %v", want.EventID, err)
		}
		if employee != want.EmployeeID || zone != want.ZoneID {
			t.Fatalf("audit row %s lost who/where: employee=%q zone=%q", want.EventID, employee, zone)
		}
		if decision != want.Decision {
			t.Fatalf("audit row %s decision=%q, want %q", want.EventID, decision, want.Decision)
		}
		wantGranted := 0
		if want.AccessGranted {
			wantGranted = 1
		}
		if granted != wantGranted {
			t.Fatalf("audit row %s access_granted=%d, want %d; the outcome was altered in transit",
				want.EventID, granted, wantGranted)
		}
		if offline != 1 {
			t.Fatalf("audit row %s is not marked as decided offline, so a later audit cannot distinguish a cached decision from a live one",
				want.EventID)
		}
	}

	// And the edge must release the durable copy only once it is safe to.
	deadline := time.Now().Add(5 * time.Second)
	for node.PendingOfflineEvents(ctx) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("edge still holds %d events after a confirmed central replay",
				node.PendingOfflineEvents(ctx))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestOfflineAuditIsNotDuplicatedOnRepeatedReplay covers the property that makes
// an always-on loop safe: it retries, so it must be idempotent. Every tick can
// re-forward whatever the previous tick did not have acknowledged, and central
// must still hold exactly one row per door entry.
func TestOfflineAuditIsNotDuplicatedOnRepeatedReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	st, policyClient := centralAuditStore(t, ctx)
	node := edgegatewayservice.NewNode("", policyClient, silentLogger())

	const events = 10
	for i := 0; i < events; i++ {
		if err := node.BufferOfflineEvent(ctx, edgeAuditEvent(i)); err != nil {
			t.Fatal(err)
		}
	}

	// Replay repeatedly, as a long-running loop would.
	for i := 0; i < 5; i++ {
		if _, err := node.Replay(ctx); err != nil {
			t.Fatalf("replay %d: %v", i, err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	if n := countAuditRows(t, st); n != events {
		t.Fatalf("central storage holds %d rows for %d door entries; repeated replay duplicated the audit trail",
			n, events)
	}
}

// TestOfflineAuditSurvivesAnEdgeRestart covers the case the whole WAL exists for:
// the edge loses power during an outage and reboots. The buffered decisions must
// still reach central storage afterwards.
func TestOfflineAuditSurvivesAnEdgeRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	st, policyClient := centralAuditStore(t, ctx)
	walPath := filepath.Join(t.TempDir(), "edge-offline.wal")

	node := edgegatewayservice.NewNode(walPath, policyClient, silentLogger())
	const events = 7
	for i := 0; i < events; i++ {
		if err := node.BufferOfflineEvent(ctx, edgeAuditEvent(i)); err != nil {
			t.Fatal(err)
		}
	}

	// Power cut: the process goes away without replaying anything.
	node = nil
	if n := countAuditRows(t, st); n != 0 {
		t.Fatalf("central storage holds %d rows before the restart", n)
	}

	// Reboot against the same WAL, and let the loop run.
	restarted := edgegatewayservice.NewNode(walPath, policyClient, silentLogger())
	if pending := restarted.PendingOfflineEvents(ctx); pending != events {
		t.Fatalf("recovered %d events from the WAL after restart, want %d; the audit trail did not survive a reboot",
			pending, events)
	}
	restarted.Replay(ctx)
	waitForAuditRows(t, st, events)
}

// edgeAuditEvent builds one buffered door decision for the end-to-end tests.
// Every field derives from the index, so a dropped or shifted field shows up as a
// specific wrong value rather than as a plausible-looking constant.
func edgeAuditEvent(i int) edgegatewayservice.OfflineEvent {
	return edgegatewayservice.OfflineEvent{
		EventID:       fmt.Sprintf("evt-e2e-%d", i),
		TurnstileID:   "turnstile-01",
		EmployeeID:    fmt.Sprintf("EMP-e2e-%d", i),
		ZoneID:        "zone-main-gate",
		AccessGranted: i%2 == 0,
		Decision:      fmt.Sprintf("decision for entry %d", i),
		TimestampUnix: 1700000000 + int64(i),
	}
}

func countAuditRows(t *testing.T, st *store.Store) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM access_audit_events`).Scan(&n); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	return n
}

// waitForAuditRows polls until the central store holds want rows, which is how
// the asynchronous replay loop is observed.
func waitForAuditRows(t *testing.T, st *store.Store, want int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var n int
	for time.Now().Before(deadline) {
		if err := st.DB().QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM access_audit_events`).Scan(&n); err != nil {
			t.Fatalf("count audit rows: %v", err)
		}
		if n >= want {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("central storage holds %d audit rows, want %d; the offline audit trail never reached central storage", n, want)
}
