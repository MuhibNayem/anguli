package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"finger-scanner/pkg/resilience"
)

// newTestLimiter builds a limiter that saturates quickly under test.
func newTestLimiter(t *testing.T, limit int, grace time.Duration) *resilience.Limiter {
	t.Helper()
	l, err := resilience.NewLimiter(resilience.LimiterConfig{Limit: limit, Grace: grace})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestOverload_RequiresLimiter(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Overload(nil limiter) did not panic; a nil limiter would nil-panic per request")
		}
	}()
	_ = Overload(OverloadConfig{})
}

func TestOverload_AdmitsBelowCapacity(t *testing.T) {
	l := newTestLimiter(t, 4, 50*time.Millisecond)
	var served atomic.Int64

	h := Overload(OverloadConfig{Limiter: l})(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		w.WriteHeader(http.StatusOK)
	})

	for i := 0; i < 4; i++ {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodPost, "/api/v1/biometrics/verify", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d got status %d; want 200", i, rec.Code)
		}
	}
	if served.Load() != 4 {
		t.Errorf("handler ran %d times; want 4", served.Load())
	}
	if l.Shed() != 0 {
		t.Errorf("Shed() = %d below capacity; want 0", l.Shed())
	}
}

func TestOverload_ShedsWith503AndRetryAfter(t *testing.T) {
	l := newTestLimiter(t, 1, time.Second)
	release := make(chan struct{})
	entered := make(chan struct{})

	h := Overload(OverloadConfig{Limiter: l, Timeout: time.Second})(
		func(w http.ResponseWriter, r *http.Request) {
			close(entered)
			<-release // hold the only slot
			w.WriteHeader(http.StatusOK)
		})

	go func() {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodPost, "/api/v1/biometrics/verify", nil))
	}()

	<-entered // the slot is now occupied

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/api/v1/biometrics/verify", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d under overload; want 503 so a load balancer can fail over", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got == "" {
		t.Error("Retry-After header missing on a shed response")
	}
	body := rec.Body.String()
	if strings.Contains(body, "overloaded:") || strings.Contains(body, "ErrWaitTimeout") {
		t.Errorf("shed response leaked internal error text: %q", body)
	}
	close(release)
}

func TestOverload_NeverExceedsConfiguredLimit(t *testing.T) {
	const limit = 4
	l := newTestLimiter(t, limit, 200*time.Millisecond)

	var (
		mu      sync.Mutex
		current int
		peak    int
	)
	h := Overload(OverloadConfig{Limiter: l})(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		current++
		if current > peak {
			peak = current
		}
		mu.Unlock()

		time.Sleep(2 * time.Millisecond)

		mu.Lock()
		current--
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})

	var wg sync.WaitGroup
	for i := 0; i < 300; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			h(rec, httptest.NewRequest(http.MethodGet, "/api/v1/doors/scan", nil))
		}()
	}
	wg.Wait()

	mu.Lock()
	got := peak
	mu.Unlock()
	if got > limit {
		t.Fatalf("peak in-flight handlers = %d; admission control must cap it at %d", got, limit)
	}
	// Shedding is deliberately not asserted here. At this offered load the
	// work drains inside the grace period, so shedding *should not* occur -
	// asserting it would mean the limiter sheds work it could have served.
	// Shedding itself is covered by TestOverload_ShedsWith503AndRetryAfter and
	// by TestLimiter_BoundsLatencyUnderOverload in pkg/resilience.
}

func TestOverload_MetricsArePublished(t *testing.T) {
	// Limit 1 so the second request is genuinely shed while the first holds
	// the only slot; with limit 2 both would be admitted and nothing to record.
	l := newTestLimiter(t, 1, 10*time.Millisecond)
	m := resilience.NewMetrics()

	release := make(chan struct{})
	entered := make(chan struct{})
	h := Overload(OverloadConfig{Limiter: l, Metrics: m, MetricsName: "test"})(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
	})

	go func() {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, "/api/v1/doors/scan", nil))
	}()
	<-entered

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/api/v1/doors/scan", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; want 503", rec.Code)
	}
	close(release)

	scrape := httptest.NewRecorder()
	m.Handler().ServeHTTP(scrape, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body := scrape.Body.String()
	for _, want := range []string{
		"anguli_limiter_shed_total",
		"anguli_limiter_in_flight",
		`limiter="test"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q", want)
		}
	}
	// Shedding must be observable; an unobservable shed policy is a guess.
	if !strings.Contains(body, "anguli_limiter_shed_total") || !strings.Contains(body, " 1") {
		t.Error("no shed was recorded in /metrics; load shedding would be invisible in production")
	}
}

func TestClassifyPriority(t *testing.T) {
	for path, want := range map[string]resilience.Priority{
		"/api/v1/doors/scan":         resilience.PriorityCritical,
		"/api/v1/doors/status":       resilience.PriorityCritical,
		"/api/v1/biometrics/verify":  resilience.PriorityCritical,
		"/api/v1/biometrics/enroll":  resilience.PriorityHigh,
		"/healthz":                   resilience.PriorityHigh,
		"/api/v1/policies/reset-apb": resilience.PriorityNormal,
		"/":                          resilience.PriorityNormal,
	} {
		if got := classifyPriority(path); got != want {
			t.Errorf("classifyPriority(%q) = %s; want %s", path, got, want)
		}
	}
}

func TestShedReason(t *testing.T) {
	if got := shedReason(nil); got != "none" {
		t.Errorf("shedReason(nil) = %q; want none", got)
	}
	if got := shedReason(resilience.ErrShed); got != "shed_immediate" {
		t.Errorf("shedReason(ErrShed) = %q; want shed_immediate", got)
	}
	if got := shedReason(resilience.ErrWaitTimeout); got != "wait_timeout" {
		t.Errorf("shedReason(ErrWaitTimeout) = %q; want wait_timeout", got)
	}
	if got := shedReason(context.DeadlineExceeded); got == "" {
		t.Error("shedReason returned an empty label; metric cardinality must stay bounded")
	}
}

func TestOverload_PreservesHandlerContext(t *testing.T) {
	l := newTestLimiter(t, 1, time.Second)
	var seen bool
	h := Overload(OverloadConfig{Limiter: l})(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Context() != nil
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if !seen {
		t.Error("handler received a nil context")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d; want 200", rec.Code)
	}
}
