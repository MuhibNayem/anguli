package middleware

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"finger-scanner/pkg/resilience"
	"finger-scanner/pkg/security/ratelimit"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testRateLimit(burst float64) func(http.HandlerFunc) http.HandlerFunc {
	l, err := ratelimit.NewKeyedLimiter(ratelimit.KeyedLimiterConfig{Rate: 1, Burst: burst})
	if err != nil {
		panic(err)
	}
	return RateLimit(RateLimitConfig{Limiter: l, Logger: quietLogger()})
}

func TestRateLimitRejectsBeyondBurst(t *testing.T) {
	allowed := 0
	mw := testRateLimit(2)
	h := mw(func(w http.ResponseWriter, r *http.Request) {
		allowed++
		w.WriteHeader(http.StatusOK)
	})

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/doors/scan", nil)
		req.Header.Set("X-Reader-ID", "turnstile-01")
		rec := httptest.NewRecorder()
		h(rec, req)

		if i < 2 {
			if rec.Code != http.StatusOK {
				t.Fatalf("request %d: status %d, want 200", i, rec.Code)
			}
		} else {
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("request %d: status %d, want 429", i, rec.Code)
			}
			if got := rec.Header().Get("Retry-After"); got != "1" {
				t.Fatalf("request %d: Retry-After=%q, want \"1\"", i, got)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Fatalf("request %d: Content-Type=%q", i, ct)
			}
			if !strings.Contains(rec.Body.String(), "rate limit exceeded") {
				t.Fatalf("request %d: body %q should not leak internals", i, rec.Body.String())
			}
		}
	}
	if allowed != 2 {
		t.Fatalf("handler ran %d times, want 2: a throttled request must not do downstream work", allowed)
	}
}

func TestRateLimitSeparatesCallers(t *testing.T) {
	mw := testRateLimit(1)
	h := mw(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	// Exhaust one reader.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/doors/scan", nil)
		req.Header.Set("X-Reader-ID", "turnstile-01")
		h(httptest.NewRecorder(), req)
	}

	// A different reader must be untouched. Every turnstile on a site shares
	// one API key, so a global limit could not make this distinction at all.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/doors/scan", nil)
	req.Header.Set("X-Reader-ID", "turnstile-02")
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("turnstile-02 got %d, want 200: one noisy door must not consume another's budget", rec.Code)
	}
}

func TestRateLimitKeysPreferStrongestCredential(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{"reader id wins", map[string]string{"X-Reader-ID": "t-1", "X-Reader-Token": "tok", "X-API-Key": "key"}, "reader:"},
		{"token beats api key", map[string]string{"X-Reader-Token": "tok", "X-API-Key": "key"}, "token:"},
		{"api key used alone", map[string]string{"X-API-Key": "key"}, "apikey:"},
		{"whitespace-only header is not a credential", map[string]string{"X-Reader-ID": "   "}, "ip:"},
		{"no credentials falls back to address", nil, "ip:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/doors/scan", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			req.RemoteAddr = "10.0.0.7:5555"
			got := callerKey(req)
			if !strings.HasPrefix(got, tc.want) {
				t.Fatalf("callerKey=%q, want prefix %q", got, tc.want)
			}
		})
	}
}

// TestCallerKeyDoesNotRetainRawCredentials is the reason callerKey hashes.
//
// The limiter holds one key per caller for the life of the process and process
// memory is dumpable. Storing the raw API key or reader token would turn a
// memory disclosure into a credential disclosure, and nothing in the limiter
// needs the original value.
func TestCallerKeyDoesNotRetainRawCredentials(t *testing.T) {
	const secret = "super-secret-api-key-value"
	req := httptest.NewRequest(http.MethodPost, "/api/v1/doors/scan", nil)
	req.Header.Set("X-API-Key", secret)
	got := callerKey(req)

	if strings.Contains(got, secret) {
		t.Fatalf("callerKey %q retains the raw credential", got)
	}

	// It must be stable, or a caller would be throttled against a new bucket
	// on every request and the limit would mean nothing.
	again := callerKey(req)
	if got != again {
		t.Fatalf("callerKey is not stable: %q then %q", got, again)
	}

	// And it must distinguish callers.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/doors/scan", nil)
	req2.Header.Set("X-API-Key", secret+"-other")
	if callerKey(req2) == got {
		t.Fatal("distinct credentials produced the same bucket key")
	}
}

func TestRemoteHostToleratesNonHostPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/doors/scan", nil)
	req.RemoteAddr = "/tmp/gateway.sock"
	if got := remoteHost(req); got != "/tmp/gateway.sock" {
		t.Fatalf("remoteHost=%q, want the raw address for a UNIX socket", got)
	}
	req.RemoteAddr = "10.0.0.7:5555"
	if got := remoteHost(req); got != "10.0.0.7" {
		t.Fatalf("remoteHost=%q, want the bare host", got)
	}
}

func TestRateLimitPublishesMetrics(t *testing.T) {
	l, err := ratelimit.NewKeyedLimiter(ratelimit.KeyedLimiterConfig{Rate: 1, Burst: 1})
	if err != nil {
		t.Fatal(err)
	}
	m := resilience.NewMetrics()
	mw := RateLimit(RateLimitConfig{Limiter: l, Metrics: m, MetricsName: "test", Logger: quietLogger()})
	h := mw(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/doors/scan", nil)
		req.Header.Set("X-Reader-ID", "t-1")
		h(httptest.NewRecorder(), req)
	}

	families, err := m.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var allowed, rejected float64
	for _, f := range families {
		for _, metric := range f.GetMetric() {
			switch f.GetName() {
			case "anguli_ratelimit_allowed_total":
				allowed += metric.GetCounter().GetValue()
			case "anguli_ratelimit_rejected_total":
				rejected += metric.GetCounter().GetValue()
			}
		}
	}
	if allowed != 1 || rejected != 2 {
		t.Fatalf("allowed=%v rejected=%v, want 1 and 2; a throttled request must be visible in metrics", allowed, rejected)
	}
}

func TestRateLimitRequiresLimiter(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("RateLimit without a Limiter should panic rather than silently pass every request")
		}
	}()
	RateLimit(RateLimitConfig{Logger: quietLogger()})
}
