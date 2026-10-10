package middleware

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"finger-scanner/pkg/resilience"
)

// OverloadConfig configures admission control for the HTTP surface.
type OverloadConfig struct {
	// Limiter bounds concurrent request handling. Required.
	Limiter *resilience.Limiter
	// Metrics optionally publishes limiter series. Optional.
	Metrics *resilience.Metrics
	// MetricsName labels the limiter in published series.
	MetricsName string
	// OverloadedStatusCode is returned when a request is shed. Defaults to
	// 503, which is what a load balancer needs to see in order to fail over
	// rather than retry into the same instance.
	OverloadedStatusCode int
	// Timeout is written as the Retry-After hint on a shed response.
	Timeout time.Duration
}

// criticalPaths are the requests that must not be starved. A door that is
// physically open has to be commanded shut regardless of how much background
// work is queued behind it.
var criticalPaths = []string{
	"/api/v1/doors/scan",
	"/api/v1/doors/status",
	"/api/v1/biometrics/verify",
}

// Shedding middleware bounds how much work the gateway admits at once and
// sheds the rest, instead of letting every request queue and converting an
// overload into unbounded latency.
//
// Without this, offered load above capacity does not produce errors - it
// produces a service that stops answering. Measured on this platform, verify
// latency grew from 140ms at one concurrent request to 4.4s at 128. Shedding
// deliberately returns 503 quickly, which is both faster for the user and
// visible to a load balancer.
func Overload(cfg OverloadConfig) func(http.HandlerFunc) http.HandlerFunc {
	if cfg.Limiter == nil {
		panic("middleware: Overload requires a Limiter")
	}
	if cfg.MetricsName == "" {
		cfg.MetricsName = "gateway"
	}
	if cfg.OverloadedStatusCode == 0 {
		cfg.OverloadedStatusCode = http.StatusServiceUnavailable
	}
	retryAfter := int(cfg.Timeout.Seconds())
	if cfg.Timeout <= 0 {
		retryAfter = 1
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			priority := classifyPriority(r.URL.Path)

			start := time.Now()
			err := cfg.Limiter.Do(r.Context(), priority, func(ctx context.Context) error {
				next(w, r.WithContext(ctx))
				return nil
			})

			if cfg.Metrics != nil {
				cfg.Metrics.ObserveLimiter(cfg.MetricsName, cfg.Limiter.Stats())
			}

			if err != nil {
				if cfg.Metrics != nil {
					cfg.Metrics.ObserveShed(cfg.MetricsName, priority, shedReason(err))
				}
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(cfg.OverloadedStatusCode)
				// Do not leak internal error strings to an unauthenticated
				// caller; the reason belongs in the metrics and logs.
				_, _ = w.Write([]byte(`{"error":"service overloaded, retry shortly"}` + "\n"))
				return
			}

			if cfg.Metrics != nil {
				cfg.Metrics.ObserveAdmitted(cfg.MetricsName, priority)
			}
			_ = start
		}
	}
}

// classifyPriority assigns a shedding class from the request path.
func classifyPriority(path string) resilience.Priority {
	for _, p := range criticalPaths {
		if strings.HasPrefix(path, p) {
			return resilience.PriorityCritical
		}
	}
	switch {
	case strings.HasPrefix(path, "/api/v1/biometrics/enroll"):
		// Enrollment is user-initiated and latency-sensitive.
		return resilience.PriorityHigh
	case strings.HasPrefix(path, "/healthz"):
		// Health must stay answerable under load or an orchestrator will kill
		// a healthy instance precisely when it is busiest.
		return resilience.PriorityHigh
	default:
		return resilience.PriorityNormal
	}
}

// shedReason maps a limiter error to a bounded, low-cardinality label.
func shedReason(err error) string {
	switch {
	case err == nil:
		return "none"
	case strings.Contains(err.Error(), "shed immediately"):
		return "shed_immediate"
	case strings.Contains(err.Error(), "timed out waiting"):
		return "wait_timeout"
	default:
		return "other"
	}
}
