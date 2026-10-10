package resilience

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics publishes Prometheus series for the resilience primitives.
//
// Rationale: load shedding and circuit breaking are only safe to enable if you
// can see them working. Without these series, a shedding policy is invisible
// until someone complains, and a breaker that is stuck open looks identical to
// a dependency that is simply slow.
type Metrics struct {
	Registry *prometheus.Registry

	limiterInFlight *prometheus.GaugeVec
	limiterWaiting  *prometheus.GaugeVec
	limiterAdmitted *prometheus.CounterVec
	limiterShed     *prometheus.CounterVec
	limiterUtil     *prometheus.GaugeVec

	breakerState       *prometheus.GaugeVec
	breakerSuccesses   *prometheus.GaugeVec
	breakerFailures    *prometheus.GaugeVec
	breakerRejected    *prometheus.GaugeVec
	breakerTransitions *prometheus.GaugeVec

	retryAttempts *prometheus.CounterVec

	rateLimitAllowed  *prometheus.CounterVec
	rateLimitRejected *prometheus.CounterVec
}

// NewMetrics builds a Metrics with its own registry, so tests do not collide
// on the default registerer's global state.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		Registry: reg,
		limiterInFlight: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "anguli_limiter_in_flight",
			Help: "Current number of admitted requests holding a concurrency slot.",
		}, []string{"limiter"}),
		limiterWaiting: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "anguli_limiter_waiting",
			Help: "Current number of callers blocked waiting for a slot.",
		}, []string{"limiter"}),
		limiterAdmitted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "anguli_limiter_admitted_total",
			Help: "Total requests granted a concurrency slot.",
		}, []string{"limiter", "priority"}),
		limiterShed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "anguli_limiter_shed_total",
			Help: "Total requests rejected by admission control.",
		}, []string{"limiter", "priority", "reason"}),
		limiterUtil: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "anguli_limiter_utilisation_ratio",
			Help: "Fraction of concurrency slots currently occupied (0..1).",
		}, []string{"limiter"}),
		breakerState: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "anguli_circuit_breaker_state",
			Help: "Circuit breaker state: 1 for the current state, 0 otherwise.",
		}, []string{"breaker", "state"}),
		// The breaker keeps its own cumulative totals, so these are gauges
		// holding absolute values rather than counters we increment here.
		// Using a CounterVec would require tracking deltas against state we
		// do not retain, and a wrong delta silently corrupts a monotonic series.
		breakerSuccesses: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "anguli_circuit_breaker_success_total",
			Help: "Total calls the breaker passed as successful.",
		}, []string{"breaker"}),
		breakerFailures: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "anguli_circuit_breaker_failure_total",
			Help: "Total call failures observed by the breaker.",
		}, []string{"breaker"}),
		breakerRejected: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "anguli_circuit_breaker_rejected_total",
			Help: "Total calls rejected without reaching the dependency.",
		}, []string{"breaker"}),
		breakerTransitions: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "anguli_circuit_breaker_transitions_total",
			Help: "Total circuit breaker state transitions.",
		}, []string{"breaker"}),
		rateLimitAllowed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "anguli_ratelimit_allowed_total",
			Help: "Sensitive requests admitted by per-caller rate limiting.",
		}, []string{"limiter"}),
		rateLimitRejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "anguli_ratelimit_rejected_total",
			Help: "Sensitive requests rejected by per-caller rate limiting. " +
				"A sustained non-zero rate is either a misconfigured limit or an enumeration attempt.",
		}, []string{"limiter"}),
		retryAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "anguli_retry_attempts_total",
			Help: "Total retry attempts by operation and outcome.",
		}, []string{"operation", "outcome"}),
	}
	reg.MustRegister(
		m.limiterInFlight, m.limiterWaiting, m.limiterAdmitted, m.limiterShed,
		m.limiterUtil, m.breakerState, m.breakerSuccesses, m.breakerFailures,
		m.breakerRejected, m.breakerTransitions, m.retryAttempts,
		m.rateLimitAllowed, m.rateLimitRejected,
	)
	return m
}

// Handler returns the /metrics HTTP handler.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}

// ObserveLimiter publishes a limiter snapshot.
func (m *Metrics) ObserveLimiter(name string, s Stats) {
	m.limiterInFlight.WithLabelValues(name).Set(float64(s.InFlight))
	m.limiterWaiting.WithLabelValues(name).Set(float64(s.Waiting))
	m.limiterUtil.WithLabelValues(name).Set(s.Utilisation)
	m.limiterAdmitted.WithLabelValues(name, "all").Add(0) // materialise the series
}

// ObserveShed records one shed event.
func (m *Metrics) ObserveShed(name string, p Priority, reason string) {
	m.limiterShed.WithLabelValues(name, p.String(), reason).Inc()
}

// ObserveAdmitted records one admission.
func (m *Metrics) ObserveAdmitted(name string, p Priority) {
	m.limiterAdmitted.WithLabelValues(name, p.String()).Inc()
}

// ObserveBreaker publishes a breaker snapshot. Exactly one state gauge is 1.
func (m *Metrics) ObserveBreaker(name string, b *Breaker) {
	for _, s := range []State{StateClosed, StateOpen, StateHalfOpen} {
		v := 0.0
		if b.State() == s {
			v = 1.0
		}
		m.breakerState.WithLabelValues(name, s.String()).Set(v)
	}
	succ, fail, rej, trans := b.Counters()
	m.breakerSuccesses.WithLabelValues(name).Set(float64(succ))
	m.breakerFailures.WithLabelValues(name).Set(float64(fail))
	m.breakerRejected.WithLabelValues(name).Set(float64(rej))
	m.breakerTransitions.WithLabelValues(name).Set(float64(trans))
}

// ObserveRateLimit records one rate-limit decision.
//
// The rejected series exists so an enumeration attempt is visible without
// having to read logs: the whole point of bounding a caller is that the
// attempt becomes observable, and a limiter nobody can watch is just a slower
// service.
func (m *Metrics) ObserveRateLimit(name string, allowed bool) {
	if allowed {
		m.rateLimitAllowed.WithLabelValues(name).Inc()
		return
	}
	m.rateLimitRejected.WithLabelValues(name).Inc()
}

// ObserveRetry records one retry attempt outcome.
func (m *Metrics) ObserveRetry(operation, outcome string) {
	m.retryAttempts.WithLabelValues(operation, outcome).Inc()
}

// DurationSeconds converts a duration for Prometheus histogram use.
func DurationSeconds(d time.Duration) float64 { return d.Seconds() }

// ParseIntDefault parses s, returning def when unparseable. Small helper for
// reading numeric configuration from the environment.
func ParseIntDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}
