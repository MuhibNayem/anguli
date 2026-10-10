package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"

	"finger-scanner/pkg/resilience"
	"finger-scanner/pkg/security/ratelimit"
)

// RateLimitConfig configures per-caller rate limiting for sensitive endpoints.
type RateLimitConfig struct {
	// Limiter holds one token bucket per caller. Required.
	Limiter *ratelimit.KeyedLimiter
	// Metrics optionally publishes allow/reject series. Optional.
	Metrics *resilience.Metrics
	// MetricsName labels the limiter in published series.
	MetricsName string
	// Logger records rejections. Required - a suppressed request that leaves
	// no trace is indistinguishable from a request that never arrived.
	Logger *slog.Logger
}

// RateLimit bounds how many sensitive requests one caller may make.
//
// This exists because of a property specific to biometrics rather than to web
// services generally. The 1:N identification path answers "who does this print
// belong to" across the whole gallery, and the gateway sits behind a single
// shared API key. Without a per-caller bound, one holder of that key can walk
// a building's roster out of the system one scan at a time, and the population
// of a site is exactly the thing an access system is not supposed to disclose.
// Fingerprint templates cannot be reissued if they leak, so the disclosure
// they cause is permanent.
//
// What this does and does not do is worth being precise about. It raises the
// cost of enumeration from minutes to hours and makes the attempt visible in
// the metrics and the log. It does NOT stop a caller who already holds valid
// credentials and is willing to be slow. That requires the credential itself to
// be scoped per reader, which is a deployment property, not a middleware
// behaviour. See docs/production-status.md.
//
// A rejected request returns 429 with Retry-After. It is not an error in the
// upstream services and no downstream work is done, so nothing is logged twice.
func RateLimit(cfg RateLimitConfig) func(http.HandlerFunc) http.HandlerFunc {
	if cfg.Limiter == nil {
		panic("middleware: RateLimit requires a Limiter")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.MetricsName == "" {
		cfg.MetricsName = "api-gateway"
	}
	// One token accrues every 1/rate seconds. Clamped to at least 1s because
	// Retry-After: 0 invites an immediate retry, which is the opposite of what
	// a caller that has been throttled needs.
	retryAfter := int(math.Ceil(1 / cfg.Limiter.Rate()))
	if retryAfter < 1 {
		retryAfter = 1
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			key := callerKey(r)
			if cfg.Limiter.Allow(key) {
				if cfg.Metrics != nil {
					cfg.Metrics.ObserveRateLimit(cfg.MetricsName, true)
				}
				next(w, r)
				return
			}

			if cfg.Metrics != nil {
				cfg.Metrics.ObserveRateLimit(cfg.MetricsName, false)
			}
			cfg.Logger.WarnContext(r.Context(), "rate limit rejected a sensitive request",
				slog.String("caller", callerLabel(key)),
				slog.String("path", r.URL.Path),
				slog.Int("retry_after_s", retryAfter),
			)

			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limit exceeded, retry shortly"}` + "\n"))
		}
	}
}

// callerKey derives the bucket key for a request.
//
// The preference order is strongest-credential-first: a reader channel is
// attributable to a physical device, an API key is not. Falling back to the
// remote address means an unauthenticated flood is still bounded rather than
// being counted against the bucket of a legitimate reader sharing a NAT egress.
func callerKey(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Reader-ID")); v != "" {
		return "reader:" + fingerprint(v)
	}
	if v := strings.TrimSpace(r.Header.Get("X-Reader-Token")); v != "" {
		return "token:" + fingerprint(v)
	}
	if v := strings.TrimSpace(r.Header.Get("X-API-Key")); v != "" {
		return "apikey:" + fingerprint(v)
	}
	return "ip:" + remoteHost(r)
}

// fingerprint reduces a credential to a short, stable, non-reversible tag.
//
// The limiter holds one of these per caller for the life of the process, and
// process memory is dumpable. Storing the raw API key there would turn a memory
// disclosure into a credential disclosure, and nothing about the limiter needs
// the original value: it only needs to tell callers apart.
func fingerprint(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:8])
}

// callerLabel renders a bucket key for logs. It is already a non-reversible
// tag, so this is a pass-through that exists to make the intent explicit
// rather than to re-hash.
func callerLabel(key string) string { return key }

// remoteHost extracts the bare host from a RemoteAddr, tolerating the
// proxy/UNIX forms that do not parse as host:port.
func remoteHost(r *http.Request) string {
	addr := r.RemoteAddr
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
