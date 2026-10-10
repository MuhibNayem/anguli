package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"finger-scanner/pkg/resilience"
	"finger-scanner/pkg/security/ratelimit"
	securitytls "finger-scanner/pkg/security/tls"
	"finger-scanner/pkg/telemetry"
	"finger-scanner/services/api-gateway/internal/clients"
	"finger-scanner/services/api-gateway/internal/handlers"
	"finger-scanner/services/api-gateway/internal/middleware"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	httpPort := os.Getenv("PORT")
	if httpPort == "" {
		httpPort = "8080"
	}

	bioAddr := os.Getenv("BIOMETRIC_ADDR")
	if bioAddr == "" {
		bioAddr = "localhost:50051"
	}

	policyAddr := os.Getenv("POLICY_ADDR")
	if policyAddr == "" {
		policyAddr = "localhost:50052"
	}

	edgeAddr := os.Getenv("EDGE_ADDR")
	if edgeAddr == "" {
		edgeAddr = "localhost:50053"
	}

	env := os.Getenv("ENVIRONMENT")
	if env == "" {
		env = "production"
	}

	tel, cleanupTel, err := telemetry.Setup(ctx, telemetry.Config{
		ServiceName:    "api-gateway",
		ServiceVersion: "1.0.0",
		Environment:    env,
		EnableStdout:   false,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup telemetry: %v\n", err)
		os.Exit(1)
	}
	defer cleanupTel(context.Background())

	logger := tel.Logger
	logger.InfoContext(ctx, "starting api-gateway", slog.String("port", httpPort), slog.String("env", env))

	// Connect to downstream gRPC services.
	//
	// Transport security comes from the environment so one build covers both
	// a single-host plaintext development cluster and a mTLS production mesh.
	// A misconfigured TLS block fails the dial rather than silently falling
	// back to cleartext - see pkg/security/tls.
	tlsCfg := securitytls.LoadConfigFromEnv()
	logger.InfoContext(ctx, "downstream transport configured", slog.String("tls", tlsCfg.Describe()))

	serviceClients, err := clients.NewServiceClients(ctx, clients.Config{
		BiometricsAddr:   bioAddr,
		AccessPolicyAddr: policyAddr,
		EdgeGatewayAddr:  edgeAddr,
		TLS:              tlsCfg,
	}, logger)
	if err != nil {
		logger.ErrorContext(ctx, "failed to initialize gRPC clients", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer serviceClients.Close()

	authConfig := middleware.NewAuthConfig(logger)

	// Overload protection: bounded concurrency with load shedding. Without a
	// ceiling, offered load above capacity does not produce errors - it
	// produces a service that stops answering.
	limiter, err := resilience.NewLimiter(resilience.LimiterConfig{
		Limit: resilience.ParseIntDefault(os.Getenv("MAX_CONCURRENT_REQUESTS"), 64),
		Grace: time.Duration(resilience.ParseIntDefault(os.Getenv("ADMISSION_GRACE_MS"), 250)) * time.Millisecond,
	})
	if err != nil {
		logger.ErrorContext(ctx, "invalid overload configuration", slog.String("error", err.Error()))
		os.Exit(1)
	}
	metrics := resilience.NewMetrics()

	// Per-dependency circuit breakers with retry and jittered backoff. These
	// are separate per service so one sick dependency cannot disconnect the
	// gateway from the two that are healthy.
	breakers, err := clients.NewBreakers(clients.BreakerConfig{})
	if err != nil {
		logger.ErrorContext(ctx, "invalid circuit breaker configuration", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// The breakers are only useful if the requests actually travel through
	// them. Constructing them here and handing them to the handler is what
	// turns them from an inert metrics source into protection.
	handler := handlers.NewGatewayHandlerWithBreakers(serviceClients, breakers, logger)
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				breakers.Observe(metrics)
			}
		}
	}()

	logger.InfoContext(ctx, "overload protection enabled",
		slog.Int("max_concurrent_requests", limiter.Limit()),
		slog.Int("admission_grace_ms", resilience.ParseIntDefault(os.Getenv("ADMISSION_GRACE_MS"), 250)),
	)

	overload := middleware.Overload(middleware.OverloadConfig{
		Limiter:     limiter,
		Metrics:     metrics,
		MetricsName: "api-gateway",
		Timeout:     time.Second,
	})

	// Per-caller rate limiting on the biometric surface.
	//
	// The concurrency limiter above protects the SERVICE from overload. This
	// one protects the DATA, which is the reason it exists: the 1:N
	// identification path answers "who does this print belong to" across the
	// whole gallery, so an unthrottled caller holding the shared API key can
	// walk the building's roster out of the system one scan at a time.
	//
	// Defaults assume a busy main gate peaking around 2 scans/second, which
	// leaves roughly 5x headroom. Raise RATE_LIMIT_RPS for a larger site rather
	// than removing it - the failure mode of a too-low limit is rejected doors,
	// so it is set deliberately and observable, never silently.
	rateLimiter, err := ratelimit.NewKeyedLimiter(ratelimit.KeyedLimiterConfig{
		Rate:    float64(resilience.ParseIntDefault(os.Getenv("RATE_LIMIT_RPS"), 10)),
		Burst:   float64(resilience.ParseIntDefault(os.Getenv("RATE_LIMIT_BURST"), 20)),
		MaxKeys: resilience.ParseIntDefault(os.Getenv("RATE_LIMIT_MAX_KEYS"), 10_000),
	})
	if err != nil {
		logger.ErrorContext(ctx, "invalid rate limit configuration", slog.String("error", err.Error()))
		os.Exit(1)
	}
	rateLimit := middleware.RateLimit(middleware.RateLimitConfig{
		Limiter: rateLimiter,
		Metrics: metrics,
		Logger:  logger,
	})

	// Evict idle caller buckets so the table tracks active readers rather than
	// every caller seen since boot. Without this the limiter's own memory
	// grows without bound, which would make it the outage it exists to avoid.
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				rateLimiter.Sweep()
			}
		}
	}()

	logger.InfoContext(ctx, "per-caller rate limiting enabled",
		slog.Float64("requests_per_second", rateLimiter.Rate()),
		slog.Float64("burst", rateLimiter.Burst()),
		slog.Int("max_tracked_callers", resilience.ParseIntDefault(os.Getenv("RATE_LIMIT_MAX_KEYS"), 10_000)),
	)

	// L3: Configurable and restricted CORS origins
	corsOrigins := os.Getenv("CORS_ALLOWED_ORIGINS")
	var origins []string
	if corsOrigins != "" {
		origins = strings.Split(corsOrigins, ",")
	} else {
		origins = []string{"http://localhost:8080", "http://127.0.0.1:8080", "http://localhost:3000"}
	}
	cors := func(next http.HandlerFunc) http.HandlerFunc {
		return middleware.SecureCORSMiddleware(origins, next)
	}

	mux := http.NewServeMux()

	// C4 & C5: Protected REST Endpoints requiring API Key or Bearer Token.
	// Every request passes admission control first so the ceiling applies
	// before any work is accepted.
	// rateLimit sits inside auth so an unauthenticated flood is rejected before
	// it can consume a legitimate reader's budget, and inside overload so a
	// throttled request never takes a concurrency slot it is not going to use.
	mux.HandleFunc("/api/v1/biometrics/enroll", overload(cors(authConfig.RequireAuth(rateLimit(handler.HandleEnroll)))))
	mux.HandleFunc("/api/v1/biometrics/verify", overload(cors(authConfig.RequireAuth(rateLimit(handler.HandleVerify)))))
	mux.HandleFunc("/api/v1/doors/scan", overload(cors(authConfig.RequireAuth(rateLimit(handler.HandleDoorScan)))))
	mux.HandleFunc("/api/v1/policies/reset-apb", overload(cors(authConfig.RequireAuth(handler.HandleResetAPB))))

	// Public Health and Status endpoints
	mux.HandleFunc("/api/v1/doors/status", overload(cors(handler.HandleDoorStatus)))
	mux.HandleFunc("/healthz", overload(cors(handler.HandleHealthz)))

	// Prometheus scrape endpoint. Deliberately unauthenticated so cluster
	// scrapers can reach it; it exposes operational counters only and no
	// biometric or identity data.
	mux.Handle("/metrics", metrics.Handler())

	// Frontend Static UI
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, "web/index.html")
	})

	server := &http.Server{
		Addr:         ":" + httpPort,
		Handler:      loggingMiddleware(mux, logger),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	serverErrChan := make(chan error, 1)
	go func() {
		logger.InfoContext(ctx, "REST API Gateway listening", slog.String("url", "http://localhost:"+httpPort))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErrChan <- err
		}
	}()

	select {
	case <-ctx.Done():
		logger.InfoContext(ctx, "shutdown signal received, draining HTTP server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.ErrorContext(ctx, "server shutdown failed", slog.String("error", err.Error()))
		}
		logger.InfoContext(ctx, "API Gateway stopped cleanly")
	case err := <-serverErrChan:
		logger.ErrorContext(ctx, "API Gateway server failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func loggingMiddleware(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logger.DebugContext(r.Context(), "http request served",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int64("latency_ms", time.Since(start).Milliseconds()),
		)
	})
}
