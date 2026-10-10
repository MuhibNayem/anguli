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

	// Connect to downstream gRPC services
	serviceClients, err := clients.NewServiceClients(ctx, clients.Config{
		BiometricsAddr:   bioAddr,
		AccessPolicyAddr: policyAddr,
		EdgeGatewayAddr:  edgeAddr,
	}, logger)
	if err != nil {
		logger.ErrorContext(ctx, "failed to initialize gRPC clients", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer serviceClients.Close()

	handler := handlers.NewGatewayHandler(serviceClients, logger)
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
	mux.HandleFunc("/api/v1/biometrics/enroll", overload(cors(authConfig.RequireAuth(handler.HandleEnroll))))
	mux.HandleFunc("/api/v1/biometrics/verify", overload(cors(authConfig.RequireAuth(handler.HandleVerify))))
	mux.HandleFunc("/api/v1/doors/scan", overload(cors(authConfig.RequireAuth(handler.HandleDoorScan))))
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
