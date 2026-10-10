package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	biometricsv1 "finger-scanner/pkg/api/v1/biometrics"
	"finger-scanner/pkg/biometrics/crypto"
	securitytls "finger-scanner/pkg/security/tls"
	"finger-scanner/pkg/store"
	"finger-scanner/pkg/telemetry"
	grpchandler "finger-scanner/services/biometric-service/internal/adapters/grpc"
	"finger-scanner/services/biometric-service/internal/adapters/sqlstore"
	"finger-scanner/services/biometric-service/internal/service"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	port := os.Getenv("PORT")
	if port == "" {
		port = "50051"
	}

	// The keyring, not a single key. MASTER_KEY is the primary used for new
	// encryptions; MASTER_KEY_PREVIOUS lists keys kept for decryption only.
	//
	// Loading just one key made rotation impossible: a compromised template
	// key otherwise exposes every enrolled person in the facility, and the
	// only remedy was re-enrolling all of them. With previous keys present the
	// service reads records written under any previously-active key while
	// writing new ones under the current primary, and the keyrotate command
	// migrates the backlog in place.
	//
	// Every failure here is fatal. A service that started with a silently
	// truncated keyring would fail to decrypt templates much later, and the
	// error would name a record rather than a configuration mistake.
	vault, err := crypto.LoadVaultFromEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}

	env := os.Getenv("ENVIRONMENT")
	if env == "" {
		env = "production"
	}

	tel, cleanupTel, err := telemetry.Setup(ctx, telemetry.Config{
		ServiceName:    "biometric-service",
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
	logger.InfoContext(ctx, "starting biometric-service",
		slog.String("port", port),
		// Which keys are loaded, and which is primary. Never the keys
		// themselves - this line goes to whatever aggregates the logs.
		slog.String("keyring", vault.KeyringDescription()),
	)

	// Durable storage. SQLite is the default so a single node needs no extra
	// service; set STORAGE_DRIVER=postgres for a shared multi-instance store.
	// Only sqlite and postgres are accepted here - store.Open rejects anything
	// else with a fatal error, so "memory" is a crash loop, not a fallback.
	st, err := store.Open(ctx, store.FromEnv())
	if err != nil {
		logger.ErrorContext(ctx, "failed to open storage", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer func() { _ = st.Close() }()

	// Refuse to serve a database that belongs to another facility. Every table
	// here is keyed without a facility, so two sites sharing one database would
	// merge their templates and policies silently.
	if err := store.ClaimConfiguredFacility(ctx, st, logger); err != nil {
		logger.ErrorContext(ctx, "refusing to start", slog.String("error", err.Error()))
		os.Exit(1)
	}

	logger.InfoContext(ctx, "storage ready",
		slog.String("driver", string(st.Driver())),
	)

	repo, err := sqlstore.New(st)
	if err != nil {
		logger.ErrorContext(ctx, "failed to build repository", slog.String("error", err.Error()))
		os.Exit(1)
	}

	biometricSvc := service.NewBiometricService(repo, vault, logger)
	grpcServerHandler := grpchandler.NewServer(biometricSvc)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		logger.ErrorContext(ctx, "failed to bind TCP port", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Transport security for the gRPC listener. This service handles biometric
	// templates and identity-bearing records; a bare grpc.NewServer() served
	// them in cleartext to anything on the pod network. Configuration comes
	// from the environment and a misconfigured block is fatal, never a silent
	// downgrade to plaintext.
	tlsCfg := securitytls.LoadConfigFromEnv()
	transportOpt, err := securitytls.ServerOption(tlsCfg)
	if err != nil {
		logger.ErrorContext(ctx, "failed to configure gRPC transport security", slog.String("error", err.Error()))
		os.Exit(1)
	}
	logger.InfoContext(ctx, "grpc transport configured", slog.String("tls", tlsCfg.Describe()))

	grpcServer := grpc.NewServer(transportOpt)
	biometricsv1.RegisterBiometricsServiceServer(grpcServer, grpcServerHandler)

	// Health check service
	healthServer := health.NewServer()
	healthServer.SetServingStatus("biometrics.v1.BiometricsService", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	reflection.Register(grpcServer)

	serverErrChan := make(chan error, 1)
	go func() {
		logger.InfoContext(ctx, "gRPC server listening", slog.String("addr", listener.Addr().String()))
		if err := grpcServer.Serve(listener); err != nil && err != grpc.ErrServerStopped {
			serverErrChan <- err
		}
	}()

	select {
	case <-ctx.Done():
		logger.InfoContext(ctx, "shutdown signal received, draining gRPC server...")
		stopped := make(chan struct{})
		go func() {
			grpcServer.GracefulStop()
			close(stopped)
		}()

		select {
		case <-stopped:
			logger.InfoContext(ctx, "gRPC server stopped cleanly")
		case <-time.After(5 * time.Second):
			logger.WarnContext(ctx, "graceful shutdown timed out, forcing stop")
			grpcServer.Stop()
		}
	case err := <-serverErrChan:
		logger.ErrorContext(ctx, "server exited unexpectedly", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
