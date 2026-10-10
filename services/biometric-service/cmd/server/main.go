package main

import (
	"context"
	"encoding/hex"
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

	masterKeyHex := os.Getenv("MASTER_KEY")
	if masterKeyHex == "" {
		fmt.Fprintf(os.Stderr, "FATAL: MASTER_KEY environment variable is mandatory and missing\n")
		os.Exit(1)
	}

	var keyBytes []byte
	if len(masterKeyHex) == 64 {
		var hexErr error
		keyBytes, hexErr = hex.DecodeString(masterKeyHex)
		if hexErr != nil {
			fmt.Fprintf(os.Stderr, "FATAL: MASTER_KEY hex decoding failed: %v\n", hexErr)
			os.Exit(1)
		}
	} else if len(masterKeyHex) == 32 {
		keyBytes = []byte(masterKeyHex)
	} else {
		fmt.Fprintf(os.Stderr, "FATAL: MASTER_KEY must be 64 hex characters or 32 raw bytes (got %d characters)\n", len(masterKeyHex))
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
	logger.InfoContext(ctx, "starting biometric-service", slog.String("port", port))

	// Dependency Injection with validated 32-byte cryptographic key
	vault, err := crypto.NewVault(keyBytes)
	if err != nil {
		logger.ErrorContext(ctx, "failed to initialize vault", slog.String("error", err.Error()))
		os.Exit(1)
	}

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

	grpcServer := grpc.NewServer()
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
