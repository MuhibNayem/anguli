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

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	edgegatewayv1 "finger-scanner/pkg/api/v1/edgegateway"
	securitytls "finger-scanner/pkg/security/tls"
	"finger-scanner/pkg/telemetry"
	grpchandler "finger-scanner/services/edge-gateway-service/internal/adapters/grpc"
	"finger-scanner/services/edge-gateway-service/internal/adapters/memory"
	"finger-scanner/services/edge-gateway-service/internal/service"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	port := os.Getenv("PORT")
	if port == "" {
		port = "50053"
	}

	env := os.Getenv("ENVIRONMENT")
	if env == "" {
		env = "production"
	}

	tel, cleanupTel, err := telemetry.Setup(ctx, telemetry.Config{
		ServiceName:    "edge-gateway-service",
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
	logger.InfoContext(ctx, "starting edge-gateway-service (Fog Node Turnstile Controller)", slog.String("port", port))

	policyAddr := os.Getenv("POLICY_ADDR")
	if policyAddr == "" {
		policyAddr = os.Getenv("ACCESS_POLICY_SERVICE_ADDR")
	}

	// Transport security, read once and used for both roles this process plays:
	// a TLS server for the gateway, and a TLS client toward the central policy
	// service. Previously both directions were hardcoded insecure, so the fog node
	// both served cleartext door decisions and sent cleartext employee identities
	// to the core.
	tlsCfg := securitytls.LoadConfigFromEnv()
	logger.InfoContext(ctx, "grpc transport configured", slog.String("tls", tlsCfg.Describe()))

	var policyClient accesscontrolv1.AccessPolicyServiceClient
	if policyAddr != "" {
		clientOpt, err := securitytls.ClientOption(tlsCfg)
		if err != nil {
			// Refuse to start. Falling back to an insecure dial here would
			// send employee identities in cleartext because of a certificate
			// path typo, which is the exact failure TLS is meant to prevent.
			logger.ErrorContext(ctx, "failed to configure central policy transport security",
				slog.String("error", err.Error()))
			os.Exit(1)
		}
		conn, err := grpc.NewClient(policyAddr, clientOpt)
		if err == nil {
			policyClient = accesscontrolv1.NewAccessPolicyServiceClient(conn)
			defer conn.Close()
			logger.InfoContext(ctx, "edge turnstile connected to central access-policy-service", slog.String("addr", policyAddr))
		} else {
			logger.WarnContext(ctx, "failed to connect to central policy service, running in offline fallback mode", slog.String("error", err.Error()))
		}
	}

	cache := memory.NewMemoryEdgeCache()
	edgeSvc := service.NewEdgeServiceWithPolicy(cache, policyClient, logger)
	grpcServerHandler := grpchandler.NewServer(edgeSvc)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		logger.ErrorContext(ctx, "failed to bind TCP port", slog.String("error", err.Error()))
		os.Exit(1)
	}

	transportOpt, err := securitytls.ServerOption(tlsCfg)
	if err != nil {
		logger.ErrorContext(ctx, "failed to configure gRPC transport security", slog.String("error", err.Error()))
		os.Exit(1)
	}
	grpcServer := grpc.NewServer(transportOpt)
	edgegatewayv1.RegisterEdgeGatewayServiceServer(grpcServer, grpcServerHandler)

	healthServer := health.NewServer()
	healthServer.SetServingStatus("edgegateway.v1.EdgeGatewayService", grpc_health_v1.HealthCheckResponse_SERVING)
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
		logger.InfoContext(ctx, "shutdown signal received, stopping edge-gateway-service...")
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
