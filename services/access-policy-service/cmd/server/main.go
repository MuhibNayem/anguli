package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	securitytls "finger-scanner/pkg/security/tls"
	"finger-scanner/pkg/store"
	"finger-scanner/pkg/telemetry"
	grpchandler "finger-scanner/services/access-policy-service/internal/adapters/grpc"
	"finger-scanner/services/access-policy-service/internal/adapters/memory"
	"finger-scanner/services/access-policy-service/internal/adapters/sqlstore"
	"finger-scanner/services/access-policy-service/internal/ports"
	"finger-scanner/services/access-policy-service/internal/service"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	port := os.Getenv("PORT")
	if port == "" {
		port = "50052"
	}

	env := os.Getenv("ENVIRONMENT")
	if env == "" {
		env = "production"
	}

	tel, cleanupTel, err := telemetry.Setup(ctx, telemetry.Config{
		ServiceName:    "access-policy-service",
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
	logger.InfoContext(ctx, "starting access-policy-service", slog.String("port", port))

	// Durable policy storage.
	//
	// Anti-passback is a shared-state rule, so an in-memory repository is not a
	// performance shortcut - it is a correctness failure. Two replicas each
	// holding their own map means an ENTRY recorded at Turnstile Lane 1 is
	// invisible to Turnstile Lane 2, and the second swipe is allowed.
	//
	// SQLite is the default for a single node. A multi-replica deployment MUST
	// set STORAGE_DRIVER=postgres; two SQLite files are two separate databases
	// and reproduce exactly the bug this replaced.
	//
	// STORAGE_DRIVER=memory selects the old in-process repository for local
	// experiments. It is checked here rather than in pkg/store because that
	// package only has real SQL drivers.
	var repo ports.PolicyRepository
	if strings.EqualFold(strings.TrimSpace(os.Getenv("STORAGE_DRIVER")), "memory") {
		logger.WarnContext(ctx,
			"using in-memory policy storage: state is lost on restart and "+
				"anti-passback is NOT shared across replicas")
		repo = memory.NewMemoryPolicyRepository()
	} else {
		st, err := store.Open(ctx, store.FromEnv())
		if err != nil {
			logger.ErrorContext(ctx, "failed to open storage", slog.String("error", err.Error()))
			os.Exit(1)
		}
		defer func() { _ = st.Close() }()

		if st.Driver() == store.DriverSQLite {
			logger.WarnContext(ctx,
				"SQLite policy storage is single-node only; "+
					"multi-replica anti-passback requires STORAGE_DRIVER=postgres",
				slog.String("driver", string(st.Driver())),
			)
		} else {
			logger.InfoContext(ctx, "storage ready", slog.String("driver", string(st.Driver())))
		}

		r, err := sqlstore.New(st)
		if err != nil {
			logger.ErrorContext(ctx, "failed to build repository", slog.String("error", err.Error()))
			os.Exit(1)
		}
		repo = r
	}

	policySvc := service.NewPolicyService(repo, logger)
	grpcServerHandler := grpchandler.NewServer(policySvc)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		logger.ErrorContext(ctx, "failed to bind TCP port", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Transport security for every gRPC hop. A bare grpc.NewServer() serves
	// cleartext: employee identities and door decisions were readable by
	// anything on the pod network. Configuration comes from the environment,
	// and a misconfigured TLS block is fatal rather than a silent downgrade.
	tlsCfg := securitytls.LoadConfigFromEnv()
	transportOpt, err := securitytls.ServerOption(tlsCfg)
	if err != nil {
		logger.ErrorContext(ctx, "failed to configure gRPC transport security", slog.String("error", err.Error()))
		os.Exit(1)
	}
	logger.InfoContext(ctx, "grpc transport configured", slog.String("tls", tlsCfg.Describe()))

	grpcServer := grpc.NewServer(transportOpt)
	accesscontrolv1.RegisterAccessPolicyServiceServer(grpcServer, grpcServerHandler)

	healthServer := health.NewServer()
	healthServer.SetServingStatus("accesscontrol.v1.AccessPolicyService", grpc_health_v1.HealthCheckResponse_SERVING)
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
		logger.InfoContext(ctx, "shutdown signal received, stopping access-policy-service...")
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
