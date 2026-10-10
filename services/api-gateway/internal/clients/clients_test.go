package clients_test

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"finger-scanner/services/api-gateway/internal/clients"
)

// startHealthServer runs a real gRPC health server so CheckHealth exercises the
// actual client path rather than a stub.
func startHealthServer(t *testing.T, serving bool) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	hs := health.NewServer()
	status := healthpb.HealthCheckResponse_NOT_SERVING
	if serving {
		status = healthpb.HealthCheckResponse_SERVING
	}
	hs.SetServingStatus("", status)
	healthpb.RegisterHealthServer(srv, hs)
	go func() { _ = srv.Serve(ln) }()

	return ln.Addr().String(), func() { srv.Stop(); _ = ln.Close() }
}

// deadAddr returns an address nothing is listening on, so the health check
// fails rather than hanging.
func deadAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestNewServiceClients_ConnectsToAllThree(t *testing.T) {
	bioAddr, stopBio := startHealthServer(t, true)
	defer stopBio()
	polAddr, stopPol := startHealthServer(t, true)
	defer stopPol()
	edgeAddr, stopEdge := startHealthServer(t, true)
	defer stopEdge()

	c, err := clients.NewServiceClients(context.Background(), clients.Config{
		BiometricsAddr:   bioAddr,
		AccessPolicyAddr: polAddr,
		EdgeGatewayAddr:  edgeAddr,
	}, nil)
	if err != nil {
		t.Fatalf("NewServiceClients: %v", err)
	}
	defer c.Close()

	if c.BiometricsClient == nil || c.AccessPolicyClient == nil || c.EdgeGatewayClient == nil {
		t.Fatal("one or more clients were not constructed")
	}
}

// TestCheckHealth_AllServing covers the healthy path end to end.
func TestCheckHealth_AllServing(t *testing.T) {
	addr, stop := startHealthServer(t, true)
	defer stop()

	c, err := clients.NewServiceClients(context.Background(), clients.Config{
		BiometricsAddr:   addr,
		AccessPolicyAddr: addr,
		EdgeGatewayAddr:  addr,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, allHealthy := c.CheckHealth(ctx)
	if !allHealthy {
		t.Errorf("allHealthy = false; results = %v", results)
	}
	for name, s := range results {
		if s != "SERVING" {
			t.Errorf("%s = %q; want SERVING", name, s)
		}
	}
}

// TestCheckHealth_ReportsNotServing: a process that is up but not serving must
// be reported unhealthy, so a load balancer stops sending it traffic.
func TestCheckHealth_ReportsNotServing(t *testing.T) {
	addr, stop := startHealthServer(t, false)
	defer stop()

	c, err := clients.NewServiceClients(context.Background(), clients.Config{
		BiometricsAddr:   addr,
		AccessPolicyAddr: addr,
		EdgeGatewayAddr:  addr,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, allHealthy := c.CheckHealth(ctx)
	if allHealthy {
		t.Error("allHealthy = true while every service reports NOT_SERVING")
	}
	for name, s := range results {
		if s != "NOT_SERVING" {
			t.Errorf("%s = %q; want NOT_SERVING", name, s)
		}
	}
}

// TestCheckHealth_UnreachableIsUnavailable proves health degrades rather than
// hanging when a dependency is gone.
func TestCheckHealth_UnreachableIsUnavailable(t *testing.T) {
	dead := deadAddr(t)
	c, err := clients.NewServiceClients(context.Background(), clients.Config{
		BiometricsAddr:   dead,
		AccessPolicyAddr: dead,
		EdgeGatewayAddr:  dead,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, allHealthy := c.CheckHealth(ctx)
	if allHealthy {
		t.Error("allHealthy = true against unreachable dependencies")
	}
	for name, s := range results {
		if s != "UNAVAILABLE" {
			t.Errorf("%s = %q; want UNAVAILABLE", name, s)
		}
	}
}

// TestNewServiceClients_ConnectIsLazy documents that construction does NOT
// validate the target: grpc.NewClient defers connection, so a misconfigured or
// dead downstream produces a working client at startup and surfaces the failure
// on the first RPC instead.
//
// This matters operationally: startup succeeds against a dead dependency, and
// the circuit breakers plus CheckHealth are what turn that into a visible,
// recoverable state rather than a crash loop.
func TestNewServiceClients_ConnectIsLazy(t *testing.T) {
	dead := deadAddr(t)
	c, err := clients.NewServiceClients(context.Background(), clients.Config{
		BiometricsAddr:   dead,
		AccessPolicyAddr: dead,
		EdgeGatewayAddr:  dead,
	}, nil)
	if err != nil {
		t.Fatalf("construction against a dead target returned an error: %v", err)
	}
	defer c.Close()
	if c.BiometricsClient == nil {
		t.Fatal("client was not constructed")
	}

	// The failure surfaces on the health check, not at construction.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, healthy := c.CheckHealth(ctx); healthy {
		t.Error("CheckHealth reported healthy against a dead target")
	}
}

// TestClose_IsSafeToCallTwice guards against a panic on the shutdown path,
// which would otherwise mask the real exit reason.
func TestClose_IsSafeToCallTwice(t *testing.T) {
	addr, stop := startHealthServer(t, true)
	defer stop()

	c, err := clients.NewServiceClients(context.Background(), clients.Config{
		BiometricsAddr:   addr,
		AccessPolicyAddr: addr,
		EdgeGatewayAddr:  addr,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	c.Close()
}
