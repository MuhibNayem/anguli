package clients

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	biometricsv1 "finger-scanner/pkg/api/v1/biometrics"
	edgegatewayv1 "finger-scanner/pkg/api/v1/edgegateway"
	securitytls "finger-scanner/pkg/security/tls"
)

// ServiceClients bundles the gRPC client connections.
type ServiceClients struct {
	BiometricsClient   biometricsv1.BiometricsServiceClient
	AccessPolicyClient accesscontrolv1.AccessPolicyServiceClient
	EdgeGatewayClient  edgegatewayv1.EdgeGatewayServiceClient
	bioConn            *grpc.ClientConn
	policyConn         *grpc.ClientConn
	edgeConn           *grpc.ClientConn
}

// Config specifies the target addresses for downstream microservices.
type Config struct {
	BiometricsAddr   string
	AccessPolicyAddr string
	EdgeGatewayAddr  string

	// TLS controls transport security for every downstream channel.
	//
	// The zero value has Enabled false, which is plaintext. That is the right
	// default for tests and single-host development, and it is deliberately
	// NOT a silent fallback: when an operator sets Enabled, a missing or
	// unreadable certificate fails the dial rather than quietly reverting to
	// cleartext. Production entrypoints populate this from
	// securitytls.LoadConfigFromEnv.
	TLS securitytls.Config
}

// NewServiceClients establishes gRPC connections to downstream microservices.
func NewServiceClients(ctx context.Context, cfg Config, logger *slog.Logger) (*ServiceClients, error) {
	// Default the logger rather than assuming one is supplied. A nil
	// *slog.Logger here panicked on the very first log line, which turns a
	// wiring mistake into a crash during startup.
	if logger == nil {
		logger = slog.Default()
	}

	// Build the transport option from the TLS config rather than hardcoding
	// insecure.NewCredentials(). This was the difference between the gateway
	// encrypting employee identities and door decisions and not: the transport
	// was plaintext on every channel regardless of what the operator asked
	// for, because nothing here ever consulted the configuration.
	credOpt, err := securitytls.ClientOption(cfg.TLS)
	if err != nil {
		return nil, fmt.Errorf("failed to configure downstream transport security: %w", err)
	}
	opts := []grpc.DialOption{credOpt}

	logger.InfoContext(ctx, "dialing downstream microservices",
		slog.String("biometrics_addr", cfg.BiometricsAddr),
		slog.String("access_policy_addr", cfg.AccessPolicyAddr),
		slog.String("edge_gateway_addr", cfg.EdgeGatewayAddr),
		slog.String("transport", cfg.TLS.Describe()),
	)

	bioConn, err := grpc.NewClient(cfg.BiometricsAddr, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to biometric-service: %w", err)
	}

	policyConn, err := grpc.NewClient(cfg.AccessPolicyAddr, opts...)
	if err != nil {
		bioConn.Close()
		return nil, fmt.Errorf("failed to connect to access-policy-service: %w", err)
	}

	edgeConn, err := grpc.NewClient(cfg.EdgeGatewayAddr, opts...)
	if err != nil {
		bioConn.Close()
		policyConn.Close()
		return nil, fmt.Errorf("failed to connect to edge-gateway-service: %w", err)
	}

	return &ServiceClients{
		BiometricsClient:   biometricsv1.NewBiometricsServiceClient(bioConn),
		AccessPolicyClient: accesscontrolv1.NewAccessPolicyServiceClient(policyConn),
		EdgeGatewayClient:  edgegatewayv1.NewEdgeGatewayServiceClient(edgeConn),
		bioConn:            bioConn,
		policyConn:         policyConn,
		edgeConn:           edgeConn,
	}, nil
}

// Close closes all underlying gRPC client connections.
func (c *ServiceClients) Close() {
	if c.bioConn != nil {
		_ = c.bioConn.Close()
	}
	if c.policyConn != nil {
		_ = c.policyConn.Close()
	}
	if c.edgeConn != nil {
		_ = c.edgeConn.Close()
	}
}

// CheckHealth queries the downstream gRPC health endpoints and returns live serving statuses (Fix L1).
func (c *ServiceClients) CheckHealth(ctx context.Context) (map[string]string, bool) {
	results := make(map[string]string)
	allHealthy := true

	check := func(name string, conn *grpc.ClientConn) {
		if conn == nil {
			results[name] = "NOT_CONFIGURED"
			allHealthy = false
			return
		}
		client := grpc_health_v1.NewHealthClient(conn)
		resp, err := client.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
		if err != nil {
			results[name] = "UNAVAILABLE"
			allHealthy = false
			return
		}
		statusStr := resp.Status.String()
		results[name] = statusStr
		if resp.Status != grpc_health_v1.HealthCheckResponse_SERVING {
			allHealthy = false
		}
	}

	check("biometric-service", c.bioConn)
	check("access-policy-service", c.policyConn)
	check("edge-gateway-service", c.edgeConn)

	return results, allHealthy
}
