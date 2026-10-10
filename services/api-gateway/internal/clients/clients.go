package clients

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	biometricsv1 "finger-scanner/pkg/api/v1/biometrics"
	edgegatewayv1 "finger-scanner/pkg/api/v1/edgegateway"
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
}

// NewServiceClients establishes gRPC connections to downstream microservices.
func NewServiceClients(ctx context.Context, cfg Config, logger *slog.Logger) (*ServiceClients, error) {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}

	logger.InfoContext(ctx, "dialing downstream microservices",
		slog.String("biometrics_addr", cfg.BiometricsAddr),
		slog.String("access_policy_addr", cfg.AccessPolicyAddr),
		slog.String("edge_gateway_addr", cfg.EdgeGatewayAddr),
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
