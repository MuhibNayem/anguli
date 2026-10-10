package edgegatewayservice

import (
	"log/slog"

	"google.golang.org/grpc"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	edgegatewayv1 "finger-scanner/pkg/api/v1/edgegateway"
	grpchandler "finger-scanner/services/edge-gateway-service/internal/adapters/grpc"
	"finger-scanner/services/edge-gateway-service/internal/adapters/memory"
	"finger-scanner/services/edge-gateway-service/internal/service"
)

// RegisterService mounts the edge gateway service onto a gRPC server in standalone mode.
func RegisterService(s *grpc.Server, logger *slog.Logger) {
	RegisterServiceWithPolicy(s, nil, logger)
}

// RegisterServiceWithPolicy mounts the edge gateway service connected to central access policy.
func RegisterServiceWithPolicy(s *grpc.Server, policyClient accesscontrolv1.AccessPolicyServiceClient, logger *slog.Logger) {
	cache := memory.NewMemoryEdgeCache()
	svc := service.NewEdgeServiceWithPolicy(cache, policyClient, logger)
	handler := grpchandler.NewServer(svc)
	edgegatewayv1.RegisterEdgeGatewayServiceServer(s, handler)
}

