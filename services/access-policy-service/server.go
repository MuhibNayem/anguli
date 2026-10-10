package accesspolicyservice

import (
	"log/slog"

	"google.golang.org/grpc"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	grpchandler "finger-scanner/services/access-policy-service/internal/adapters/grpc"
	"finger-scanner/services/access-policy-service/internal/adapters/memory"
	"finger-scanner/services/access-policy-service/internal/service"
)

// RegisterService mounts the access policy service onto a gRPC server.
func RegisterService(s *grpc.Server, logger *slog.Logger) {
	repo := memory.NewMemoryPolicyRepository()
	svc := service.NewPolicyService(repo, logger)
	handler := grpchandler.NewServer(svc)
	accesscontrolv1.RegisterAccessPolicyServiceServer(s, handler)
}
