package biometricservice

import (
	"log/slog"

	"google.golang.org/grpc"

	biometricsv1 "finger-scanner/pkg/api/v1/biometrics"
	"finger-scanner/pkg/biometrics/crypto"
	grpchandler "finger-scanner/services/biometric-service/internal/adapters/grpc"
	"finger-scanner/services/biometric-service/internal/adapters/memory"
	"finger-scanner/services/biometric-service/internal/service"
)

// RegisterService mounts the biometric service onto a gRPC server.
func RegisterService(s *grpc.Server, masterKey []byte, logger *slog.Logger) error {
	vault, err := crypto.NewVault(masterKey)
	if err != nil {
		return err
	}
	repo := memory.NewInMemoryRepository()
	svc := service.NewBiometricService(repo, vault, logger)
	handler := grpchandler.NewServer(svc)
	biometricsv1.RegisterBiometricsServiceServer(s, handler)
	return nil
}
