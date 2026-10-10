package accesspolicyservice

import (
	"log/slog"

	"google.golang.org/grpc"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	"finger-scanner/pkg/store"
	grpchandler "finger-scanner/services/access-policy-service/internal/adapters/grpc"
	"finger-scanner/services/access-policy-service/internal/adapters/memory"
	"finger-scanner/services/access-policy-service/internal/adapters/sqlstore"
	"finger-scanner/services/access-policy-service/internal/ports"
	"finger-scanner/services/access-policy-service/internal/service"
)

// RegisterService mounts the access policy service onto a gRPC server backed by
// the in-memory repository. It exists for tests and local experiments; the daemon
// uses durable storage instead, because in-memory state is lost on restart and
// anti-passback is not shared across replicas.
func RegisterService(s *grpc.Server, logger *slog.Logger) {
	mount(s, memory.NewMemoryPolicyRepository(), logger)
}

// RegisterServiceWithStorage mounts the access policy service onto a gRPC server
// backed by real SQL storage.
//
// The store is already migrated by store.Open, so this entry point requires a
// schema that includes access_audit_events. An explicit Migrate call here was
// tried and removed: mutation testing showed removing it changed nothing, and a
// redundant migration is one more thing that can disagree with the real one.
//
// This exists so an end-to-end test can exercise the durable path the daemon
// actually uses. The sqlstore adapter is internal to this module, so before this
// there was no way to reach it from an integration test - only the in-memory path
// production does not use. That is precisely how a schema defect could sit in the
// migration while every unit test passed against its own fixture: this change
// caught one, a missing primary key that made ON CONFLICT DO NOTHING invalid.
func RegisterServiceWithStorage(s *grpc.Server, st *store.Store, logger *slog.Logger) error {
	repo, err := sqlstore.New(st)
	if err != nil {
		return err
	}
	mount(s, repo, logger)
	return nil
}

func mount(s *grpc.Server, repo ports.PolicyRepository, logger *slog.Logger) {
	handler := grpchandler.NewServer(service.NewPolicyService(repo, logger))
	accesscontrolv1.RegisterAccessPolicyServiceServer(s, handler)
}
