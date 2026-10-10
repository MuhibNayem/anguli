package grpc

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	"finger-scanner/services/access-policy-service/internal/domain"
	"finger-scanner/services/access-policy-service/internal/service"
)

// Server implements accesscontrolv1.AccessPolicyServiceServer.
type Server struct {
	accesscontrolv1.UnimplementedAccessPolicyServiceServer
	svc service.PolicyUseCase
}

func NewServer(svc service.PolicyUseCase) *Server {
	return &Server{svc: svc}
}

func (s *Server) EvaluateAccess(ctx context.Context, req *accesscontrolv1.EvaluateAccessRequest) (*accesscontrolv1.EvaluateAccessResponse, error) {
	if req.EmployeeId == "" || req.ZoneId == "" {
		return nil, status.Error(codes.InvalidArgument, "employee_id and zone_id are required")
	}

	res, err := s.svc.Evaluate(
		ctx,
		req.EmployeeId,
		req.ZoneId,
		req.DoorId,
		int32(req.Direction),
		req.BiometricVerified,
		req.BiometricScore,
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "evaluation error: %v", err)
	}

	return &accesscontrolv1.EvaluateAccessResponse{
		Decision:            accesscontrolv1.AccessDecision(res.Decision),
		IsGranted:           res.IsGranted,
		Reason:              res.Reason,
		RelayOpenDurationMs: res.RelayOpenDurationMs,
	}, nil
}

func (s *Server) ConfigurePolicy(ctx context.Context, req *accesscontrolv1.ConfigurePolicyRequest) (*accesscontrolv1.ConfigurePolicyResponse, error) {
	if req.Rule == nil || req.Rule.ZoneId == "" {
		return nil, status.Error(codes.InvalidArgument, "valid rule with zone_id is required")
	}

	err := s.svc.Configure(ctx, &domain.PolicyRule{
		ZoneID:                req.Rule.ZoneId,
		AllowedRole:           req.Rule.AllowedRole,
		RequireBiometrics:     req.Rule.RequireBiometrics,
		MinBiometricScore:     req.Rule.MinBiometricScore,
		EnforceAntiPassback:   req.Rule.EnforceAntiPassback,
		AntiPassbackWindowSec: req.Rule.AntiPassbackWindowSec,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to configure rule: %v", err)
	}

	return &accesscontrolv1.ConfigurePolicyResponse{
		Success: true,
		Message: "Policy updated successfully",
	}, nil
}

func (s *Server) GetPolicy(ctx context.Context, req *accesscontrolv1.GetPolicyRequest) (*accesscontrolv1.GetPolicyResponse, error) {
	rule, err := s.svc.Get(ctx, req.ZoneId)
	if err != nil {
		return &accesscontrolv1.GetPolicyResponse{Found: false}, nil
	}

	return &accesscontrolv1.GetPolicyResponse{
		Found: true,
		Rule: &accesscontrolv1.PolicyRule{
			ZoneId:                rule.ZoneID,
			AllowedRole:           rule.AllowedRole,
			RequireBiometrics:     rule.RequireBiometrics,
			MinBiometricScore:     rule.MinBiometricScore,
			EnforceAntiPassback:   rule.EnforceAntiPassback,
			AntiPassbackWindowSec: rule.AntiPassbackWindowSec,
		},
	}, nil
}

func (s *Server) ResetAntiPassback(ctx context.Context, req *accesscontrolv1.ResetAntiPassbackRequest) (*accesscontrolv1.ResetAntiPassbackResponse, error) {
	err := s.svc.ResetAPB(ctx, req.EmployeeId, req.ZoneId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to reset anti-passback: %v", err)
	}

	return &accesscontrolv1.ResetAntiPassbackResponse{
		Success: true,
		Message: "Anti-passback reset for employee",
	}, nil
}
