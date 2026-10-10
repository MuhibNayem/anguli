package grpc

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	edgegatewayv1 "finger-scanner/pkg/api/v1/edgegateway"
	"finger-scanner/pkg/biometrics/mcc"
	"finger-scanner/pkg/biometrics/minutiae"
	"finger-scanner/services/edge-gateway-service/internal/domain"
	"finger-scanner/services/edge-gateway-service/internal/service"
)

// Server implements edgegatewayv1.EdgeGatewayServiceServer.
type Server struct {
	edgegatewayv1.UnimplementedEdgeGatewayServiceServer
	svc service.EdgeUseCase
}

func NewServer(svc service.EdgeUseCase) *Server {
	return &Server{svc: svc}
}

func (s *Server) ProcessTurnstileScan(ctx context.Context, req *edgegatewayv1.ProcessTurnstileScanRequest) (*edgegatewayv1.ProcessTurnstileScanResponse, error) {
	if req.TurnstileId == "" {
		return nil, status.Error(codes.InvalidArgument, "turnstile_id is required")
	}

	res, err := s.svc.ProcessScan(
		ctx,
		req.TurnstileId,
		req.ZoneId,
		int32(req.Direction),
		req.EmployeeId,
		req.ProbeImageRawGray,
		req.ImageWidth,
		req.ImageHeight,
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "turnstile scan error: %v", err)
	}

	return &edgegatewayv1.ProcessTurnstileScanResponse{
		IsAccessGranted:        res.IsAccessGranted,
		Decision:               accesscontrolv1.AccessDecision(res.Decision),
		MatchedEmployeeId:      res.MatchedEmployeeID,
		MatchScore:             res.MatchScore,
		Reason:                 res.Reason,
		RelayStrikeDurationMs:  res.RelayStrikeDurationMs,
		TotalLatencyMs:         res.TotalLatencyMs,
		ProcessedOffline:       res.ProcessedOffline,
	}, nil
}

func (s *Server) SyncFacilityRoster(ctx context.Context, req *edgegatewayv1.SyncFacilityRosterRequest) (*edgegatewayv1.SyncFacilityRosterResponse, error) {
	var items []*domain.CachedEmployee
	for _, it := range req.Items {
		var cyls []mcc.Cylinder
		if len(it.MccCylinderBytes) > 0 {
			c, err := mcc.DeserializeAll(it.MccCylinderBytes)
			if err == nil {
				cyls = c
			}
		}

		if len(cyls) == 0 && len(it.Minutiae) > 0 {
			var pts []minutiae.Minutia
			for _, m := range it.Minutiae {
				pts = append(pts, minutiae.Minutia{
					X:       uint16(m.X),
					Y:       uint16(m.Y),
					Angle:   m.Angle,
					Type:    minutiae.MinutiaType(m.Type),
					Quality: uint8(m.Quality),
				})
			}
			t := mcc.BuildTemplate(it.EmployeeId, pts)
			cyls = t.Cylinders
		}

		items = append(items, &domain.CachedEmployee{
			EmployeeID: it.EmployeeId,
			FullName:   it.FullName,
			Role:       it.Role,
			Position:   int32(it.Position),
			Cylinders:  cyls,
			IsActive:   it.IsActive,
		})
	}

	synced, err := s.svc.SyncRoster(ctx, items)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "roster sync error: %v", err)
	}

	if len(req.Policies) > 0 {
		var policyRules []*domain.PolicyRule
		for _, p := range req.Policies {
			policyRules = append(policyRules, &domain.PolicyRule{
				ZoneID:                p.ZoneId,
				AllowedRole:           p.AllowedRole,
				RequireBiometrics:     p.RequireBiometrics,
				MinBiometricScore:     p.MinBiometricScore,
				EnforceAntiPassback:   p.EnforceAntiPassback,
				AntiPassbackWindowSec: p.AntiPassbackWindowSec,
			})
		}
		_ = s.svc.SyncPolicies(ctx, policyRules)
	}

	return &edgegatewayv1.SyncFacilityRosterResponse{
		Success:     true,
		SyncedCount: synced,
		Message:     "Local edge roster and policy rules synchronized successfully",
	}, nil
}

func (s *Server) GetTurnstileStatus(ctx context.Context, req *edgegatewayv1.GetTurnstileStatusRequest) (*edgegatewayv1.GetTurnstileStatusResponse, error) {
	st, err := s.svc.GetStatus(ctx, req.TurnstileId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "status retrieval error: %v", err)
	}

	return &edgegatewayv1.GetTurnstileStatusResponse{
		Status: &edgegatewayv1.TurnstileStatus{
			TurnstileId:          st.TurnstileID,
			ZoneId:               st.ZoneID,
			IsOnline:             st.IsOnline,
			ReaderConnected:      st.ReaderConnected,
			LocalRosterCount:     st.LocalRosterCount,
			OfflinePendingEvents: st.OfflinePendingEvents,
			UptimeSeconds:        st.StartTimeUnix,
		},
	}, nil
}

func (s *Server) ReplayOfflineEvents(ctx context.Context, req *edgegatewayv1.ReplayOfflineEventsRequest) (*edgegatewayv1.ReplayOfflineEventsResponse, error) {
	events, err := s.svc.ReplayEvents(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "offline event replay error: %v", err)
	}

	return &edgegatewayv1.ReplayOfflineEventsResponse{
		Success:       true,
		ReplayedCount: uint32(len(events)),
	}, nil
}
