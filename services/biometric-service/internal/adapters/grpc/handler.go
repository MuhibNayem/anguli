package grpc

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	biometricsv1 "finger-scanner/pkg/api/v1/biometrics"
	"finger-scanner/services/biometric-service/internal/service"
)

// Server implements biometricsv1.BiometricsServiceServer.
type Server struct {
	biometricsv1.UnimplementedBiometricsServiceServer
	svc service.BiometricUseCase
}

// NewServer creates a new gRPC server handler.
func NewServer(svc service.BiometricUseCase) *Server {
	return &Server{
		svc: svc,
	}
}

func (s *Server) EnrollFingerprint(ctx context.Context, req *biometricsv1.EnrollFingerprintRequest) (*biometricsv1.EnrollFingerprintResponse, error) {
	if req.EmployeeId == "" {
		return nil, status.Error(codes.InvalidArgument, "employee_id is required")
	}
	if len(req.ImageRawGray) == 0 {
		return nil, status.Error(codes.InvalidArgument, "image_raw_gray buffer is required")
	}

	start := time.Now()
	tmpl, err := s.svc.Enroll(
		ctx,
		req.EmployeeId,
		req.FullName,
		int32(req.Position),
		req.ImageRawGray,
		req.Width,
		req.Height,
		req.Dpi,
	)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "enrollment failed: %v", err)
	}

	elapsed := time.Since(start).Microseconds()
	return &biometricsv1.EnrollFingerprintResponse{
		TemplateId:          tmpl.TemplateID,
		EmployeeId:          tmpl.EmployeeID,
		NfiqQualityScore:    tmpl.NFIQScore,
		IsQualityAcceptable: true,
		MinutiaeCount:       tmpl.MinutiaeCount,
		Message:             "Enrollment successful",
		ProcessingTimeUs:    elapsed,
	}, nil
}

func (s *Server) VerifyFingerprint(ctx context.Context, req *biometricsv1.VerifyFingerprintRequest) (*biometricsv1.VerifyFingerprintResponse, error) {
	if req.EmployeeId == "" {
		return nil, status.Error(codes.InvalidArgument, "employee_id is required")
	}
	if len(req.ProbeImageRawGray) == 0 {
		return nil, status.Error(codes.InvalidArgument, "probe_image_raw_gray is required")
	}

	start := time.Now()
	res, nfiq, err := s.svc.Verify(
		ctx,
		req.EmployeeId,
		int32(req.Position),
		req.ProbeImageRawGray,
		req.Width,
		req.Height,
	)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "verification error: %v", err)
	}

	elapsed := time.Since(start).Microseconds()
	reason := "Match confirmed"
	if !res.IsMatch {
		reason = "Score below enterprise acceptance threshold"
	}

	return &biometricsv1.VerifyFingerprintResponse{
		IsMatch:          res.IsMatch,
		Score:            res.Score,
		MatchedCylinders: uint32(res.MatchedPairs),
		NfiqQualityScore: nfiq,
		MatchingTimeUs:   elapsed,
		Reason:           reason,
	}, nil
}

func (s *Server) IdentifyFingerprint(ctx context.Context, req *biometricsv1.IdentifyFingerprintRequest) (*biometricsv1.IdentifyFingerprintResponse, error) {
	if len(req.ProbeImageRawGray) == 0 {
		return nil, status.Error(codes.InvalidArgument, "probe image required")
	}

	start := time.Now()
	candidates, err := s.svc.Identify(ctx, req.ProbeImageRawGray, req.Width, req.Height, req.TopK)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "identification error: %v", err)
	}

	var pbCandidates []*biometricsv1.CandidateMatch
	var topScore float64
	var matchedEmpID string
	var isIdentified bool

	for _, c := range candidates {
		pbCandidates = append(pbCandidates, &biometricsv1.CandidateMatch{
			EmployeeId: c.EmployeeID,
			Score:      c.Score,
			Position:   biometricsv1.FingerPosition(c.Position),
		})
		if c.Score > topScore {
			topScore = c.Score
			matchedEmpID = c.EmployeeID
			isIdentified = true
		}
	}

	elapsed := time.Since(start).Microseconds()
	return &biometricsv1.IdentifyFingerprintResponse{
		IsIdentified:         isIdentified,
		MatchedEmployeeId:    matchedEmpID,
		TopScore:             topScore,
		Candidates:           pbCandidates,
		IdentificationTimeUs: elapsed,
	}, nil
}

func (s *Server) GetTemplate(ctx context.Context, req *biometricsv1.GetTemplateRequest) (*biometricsv1.GetTemplateResponse, error) {
	tmpl, payload, err := s.svc.GetTemplate(ctx, req.EmployeeId, int32(req.Position))
	if err != nil {
		return &biometricsv1.GetTemplateResponse{Found: false}, nil
	}

	var pbMinutiae []*biometricsv1.Minutia
	if payload != nil {
		for _, m := range payload.Minutiae {
			pbMinutiae = append(pbMinutiae, &biometricsv1.Minutia{
				X:       uint32(m.X),
				Y:       uint32(m.Y),
				Angle:   m.Angle,
				Type:    biometricsv1.MinutiaType(m.Type),
				Quality: uint32(m.Quality),
			})
		}
	}

	return &biometricsv1.GetTemplateResponse{
		Found: true,
		Template: &biometricsv1.TemplateRecord{
			TemplateId:       tmpl.TemplateID,
			EmployeeId:       tmpl.EmployeeID,
			Position:         biometricsv1.FingerPosition(tmpl.Position),
			NfiqScore:        tmpl.NFIQScore,
			Minutiae:         pbMinutiae,
			EncryptedPayload: tmpl.EncryptedPayload,
			EnrolledAtUnix:   tmpl.EnrolledAtUnix,
		},
	}, nil
}

// RevokeFingerprint flags an enrolled template out of every matching path.
//
// "Nothing to revoke" is reported as revoked=false rather than as an error.
// An offboarding job that runs twice, or races a re-enrollment, must be able to
// proceed without treating the second run as a failure - and treating it as one
// is exactly how people end up leaving someone enrolled after a failed job.
func (s *Server) RevokeFingerprint(
	ctx context.Context, req *biometricsv1.RevokeFingerprintRequest,
) (*biometricsv1.RevokeFingerprintResponse, error) {
	if req.GetEmployeeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "employee_id is required")
	}

	revoked, err := s.svc.Revoke(ctx, req.GetEmployeeId(), int32(req.GetPosition()), req.GetReason())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "revoke template: %v", err)
	}
	return &biometricsv1.RevokeFingerprintResponse{
		Revoked:    revoked,
		EmployeeId: req.GetEmployeeId(),
	}, nil
}
