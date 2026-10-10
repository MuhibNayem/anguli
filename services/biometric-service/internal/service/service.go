package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"finger-scanner/pkg/biometrics/crypto"
	"finger-scanner/pkg/biometrics/image"
	"finger-scanner/pkg/biometrics/mcc"
	"finger-scanner/pkg/biometrics/minutiae"
	"finger-scanner/pkg/biometrics/quality"
	"finger-scanner/services/biometric-service/internal/domain"
	"finger-scanner/services/biometric-service/internal/ports"
)

var (
	ErrQualityTooLow        = errors.New("biometric image quality below enterprise threshold (NFIQ < 65)")
	ErrEmployeeNotFound     = errors.New("employee template not found for verification")
	ErrInvalidDimensions    = errors.New("image width and height must be strictly positive")
	ErrInsufficientMinutiae = errors.New("image has insufficient minutiae points (< 10) for reliable identification")
)

var tracer = otel.Tracer("finger-scanner/services/biometric-service")

// BiometricUseCase defines the core application interface.
type BiometricUseCase interface {
	Enroll(ctx context.Context, empID, fullName string, position int32, rawPix []byte, width, height, dpi uint32) (*domain.EnrolledTemplate, error)
	Verify(ctx context.Context, empID string, position int32, probePix []byte, width, height uint32) (*mcc.MatchVerificationResult, uint32, error)
	Identify(ctx context.Context, probePix []byte, width, height uint32, topK uint32) ([]CandidateResult, error)
	GetTemplate(ctx context.Context, empID string, position int32) (*domain.EnrolledTemplate, *domain.DecryptedTemplatePayload, error)
}

// CandidateResult represents a ranked match in 1:N search.
type CandidateResult struct {
	EmployeeID string
	Position   int32
	Score      float64
}

type biometricService struct {
	repo      ports.TemplateRepository
	assessor  *quality.QualityAssessor
	extractor *minutiae.Extractor
	matcher   *mcc.Matcher
	vault     *crypto.Vault
	logger    *slog.Logger
}

// NewBiometricService instantiates a production biometric service.
func NewBiometricService(
	repo ports.TemplateRepository,
	vault *crypto.Vault,
	logger *slog.Logger,
) BiometricUseCase {
	if logger == nil {
		logger = slog.Default()
	}

	return &biometricService{
		repo:      repo,
		assessor:  quality.NewQualityAssessor(),
		extractor: minutiae.NewExtractor(),
		matcher:   mcc.NewMatcher(0.35, 60.0, logger),
		vault:     vault,
		logger:    logger,
	}
}

func (s *biometricService) Enroll(
	ctx context.Context,
	empID, fullName string,
	position int32,
	rawPix []byte,
	width, height, dpi uint32,
) (*domain.EnrolledTemplate, error) {
	ctx, span := tracer.Start(ctx, "BiometricService.Enroll",
		trace.WithAttributes(
			attribute.String("employee.id", empID),
			attribute.Int("position", int(position)),
			attribute.Int("image.width", int(width)),
			attribute.Int("image.height", int(height)),
		),
	)
	defer span.End()

	if width == 0 || height == 0 {
		return nil, ErrInvalidDimensions
	}

	img, err := image.NewGrayImage(int(width), int(height), rawPix)
	if err != nil {
		return nil, fmt.Errorf("failed to parse gray image: %w", err)
	}

	// Step 1: Normalize & Binarize
	norm := img.Normalize(128, 2000)
	bin := norm.AdaptiveBinarize(15)

	// Step 2: Zhang-Suen 1-pixel skeletonization
	skel := image.ZhangSuenThinning(bin, int(width), int(height))

	// Step 3: Extract minutiae
	orientations := norm.OrientationField(16)
	points := s.extractor.Extract(skel, int(width), int(height), orientations, 16)

	if len(points) < 8 {
		return nil, ErrInsufficientMinutiae
	}

	// Step 4: Strict NFIQ 2.2 Quality Gating (Must be >= 65)
	nfiqScore, isAcceptable := s.assessor.Evaluate(norm, points)
	span.SetAttributes(
		attribute.Int("nfiq.score", int(nfiqScore)),
		attribute.Bool("nfiq.acceptable", isAcceptable),
		attribute.Int("minutiae.count", len(points)),
	)

	if !isAcceptable {
		s.logger.WarnContext(ctx, "enrollment rejected due to low quality",
			slog.String("employee_id", empID),
			slog.Int("nfiq_score", int(nfiqScore)),
			slog.Int("minutiae_count", len(points)),
		)
		return nil, fmt.Errorf("%w: score %d < %d", ErrQualityTooLow, nfiqScore, quality.EnterpriseThreshold)
	}

	// Step 5: Generate MCC cylinders
	tmplID := uuid.New().String()
	mccTemplate := mcc.BuildTemplate(tmplID, points)

	// Step 6: Envelope encryption via AES-256-GCM of entire sensitive payload
	payload := domain.DecryptedTemplatePayload{
		Minutiae:  points,
		Cylinders: mccTemplate.Cylinders,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize template payload: %w", err)
	}

	ciphertext, err := s.vault.EncryptTemplate(payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("vault encryption failed: %w", err)
	}

	enrolled := &domain.EnrolledTemplate{
		TemplateID:       tmplID,
		EmployeeID:       empID,
		FullName:         fullName,
		Position:         position,
		NFIQScore:        nfiqScore,
		MinutiaeCount:    uint32(len(points)),
		EncryptedPayload: ciphertext,
		EnrolledAtUnix:   time.Now().Unix(),
	}

	if err := s.repo.Save(ctx, enrolled); err != nil {
		return nil, fmt.Errorf("failed to persist enrolled template: %w", err)
	}

	s.logger.InfoContext(ctx, "fingerprint enrolled successfully",
		slog.String("employee_id", empID),
		slog.String("template_id", tmplID),
		slog.Int("nfiq_score", int(nfiqScore)),
		slog.Int("minutiae_count", len(points)),
	)

	return enrolled, nil
}

func (s *biometricService) Verify(
	ctx context.Context,
	empID string,
	position int32,
	probePix []byte,
	width, height uint32,
) (*mcc.MatchVerificationResult, uint32, error) {
	ctx, span := tracer.Start(ctx, "BiometricService.Verify",
		trace.WithAttributes(
			attribute.String("employee.id", empID),
			attribute.Int("position", int(position)),
		),
	)
	defer span.End()

	enrolled, err := s.repo.GetByEmployeeAndPosition(ctx, empID, position)
	if err != nil {
		return nil, 0, ErrEmployeeNotFound
	}

	// Read path decryption: decrypt ciphertext from persistent storage
	decryptedBytes, err := s.vault.DecryptTemplate(enrolled.EncryptedPayload)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to decrypt gallery template: %w", err)
	}
	var galleryPayload domain.DecryptedTemplatePayload
	if err := json.Unmarshal(decryptedBytes, &galleryPayload); err != nil {
		return nil, 0, fmt.Errorf("failed to deserialize gallery template: %w", err)
	}

	img, err := image.NewGrayImage(int(width), int(height), probePix)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid probe image: %w", err)
	}

	norm := img.Normalize(128, 2000)
	bin := norm.AdaptiveBinarize(15)
	skel := image.ZhangSuenThinning(bin, int(width), int(height))
	orientations := norm.OrientationField(16)
	probePoints := s.extractor.Extract(skel, int(width), int(height), orientations, 16)

	nfiqScore, acceptable := s.assessor.Evaluate(norm, probePoints)
	if !acceptable {
		s.logger.WarnContext(ctx, "probe rejected by quality gate",
			slog.String("employee_id", empID),
			slog.Int("nfiq_score", int(nfiqScore)),
		)
		return &mcc.MatchVerificationResult{IsMatch: false, Score: 0.0}, nfiqScore, nil
	}

	probeTemplate := mcc.BuildTemplate("probe", probePoints)
	galleryTemplate := &mcc.Template{
		ID:        enrolled.TemplateID,
		Cylinders: galleryPayload.Cylinders,
	}

	res, err := s.matcher.Verify(ctx, probeTemplate, galleryTemplate)
	if err != nil {
		return nil, nfiqScore, fmt.Errorf("matcher failed: %w", err)
	}

	return &res, nfiqScore, nil
}

func (s *biometricService) Identify(
	ctx context.Context,
	probePix []byte,
	width, height uint32,
	topK uint32,
) ([]CandidateResult, error) {
	ctx, span := tracer.Start(ctx, "BiometricService.Identify")
	defer span.End()

	img, err := image.NewGrayImage(int(width), int(height), probePix)
	if err != nil {
		return nil, fmt.Errorf("invalid probe image: %w", err)
	}

	norm := img.Normalize(128, 2000)
	bin := norm.AdaptiveBinarize(15)
	skel := image.ZhangSuenThinning(bin, int(width), int(height))
	orientations := norm.OrientationField(16)
	probePoints := s.extractor.Extract(skel, int(width), int(height), orientations, 16)

	nfiqScore, acceptable := s.assessor.Evaluate(norm, probePoints)
	if !acceptable {
		return nil, fmt.Errorf("probe quality unacceptable for 1:N identification (NFIQ: %d)", nfiqScore)
	}

	probeTemplate := mcc.BuildTemplate("probe-search", probePoints)

	all, err := s.repo.ListAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list templates: %w", err)
	}

	var candidates []CandidateResult
	for _, galleryItem := range all {
		decryptedBytes, err := s.vault.DecryptTemplate(galleryItem.EncryptedPayload)
		if err != nil {
			continue
		}
		var galleryPayload domain.DecryptedTemplatePayload
		if err := json.Unmarshal(decryptedBytes, &galleryPayload); err != nil {
			continue
		}

		galleryTemplate := &mcc.Template{
			ID:        galleryItem.TemplateID,
			Cylinders: galleryPayload.Cylinders,
		}

		res, err := s.matcher.Verify(ctx, probeTemplate, galleryTemplate)
		if err == nil && res.IsMatch {
			candidates = append(candidates, CandidateResult{
				EmployeeID: galleryItem.EmployeeID,
				Position:   galleryItem.Position,
				Score:      res.Score,
			})
		}
	}

	// Sort candidates descending by match score
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Score > candidates[j].Score
	})

	if topK > 0 && len(candidates) > int(topK) {
		candidates = candidates[:topK]
	}

	return candidates, nil
}

func (s *biometricService) GetTemplate(ctx context.Context, empID string, position int32) (*domain.EnrolledTemplate, *domain.DecryptedTemplatePayload, error) {
	enrolled, err := s.repo.GetByEmployeeAndPosition(ctx, empID, position)
	if err != nil {
		return nil, nil, err
	}

	decryptedBytes, err := s.vault.DecryptTemplate(enrolled.EncryptedPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt template: %w", err)
	}
	var payload domain.DecryptedTemplatePayload
	if err := json.Unmarshal(decryptedBytes, &payload); err != nil {
		return nil, nil, fmt.Errorf("failed to deserialize template payload: %w", err)
	}

	return enrolled, &payload, nil
}
