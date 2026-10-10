package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	"finger-scanner/pkg/biometrics/image"
	"finger-scanner/pkg/biometrics/mcc"
	"finger-scanner/pkg/biometrics/minutiae"
	"finger-scanner/services/edge-gateway-service/internal/domain"
	"finger-scanner/services/edge-gateway-service/internal/ports"
)

var tracer = otel.Tracer("finger-scanner/services/edge-gateway-service")

// ScanResult captures the turnstile door decision and metrics.
type ScanResult struct {
	IsAccessGranted       bool
	Decision              int32 // 1 = Granted, 5 = Mismatch
	MatchedEmployeeID     string
	MatchScore            float64
	Reason                string
	RelayStrikeDurationMs int64
	TotalLatencyMs        int64
	ProcessedOffline      bool
}

// EdgeUseCase defines turnstile gateway operations.
type EdgeUseCase interface {
	ProcessScan(ctx context.Context, turnstileID, zoneID string, direction int32, employeeID string, probePix []byte, width, height uint32) (*ScanResult, error)
	SyncRoster(ctx context.Context, items []*domain.CachedEmployee) (uint32, error)
	SyncPolicies(ctx context.Context, rules []*domain.PolicyRule) error
	GetStatus(ctx context.Context, turnstileID string) (*domain.TurnstileState, error)
	ReplayEvents(ctx context.Context) ([]*domain.OfflineAuditLog, error)
}

type edgeService struct {
	cache        ports.EdgeRepository
	extractor    *minutiae.Extractor
	matcher      *mcc.Matcher
	policyClient accesscontrolv1.AccessPolicyServiceClient
	logger       *slog.Logger
	startupTime  int64
}

// NewEdgeService instantiates a production edge service in standalone mode.
func NewEdgeService(cache ports.EdgeRepository, logger *slog.Logger) EdgeUseCase {
	return NewEdgeServiceWithPolicy(cache, nil, logger)
}

// NewEdgeServiceWithPolicy instantiates an edge service connected to central policy evaluation.
func NewEdgeServiceWithPolicy(cache ports.EdgeRepository, policyClient accesscontrolv1.AccessPolicyServiceClient, logger *slog.Logger) EdgeUseCase {
	if logger == nil {
		logger = slog.Default()
	}

	return &edgeService{
		cache:        cache,
		extractor:    minutiae.NewExtractor(),
		matcher:      mcc.NewMatcher(0.35, 60.0, logger),
		policyClient: policyClient,
		logger:       logger,
		startupTime:  time.Now().Unix(),
	}
}

func (s *edgeService) ProcessScan(
	ctx context.Context,
	turnstileID, zoneID string,
	direction int32,
	employeeID string,
	probePix []byte,
	width, height uint32,
) (*ScanResult, error) {
	startTime := time.Now()
	ctx, span := tracer.Start(ctx, "EdgeGateway.ProcessScan",
		trace.WithAttributes(
			attribute.String("turnstile.id", turnstileID),
			attribute.String("zone.id", zoneID),
			attribute.String("employee.id", employeeID),
		),
	)
	defer span.End()

	if len(probePix) == 0 || width == 0 || height == 0 {
		return &ScanResult{
			IsAccessGranted: false,
			Decision:        5,
			Reason:          "Invalid or empty probe image",
			TotalLatencyMs:  (time.Since(startTime).Nanoseconds() + 999_999) / 1_000_000,
		}, nil
	}

	// 1. Extract minutiae from probe impression
	img, err := image.NewGrayImage(int(width), int(height), probePix)
	if err != nil {
		return nil, fmt.Errorf("failed to process image: %w", err)
	}

	norm := img.Normalize(128, 2000)
	bin := norm.AdaptiveBinarize(15)
	skel := image.ZhangSuenThinning(bin, int(width), int(height))
	orientations := norm.OrientationField(16)
	points := s.extractor.Extract(skel, int(width), int(height), orientations, 16)

	probeTemplate := mcc.BuildTemplate("probe-edge", points)

	var bestScore float64
	var matchedEmpID string
	var isMatch bool

	// 2. Matching Strategy: 1:1 if employeeID supplied via badge, else 1:N across local site roster
	if employeeID != "" {
		// 1:1 Fast Direct Lookup in Local Cache (< 1.5ms)
		cached, err := s.cache.GetEmployee(ctx, employeeID)
		if err == nil && cached.IsActive {
			galleryTemplate := &mcc.Template{
				ID:        cached.EmployeeID,
				Cylinders: cached.Cylinders,
			}
			res, err := s.matcher.Verify(ctx, probeTemplate, galleryTemplate)
			if err == nil {
				bestScore = res.Score
				isMatch = res.IsMatch
				// M10: Do not set matchedEmpID on failed match
				if isMatch {
					matchedEmpID = cached.EmployeeID
				}
			}
		}
	} else {
		// 1:N Local Cache Search across site roster
		roster, err := s.cache.ListAllEmployees(ctx)
		if err == nil {
			var topScore, secondScore float64
			var topEmpID string
			var matchCount int

			for _, cached := range roster {
				if !cached.IsActive {
					continue
				}
				galleryTemplate := &mcc.Template{
					ID:        cached.EmployeeID,
					Cylinders: cached.Cylinders,
				}
				res, err := s.matcher.Verify(ctx, probeTemplate, galleryTemplate)
				if err == nil && res.IsMatch {
					matchCount++
					if res.Score > topScore {
						secondScore = topScore
						topScore = res.Score
						topEmpID = cached.EmployeeID
					} else if res.Score > secondScore {
						secondScore = res.Score
					}
				}
			}

			// H6: Enforce strict score margin check in 1:N matching
			if matchCount == 0 {
				isMatch = false
			} else if matchCount == 1 {
				isMatch = true
				bestScore = topScore
				matchedEmpID = topEmpID
			} else {
				margin := topScore - secondScore
				const minMargin = 8.0
				if margin >= minMargin {
					isMatch = true
					bestScore = topScore
					matchedEmpID = topEmpID
				} else {
					isMatch = false
					bestScore = topScore
					matchedEmpID = ""
					s.logger.WarnContext(ctx, "ambiguous 1:N biometric match rejected",
						slog.Float64("top_score", topScore),
						slog.Float64("second_score", secondScore),
						slog.Float64("margin", margin),
					)
				}
			}
		}
	}

	// M14: Ceiling division so latency SLA is strictly measurable
	elapsed := time.Since(startTime)
	elapsedMs := (elapsed.Nanoseconds() + 999_999) / 1_000_000

	var decision int32 = 5 // Biometric mismatch
	reason := "Biometric verification failed"
	var relayDuration int64 = 0
	processedOffline := false

	// Policy Evaluation: Central Primary with Dynamic Fog Node Local Policy Failover
	if isMatch {
		decision = 0
		reason = "Evaluating policy"
		evaluatedCentral := false
		if s.policyClient != nil {
			evalCtx, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
			policyResp, err := s.policyClient.EvaluateAccess(evalCtx, &accesscontrolv1.EvaluateAccessRequest{
				EmployeeId:        matchedEmpID,
				ZoneId:            zoneID,
				DoorId:            turnstileID,
				Direction:         accesscontrolv1.DoorDirection(direction),
				BiometricVerified: true,
				BiometricScore:    bestScore,
				TimestampUnix:     time.Now().Unix(),
			})
			cancel()

			if err == nil && policyResp != nil {
				evaluatedCentral = true
				if policyResp.IsGranted {
					decision = int32(policyResp.Decision)
					reason = policyResp.Reason
					relayDuration = policyResp.RelayOpenDurationMs
					// Replicate pass event to local cache for APB continuity
					_ = s.cache.RecordPassEvent(ctx, &domain.PassEvent{
						EmployeeID: matchedEmpID,
						ZoneID:     zoneID,
						DoorID:     turnstileID,
						Direction:  direction,
						Timestamp:  time.Now().Unix(),
					})
				} else {
					decision = int32(policyResp.Decision)
					isMatch = false
					reason = policyResp.Reason
					relayDuration = 0
				}
			} else {
				s.logger.WarnContext(ctx, "central access policy service unreachable, failing over dynamically to cached edge policy",
					slog.String("error", fmt.Sprintf("%v", err)),
					slog.String("turnstile_id", turnstileID),
					slog.String("zone_id", zoneID),
					slog.String("employee_id", matchedEmpID),
				)
			}
		}

		if !evaluatedCentral {
			// 100% OFFLINE FOG NODE SURVIVABILITY:
			// Evaluate local cached zone policy and local symmetric APB
			processedOffline = true

			// 1. Retrieve local cached policy rule for zone
			rule, err := s.cache.GetPolicyRule(ctx, zoneID)
			if err != nil {
				rule = &domain.PolicyRule{
					ZoneID:                zoneID,
					AllowedRole:           "EMPLOYEE",
					RequireBiometrics:     true,
					MinBiometricScore:     60.0,
					EnforceAntiPassback:   true,
					AntiPassbackWindowSec: 60,
				}
			}

			// 2. Local Role Clearance Check
			emp, _ := s.cache.GetEmployee(ctx, matchedEmpID)
			empRole := "EMPLOYEE"
			if emp != nil && emp.Role != "" {
				empRole = emp.Role
			}

			if !roleCleared(empRole, rule.AllowedRole) {
				decision = 2 // ACCESS_DECISION_DENIED_INVALID_ZONE
				isMatch = false
				reason = fmt.Sprintf("Access denied (offline cached policy): role '%s' does not satisfy zone requirement '%s'", empRole, rule.AllowedRole)
				relayDuration = 0
			} else if rule.RequireBiometrics && bestScore < rule.MinBiometricScore {
				// 3. Local Biometric Threshold Check
				decision = 5 // ACCESS_DECISION_DENIED_BIOMETRIC_MISMATCH
				isMatch = false
				reason = fmt.Sprintf("Access denied (offline cached policy): biometric score %.1f below zone threshold %.1f", bestScore, rule.MinBiometricScore)
				relayDuration = 0
			} else if rule.EnforceAntiPassback {
				// 4. Local Symmetric Anti-Passback Check
				now := time.Now().Unix()
				lastEvent, _ := s.cache.GetLastPassEvent(ctx, matchedEmpID, zoneID)

				// The offline APB branches below test for entry and exit explicitly. An
				// unrecognised direction matches neither and would otherwise skip the rule
				// entirely, so it is rejected before either branch is reached - here, where the
				// WAN is already down and the cached path is the only one that will run.
				if direction != directionEntry && direction != directionExit {
					decision = 2 // ACCESS_DECISION_DENIED_INVALID_ZONE
					isMatch = false
					reason = fmt.Sprintf("Access denied (offline cached policy): unrecognised door direction %d; entry (1) or exit (2) is required", direction)
					relayDuration = 0
				} else if direction == directionEntry { // Entry attempt
					if lastEvent != nil && lastEvent.Direction == 1 {
						elapsed := now - lastEvent.Timestamp
						if rule.AntiPassbackWindowSec == 0 || elapsed < int64(rule.AntiPassbackWindowSec) {
							decision = 3 // ACCESS_DECISION_DENIED_ANTI_PASSBACK
							isMatch = false
							reason = fmt.Sprintf("Anti-passback violation (offline cached policy): entry already logged %d seconds ago (window %ds)", elapsed, rule.AntiPassbackWindowSec)
							relayDuration = 0
						}
					}
				} else if direction == directionExit {
					if lastEvent == nil || lastEvent.Direction != 1 {
						decision = 3 // ACCESS_DECISION_DENIED_ANTI_PASSBACK
						isMatch = false
						reason = "Anti-passback violation (offline cached policy): cannot exit zone without prior recorded entry"
						relayDuration = 0
					}
				}
			}

			if isMatch && relayDuration == 0 && decision != 2 && decision != 3 && decision != 5 {
				// Access Granted: strike relay solenoid and log local pass event
				decision = 1 // ACCESS_DECISION_GRANTED
				reason = "Access granted: verified at edge turnstile (offline cached policy)"
				relayDuration = 2500 // 2.5 seconds unlock pulse

				_ = s.cache.RecordPassEvent(ctx, &domain.PassEvent{
					EmployeeID: matchedEmpID,
					ZoneID:     zoneID,
					DoorID:     turnstileID,
					Direction:  direction,
					Timestamp:  time.Now().Unix(),
				})
			}
		}
	}

	// Always append to local crash-proof disk WAL
	_ = s.cache.AppendOfflineEvent(ctx, &domain.OfflineAuditLog{
		EventID:       uuid.New().String(),
		TurnstileID:   turnstileID,
		EmployeeID:    matchedEmpID,
		ZoneID:        zoneID,
		AccessGranted: isMatch && relayDuration > 0,
		Decision:      reason,
		TimestampUnix: time.Now().Unix(),
	})

	s.logger.InfoContext(ctx, "turnstile scan evaluated",
		slog.String("turnstile_id", turnstileID),
		slog.String("employee_id", matchedEmpID),
		slog.Bool("granted", isMatch && relayDuration > 0),
		slog.Bool("offline", processedOffline),
		slog.Float64("score", bestScore),
		slog.Int64("latency_ms", elapsedMs),
	)

	return &ScanResult{
		IsAccessGranted:       isMatch && relayDuration > 0,
		Decision:              decision,
		MatchedEmployeeID:     matchedEmpID,
		MatchScore:            bestScore,
		Reason:                reason,
		RelayStrikeDurationMs: relayDuration,
		TotalLatencyMs:        elapsedMs,
		ProcessedOffline:      processedOffline,
	}, nil
}

func (s *edgeService) SyncRoster(ctx context.Context, items []*domain.CachedEmployee) (uint32, error) {
	var count uint32
	for _, it := range items {
		if err := s.cache.UpsertEmployee(ctx, it); err == nil {
			count++
		}
	}
	s.logger.InfoContext(ctx, "roster synchronized at edge", slog.Int("synced_count", int(count)))
	return count, nil
}

func (s *edgeService) SyncPolicies(ctx context.Context, rules []*domain.PolicyRule) error {
	for _, r := range rules {
		if err := s.cache.UpsertPolicyRule(ctx, r); err != nil {
			return err
		}
	}
	s.logger.InfoContext(ctx, "policies synchronized at edge", slog.Int("synced_count", len(rules)))
	return nil
}

func (s *edgeService) GetStatus(ctx context.Context, turnstileID string) (*domain.TurnstileState, error) {
	employees, _ := s.cache.ListAllEmployees(ctx)
	pendingCount := s.cache.GetOfflineEventCount(ctx)

	// Dynamically test if central access policy service is alive
	isOnline := false
	if s.policyClient != nil {
		probeCtx, cancel := context.WithTimeout(ctx, 80*time.Millisecond)
		_, err := s.policyClient.GetPolicy(probeCtx, &accesscontrolv1.GetPolicyRequest{ZoneId: "zone-main-gate"})
		cancel()
		if err == nil {
			isOnline = true
		}
	}

	zoneID := "zone-main-gate"
	if turnstileID != "" {
		if rule, err := s.cache.GetPolicyRule(ctx, turnstileID); err == nil && rule != nil {
			zoneID = rule.ZoneID
		}
	}

	return &domain.TurnstileState{
		TurnstileID:          turnstileID,
		ZoneID:               zoneID,
		IsOnline:             isOnline,
		ReaderConnected:      true,
		LocalRosterCount:     uint32(len(employees)),
		OfflinePendingEvents: pendingCount,
		StartTimeUnix:        s.startupTime,
	}, nil
}

// Door directions, mirroring accesscontrol.v1.DoorDirection. Named so a value
// arriving outside the enum is compared against a defined set rather than a
// magic number.
const (
	// directionEntry is a movement into a zone.
	directionEntry int32 = 1
	// directionExit is a movement out of a zone.
	directionExit int32 = 2
)

func roleRank(role string) int {
	switch role {
	case "SECURITY_ADMIN":
		return 3
	case "OPERATOR":
		return 2
	case "EMPLOYEE", "AGENT", "STAFF":
		return 1
	default:
		return 0
	}
}

// roleCleared reports whether an employee's role satisfies a zone's requirement.
//
// It fails closed on BOTH sides, which the raw rank comparison did not. The
// clearance test used to be `roleRank(employee) < roleRank(required)`, and an
// unrecognised *required* role scores 0, making the test `1 < 0` - false, so
// nothing was denied and the grant proceeded. The employee side was already
// safe, because an unknown employee role scores 0 and fails `0 < 1`. Only the
// required side was fail-open, and the asymmetry is invisible at the call site.
//
// So a requirement the system does not recognise denies access. It is not a
// graceful default: "ADMINISTRATOR" is a perfectly plausible name for a role
// outside this switch, and configuring a server room with it would otherwise
// hand the room to every employee and contractor on the roster, silently. A
// zone locked until the role is spelled correctly is recoverable; a data centre
// quietly opened to everyone is not.
//
// An empty requirement means no clearance requirement, which is a different
// statement from an unrecognised one and is still allowed.
func roleCleared(employeeRole, requiredRole string) bool {
	if requiredRole == "" {
		return true
	}
	required := roleRank(requiredRole)
	if required == 0 {
		return false
	}
	return roleRank(employeeRole) >= required
}

// ReplayEvents forwards buffered door decisions to central storage.
//
// The previous implementation drained the queue and returned the events to a
// caller that discarded them, while truncating the durable WAL in the same
// call. That is the worst possible shape: replaying destroyed the only copy of
// the audit trail, and the central access_events table was never written by any
// code path, so nothing replaced it.
//
// The sequence is now take -> forward -> acknowledge. The WAL is truncated only
// after the forward is confirmed, and a failure restores the events so the next
// attempt still carries them. Because recording upstream deduplicates on
// event_id, a retry after a partially-committed batch is safe.
func (s *edgeService) ReplayEvents(ctx context.Context) ([]*domain.OfflineAuditLog, error) {
	taken, err := s.cache.TakeOfflineEvents(ctx)
	if err != nil {
		return nil, err
	}
	if len(taken) == 0 {
		return nil, nil
	}

	if s.policyClient == nil {
		// No upstream configured. The events must go back, not be dropped.
		_ = s.cache.RestoreOfflineEvents(ctx, taken)
		return nil, errors.New("edge: cannot replay offline events, no access-policy client is configured")
	}

	// Batch, so a long outage does not produce one RPC per door entry.
	const batchSize = 200
	for start := 0; start < len(taken); start += batchSize {
		end := start + batchSize
		if end > len(taken) {
			end = len(taken)
		}
		chunk := taken[start:end]
		if err := s.forwardAccessEvents(ctx, chunk); err != nil {
			// Put back everything not yet confirmed, including this chunk:
			// upstream may have committed part of it, and the event ids make
			// the retry idempotent.
			_ = s.cache.RestoreOfflineEvents(ctx, taken[start:])
			s.logger.ErrorContext(ctx, "offline audit replay failed; events retained",
				slog.Int("retained", len(taken)-start),
				slog.String("error", err.Error()),
			)
			return nil, err
		}
	}

	if err := s.cache.AcknowledgeOfflineEvents(ctx); err != nil {
		// The events are stored upstream, so this is a retention problem
		// rather than a lost-audit problem. Report it rather than pretend the
		// replay was clean.
		s.logger.ErrorContext(ctx, "offline audit replay succeeded but the local WAL could not be truncated",
			slog.String("error", err.Error()),
		)
		return taken, nil
	}

	s.logger.InfoContext(ctx, "offline access events replayed to central storage",
		slog.Int("events", len(taken)),
	)
	return taken, nil
}

// forwardAccessEvents sends one batch of door decisions upstream.
func (s *edgeService) forwardAccessEvents(ctx context.Context, events []*domain.OfflineAuditLog) error {
	req := &accesscontrolv1.RecordAccessEventsRequest{
		Events: make([]*accesscontrolv1.AccessAuditEvent, 0, len(events)),
	}
	for _, e := range events {
		req.Events = append(req.Events, &accesscontrolv1.AccessAuditEvent{
			EventId:          e.EventID,
			TurnstileId:      e.TurnstileID,
			EmployeeId:       e.EmployeeID,
			ZoneId:           e.ZoneID,
			Decision:         e.Decision,
			AccessGranted:    e.AccessGranted,
			ProcessedOffline: true,
			OccurredUnix:     e.TimestampUnix,
		})
	}

	callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := s.policyClient.RecordAccessEvents(callCtx, req); err != nil {
		return err
	}
	return nil
}
