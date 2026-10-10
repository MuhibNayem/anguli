package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"finger-scanner/services/access-policy-service/internal/domain"
	"finger-scanner/services/access-policy-service/internal/ports"
)

var tracer = otel.Tracer("finger-scanner/services/access-policy-service")

// EvaluationResult captures the outcome of an access control decision.
type EvaluationResult struct {
	Decision            int32
	IsGranted           bool
	Reason              string
	RelayOpenDurationMs int64
}

// PolicyUseCase defines access control operations.
type PolicyUseCase interface {
	Evaluate(ctx context.Context, empID, zoneID, doorID string, direction int32, bioVerified bool, bioScore float64) (*EvaluationResult, error)
	Configure(ctx context.Context, rule *domain.PolicyRule) error
	Get(ctx context.Context, zoneID string) (*domain.PolicyRule, error)
	ResetAPB(ctx context.Context, empID, zoneID string) error
}

type policyService struct {
	repo   ports.PolicyRepository
	logger *slog.Logger
}

func NewPolicyService(repo ports.PolicyRepository, logger *slog.Logger) PolicyUseCase {
	if logger == nil {
		logger = slog.Default()
	}
	return &policyService{
		repo:   repo,
		logger: logger,
	}
}

// roleRank assigns a hierarchical clearance level to standard enterprise roles.
func roleRank(role string) int {
	switch strings.ToUpper(strings.TrimSpace(role)) {
	case "SECURITY_ADMIN", "ADMIN", "SUPERADMIN":
		return 3
	case "OPERATOR", "SECURITY_OPERATOR":
		return 2
	case "EMPLOYEE", "AGENT", "STAFF":
		return 1
	default:
		return 0
	}
}

func (s *policyService) Evaluate(
	ctx context.Context,
	empID, zoneID, doorID string,
	direction int32,
	bioVerified bool,
	bioScore float64,
) (*EvaluationResult, error) {
	ctx, span := tracer.Start(ctx, "PolicyService.Evaluate",
		trace.WithAttributes(
			attribute.String("employee.id", empID),
			attribute.String("zone.id", zoneID),
			attribute.String("door.id", doorID),
			attribute.Int("direction", int(direction)),
			attribute.Bool("bio.verified", bioVerified),
			attribute.Float64("bio.score", bioScore),
		),
	)
	defer span.End()

	// 1. Retrieve zone policy rule (H9: fail closed on unconfigured or unrecognized zones)
	rule, err := s.repo.GetRule(ctx, zoneID)
	if err != nil {
		if errors.Is(err, ports.ErrNotFound) {
			s.logger.WarnContext(ctx, "access denied: unknown or unconfigured zone",
				slog.String("zone_id", zoneID),
				slog.String("employee_id", empID),
			)
			return &EvaluationResult{
				Decision:            2, // ACCESS_DECISION_DENIED_INVALID_ZONE
				IsGranted:           false,
				Reason:              fmt.Sprintf("Zone '%s' is not configured or recognized", zoneID),
				RelayOpenDurationMs: 0,
			}, nil
		}
		return nil, fmt.Errorf("failed to retrieve policy rule: %w", err)
	}

	// 2. Role Clearance Evaluation (H4: enforce AllowedRole requirements)
	if rule.AllowedRole != "" {
		empRole, err := s.repo.GetEmployeeRole(ctx, empID)
		if err != nil {
			s.logger.WarnContext(ctx, "failed to get employee role, defaulting to EMPLOYEE",
				slog.String("employee_id", empID),
				slog.String("error", err.Error()),
			)
			empRole = "EMPLOYEE"
		}

		if roleRank(empRole) < roleRank(rule.AllowedRole) {
			s.logger.WarnContext(ctx, "access denied: insufficient role clearance",
				slog.String("employee_id", empID),
				slog.String("employee_role", empRole),
				slog.String("required_role", rule.AllowedRole),
				slog.String("zone_id", zoneID),
			)
			return &EvaluationResult{
				Decision:            2, // ACCESS_DECISION_DENIED_INVALID_ZONE
				IsGranted:           false,
				Reason:              fmt.Sprintf("Access denied: role '%s' has insufficient clearance for zone requiring '%s'", empRole, rule.AllowedRole),
				RelayOpenDurationMs: 0,
			}, nil
		}
	}

	// 3. Biometric verification check
	if rule.RequireBiometrics {
		if !bioVerified || bioScore < rule.MinBiometricScore {
			s.logger.WarnContext(ctx, "access denied: biometric score below threshold",
				slog.String("employee_id", empID),
				slog.Float64("score", bioScore),
				slog.Float64("required", rule.MinBiometricScore),
			)
			return &EvaluationResult{
				Decision:            5, // ACCESS_DECISION_DENIED_BIOMETRIC_MISMATCH
				IsGranted:           false,
				Reason:              fmt.Sprintf("Biometric score %.1f below zone threshold %.1f", bioScore, rule.MinBiometricScore),
				RelayOpenDurationMs: 0,
			}, nil
		}
	}

	now := time.Now().Unix()

	// 4. Symmetric Anti-Passback check (C3: prevent bypass via fake exit or duplicate entries)
	//
	// KNOWN LIMITATION - read-modify-write, not atomic.
	//
	// This check and the RecordPassEvent at step 5 are two separate calls with
	// no transaction between them. Two ENTRY swipes for the same employee at
	// the same zone that arrive concurrently - the same person at Turnstile
	// Lane 1 and Lane 2 in the same instant, which is precisely the case
	// anti-passback exists to stop - can both observe "no prior entry" and
	// both be granted.
	//
	// This is a TOCTOU race and it is NOT fixed by durable storage. Sharing
	// state across replicas (what the sqlstore adapter does) is necessary but
	// not sufficient; it makes the state visible, not the decision exclusive.
	// It is reachable only in a multi-replica deployment, because a single
	// process would have to interleave two goroutines at exactly this point.
	//
	// The fix is a transactional compare-and-set at the port level: take a
	// per-(employee, zone) lock and do the read and the insert inside one
	// transaction, serializable on Postgres or guarded by a unique constraint.
	// That is deliberately NOT implemented here - a process-local mutex would
	// close the single-replica case while leaving the multi-replica case open,
	// which is the worst outcome: it reads like the problem is solved.
	if rule.EnforceAntiPassback {
		lastEvent, err := s.repo.GetLastPassEvent(ctx, empID, zoneID)
		if err != nil && !errors.Is(err, ports.ErrNotFound) {
			return nil, fmt.Errorf("failed to check anti-passback state: %w", err)
		}
		// A missing pass event means the employee has never been through this
		// zone, which is exactly what an ENTRY should be allowed to do. It is
		// not a fault, so it must not become one.

		if direction == 1 { // Entry attempt
			if lastEvent != nil && lastEvent.Direction == 1 {
				elapsed := now - lastEvent.Timestamp
				if rule.AntiPassbackWindowSec == 0 || elapsed < int64(rule.AntiPassbackWindowSec) {
					s.logger.WarnContext(ctx, "access denied: anti-passback violation on entry",
						slog.String("employee_id", empID),
						slog.Int64("elapsed_sec", elapsed),
						slog.Int("window_sec", int(rule.AntiPassbackWindowSec)),
					)
					return &EvaluationResult{
						Decision:            3, // ACCESS_DECISION_DENIED_ANTI_PASSBACK
						IsGranted:           false,
						Reason:              fmt.Sprintf("Anti-passback violation: entry already logged %d seconds ago (window %ds)", elapsed, rule.AntiPassbackWindowSec),
						RelayOpenDurationMs: 0,
					}, nil
				}
			}
		} else if direction == 2 { // Exit attempt
			// An employee cannot exit if there is no prior recorded entry, or if they have already exited
			if lastEvent == nil || lastEvent.Direction != 1 {
				s.logger.WarnContext(ctx, "access denied: anti-passback violation on exit",
					slog.String("employee_id", empID),
					slog.String("zone_id", zoneID),
				)
				return &EvaluationResult{
					Decision:            3, // ACCESS_DECISION_DENIED_ANTI_PASSBACK
					IsGranted:           false,
					Reason:              "Anti-passback violation: cannot exit zone without prior recorded entry",
					RelayOpenDurationMs: 0,
				}, nil
			}
		}
	}

	// 5. Access Granted: Commit pass event to state repository (H11: Fail closed if audit state cannot be written)
	event := &domain.PassEvent{
		EmployeeID: empID,
		ZoneID:     zoneID,
		DoorID:     doorID,
		Direction:  direction,
		Timestamp:  now,
	}
	if err := s.repo.RecordPassEvent(ctx, event); err != nil {
		s.logger.ErrorContext(ctx, "failed to record pass event: failing closed for audit integrity",
			slog.String("employee_id", empID),
			slog.String("zone_id", zoneID),
			slog.String("error", err.Error()),
		)
		return &EvaluationResult{
			Decision:            0, // ACCESS_DECISION_UNSPECIFIED
			IsGranted:           false,
			Reason:              "Internal audit failure: unable to record passage state (failing closed)",
			RelayOpenDurationMs: 0,
		}, fmt.Errorf("failed to commit pass event audit record: %w", err)
	}

	s.logger.InfoContext(ctx, "access granted",
		slog.String("employee_id", empID),
		slog.String("zone_id", zoneID),
		slog.String("door_id", doorID),
		slog.Int("direction", int(direction)),
	)

	return &EvaluationResult{
		Decision:            1, // ACCESS_DECISION_GRANTED
		IsGranted:           true,
		Reason:              "Access granted by policy rule",
		RelayOpenDurationMs: 2500, // 2.5 seconds unlock pulse
	}, nil
}

func (s *policyService) Configure(ctx context.Context, rule *domain.PolicyRule) error {
	return s.repo.SaveRule(ctx, rule)
}

func (s *policyService) Get(ctx context.Context, zoneID string) (*domain.PolicyRule, error) {
	return s.repo.GetRule(ctx, zoneID)
}

func (s *policyService) ResetAPB(ctx context.Context, empID, zoneID string) error {
	return s.repo.ResetAntiPassback(ctx, empID, zoneID)
}
