package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"finger-scanner/services/access-policy-service/internal/domain"
	"finger-scanner/services/access-policy-service/internal/ports"
)

var tracer = otel.Tracer("finger-scanner/services/access-policy-service")

// Door directions, mirroring accesscontrol.v1.DoorDirection.
//
// Named here rather than taken from the generated proto so the service layer
// does not depend on the wire types, and so a value that arrives outside the
// enum is still compared against a defined set instead of a magic number.
const (
	// DirectionEntry is a movement into a zone.
	DirectionEntry int32 = 1
	// DirectionExit is a movement out of a zone.
	DirectionExit int32 = 2
)

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
	RecordAccessEvents(ctx context.Context, events []*domain.AccessAuditEvent) (recorded int, duplicates int, err error)
	// QueryAccessEvents reads a page of the audit trail. pageToken is an opaque
	// cursor; an empty nextPageToken means the result is exhausted.
	QueryAccessEvents(ctx context.Context, filter domain.AccessEventFilter, pageToken string) (events []*domain.AccessAuditEvent, nextPageToken string, err error)
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

// roleCleared reports whether an employee's role satisfies a zone's requirement.
//
// It fails closed on BOTH sides. The clearance test used to be
// `roleRank(employee) < roleRank(required)`, and an unrecognised *required*
// role scores 0, so the test became `1 < 0` - false, nothing was denied, and
// the grant proceeded. The employee side was already safe, because an unknown
// employee role scores 0 and fails `0 < 1`; only the required side was
// fail-open, and the asymmetry is invisible at the call site.
//
// So a requirement naming a role this system does not recognise denies access
// rather than admitting everyone. "ADMINISTRATOR" looks like a role and is not
// one, and a zone configured with it would otherwise be open to the whole
// roster with nothing logged.
//
// An empty requirement means no clearance requirement, which is a different
// statement from an unrecognised one and is still permitted.
func roleCleared(employeeRole, requiredRole string) bool {
	if strings.TrimSpace(requiredRole) == "" {
		return true
	}
	required := roleRank(requiredRole)
	if required == 0 {
		return false
	}
	return roleRank(employeeRole) >= required
}

// knownRole reports whether a role name is one the hierarchy understands. It
// exists so a misconfiguration can be rejected at the point it is written,
// rather than only being noticed the first time somebody is refused.
func knownRole(role string) bool {
	return strings.TrimSpace(role) == "" || roleRank(role) > 0
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

	// 0. Direction must name a real movement.
	//
	// The anti-passback evaluation branched on `direction == 1` for entry and
	// `direction == 2` for exit. Anything else matched neither branch, fell
	// through to the grant, and recorded a pass event - so an unrecognised
	// direction silently skipped the rule entirely.
	//
	// That is not hypothetical. proto3 defaults an unset enum field to zero and
	// DOOR_DIRECTION_UNSPECIFIED is zero, so a caller that omits `direction`
	// sends exactly the value that disables anti-passback.
	//
	// This is checked before anything else so that a malformed request cannot
	// record a movement: a bogus pass event would also be what the next
	// legitimate scan is judged against.
	//
	// The trade is not symmetric. Reading the direction wrong could strand
	// someone inside a zone with no recorded exit; granting it bypasses a
	// physical access control outright. So it denies.
	if direction != DirectionEntry && direction != DirectionExit {
		s.logger.WarnContext(ctx, "access denied: unrecognised door direction",
			slog.String("employee_id", empID),
			slog.String("zone_id", zoneID),
			slog.Int("direction", int(direction)),
		)
		return &EvaluationResult{
			Decision: 2, // ACCESS_DECISION_DENIED_INVALID_ZONE
			// A malformed request is not the employee's fault, so the reason
			// says what is wrong with it rather than blaming them.
			IsGranted:           false,
			Reason:              fmt.Sprintf("Unrecognised door direction %d; entry (1) or exit (2) is required", direction),
			RelayOpenDurationMs: 0,
		}, nil
	}

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

		if !roleCleared(empRole, rule.AllowedRole) {
			s.logger.WarnContext(ctx, "access denied: insufficient role clearance",
				slog.String("employee_id", empID),
				slog.String("employee_role", empRole),
				slog.String("required_role", rule.AllowedRole),
				slog.String("zone_id", zoneID),
			)
			return &EvaluationResult{
				Decision:            2, // ACCESS_DECISION_DENIED_INVALID_ZONE
				IsGranted:           false,
				Reason:              fmt.Sprintf("Access denied: role '%s' does not satisfy zone requirement '%s'", empRole, rule.AllowedRole),
				RelayOpenDurationMs: 0,
			}, nil
		}
	}

	// 3. Biometric verification check
	if rule.RequireBiometrics {
		// A threshold below zero means the rule cannot be evaluated, not that it
		// is permissive: `score < threshold` would never be true, so every
		// verified print would pass. Configure rejects such a value, but a rule
		// stored before that check existed - or written by a tool bypassing it -
		// must fail closed here too.
		if rule.MinBiometricScore < 0 {
			s.logger.WarnContext(ctx, "access denied: zone policy has an unusable biometric threshold",
				slog.String("employee_id", empID),
				slog.String("zone_id", zoneID),
				slog.Float64("threshold", rule.MinBiometricScore),
			)
			return &EvaluationResult{
				Decision:  2, // ACCESS_DECISION_DENIED_INVALID_ZONE
				IsGranted: false,
				Reason: fmt.Sprintf("Zone '%s' has a biometric threshold of %.2f, which is outside "+
					"the valid range 0-100; the zone is locked until it is reconfigured",
					zoneID, rule.MinBiometricScore),
				RelayOpenDurationMs: 0,
			}, nil
		}
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

	// 4 + 5. Symmetric anti-passback check and pass-event commit.
	//
	// These two steps run together inside a lock scoped to this
	// (employee, zone) pair. Doing them as separate calls let two turnstiles
	// served by different replicas both observe "no prior entry" in the same
	// instant and both admit the employee - the exact event the rule exists to
	// prevent. Sharing state across replicas fixes visibility; holding the lock
	// across the read AND the write is what makes the decision exclusive.
	//
	// The result is carried out of the closure rather than returned from it,
	// so every denial path keeps its specific ACCESS_DECISION code and reason.
	if rule.EnforceAntiPassback {
		var result *EvaluationResult
		var err error

		lockErr := s.repo.WithPassEventLock(ctx, empID, zoneID, func(ctx context.Context) error {
			result, err = s.evaluateAndRecord(ctx, rule, empID, zoneID, doorID, direction, now)
			return err
		})
		if lockErr != nil {
			return nil, lockErr
		}
		if result != nil {
			return result, nil
		}
	}

	// Anti-passback disabled: record the pass event without the lock, because
	// there is no read to make exclusive.
	event := &domain.PassEvent{
		EmployeeID: empID,
		ZoneID:     zoneID,
		DoorID:     doorID,
		Direction:  direction,
		Timestamp:  now,
	}
	if err := s.repo.RecordPassEvent(ctx, event); err != nil {
		return s.failClosedAudit(ctx, empID, zoneID, err)
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

// evaluateAndRecord applies the anti-passback rule to the last recorded event
// and, if allowed, records the new one. It runs entirely inside the
// repository's pass-event lock.
//
// It returns (nil, nil) to mean "allowed, record it", which is the only way
// the caller gets back a non-nil result with a nil error: every denial carries
// its own reason, and letting them collapse into a generic error would throw
// away the decision code the edge gateway relays to the operator.
func (s *policyService) evaluateAndRecord(
	ctx context.Context,
	rule *domain.PolicyRule,
	empID, zoneID, doorID string,
	direction int32,
	now int64,
) (*EvaluationResult, error) {
	lastEvent, err := s.repo.GetLastPassEvent(ctx, empID, zoneID)
	if err != nil && !errors.Is(err, ports.ErrNotFound) {
		return nil, fmt.Errorf("failed to check anti-passback state: %w", err)
	}
	// A missing pass event means the employee has never been through this
	// zone, which is exactly what an ENTRY should be allowed to do. It is
	// not a fault, so it must not become one.

	if direction == DirectionEntry {
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
	} else if direction == DirectionExit {
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

	event := &domain.PassEvent{
		EmployeeID: empID,
		ZoneID:     zoneID,
		DoorID:     doorID,
		Direction:  direction,
		Timestamp:  now,
	}
	if err := s.repo.RecordPassEvent(ctx, event); err != nil {
		return s.failClosedAudit(ctx, empID, zoneID, err)
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
		RelayOpenDurationMs: 2500,
	}, nil
}

// failClosedAudit denies access when the pass event cannot be written.
//
// An access decision whose audit record is missing is not an access decision:
// the system would have no way to answer who went where. Returning a granted
// result alongside the error would let a caller that ignores the error wave
// someone through with no record of it.
func (s *policyService) failClosedAudit(ctx context.Context, empID, zoneID string, err error) (*EvaluationResult, error) {
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

// Configure stores a zone policy.
//
// An unrecognised allowed_role is rejected here rather than stored. The
// evaluation path already denies for one, so this is not the only thing keeping
// the door shut - but storing it means the zone silently stops admitting
// everyone at some later moment, and the operator who typed the role has long
// forgotten. Failing at configuration points the mistake at whoever made it.
func (s *policyService) Configure(ctx context.Context, rule *domain.PolicyRule) error {
	if rule == nil {
		return errors.New("cannot configure a nil policy rule")
	}
	if rule.AllowedRole != "" && !knownRole(rule.AllowedRole) {
		return fmt.Errorf(
			"policy for zone %q requires role %q, which is not a role this system knows "+
				"(SECURITY_ADMIN, OPERATOR, EMPLOYEE and their aliases); an unrecognised "+
				"requirement would deny everyone, so it is rejected rather than stored",
			rule.ZoneID, rule.AllowedRole)
	}
	// The match score is a percentage, so the threshold is too. A negative value
	// makes `score < threshold` never true, so every verified print passes no
	// matter how poor the match - a configured control silently switched off by
	// a value that looks like a number. A value above 100 would fail every scan,
	// which is the safe direction but still a mistake worth reporting rather
	// than locking a zone at 3am.
	if rule.MinBiometricScore < 0 || rule.MinBiometricScore > 100 {
		return fmt.Errorf(
			"policy for zone %q has a biometric threshold of %.2f, outside the valid "+
				"range 0-100; below 0 would admit every print regardless of match score",
			rule.ZoneID, rule.MinBiometricScore)
	}
	return s.repo.SaveRule(ctx, rule)
}

func (s *policyService) Get(ctx context.Context, zoneID string) (*domain.PolicyRule, error) {
	return s.repo.GetRule(ctx, zoneID)
}

func (s *policyService) ResetAPB(ctx context.Context, empID, zoneID string) error {
	return s.repo.ResetAntiPassback(ctx, empID, zoneID)
}

// RecordAccessEvents durably stores door decisions reported by an edge node.
//
// Until this existed, the central access_events table was created by the schema
// and then never written by any code path. Every turnstile decision was buffered
// at the edge and destroyed when the buffer was replayed, so "who was let
// through which door, and when" had no central answer at all. The edge's local
// WAL was the only copy - one disk on one machine.
func (s *policyService) RecordAccessEvents(
	ctx context.Context, events []*domain.AccessAuditEvent,
) (int, int, error) {
	if len(events) == 0 {
		return 0, 0, nil
	}
	recorded, duplicates, err := s.repo.RecordAccessEvents(ctx, events)
	if err != nil {
		return recorded, duplicates, err
	}
	s.logger.InfoContext(ctx, "access events recorded",
		slog.Int("received", len(events)),
		slog.Int("recorded", recorded),
		slog.Int("duplicates", duplicates),
	)
	return recorded, duplicates, nil
}

// QueryAccessEvents reads the central access audit trail.
//
// The page token is base64-encoded JSON that a client can forge, so it is decoded
// and validated here rather than trusted. A malformed or tampered token is an
// error, not a silent reset to the first page: quietly returning page one would
// look to an operator like the trail had no more entries, which is the worst
// possible answer during an investigation.
//
// It is worth being precise about what that validation does and does not buy.
// The token is not signed, and it does not need to be: it is a pagination
// position, not a capability. Every request is authorised independently, and the
// caller supplies its own filters on each call, so a forged token buys nothing a
// caller could not get by varying its own query. What the checks prevent is a
// cursor with no usable position - which would silently skip or repeat rows, or
// crash the decode - and a mistyped token quietly reading as "start from the
// top". Signing it would add a secret to rotate for no access-control gain.
func (s *policyService) QueryAccessEvents(
	ctx context.Context, filter domain.AccessEventFilter, pageToken string,
) ([]*domain.AccessAuditEvent, string, error) {
	if filter.FromUnix > 0 && filter.ToUnix > 0 && filter.ToUnix < filter.FromUnix {
		return nil, "", status.Error(codes.InvalidArgument, "to_unix must not precede from_unix")
	}

	if pageToken != "" {
		cursor, err := decodePageToken(pageToken)
		if err != nil {
			return nil, "", status.Errorf(codes.InvalidArgument, "invalid page_token: %v", err)
		}
		filter.CursorUnix = cursor.OccurredUnix
		filter.CursorEventID = cursor.EventID
	}

	events, nextUnix, nextID, err := s.repo.QueryAccessEvents(ctx, filter)
	if err != nil {
		return nil, "", err
	}
	if nextID == "" {
		return events, "", nil
	}
	next, err := encodePageToken(pageCursor{OccurredUnix: nextUnix, EventID: nextID})
	if err != nil {
		return nil, "", err
	}
	return events, next, nil
}

// pageCursor is the position a page token encodes.
type pageCursor struct {
	OccurredUnix int64  `json:"u"`
	EventID      string `json:"e"`
}

func encodePageToken(c pageCursor) (string, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("encode page token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodePageToken(token string) (pageCursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return pageCursor{}, fmt.Errorf("not valid base64")
	}
	var c pageCursor
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return pageCursor{}, fmt.Errorf("not a valid cursor")
	}
	if c.EventID == "" {
		// A cursor with no event id has no position in the total order, so it
		// cannot be used without silently skipping or repeating rows.
		return pageCursor{}, fmt.Errorf("cursor has no event id")
	}
	return c, nil
}
