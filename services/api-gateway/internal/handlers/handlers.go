package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	biometricsv1 "finger-scanner/pkg/api/v1/biometrics"
	edgegatewayv1 "finger-scanner/pkg/api/v1/edgegateway"
	"finger-scanner/pkg/store"
	"finger-scanner/services/api-gateway/internal/clients"
)

type GatewayHandler struct {
	clients *clients.ServiceClients
	// breakers fronts every downstream RPC. When nil, calls pass straight
	// through, which keeps unit tests that build a handler directly working.
	breakers *clients.Breakers
	logger   *slog.Logger
	// facilityID names the facility this gateway serves, and is stamped on the
	// edge roster syncs it makes.
	//
	// It was previously the literal "facility-primary" in both call sites. A
	// field that exists in the API and is then discarded is worse than no field:
	// it reads as though facilities were distinguished when nothing distinguished
	// them. It comes from FACILITY_ID, which the stateful services also use to
	// claim the database, so one deployment's identity is consistent across the
	// whole system.
	facilityID string
}

func NewGatewayHandler(c *clients.ServiceClients, logger *slog.Logger) *GatewayHandler {
	return NewGatewayHandlerWithBreakers(c, nil, logger)
}

// NewGatewayHandlerWithBreakers builds a handler whose downstream calls are
// gated by per-dependency circuit breakers with jittered retries.
//
// A nil breakers value disables the gate rather than failing construction, so
// callers that genuinely have no dependencies wired can still use it.
func NewGatewayHandlerWithBreakers(c *clients.ServiceClients, b *clients.Breakers, logger *slog.Logger) *GatewayHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &GatewayHandler{
		clients:    c,
		breakers:   b,
		logger:     logger,
		facilityID: store.FacilityIDFromEnv(),
	}
}

// call runs one downstream RPC behind its circuit breaker.
//
// The breaker gate is consulted before the retry loop, so a dependency already
// known to be down is not contacted even once. Making this a helper rather
// than repeating the closure at each call site is what keeps the wiring honest:
// a new downstream call added later is either wrapped deliberately or visibly
// not wrapped, instead of silently bypassing protection.
func call[T any](ctx context.Context, h *GatewayHandler, w clients.WhichDownstream, fn func(context.Context) (T, error)) (T, error) {
	var zero T
	if h.breakers == nil {
		return fn(ctx)
	}
	var out T
	err := h.breakers.Call(ctx, w, func(c context.Context) error {
		var err error
		out, err = fn(c)
		return err
	})
	if err != nil {
		return zero, err
	}
	return out, nil
}

// EnrollRequest represents REST JSON payload for enrollment.
type EnrollRequest struct {
	EmployeeID  string `json:"employee_id"`
	FullName    string `json:"full_name"`
	Position    int32  `json:"position"`
	ImageBase64 string `json:"image_base64,omitempty"`
	Width       uint32 `json:"width,omitempty"`
	Height      uint32 `json:"height,omitempty"`
}

func (h *GatewayHandler) HandleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// L4: Bound incoming request body size to 10MB to prevent memory DoS attacks
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)

	var req EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json payload: " + err.Error()})
		return
	}

	if req.EmployeeID == "" {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "employee_id is required"})
		return
	}

	width := req.Width
	height := req.Height
	if width == 0 {
		width = 120
	}
	if height == 0 {
		height = 120
	}

	var pix []byte
	if req.ImageBase64 != "" {
		data, err := base64.StdEncoding.DecodeString(req.ImageBase64)
		if err != nil {
			h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid base64 image data"})
			return
		}
		pix = data
	} else {
		// M13: Generate distinct 500 DPI fingerprint structure seeded by employee identity
		pix = generateSyntheticPrint(int(width), int(height), req.EmployeeID, 0)
	}

	resp, err := call(r.Context(), h, clients.DownstreamBiometrics,
		func(ctx context.Context) (*biometricsv1.EnrollFingerprintResponse, error) {
			return h.clients.BiometricsClient.EnrollFingerprint(ctx, &biometricsv1.EnrollFingerprintRequest{
				EmployeeId:   req.EmployeeID,
				FullName:     req.FullName,
				Position:     biometricsv1.FingerPosition(req.Position),
				ImageRawGray: pix,
				Width:        width,
				Height:       height,
				Dpi:          500,
			})
		})
	if err != nil {
		h.logger.ErrorContext(r.Context(), "gRPC enrollment error", slog.String("error", err.Error()))
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// L7: Synchronize template to edge gateway cache with explicit error logging and reporting
	edgeSynced := false
	tmplResp, err := call(r.Context(), h, clients.DownstreamBiometrics,
		func(ctx context.Context) (*biometricsv1.GetTemplateResponse, error) {
			return h.clients.BiometricsClient.GetTemplate(ctx, &biometricsv1.GetTemplateRequest{
				EmployeeId: req.EmployeeID,
				Position:   biometricsv1.FingerPosition(req.Position),
			})
		})
	if err == nil && tmplResp.Found {
		syncResp, syncErr := call(r.Context(), h, clients.DownstreamEdge,
			func(ctx context.Context) (*edgegatewayv1.SyncFacilityRosterResponse, error) {
				return h.clients.EdgeGatewayClient.SyncFacilityRoster(ctx, &edgegatewayv1.SyncFacilityRosterRequest{
					FacilityId: h.facilityID,
					Items: []*edgegatewayv1.SyncEmployeeItem{
						{
							EmployeeId: req.EmployeeID,
							FullName:   req.FullName,
							Role:       "EMPLOYEE",
							Position:   biometricsv1.FingerPosition(req.Position),
							Minutiae:   tmplResp.Template.Minutiae,
							IsActive:   true,
						},
					},
				})
			})
		if syncErr != nil {
			h.logger.WarnContext(r.Context(), "edge gateway roster sync failed during enrollment",
				slog.String("employee_id", req.EmployeeID),
				slog.String("error", syncErr.Error()),
			)
		} else if syncResp != nil && syncResp.Success {
			edgeSynced = true
		}
	}

	h.writeJSON(w, http.StatusOK, map[string]any{
		"template_id":           resp.TemplateId,
		"employee_id":           resp.EmployeeId,
		"nfiq_quality_score":    resp.NfiqQualityScore,
		"is_quality_acceptable": resp.IsQualityAcceptable,
		"minutiae_count":        resp.MinutiaeCount,
		"edge_synced":           edgeSynced,
		"message":               resp.Message,
		"processing_time_us":    resp.ProcessingTimeUs,
	})
}

// VerifyRequest represents 1:1 match request.
type VerifyRequest struct {
	EmployeeID  string `json:"employee_id"`
	Position    int32  `json:"position"`
	ImageBase64 string `json:"image_base64,omitempty"`
	Width       uint32 `json:"width,omitempty"`
	Height      uint32 `json:"height,omitempty"`
	NoiseFactor int    `json:"noise_factor,omitempty"` // For interactive simulation
}

func (h *GatewayHandler) HandleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// L4: Bound incoming body size
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}

	// L9: Support user-supplied dimensions with consistent 120x120 fallback
	width := req.Width
	height := req.Height
	if width == 0 {
		width = 120
	}
	if height == 0 {
		height = 120
	}

	var pix []byte
	if req.ImageBase64 != "" {
		data, err := base64.StdEncoding.DecodeString(req.ImageBase64)
		if err != nil {
			h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid base64 image data"})
			return
		}
		pix = data
	} else {
		// M13: Use employee ID seed to generate matching genuine structure
		pix = generateSyntheticPrint(int(width), int(height), req.EmployeeID, req.NoiseFactor)
	}

	resp, err := call(r.Context(), h, clients.DownstreamBiometrics,
		func(ctx context.Context) (*biometricsv1.VerifyFingerprintResponse, error) {
			return h.clients.BiometricsClient.VerifyFingerprint(ctx, &biometricsv1.VerifyFingerprintRequest{
				EmployeeId:        req.EmployeeID,
				Position:          biometricsv1.FingerPosition(req.Position),
				ProbeImageRawGray: pix,
				Width:             width,
				Height:            height,
			})
		})
	if err != nil {
		h.writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]any{
		"is_match":           resp.IsMatch,
		"score":              resp.Score,
		"matched_cylinders":  resp.MatchedCylinders,
		"nfiq_quality_score": resp.NfiqQualityScore,
		"matching_time_us":   resp.MatchingTimeUs,
		"reason":             resp.Reason,
	})
}

// DoorScanRequest simulates a turnstile doorstep swipe.
type DoorScanRequest struct {
	TurnstileID      string `json:"turnstile_id"`
	ZoneID           string `json:"zone_id"`
	Direction        int32  `json:"direction"` // 1 = Entry, 2 = Exit
	EmployeeID       string `json:"employee_id,omitempty"`
	CredentialCardID string `json:"credential_card_id,omitempty"`
	NoiseFactor      int    `json:"noise_factor,omitempty"`
}

func (h *GatewayHandler) HandleDoorScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// L4: Bound incoming request body size
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)

	var req DoorScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}

	if req.TurnstileID == "" {
		req.TurnstileID = "turnstile-lane-01"
	}
	if req.ZoneID == "" {
		req.ZoneID = "zone-main-gate"
	}
	if req.Direction == 0 {
		req.Direction = 1 // Entry
	}

	// C5: Prevent untrusted 1:1 identity claims.
	//
	// Only a HEADER can authenticate the reader channel. A header sent as
	// "X-Reader-Token:   " is not a credential, so each value is trimmed before
	// it is compared against ""; comparing the raw value let a whitespace-only
	// header satisfy this gate, which is the entire control it exists to
	// enforce.
	//
	// Deliberately NOT part of this check: req.CredentialCardID. That field is
	// decoded from the request body, which is caller-controlled, so counting it
	// as a credential lets any caller post
	//     {"employee_id":"...","credential_card_id":"anything"}
	// and satisfy the gate without ever proving the request came from real
	// hardware. The badge value stays in the body because it is the identity
	// CLAIM; the reader-channel header is what makes that claim trustworthy.
	if req.EmployeeID != "" {
		readerToken := strings.TrimSpace(r.Header.Get("X-Reader-Token"))
		readerID := strings.TrimSpace(r.Header.Get("X-Reader-ID"))
		apiKey := strings.TrimSpace(r.Header.Get("X-API-Key"))
		if readerToken == "" && readerID == "" && apiKey == "" {
			h.writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "untrusted identity claim: 1:1 verification requires an authenticated reader channel (X-Reader-Token, X-Reader-ID or X-API-Key)",
			})
			return
		}
	}

	width := uint32(120)
	height := uint32(120)
	// M13: Use employee ID as seed so synthetic prints vary by individual
	probePix := generateSyntheticPrint(int(width), int(height), req.EmployeeID, req.NoiseFactor)

	// Call edge gateway turnstile controller (executes matching, policy evaluation, and relay strike)
	edgeResp, err := call(r.Context(), h, clients.DownstreamEdge,
		func(ctx context.Context) (*edgegatewayv1.ProcessTurnstileScanResponse, error) {
			return h.clients.EdgeGatewayClient.ProcessTurnstileScan(ctx, &edgegatewayv1.ProcessTurnstileScanRequest{
				TurnstileId:       req.TurnstileID,
				ZoneId:            req.ZoneID,
				Direction:         accesscontrolv1.DoorDirection(req.Direction),
				EmployeeId:        req.EmployeeID,
				CredentialCardId:  req.CredentialCardID,
				ProbeImageRawGray: probePix,
				ImageWidth:        width,
				ImageHeight:       height,
				ScanTimestampUnix: time.Now().Unix(),
			})
		})
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "edge gateway scan error: " + err.Error()})
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]any{
		"is_access_granted":        edgeResp.IsAccessGranted,
		"decision":                 edgeResp.Decision.String(),
		"matched_employee_id":      edgeResp.MatchedEmployeeId,
		"match_score":              edgeResp.MatchScore,
		"reason":                   edgeResp.Reason,
		"relay_strike_duration_ms": edgeResp.RelayStrikeDurationMs,
		"total_latency_ms":         edgeResp.TotalLatencyMs,
		"processed_offline":        edgeResp.ProcessedOffline,
	})
}

func (h *GatewayHandler) HandleDoorStatus(w http.ResponseWriter, r *http.Request) {
	turnstileID := r.URL.Query().Get("turnstile_id")
	if turnstileID == "" {
		turnstileID = "turnstile-lane-01"
	}

	resp, err := h.clients.EdgeGatewayClient.GetTurnstileStatus(r.Context(), &edgegatewayv1.GetTurnstileStatusRequest{
		TurnstileId: turnstileID,
	})
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.writeJSON(w, http.StatusOK, resp.Status)
}

func (h *GatewayHandler) HandleResetAPB(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// L4: Bound body size
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)

	var req struct {
		EmployeeID string `json:"employee_id"`
		ZoneID     string `json:"zone_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	resp, err := call(r.Context(), h, clients.DownstreamPolicy,
		func(ctx context.Context) (*accesscontrolv1.ResetAntiPassbackResponse, error) {
			return h.clients.AccessPolicyClient.ResetAntiPassback(ctx, &accesscontrolv1.ResetAntiPassbackRequest{
				EmployeeId: req.EmployeeID,
				ZoneId:     req.ZoneID,
			})
		})
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// HandleQueryAccessEvents exposes the central access audit trail to operators.
//
// Admin-only, not reader: the trail enumerates who entered which door and when,
// across the whole estate. A turnstile credential can grant itself entry; it must
// not be able to read the movement history of everyone.
func (h *GatewayHandler) HandleQueryAccessEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	req := &accesscontrolv1.QueryAccessEventsRequest{
		EmployeeId:  q.Get("employee_id"),
		ZoneId:      q.Get("zone_id"),
		TurnstileId: q.Get("turnstile_id"),
		PageToken:   q.Get("page_token"),
	}
	var err error
	if req.FromUnix, err = optionalUnix(q.Get("from_unix")); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "from_unix must be a whole number of seconds"})
		return
	}
	if req.ToUnix, err = optionalUnix(q.Get("to_unix")); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "to_unix must be a whole number of seconds"})
		return
	}
	switch q.Get("outcome") {
	case "":
	case "granted":
		req.Outcome = accesscontrolv1.AccessEventOutcome_ACCESS_EVENT_OUTCOME_GRANTED
	case "denied":
		req.Outcome = accesscontrolv1.AccessEventOutcome_ACCESS_EVENT_OUTCOME_DENIED
	default:
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "outcome must be one of granted, denied"})
		return
	}
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be a non-negative integer"})
			return
		}
		req.Limit = uint32(n)
	}

	resp, err := call(r.Context(), h, clients.DownstreamPolicy,
		func(ctx context.Context) (*accesscontrolv1.QueryAccessEventsResponse, error) {
			return h.clients.AccessPolicyClient.QueryAccessEvents(ctx, req)
		})
	if err != nil {
		h.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	// Rendered as plain JSON objects rather than protojson so the wire shape is
	// stable for an operator's tooling; the proto field names are snake_case
	// already, so the mapping is mechanical.
	type event struct {
		EventID          string `json:"event_id"`
		TurnstileID      string `json:"turnstile_id"`
		EmployeeID       string `json:"employee_id"`
		ZoneID           string `json:"zone_id"`
		Decision         string `json:"decision"`
		AccessGranted    bool   `json:"access_granted"`
		ProcessedOffline bool   `json:"processed_offline"`
		OccurredUnix     int64  `json:"occurred_unix"`
	}
	out := make([]event, 0, len(resp.GetEvents()))
	for _, e := range resp.GetEvents() {
		out = append(out, event{
			EventID:          e.GetEventId(),
			TurnstileID:      e.GetTurnstileId(),
			EmployeeID:       e.GetEmployeeId(),
			ZoneID:           e.GetZoneId(),
			Decision:         e.GetDecision(),
			AccessGranted:    e.GetAccessGranted(),
			ProcessedOffline: e.GetProcessedOffline(),
			OccurredUnix:     e.GetOccurredUnix(),
		})
	}
	h.writeJSON(w, http.StatusOK, map[string]any{
		"events":          out,
		"next_page_token": resp.GetNextPageToken(),
	})
}

// optionalUnix parses an optional epoch-seconds parameter. An empty value means
// unbounded rather than zero, so "no filter" and "since 1970" stay distinct.
//
// A negative value is rejected rather than passed on. Downstream, a non-positive
// bound means "unbounded", so -5 would be read as no filter at all: an operator
// who mistypes a date would get the entire trail back and draw a conclusion from
// it. Rejecting is the only safe reading.
func optionalUnix(raw string) (int64, error) {
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, fmt.Errorf("must not be negative")
	}
	return n, nil
}

// HandleHealthz performs live end-to-end health checks against downstream gRPC microservices (Fix L1).
func (h *GatewayHandler) HandleHealthz(w http.ResponseWriter, r *http.Request) {
	statuses, healthy := h.clients.CheckHealth(r.Context())

	statusCode := http.StatusOK
	statusStr := "UP"
	if !healthy {
		statusCode = http.StatusServiceUnavailable
		statusStr = "DEGRADED"
	}

	h.writeJSON(w, statusCode, map[string]any{
		"status":    statusStr,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"services":  statuses,
	})
}

func (h *GatewayHandler) writeJSON(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(data)
}

// generateSyntheticPrint creates a realistic 500 DPI synthetic fingerprint pattern with core loops, arches, and forks, seeded by employee ID (Fix M13).
func generateSyntheticPrint(w, h int, seed string, noiseFactor int) []byte {
	pix := make([]byte, w*h)
	for i := range pix {
		pix[i] = 210
	}

	hHasher := fnv.New32a()
	if seed == "" {
		seed = "default-seed"
	}
	_, _ = hHasher.Write([]byte(seed))
	seedHash := hHasher.Sum32()

	// Unique parameters per seed
	freqMod := 0.8 + float64(seedHash%20)/50.0
	phaseMod := float64(seedHash%100) / 10.0
	centerX := float64(w)/2.0 + float64(int(seedHash%9)-4)
	centerY := float64(h)/2.0 + float64(int((seedHash>>4)%9)-4)

	// Draw concentric elliptical sinusoidal ridge flow simulating loop/whorl fingerprint patterns
	for y := 10; y < h-10; y++ {
		for x := 10; x < w-10; x++ {
			dx := float64(x) - centerX
			dy := (float64(y) - centerY) * 1.3

			r := math.Sqrt(dx*dx + dy*dy)
			// True sinusoidal wave: 0 to 1
			sinVal := 0.5 * (1.0 + math.Sin(r*freqMod+phaseMod))
			val := int(80.0 + 130.0*sinVal)

			if noiseFactor > 0 {
				val += (x*y*noiseFactor)%30 - 15
			}
			if val < 30 {
				val = 30
			} else if val > 240 {
				val = 240
			}
			pix[y*w+x] = byte(val)
		}
	}
	return pix
}

// RevokeRequest identifies a single enrolled finger to revoke.
type RevokeRequest struct {
	EmployeeID string `json:"employee_id"`
	Position   int32  `json:"position"`
	Reason     string `json:"reason,omitempty"`
}

// HandleRevokeTemplate is the offboarding control.
//
// Until this route existed, the platform could add people but never remove
// them: the repository had a revoked flag and an audit table, no service
// operation could set them, and no route could reach the service. A terminated
// employee's fingerprint therefore kept opening doors - centrally and at every
// edge node, which is a cache the platform owns and cannot remotely recall on
// demand.
//
// The edge is told explicitly, because revoking centrally is not sufficient on
// its own: an edge that has never been told will keep serving a template it
// cached at enrollment. A failure to propagate is reported rather than
// swallowed, so the operator learns the offboarding is incomplete instead of
// assuming it worked.
func (h *GatewayHandler) HandleRevokeTemplate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req RevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}
	if req.EmployeeID == "" {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "employee_id is required"})
		return
	}
	if strings.TrimSpace(req.Reason) == "" {
		// An unlabelled revocation is still recorded as UNSPECIFIED rather
		// than refused. Refusing here would leave the employee enrolled, which
		// is a far worse outcome than a vague audit reason.
		req.Reason = "UNSPECIFIED"
	}

	resp, err := call(r.Context(), h, clients.DownstreamBiometrics,
		func(ctx context.Context) (*biometricsv1.RevokeFingerprintResponse, error) {
			return h.clients.BiometricsClient.RevokeFingerprint(ctx, &biometricsv1.RevokeFingerprintRequest{
				EmployeeId: req.EmployeeID,
				Position:   biometricsv1.FingerPosition(req.Position),
				Reason:     req.Reason,
			})
		})
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// Tell the edge to drop them. This runs after the central revoke succeeds,
	// so a failure here leaves the person denied centrally but still cached at
	// the edge - reported, not hidden.
	edgeSynced := false
	syncResp, syncErr := call(r.Context(), h, clients.DownstreamEdge,
		func(ctx context.Context) (*edgegatewayv1.SyncFacilityRosterResponse, error) {
			return h.clients.EdgeGatewayClient.SyncFacilityRoster(ctx, &edgegatewayv1.SyncFacilityRosterRequest{
				FacilityId: h.facilityID,
				Items: []*edgegatewayv1.SyncEmployeeItem{{
					EmployeeId: req.EmployeeID,
					Position:   biometricsv1.FingerPosition(req.Position),
					IsActive:   false,
				}},
			})
		})
	if syncErr != nil {
		h.logger.ErrorContext(r.Context(), "edge roster purge failed during revocation; "+
			"the edge may still match this employee",
			slog.String("employee_id", req.EmployeeID),
			slog.String("error", syncErr.Error()),
		)
	} else if syncResp != nil && syncResp.Success {
		edgeSynced = true
	}

	h.writeJSON(w, http.StatusOK, map[string]any{
		"employee_id":  req.EmployeeID,
		"revoked":      resp.Revoked,
		"reason":       req.Reason,
		"edge_synced":  edgeSynced,
		"already_gone": !resp.Revoked,
	})
}
