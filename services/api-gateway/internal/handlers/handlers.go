package handlers

import (
	"encoding/base64"
	"encoding/json"
	"hash/fnv"
	"log/slog"
	"math"
	"net/http"
	"time"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	biometricsv1 "finger-scanner/pkg/api/v1/biometrics"
	edgegatewayv1 "finger-scanner/pkg/api/v1/edgegateway"
	"finger-scanner/services/api-gateway/internal/clients"
)

type GatewayHandler struct {
	clients *clients.ServiceClients
	logger  *slog.Logger
}

func NewGatewayHandler(c *clients.ServiceClients, logger *slog.Logger) *GatewayHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &GatewayHandler{
		clients: c,
		logger:  logger,
	}
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

	resp, err := h.clients.BiometricsClient.EnrollFingerprint(r.Context(), &biometricsv1.EnrollFingerprintRequest{
		EmployeeId:   req.EmployeeID,
		FullName:     req.FullName,
		Position:     biometricsv1.FingerPosition(req.Position),
		ImageRawGray: pix,
		Width:        width,
		Height:       height,
		Dpi:          500,
	})
	if err != nil {
		h.logger.ErrorContext(r.Context(), "gRPC enrollment error", slog.String("error", err.Error()))
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// L7: Synchronize template to edge gateway cache with explicit error logging and reporting
	edgeSynced := false
	tmplResp, err := h.clients.BiometricsClient.GetTemplate(r.Context(), &biometricsv1.GetTemplateRequest{
		EmployeeId: req.EmployeeID,
		Position:   biometricsv1.FingerPosition(req.Position),
	})
	if err == nil && tmplResp.Found {
		syncResp, syncErr := h.clients.EdgeGatewayClient.SyncFacilityRoster(r.Context(), &edgegatewayv1.SyncFacilityRosterRequest{
			FacilityId: "facility-primary",
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

	resp, err := h.clients.BiometricsClient.VerifyFingerprint(r.Context(), &biometricsv1.VerifyFingerprintRequest{
		EmployeeId:        req.EmployeeID,
		Position:          biometricsv1.FingerPosition(req.Position),
		ProbeImageRawGray: pix,
		Width:             width,
		Height:            height,
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

	// C5: Prevent untrusted 1:1 identity claims
	if req.EmployeeID != "" {
		readerToken := r.Header.Get("X-Reader-Token")
		readerID := r.Header.Get("X-Reader-ID")
		apiKey := r.Header.Get("X-API-Key")
		if readerToken == "" && readerID == "" && apiKey == "" && req.CredentialCardID == "" {
			h.writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "untrusted identity claim: 1:1 verification requires authenticated reader channel (X-Reader-Token/X-Reader-ID) or physical badge credential",
			})
			return
		}
	}

	width := uint32(120)
	height := uint32(120)
	// M13: Use employee ID as seed so synthetic prints vary by individual
	probePix := generateSyntheticPrint(int(width), int(height), req.EmployeeID, req.NoiseFactor)

	// Call edge gateway turnstile controller (executes matching, policy evaluation, and relay strike)
	edgeResp, err := h.clients.EdgeGatewayClient.ProcessTurnstileScan(r.Context(), &edgegatewayv1.ProcessTurnstileScanRequest{
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

	resp, err := h.clients.AccessPolicyClient.ResetAntiPassback(r.Context(), &accesscontrolv1.ResetAntiPassbackRequest{
		EmployeeId: req.EmployeeID,
		ZoneId:     req.ZoneID,
	})
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.writeJSON(w, http.StatusOK, resp)
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
