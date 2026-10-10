package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"finger-scanner/services/api-gateway/internal/middleware"
)

func TestAuthMiddleware(t *testing.T) {
	authConfig := &middleware.AuthConfig{
		MasterAPIKey: "test-secret-key-12345",
		ReaderKey:    "test-reader-key-54321",
	}

	handler := authConfig.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// 1. Missing authentication -> 401 Unauthorized (Fix C4)
	reqNoAuth := httptest.NewRequest(http.MethodPost, "/api/v1/doors/scan", nil)
	recNoAuth := httptest.NewRecorder()
	handler.ServeHTTP(recNoAuth, reqNoAuth)
	if recNoAuth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing auth, got %d", recNoAuth.Code)
	}

	// 2. Invalid API key -> 401 Unauthorized
	reqInvalid := httptest.NewRequest(http.MethodPost, "/api/v1/doors/scan", nil)
	reqInvalid.Header.Set("X-API-Key", "wrong-key")
	recInvalid := httptest.NewRecorder()
	handler.ServeHTTP(recInvalid, reqInvalid)
	if recInvalid.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid auth, got %d", recInvalid.Code)
	}

	// 3. Valid X-API-Key -> 200 OK
	reqValidAPI := httptest.NewRequest(http.MethodPost, "/api/v1/doors/scan", nil)
	reqValidAPI.Header.Set("X-API-Key", "test-secret-key-12345")
	recValidAPI := httptest.NewRecorder()
	handler.ServeHTTP(recValidAPI, reqValidAPI)
	if recValidAPI.Code != http.StatusOK {
		t.Errorf("expected 200 for valid API key, got %d", recValidAPI.Code)
	}

	// 4. Valid Bearer Token -> 200 OK
	reqValidBearer := httptest.NewRequest(http.MethodPost, "/api/v1/doors/scan", nil)
	reqValidBearer.Header.Set("Authorization", "Bearer test-secret-key-12345")
	recValidBearer := httptest.NewRecorder()
	handler.ServeHTTP(recValidBearer, reqValidBearer)
	if recValidBearer.Code != http.StatusOK {
		t.Errorf("expected 200 for valid Bearer token, got %d", recValidBearer.Code)
	}

	// 5. Valid Reader Key -> 200 OK (Fix C5)
	reqValidReader := httptest.NewRequest(http.MethodPost, "/api/v1/doors/scan", nil)
	reqValidReader.Header.Set("X-Reader-Token", "test-reader-key-54321")
	recValidReader := httptest.NewRecorder()
	handler.ServeHTTP(recValidReader, reqValidReader)
	if recValidReader.Code != http.StatusOK {
		t.Errorf("expected 200 for valid Reader key, got %d", recValidReader.Code)
	}
}

func TestSecureCORSMiddleware(t *testing.T) {
	allowed := []string{"http://localhost:8080", "https://corp.biometrics.internal"}
	handler := middleware.SecureCORSMiddleware(allowed, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// 1. Allowed origin reflected
	reqAllowed := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	reqAllowed.Header.Set("Origin", "https://corp.biometrics.internal")
	recAllowed := httptest.NewRecorder()
	handler.ServeHTTP(recAllowed, reqAllowed)
	if recAllowed.Header().Get("Access-Control-Allow-Origin") != "https://corp.biometrics.internal" {
		t.Errorf("expected origin to be reflected, got %s", recAllowed.Header().Get("Access-Control-Allow-Origin"))
	}

	// 2. Disallowed origin NOT reflected (Fix L3)
	reqDisallowed := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	reqDisallowed.Header.Set("Origin", "http://evil-attacker-site.com")
	recDisallowed := httptest.NewRecorder()
	handler.ServeHTTP(recDisallowed, reqDisallowed)
	if recDisallowed.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("expected origin to be blocked, got %s", recDisallowed.Header().Get("Access-Control-Allow-Origin"))
	}
}
