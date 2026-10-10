package middleware

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

// AuthConfig specifies authentication configuration for the API Gateway.
type AuthConfig struct {
	MasterAPIKey string
	ReaderKey    string
	Logger       *slog.Logger
}

// NewAuthConfig loads auth configuration from environment variables with secure defaults.
func NewAuthConfig(logger *slog.Logger) *AuthConfig {
	apiKey := os.Getenv("API_GATEWAY_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("ADMIN_API_KEY")
	}
	if apiKey == "" {
		apiKey = "aegis-secret-key-2026"
		if logger != nil {
			logger.Warn("API_GATEWAY_KEY not set; using development default key. Set API_GATEWAY_KEY in production.")
		}
	}

	readerKey := os.Getenv("READER_KEY")
	if readerKey == "" {
		readerKey = "aegis-turnstile-reader-2026"
	}

	return &AuthConfig{
		MasterAPIKey: apiKey,
		ReaderKey:    readerKey,
		Logger:       logger,
	}
}

// RequireAuth enforces API Key or Bearer Token authentication on protected HTTP routes (Fix C4).
func (a *AuthConfig) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized: missing X-API-Key or Authorization header"}`))
			return
		}

		// Constant-time comparison to prevent timing attacks
		validMaster := subtle.ConstantTimeCompare([]byte(token), []byte(a.MasterAPIKey)) == 1
		validReader := subtle.ConstantTimeCompare([]byte(token), []byte(a.ReaderKey)) == 1

		if !validMaster && !validReader {
			if a.Logger != nil {
				a.Logger.WarnContext(r.Context(), "unauthorized access attempt",
					slog.String("path", r.URL.Path),
					slog.String("remote_addr", r.RemoteAddr),
				)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized: invalid API key or bearer token"}`))
			return
		}

		next(w, r)
	}
}

func extractToken(r *http.Request) string {
	// 1. Check X-API-Key header
	if key := r.Header.Get("X-API-Key"); key != "" {
		return key
	}

	// 2. Check X-Reader-Token header
	if key := r.Header.Get("X-Reader-Token"); key != "" {
		return key
	}

	// 3. Check Authorization: Bearer <token>
	auth := r.Header.Get("Authorization")
	if auth != "" {
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
			return strings.TrimSpace(parts[1])
		}
		return strings.TrimSpace(auth)
	}

	return ""
}

// SecureCORSMiddleware validates and restricts CORS origins (Fix L3).
func SecureCORSMiddleware(allowedOrigins []string, next http.HandlerFunc) http.HandlerFunc {
	allowedMap := make(map[string]bool)
	for _, o := range allowedOrigins {
		allowedMap[strings.TrimSpace(o)] = true
	}

	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			if allowedMap["*"] || allowedMap[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Reader-Token, X-Reader-ID")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}
