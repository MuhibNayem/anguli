package middleware

import (
	"crypto/subtle"
	"errors"
	"fmt"
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

	// Development reports whether insecure built-in credentials were accepted.
	// It exists so the caller can log the fact once, loudly, at startup.
	Development bool
}

// ErrInsecureCredentials is returned when production has no credentials
// configured.
//
// This is an error rather than a fallback. The previous behaviour was to
// substitute a key that is published in this repository, which meant any
// deployment that forgot to set the variable ran with a publicly-known
// credential - and, because the reader key was accepted on every route,
// that credential could enroll employees, revoke employees and reset
// anti-passback. A secret that is in the source code is not a secret.
var ErrInsecureCredentials = errors.New(
	"gateway: API_GATEWAY_KEY and READER_KEY must be set unless ENVIRONMENT is development")

// NewAuthConfig loads auth configuration from environment variables.
//
// Outside development, a missing key is fatal. Development keeps the built-in
// values so `docker compose up` still works without ceremony, but says so
// loudly, because the whole point is that the operator must not be surprised.
func NewAuthConfig(logger *slog.Logger) (*AuthConfig, error) {
	env := strings.ToLower(strings.TrimSpace(os.Getenv("ENVIRONMENT")))
	isDev := env == "development" || env == "dev"

	apiKey := os.Getenv("API_GATEWAY_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("ADMIN_API_KEY")
	}
	readerKey := os.Getenv("READER_KEY")

	if apiKey == "" || readerKey == "" {
		if !isDev {
			return nil, fmt.Errorf("%w (API_GATEWAY_KEY set: %t, READER_KEY set: %t, ENVIRONMENT=%q)",
				ErrInsecureCredentials, apiKey != "", readerKey != "", env)
		}
		if logger != nil {
			logger.Warn("running with BUILT-IN DEVELOPMENT CREDENTIALS; " +
				"these values are published in the source repository and grant " +
				"administrative access. Never do this outside a laptop.")
		}
		if apiKey == "" {
			apiKey = "aegis-secret-key-2026"
		}
		if readerKey == "" {
			readerKey = "aegis-turnstile-reader-2026"
		}
	}

	if apiKey == readerKey {
		// A shared value between the admin and reader credentials collapses
		// the privilege separation this file exists to provide, and does it
		// silently. Refuse rather than pretend.
		return nil, errors.New(
			"gateway: API_GATEWAY_KEY and READER_KEY must differ; sharing one value " +
				"gives every turnstile administrative access")
	}

	return &AuthConfig{
		MasterAPIKey: apiKey,
		ReaderKey:    readerKey,
		Logger:       logger,
		Development:  isDev,
	}, nil
}

// RequireAuth enforces API Key or Bearer Token authentication on protected
// HTTP routes. It accepts either the admin key or the reader key, so it is
// appropriate for door traffic and nothing else.
func (a *AuthConfig) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return a.require(next, false)
}

// RequireAdmin accepts the administrator key only.
//
// It exists because RequireAuth accepts both credentials, and the reader key
// sits on every turnstile in the building. Without a distinction, anyone who
// could observe one reader could enroll their own fingerprint, revoke real
// employees, or clear anti-passback for anyone - and clearing anti-passback is
// a direct bypass of the tail-entry control.
//
// Operations that grant, revoke or reset must use this. Operations that answer
// a scan use RequireAuth.
func (a *AuthConfig) RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return a.require(next, true)
}

func (a *AuthConfig) require(next http.HandlerFunc, adminOnly bool) http.HandlerFunc {
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

		if !validMaster {
			// A reader credential is a real credential, but it is not an
			// administrative one. Check it only when it would actually pass,
			// so an admin-only route does not spend a comparison on it - and
			// so the rejection reason is unambiguous.
			validReader := !adminOnly &&
				subtle.ConstantTimeCompare([]byte(token), []byte(a.ReaderKey)) == 1
			if !validReader {
				if a.Logger != nil {
					a.Logger.WarnContext(r.Context(), "unauthorized access attempt",
						slog.String("path", r.URL.Path),
						slog.String("remote_addr", r.RemoteAddr),
						slog.Bool("admin_only", adminOnly),
					)
				}
				w.Header().Set("Content-Type", "application/json")
				if adminOnly {
					// 403, not 401: the caller authenticated successfully and
					// still is not allowed. Reporting 401 would invite a retry
					// loop with the same credential.
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`{"error":"forbidden: this operation requires the administrator key"}`))
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"unauthorized: invalid API key or bearer token"}`))
				return
			}
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
