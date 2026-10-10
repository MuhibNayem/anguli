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

	// PreviousMasterAPIKey and PreviousReaderKey are the credentials being
	// retired. While set they are accepted as well as the current ones.
	//
	// They exist because the alternative locks the building. A turnstile is a
	// physical device bolted to a door: rotating its credential means touching
	// every reader, one at a time, and the gateway cannot be told "the new key
	// is live" until they are all done. Without an overlap, restarting the
	// gateway on a new key returns 401 to every door still holding the old one.
	//
	// They must be unset once the rollout is complete. A previous credential
	// left behind is a live credential with no owner keeping track of it.
	PreviousMasterAPIKey string
	PreviousReaderKey    string

	// Development reports whether insecure built-in credentials were accepted.
	// It exists so the caller can log the fact once, loudly, at startup.
	Development bool
}

// overlapActive reports whether a retiring credential is still accepted.
func (a *AuthConfig) overlapActive() bool {
	return a.PreviousMasterAPIKey != "" || a.PreviousReaderKey != ""
}

// credentialMatches compares a presented token against a secret in constant
// time.
//
// An empty secret must never match, including when the token is also empty -
// which is why the length check is first rather than relying on
// ConstantTimeCompare's behaviour with empty inputs.
func credentialMatches(token, secret string) bool {
	if secret == "" || token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(secret)) == 1
}

// isAdmin reports whether a token carries administrative authority, accepting
// either the current or the retiring admin credential.
func (a *AuthConfig) isAdmin(token string) bool {
	return credentialMatches(token, a.MasterAPIKey) ||
		credentialMatches(token, a.PreviousMasterAPIKey)
}

// isReader reports whether a token is a reader credential, current or retiring.
func (a *AuthConfig) isReader(token string) bool {
	return credentialMatches(token, a.ReaderKey) ||
		credentialMatches(token, a.PreviousReaderKey)
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

	prevAPI := strings.TrimSpace(os.Getenv("API_GATEWAY_KEY_PREVIOUS"))
	prevReader := strings.TrimSpace(os.Getenv("READER_KEY_PREVIOUS"))

	// The overlap must not undo the privilege separation it exists to preserve.
	// These are the combinations that would quietly turn a reader credential
	// into an administrative one, which is the exact vulnerability the split
	// above removed.
	collisions := []struct {
		what       string
		a, b       string
		aEnv, bEnv string
	}{
		{
			what: "API_GATEWAY_KEY_PREVIOUS", a: prevAPI, b: readerKey,
			aEnv: "API_GATEWAY_KEY_PREVIOUS", bEnv: "READER_KEY",
		},
		{
			what: "READER_KEY_PREVIOUS", a: prevReader, b: apiKey,
			aEnv: "READER_KEY_PREVIOUS", bEnv: "API_GATEWAY_KEY",
		},
		{
			what: "READER_KEY_PREVIOUS", a: prevReader, b: prevAPI,
			aEnv: "READER_KEY_PREVIOUS", bEnv: "API_GATEWAY_KEY_PREVIOUS",
		},
		{
			what: "READER_KEY_PREVIOUS", a: prevReader, b: readerKey,
			aEnv: "READER_KEY_PREVIOUS", bEnv: "READER_KEY",
		},
	}
	for _, c := range collisions {
		if c.a == "" {
			continue
		}
		if c.a == c.b {
			return nil, fmt.Errorf(
				"gateway: %s must not equal %s; a retiring credential that matches a live "+
					"one grants the privilege of the live credential, so a turnstile could "+
					"authenticate as an administrator during the rotation window",
				c.aEnv, c.bEnv)
		}
	}
	if prevAPI != "" && prevAPI == apiKey {
		return nil, errors.New(
			"gateway: API_GATEWAY_KEY_PREVIOUS is identical to API_GATEWAY_KEY; " +
				"nothing is being retired, so the overlap serves no purpose")
	}

	cfg := &AuthConfig{
		MasterAPIKey: apiKey,
		ReaderKey:    readerKey,
		Logger:       logger,
		Development:  isDev,
	}
	if prevAPI != "" {
		cfg.PreviousMasterAPIKey = prevAPI
	}
	if prevReader != "" {
		cfg.PreviousReaderKey = prevReader
	}

	if cfg.overlapActive() && logger != nil {
		// Loud, because the failure mode of forgetting is silent: the retiring
		// credential keeps working for as long as nobody notices, and the reason
		// it was retired is exactly the thing an operator needs to remember.
		logger.Warn("CREDENTIAL ROTATION IN PROGRESS: the previous credential is still accepted. "+
			"Unset API_GATEWAY_KEY_PREVIOUS and READER_KEY_PREVIOUS once every turnstile and "+
			"client has been updated, otherwise a retired credential stays valid indefinitely.",
			slog.Bool("previous_admin_key_accepted", cfg.PreviousMasterAPIKey != ""),
			slog.Bool("previous_reader_key_accepted", cfg.PreviousReaderKey != ""))
	}

	return cfg, nil
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

		// Constant-time comparison throughout, to prevent timing attacks.
		if !a.isAdmin(token) {
			// A reader credential is a real credential, but it is not an
			// administrative one. Check it only when it would actually pass, so
			// an admin-only route does not spend comparisons on it - and so the
			// rejection reason is unambiguous.
			validReader := !adminOnly && a.isReader(token)
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
