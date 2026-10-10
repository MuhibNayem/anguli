package middleware

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

const (
	testMaster = "master-key-for-tests"
	testReader = "reader-key-for-tests"
)

func newAuth() *AuthConfig {
	return &AuthConfig{MasterAPIKey: testMaster, ReaderKey: testReader, Logger: quiet()}
}

func call(t *testing.T, mw func(http.HandlerFunc) http.HandlerFunc, key string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/reset-apb", nil)
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}
	rec := httptest.NewRecorder()
	mw(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })(rec, req)
	return rec.Code
}

// TestRequireAdminRejectsReaderCredential is the privilege-separation assertion.
//
// The reader key sits on every turnstile in the building. Before this split,
// RequireAuth accepted it on every route, so anyone who could observe one
// reader could enroll their own fingerprint, revoke real employees, or reset
// anti-passback for anyone - and clearing anti-passback is a direct bypass of
// the tail-entry control.
func TestRequireAdminRejectsReaderCredential(t *testing.T) {
	a := newAuth()

	if got := call(t, a.RequireAdmin, testReader); got != http.StatusForbidden {
		t.Fatalf("reader key on an admin route = %d, want 403", got)
	}
	if got := call(t, a.RequireAdmin, testMaster); got != http.StatusOK {
		t.Fatalf("admin key on an admin route = %d, want 200", got)
	}
	if got := call(t, a.RequireAdmin, "wrong-key"); got != http.StatusForbidden {
		t.Fatalf("wrong key on an admin route = %d, want 403", got)
	}
	if got := call(t, a.RequireAdmin, ""); got != http.StatusUnauthorized {
		t.Fatalf("no credential on an admin route = %d, want 401", got)
	}
}

// TestRequireAuthStillAcceptsReaderCredential guards the other direction: door
// traffic must keep working with a reader credential, or every turnstile in a
// real deployment breaks.
func TestRequireAuthStillAcceptsReaderCredential(t *testing.T) {
	a := newAuth()

	if got := call(t, a.RequireAuth, testReader); got != http.StatusOK {
		t.Fatalf("reader key on a door route = %d, want 200", got)
	}
	if got := call(t, a.RequireAuth, testMaster); got != http.StatusOK {
		t.Fatalf("admin key on a door route = %d, want 200", got)
	}
	if got := call(t, a.RequireAuth, "wrong-key"); got != http.StatusUnauthorized {
		t.Fatalf("wrong key on a door route = %d, want 401", got)
	}
	if got := call(t, a.RequireAuth, ""); got != http.StatusUnauthorized {
		t.Fatalf("no credential on a door route = %d, want 401", got)
	}
}

// TestNewAuthConfigRefusesBuiltInCredentialsInProduction is the second half of
// the fix.
//
// The reader key defaulted to a constant published in this repository, with no
// warning at all, and no deployment configuration set it. Combined with the
// missing privilege separation, that constant granted administrative access to
// anyone who had read the source.
func TestNewAuthConfigRefusesBuiltInCredentialsInProduction(t *testing.T) {
	for _, tc := range []struct{ name, env string }{
		{"unset", ""},
		{"production", "production"},
		{"staging", "staging"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ENVIRONMENT", tc.env)
			t.Setenv("API_GATEWAY_KEY", "")
			t.Setenv("ADMIN_API_KEY", "")
			t.Setenv("READER_KEY", "")

			cfg, err := NewAuthConfig(quiet())
			if err == nil {
				t.Fatalf("NewAuthConfig accepted missing credentials in %q and returned %+v", tc.env, cfg)
			}
		})
	}
}

func TestNewAuthConfigAcceptsExplicitCredentials(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("API_GATEWAY_KEY", testMaster)
	t.Setenv("READER_KEY", testReader)

	cfg, err := NewAuthConfig(quiet())
	if err != nil {
		t.Fatalf("NewAuthConfig with both keys set: %v", err)
	}
	if cfg.MasterAPIKey != testMaster || cfg.ReaderKey != testReader {
		t.Fatalf("config = %+v, want the supplied keys", cfg)
	}
	if cfg.Development {
		t.Fatal("Development should be false in production")
	}
}

// TestNewAuthConfigAcceptsAdminAPIKeyAlias preserves the documented fallback.
func TestNewAuthConfigAcceptsAdminAPIKeyAlias(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("API_GATEWAY_KEY", "")
	t.Setenv("ADMIN_API_KEY", testMaster)
	t.Setenv("READER_KEY", testReader)

	cfg, err := NewAuthConfig(quiet())
	if err != nil {
		t.Fatalf("ADMIN_API_KEY alias: %v", err)
	}
	if cfg.MasterAPIKey != testMaster {
		t.Fatalf("MasterAPIKey = %q, want the ADMIN_API_KEY value", cfg.MasterAPIKey)
	}
}

// TestNewAuthConfigRefusesIdenticalKeys catches a misconfiguration that would
// silently collapse the privilege separation this file exists to provide.
func TestNewAuthConfigRefusesIdenticalKeys(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("API_GATEWAY_KEY", "same-value")
	t.Setenv("READER_KEY", "same-value")

	if _, err := NewAuthConfig(quiet()); err == nil {
		t.Fatal("NewAuthConfig accepted identical admin and reader keys; " +
			"that gives every turnstile administrative access")
	}
}

// TestNewAuthConfigAllowsDevelopmentDefaults keeps `docker compose up` working
// on a laptop without ceremony, which is the only place a published default is
// acceptable.
func TestNewAuthConfigAllowsDevelopmentDefaults(t *testing.T) {
	for _, env := range []string{"development", "dev", "DEVELOPMENT"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv("ENVIRONMENT", env)
			t.Setenv("API_GATEWAY_KEY", "")
			t.Setenv("ADMIN_API_KEY", "")
			t.Setenv("READER_KEY", "")

			cfg, err := NewAuthConfig(quiet())
			if err != nil {
				t.Fatalf("development mode should accept built-in credentials: %v", err)
			}
			if !cfg.Development {
				t.Fatal("Development should be true when built-in credentials were used")
			}
			if cfg.MasterAPIKey == cfg.ReaderKey {
				t.Fatal("development defaults must still differ from each other")
			}
		})
	}
}

// TestDevelopmentDefaultsAreDistinct guards the specific values that shipped
// before this fix, because they are in published git history and in every fork.
func TestDevelopmentDefaultsAreDistinct(t *testing.T) {
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("API_GATEWAY_KEY", "")
	t.Setenv("ADMIN_API_KEY", "")
	t.Setenv("READER_KEY", "")
	_ = os.Unsetenv("API_GATEWAY_KEY")

	cfg, err := NewAuthConfig(quiet())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MasterAPIKey == cfg.ReaderKey {
		t.Fatalf("built-in credentials must differ; both were %q", cfg.MasterAPIKey)
	}
}
