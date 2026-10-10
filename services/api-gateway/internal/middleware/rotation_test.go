package middleware

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

// configureAuth builds a config from a specific environment, which is how a
// rotation is actually expressed to the process.
func configureAuth(t *testing.T, env map[string]string) (*AuthConfig, error) {
	t.Helper()
	for k, v := range env {
		t.Setenv(k, v)
	}
	return NewAuthConfig(quiet())
}

const (
	rotCurrentAdmin  = "admin-key-current"
	rotCurrentReader = "reader-key-current"
	rotOldAdmin      = "admin-key-retiring"
	rotOldReader     = "reader-key-retiring"
)

func rotEnv() map[string]string {
	return map[string]string{
		"ENVIRONMENT":              "production",
		"API_GATEWAY_KEY":          rotCurrentAdmin,
		"READER_KEY":               rotCurrentReader,
		"API_GATEWAY_KEY_PREVIOUS": rotOldAdmin,
		"READER_KEY_PREVIOUS":      rotOldReader,
	}
}

// TestRotationAcceptsBothOldAndNewCredentials is the whole point.
//
// A turnstile is bolted to a door. Rotating its credential means physically
// updating every reader, and the gateway cannot be told the new key is live
// until they are all done. Without an overlap, restarting on a new key returns
// 401 to every door still holding the old one: a building-wide lockout created
// by a routine security procedure.
func TestRotationAcceptsBothOldAndNewCredentials(t *testing.T) {
	cfg, err := configureAuth(t, rotEnv())
	if err != nil {
		t.Fatalf("a legitimate rotation was refused: %v", err)
	}
	if !cfg.overlapActive() {
		t.Fatal("overlapActive is false with both previous keys configured")
	}

	// Door routes accept both generations of reader key.
	for _, key := range []string{rotCurrentReader, rotOldReader} {
		if got := call(t, cfg.RequireAuth, key); got != http.StatusOK {
			t.Errorf("RequireAuth with %q = %d, want 200; a turnstile would be locked out mid-rotation", key, got)
		}
	}
	// Admin routes accept both generations of admin key.
	for _, key := range []string{rotCurrentAdmin, rotOldAdmin} {
		if got := call(t, cfg.RequireAdmin, key); got != http.StatusOK {
			t.Errorf("RequireAdmin with %q = %d, want 200", key, got)
		}
	}
}

// TestRotationDoesNotGrantReaderCredentialsAdminAccess is the invariant that
// makes the overlap safe, and the reason the collision checks exist.
//
// During the window four credentials are live. If a reader credential is ever
// accepted on an admin route, the privilege separation this package was built
// to restore is silently undone for the duration of a routine maintenance task.
func TestRotationDoesNotGrantReaderCredentialsAdminAccess(t *testing.T) {
	cfg, err := configureAuth(t, rotEnv())
	if err != nil {
		t.Fatal(err)
	}

	// Neither generation of reader credential may enrol, revoke or reset APB.
	for _, key := range []string{rotCurrentReader, rotOldReader} {
		if got := call(t, cfg.RequireAdmin, key); got != http.StatusForbidden {
			t.Errorf("RequireAdmin with reader key %q = %d, want 403", key, got)
		}
	}
}

// TestRotationRejectsCollisionsThatWouldEscalatePrivilege covers the ways the
// overlap can be configured by accident into a privilege escalation.
//
// Each case is a configuration where a credential that should be a reader is
// equal to one that should be admin. Accepting it would let anyone holding a
// turnstile enrol a fingerprint or clear anti-passback.
func TestRotationRejectsCollisionsThatWouldEscalatePrivilege(t *testing.T) {
	cases := map[string]map[string]string{
		"retiring admin equals the live reader key": {
			"API_GATEWAY_KEY_PREVIOUS": rotCurrentReader,
		},
		"retiring reader equals the live admin key": {
			"READER_KEY_PREVIOUS": rotCurrentAdmin,
		},
		"the two retiring keys are the same": {
			"READER_KEY_PREVIOUS": rotOldAdmin,
		},
		"retiring reader equals the live reader key": {
			"READER_KEY_PREVIOUS": rotCurrentReader,
		},
	}

	for name, override := range cases {
		t.Run(name, func(t *testing.T) {
			env := rotEnv()
			for k, v := range override {
				env[k] = v
			}
			_, err := configureAuth(t, env)
			if err == nil {
				t.Fatal("a collision that escalates a reader credential to administrator was accepted")
			}
			// The message has to name the variables, or an operator cannot act.
			if !strings.Contains(err.Error(), "PREVIOUS") && !strings.Contains(err.Error(), "must not equal") {
				t.Fatalf("error does not explain the collision: %v", err)
			}
		})
	}
}

// TestRotationRejectsARetiringAdminKeyEqualToTheCurrentOne: an overlap with
// nothing to retire is a configuration mistake, not a rotation.
func TestRotationRejectsARetiringAdminKeyEqualToTheCurrentOne(t *testing.T) {
	_, err := configureAuth(t, map[string]string{
		"ENVIRONMENT":              "production",
		"API_GATEWAY_KEY":          rotCurrentAdmin,
		"READER_KEY":               rotCurrentReader,
		"API_GATEWAY_KEY_PREVIOUS": rotCurrentAdmin,
	})
	if err == nil {
		t.Fatal("an overlap that retires nothing was accepted")
	}
	if !strings.Contains(err.Error(), "nothing is being retired") {
		t.Fatalf("error does not explain why: %v", err)
	}
}

// TestRotationIsOptional confirms the ordinary steady state is unaffected: no
// previous keys configured means exactly the two live credentials.
func TestRotationIsOptional(t *testing.T) {
	cfg, err := configureAuth(t, map[string]string{
		"ENVIRONMENT":     "production",
		"API_GATEWAY_KEY": rotCurrentAdmin,
		"READER_KEY":      rotCurrentReader,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.overlapActive() {
		t.Fatal("overlap reported active with no previous keys configured")
	}
	if got := call(t, cfg.RequireAuth, rotOldReader); got != http.StatusUnauthorized {
		t.Errorf("an unknown key was accepted outside a rotation: %d", got)
	}
	if got := call(t, cfg.RequireAdmin, rotCurrentReader); got != http.StatusForbidden {
		t.Errorf("reader key on an admin route = %d, want 403", got)
	}
}

// TestRotationWarnsThatTheOldCredentialStillWorks. The failure mode of
// forgetting to clean up is silent - the retired credential simply keeps
// working - so the startup message is the only thing that will prevent it.
func TestRotationWarnsThatTheOldCredentialStillWorks(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("API_GATEWAY_KEY", rotCurrentAdmin)
	t.Setenv("READER_KEY", rotCurrentReader)
	t.Setenv("API_GATEWAY_KEY_PREVIOUS", rotOldAdmin)
	t.Setenv("READER_KEY_PREVIOUS", rotOldReader)

	if _, err := NewAuthConfig(logger); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "ROTATION IN PROGRESS") {
		t.Fatalf("no rotation warning was logged: %s", out)
	}
	for _, want := range []string{"API_GATEWAY_KEY_PREVIOUS", "READER_KEY_PREVIOUS"} {
		if !strings.Contains(out, want) {
			t.Errorf("warning does not mention %s: %s", want, out)
		}
	}

	// And steady state must stay quiet: a warning that always fires trains
	// operators to ignore it.
	buf.Reset()
	t.Setenv("API_GATEWAY_KEY_PREVIOUS", "")
	t.Setenv("READER_KEY_PREVIOUS", "")
	if _, err := NewAuthConfig(logger); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "ROTATION IN PROGRESS") {
		t.Errorf("a rotation warning fired with no rotation configured: %s", buf.String())
	}
}

// TestPreviousCredentialsAreTrimmed mirrors the facility identity: an operator
// who leaves whitespace in a secret file should not end up with a credential
// that no device actually holds.
func TestPreviousCredentialsAreTrimmed(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("API_GATEWAY_KEY", rotCurrentAdmin)
	t.Setenv("READER_KEY", rotCurrentReader)
	t.Setenv("API_GATEWAY_KEY_PREVIOUS", "  "+rotOldAdmin+"  ")
	t.Setenv("READER_KEY_PREVIOUS", "  "+rotOldReader+"\n")

	cfg, err := NewAuthConfig(quiet())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PreviousMasterAPIKey != rotOldAdmin {
		t.Fatalf("previous admin key is %q; whitespace makes it a credential no device holds", cfg.PreviousMasterAPIKey)
	}
	if cfg.PreviousReaderKey != rotOldReader {
		t.Fatalf("previous reader key is %q", cfg.PreviousReaderKey)
	}
}

// TestEmptyRetiringCredentialsAreNotTreatedAsValues: an unset variable must
// never match, or a caller presenting an empty token would authenticate.
func TestEmptyRetiringCredentialsAreNotTreatedAsValues(t *testing.T) {
	cfg := &AuthConfig{MasterAPIKey: rotCurrentAdmin, ReaderKey: rotCurrentReader}
	if cfg.isAdmin("") || cfg.isReader("") {
		t.Fatal("an empty token authenticated")
	}
	if got := call(t, cfg.RequireAuth, ""); got != http.StatusUnauthorized {
		t.Fatalf("empty credential = %d, want 401", got)
	}
}

// TestRotationStillRefusesInsecureProductionCredentials: adding the overlap must
// not reopen the earlier hole where a missing key fell back to a published one.
func TestRotationStillRefusesInsecureProductionCredentials(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("API_GATEWAY_KEY", "")
	t.Setenv("READER_KEY", "")
	t.Setenv("ADMIN_API_KEY", "")
	t.Setenv("API_GATEWAY_KEY_PREVIOUS", rotOldAdmin)
	t.Setenv("READER_KEY_PREVIOUS", rotOldReader)

	if _, err := NewAuthConfig(quiet()); err == nil {
		t.Fatal("production started with no live credentials because previous ones were set")
	}
}
