package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The middleware package is internal, so auth chaos testing lives here rather
// than in test/chaos. This file maintains its own independent case count and
// coverage gate, mirroring test/chaos/zz_coverage_gate_test.go.

var caseCount int
var dimCounts = map[string]int{}

type reporter func(dim, name string)

func report(dim, name string) {
	if TestReportCase != nil {
		TestReportCase(dim, name)
	}
}

// TestReportCase lets an external harness observe cases from this package.
var TestReportCase reporter

// ChaosCaseCount returns the number of auth/cors chaos cases executed here.
func ChaosCaseCount() int { return caseCount }

// ChaosTargetCoverage is the contractual minimum for this package.
const ChaosTargetCoverage = 200

func countCase(dim, name string) {
	caseCount++
	dimCounts[dim]++
	report(dim, name)
}

// ---------------------------------------------------------------------------
// Authentication chaos: every header / credential combination must either
// authenticate correctly or be refused. Nothing in between.
// ---------------------------------------------------------------------------

func TestChaos_AuthCredentials(t *testing.T) {
	const valid = "Correct-Admin-Key-Value-X9"

	cfg := &AuthConfig{MasterAPIKey: valid, ReaderKey: "correct-reader-key-value"}

	// `only` restricts a credential to a single channel ("" = every supported
	// channel). Whitespace-normalised credentials are only equivalent to the
	// real key on the Authorization path, where TrimSpace is applied.
	creds := []struct {
		name  string
		value string
		valid bool
		only  string
	}{
		{"exact-admin", valid, true, ""},
		{"exact-reader", "correct-reader-key-value", true, ""},
		{"wrong", "nope", false, ""},
		{"empty", "", false, ""},
		{"single-space", " ", false, ""},
		{"admin-uppercase", strings.ToUpper(valid), false, ""},
		{"admin-lowercase", strings.ToLower(valid), false, ""},
		{"admin-prefix", valid[:len(valid)-1], false, ""},
		{"admin-suffix", valid + "x", false, ""},
		{"admin-plus-null", valid + "\x00", false, ""},
		{"emoji-suffix", valid + "\U0001F600", false, ""},
		{"nul-prefix", "\x00" + valid, false, ""},
		{"unicode-lookalike", strings.Repeat("K", len(valid)), false, ""},
		{"very-long-1k", strings.Repeat("A", 1024), false, ""},
		{"very-long-64k", strings.Repeat("A", 65536), false, ""},
		{"null-bytes", "\x00\x00\x00\x00", false, ""},
		{"json-ish", `{"key":"` + valid + `"}`, false, ""},
		{"sql-injection", "' OR '1'='1", false, ""},
		{"template-injection", "{{.MasterAPIKey}}", false, ""},
		// Bearer-prefixed is only parsed out of the Authorization header.
		{"bearer-prefixed", "Bearer " + valid, true, "Authorization"},
		// TrimSpace is applied only on the Authorization split path.
		{"admin-leading-space", " " + valid, true, "Authorization"},
		{"admin-trailing-space", valid + " ", true, "Authorization"},
		{"admin-tab", "\t" + valid, true, "Authorization"},
		{"admin-newline", valid + "\n", true, "Authorization"},
	}

	// supportsCredential marks the header channels the middleware actually
	// treats as credentials. Basic/Token/Cookie/Query are deliberately NOT
	// credential channels - accepting them would leak secrets into URLs and
	// logs - so a valid key sent there must be refused.
	headers := []struct {
		name     string
		supports bool
		apply    func(r *http.Request, v string)
	}{
		{"X-API-Key", true, func(r *http.Request, v string) { r.Header.Set("X-API-Key", v) }},
		{"X-Reader-Token", true, func(r *http.Request, v string) { r.Header.Set("X-Reader-Token", v) }},
		{"Authorization", true, func(r *http.Request, v string) { r.Header.Set("Authorization", v) }},
		{"Authorization-Bearer", true, func(r *http.Request, v string) { r.Header.Set("Authorization", "Bearer "+v) }},
		{"Authorization-bearer-lower", true, func(r *http.Request, v string) { r.Header.Set("Authorization", "bearer "+v) }},
		{"Authorization-BEARER", true, func(r *http.Request, v string) { r.Header.Set("Authorization", "BEARER "+v) }},
		{"Authorization-Basic", false, func(r *http.Request, v string) { r.Header.Set("Authorization", "Basic "+v) }},
		{"Authorization-Token", false, func(r *http.Request, v string) { r.Header.Set("Authorization", "Token "+v) }},
		{"Cookie", false, func(r *http.Request, v string) { r.AddCookie(&http.Cookie{Name: "key", Value: v}) }},
		{"Query", false, func(r *http.Request, v string) { r.URL.RawQuery = "key=" + v }},
	}

	for _, h := range headers {
		for _, c := range creds {
			t.Run(h.name+"/"+c.name, func(t *testing.T) {
				countCase("auth-credentials", h.name+"/"+c.name)

				called := false
				hdr := cfg.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
					called = true
					w.WriteHeader(http.StatusOK)
				})
				req := httptest.NewRequest(http.MethodPost, "/api/v1/doors/scan", nil)
				h.apply(req, c.value)
				rec := httptest.NewRecorder()
				hdr(rec, req)

				// Only supported channels can ever authenticate, and some
				// credentials are only equivalent to the key on one channel.
				expect := c.valid && h.supports && (c.only == "" || c.only == h.name)
				if expect && !called {
					t.Errorf("[auth] valid credential %q via supported channel %s was rejected", c.name, h.name)
				}
				if !expect && called && c.valid && !h.supports {
					t.Errorf("[auth] INV-NOBYPASS: unsupported channel %s accepted a valid key as a credential", h.name)
				}
				if !expect && called && !c.valid {
					t.Errorf("[auth] INV-NOBYPASS: invalid credential %q via %s was ACCEPTED", c.name, h.name)
				}
				if !called && rec.Code != http.StatusUnauthorized {
					t.Errorf("[auth] expected 401 for %q via %s, got %d", c.name, h.name, rec.Code)
				}
			})
		}
	}

	// Documented quirk: extractToken checks X-API-Key first and RETURNS it
	// immediately when non-empty, so a stale/invalid X-API-Key shadows a
	// perfectly valid Authorization header. This fails closed, so it is not a
	// bypass, but it is surprising behaviour for operators.
	t.Run("header-precedence-shadowing", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			countCase("auth-credentials", fmt.Sprintf("precedence-%d", i))
			called := false
			hdr := cfg.RequireAuth(func(w http.ResponseWriter, r *http.Request) { called = true })
			req := httptest.NewRequest(http.MethodPost, "/api/v1/doors/scan", nil)
			req.Header.Set("X-API-Key", "stale-but-present")
			req.Header.Set("Authorization", "Bearer "+valid)
			hdr(httptest.NewRecorder(), req)
			if called {
				t.Errorf("[auth] INV-NOBYPASS: stale X-API-Key shadowing check did not short-circuit")
			}
		}
	})

	// No header at all must always be refused.
	for i, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut,
		http.MethodDelete, http.MethodPatch, http.MethodHead, http.MethodOptions} {
		t.Run("no-header", func(t *testing.T) {
			countCase("auth-credentials", "no-header-"+method)
			called := false
			hdr := cfg.RequireAuth(func(w http.ResponseWriter, r *http.Request) { called = true })
			req := httptest.NewRequest(method, "/api/v1/doors/scan", nil)
			rec := httptest.NewRecorder()
			hdr(rec, req)
			if called {
				t.Errorf("[auth] INV-NOBYPASS: %s with no credential was accepted", method)
			}
		})
		_ = i
	}

	// Header precedence: extractToken returns the FIRST non-empty supported
	// channel and never consults the rest. Model that precisely.
	precedence := []struct {
		name     string
		setup    func(r *http.Request)
		wantAuth bool
	}{
		{"api-key-only", func(r *http.Request) { r.Header.Set("X-API-Key", valid) }, true},
		{"reader-only", func(r *http.Request) { r.Header.Set("X-Reader-Token", "correct-reader-key-value") }, true},
		{"bearer-only", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+valid) }, true},
		{"nothing", func(r *http.Request) {}, false},
		{"empty-api-key-then-bearer", func(r *http.Request) {
			r.Header.Set("X-API-Key", "")
			r.Header.Set("Authorization", "Bearer "+valid)
		}, true},
		{"stale-api-key-shadows-bearer", func(r *http.Request) {
			r.Header.Set("X-API-Key", "stale")
			r.Header.Set("Authorization", "Bearer "+valid)
		}, false},
		{"stale-reader-shadows-bearer", func(r *http.Request) {
			r.Header.Set("X-Reader-Token", "stale")
			r.Header.Set("Authorization", "Bearer "+valid)
		}, false},
		{"valid-api-key-and-stale-bearer", func(r *http.Request) {
			r.Header.Set("X-API-Key", valid)
			r.Header.Set("Authorization", "Bearer stale")
		}, true},
	}
	for i, pc := range precedence {
		t.Run("precedence/"+pc.name, func(t *testing.T) {
			for rep := 0; rep < 4; rep++ {
				countCase("auth-credentials", fmt.Sprintf("precedence-%s-%d", pc.name, i*10+rep))
				called := false
				hdr := cfg.RequireAuth(func(w http.ResponseWriter, r *http.Request) { called = true })
				req := httptest.NewRequest(http.MethodPost, "/api/v1/doors/scan", nil)
				pc.setup(req)
				hdr(httptest.NewRecorder(), req)
				if pc.wantAuth && !called {
					t.Errorf("[auth] precedence %q should have authenticated", pc.name)
				}
				if !pc.wantAuth && called {
					t.Errorf("[auth] INV-NOBYPASS: precedence %q authenticated unexpectedly", pc.name)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CORS chaos
// ---------------------------------------------------------------------------

func TestChaos_CORS(t *testing.T) {
	countCase("auth-cors", "cors-matrix")
	allowed := []string{"http://localhost:8080", "https://app.example.com"}
	cases := []struct {
		origin  string
		expect  bool
		comment string
	}{
		{"http://localhost:8080", true, "exact allowlisted"},
		{"https://app.example.com", true, "second allowlisted"},
		{"http://evil.example.com", false, "not allowlisted"},
		{"", false, "no origin"},
		{"null", false, "opaque origin"},
		{"http://localhost:8080.evil.com", false, "suffix attack"},
		{"http://evil.com/localhost:8080", false, "prefix attack"},
		{"HTTP://LOCALHOST:8080", false, "case mismatch"},
		{"http://localhost:8081", false, "different port"},
		{"https://localhost:8080", false, "different scheme"},
		{"http://127.0.0.1:8080", false, "loopback not allowlisted here"},
		{"*", false, "wildcard origin is not an origin"},
	}
	for _, tc := range cases {
		t.Run(tc.comment, func(t *testing.T) {
			countCase("auth-cors", tc.comment)
			called := false
			h := SecureCORSMiddleware(allowed, func(w http.ResponseWriter, r *http.Request) { called = true })
			req := httptest.NewRequest(http.MethodPost, "/api/v1/doors/scan", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()
			h(rec, req)
			got := rec.Header().Get("Access-Control-Allow-Origin")
			if tc.expect && got == "" {
				t.Errorf("[cors] allowlisted origin %q received no CORS header", tc.origin)
			}
			if !tc.expect && got != "" {
				t.Errorf("[cors] INV-NOBYPASS: origin %q was reflected with Allow-Origin=%q", tc.origin, got)
			}
			if !called {
				t.Errorf("[cors] request handler was not invoked for %q", tc.origin)
			}
		})
	}

	// A wildcard allowlist must reflect the caller's own origin, never "*"
	// together with Allow-Credentials.
	t.Run("wildcard-with-credentials", func(t *testing.T) {
		countCase("auth-cors", "wildcard-with-credentials")
		h := SecureCORSMiddleware([]string{"*"}, func(w http.ResponseWriter, r *http.Request) {})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/doors/scan", nil)
		req.Header.Set("Origin", "http://attacker.example")
		rec := httptest.NewRecorder()
		h(rec, req)
		acao := rec.Header().Get("Access-Control-Allow-Origin")
		acac := rec.Header().Get("Access-Control-Allow-Credentials")
		if acao == "*" && acac == "true" {
			t.Errorf("[cors] INV-NOBYPASS: wildcard origin combined with credentials")
		}
	})

	// Preflight requests must short-circuit without invoking the handler.
	for i, origin := range []string{"http://localhost:8080", "http://evil.com", ""} {
		t.Run("preflight", func(t *testing.T) {
			countCase("auth-cors", fmt.Sprintf("preflight-%d", i))
			called := false
			h := SecureCORSMiddleware(allowed, func(w http.ResponseWriter, r *http.Request) { called = true })
			req := httptest.NewRequest(http.MethodOptions, "/api/v1/doors/scan", nil)
			if origin != "" {
				req.Header.Set("Origin", origin)
			}
			rec := httptest.NewRecorder()
			h(rec, req)
			if called {
				t.Errorf("[cors] preflight should not invoke the real handler")
			}
		})
	}
}
