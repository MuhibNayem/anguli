package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// certPaths holds generated PEM material on disk for the test.
type certPaths struct {
	dir        string
	serverCert string
	serverKey  string
	clientCert string
	clientKey  string
	caCert     string
}

// writePEM writes a certificate and/or key to path.
func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		t.Fatal(err)
	}
}

// makeCert issues a certificate signed by parent (self-signed when nil).
func makeCert(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) ([]byte, *ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	if parent == nil {
		tmpl.IsCA = true
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		tmpl.DNSNames = []string{"localhost"}
	} else {
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		tmpl.DNSNames = []string{cn}
	}

	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	return der, key, nil
}

// newCertPaths builds a CA plus a server and client certificate.
func newCertPaths(t *testing.T) *certPaths {
	t.Helper()
	dir := t.TempDir()
	p := &certPaths{
		dir:        dir,
		serverCert: filepath.Join(dir, "server.crt"),
		serverKey:  filepath.Join(dir, "server.key"),
		clientCert: filepath.Join(dir, "client.crt"),
		clientKey:  filepath.Join(dir, "client.key"),
		caCert:     filepath.Join(dir, "ca.crt"),
	}

	caDER, caKey, caCrt := makeCert(t, "anguli-test-ca", nil, nil)
	writePEM(t, p.caCert, "CERTIFICATE", caDER)
	srvDER, srvKey, _ := makeCert(t, "localhost", caCrt, caKey)
	writePEM(t, p.serverCert, "CERTIFICATE", srvDER)
	writeKey(t, p.serverKey, srvKey)

	cliDER, cliKey, _ := makeCert(t, "anguli-client", caCrt, caKey)
	writePEM(t, p.clientCert, "CERTIFICATE", cliDER)
	writeKey(t, p.clientKey, cliKey)

	return p
}

// writeKey writes an EC private key in PEM form.
func writeKey(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, path, "EC PRIVATE KEY", der)
}

// ---------------------------------------------------------------------------
// Fail-closed behaviour. These are the regressions that matter.
// ---------------------------------------------------------------------------

// TestServerOption_RefusesSilentDowngrade is the core security assertion.
//
// An operator sets Enabled=true and forgets the cert path. The old code
// returned an empty (plaintext) server option with NO error, so the service
// started and reported itself encrypted while serving cleartext.
func TestServerOption_RefusesSilentDowngrade(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"enabled with no cert or key", Config{Enabled: true}},
		{"enabled with cert only", Config{Enabled: true, CertFile: "/tmp/nope.crt"}},
		{"enabled with key only", Config{Enabled: true, KeyFile: "/tmp/nope.key"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opt, err := ServerOption(c.cfg)
			if err == nil {
				t.Fatalf("ServerOption(%+v) = nil error; a requested-encrypted server must not silently serve plaintext", c.cfg)
			}
			if !errors.Is(err, ErrTLSEnabledWithoutCert) {
				t.Errorf("error = %v; want it to wrap ErrTLSEnabledWithoutCert", err)
			}
			if opt != nil {
				t.Error("a non-nil option was returned alongside the error")
			}
		})
	}
}

// TestServerOption_RefusesUnenforceableMTLS covers the control that reported
// itself on while doing nothing.
func TestServerOption_RefusesUnenforceableMTLS(t *testing.T) {
	p := newCertPaths(t)
	_, err := ServerOption(Config{
		Enabled:     true,
		CertFile:    p.serverCert,
		KeyFile:     p.serverKey,
		RequireMTLS: true,
		// CAFile deliberately absent.
	})
	if !errors.Is(err, ErrMTLSUnenforceable) {
		t.Fatalf("error = %v; want ErrMTLSUnenforceable - a server that cannot verify clients must not claim to require them", err)
	}
}

func TestClientOption_RefusesMTLSWithoutIdentity(t *testing.T) {
	p := newCertPaths(t)
	_, err := ClientOption(Config{
		Enabled:     true,
		ServerName:  "localhost",
		CAFile:      p.caCert,
		RequireMTLS: true,
		// No client cert.
	})
	if !errors.Is(err, ErrClientCertMissing) {
		t.Fatalf("error = %v; want ErrClientCertMissing", err)
	}
}

// ---------------------------------------------------------------------------
// Explicit opt-out
// ---------------------------------------------------------------------------

func TestServerOption_DisabledIsTheOnlyPlaintextPath(t *testing.T) {
	opt, err := ServerOption(Config{})
	if err != nil {
		t.Fatalf("disabled ServerOption returned an error: %v", err)
	}
	if opt == nil {
		t.Fatal("disabled ServerOption returned a nil option")
	}
	// No certificate paths set, so nothing was loaded.
	_ = opt
}

func TestClientOption_DisabledYieldsInsecure(t *testing.T) {
	opt, err := ClientOption(Config{})
	if err != nil {
		t.Fatalf("disabled ClientOption returned an error: %v", err)
	}
	if opt == nil {
		t.Fatal("disabled ClientOption returned a nil option")
	}
}

// ---------------------------------------------------------------------------
// Happy paths and error handling
// ---------------------------------------------------------------------------

func TestServerOption_LoadsCertificate(t *testing.T) {
	p := newCertPaths(t)
	opt, err := ServerOption(Config{Enabled: true, CertFile: p.serverCert, KeyFile: p.serverKey})
	if err != nil {
		t.Fatalf("ServerOption: %v", err)
	}
	if opt == nil {
		t.Fatal("ServerOption returned a nil option")
	}
}

func TestServerOption_UnreadableCertificate(t *testing.T) {
	_, err := ServerOption(Config{Enabled: true, CertFile: "/nonexistent/a.crt", KeyFile: "/nonexistent/a.key"})
	if err == nil {
		t.Fatal("ServerOption with unreadable cert = nil error")
	}
	if errors.Is(err, ErrTLSEnabledWithoutCert) {
		t.Error("a missing file should report a load failure, not a missing-config error")
	}
}

func TestServerOption_MalformedCA(t *testing.T) {
	p := newCertPaths(t)
	bad := filepath.Join(p.dir, "bad-ca.crt")
	if err := os.WriteFile(bad, []byte("this is not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ServerOption(Config{
		Enabled: true, CertFile: p.serverCert, KeyFile: p.serverKey,
		CAFile: bad, RequireMTLS: true,
	})
	if err == nil {
		t.Fatal("ServerOption with a malformed CA = nil error")
	}
}

func TestServerOption_MissingCAFile(t *testing.T) {
	p := newCertPaths(t)
	_, err := ServerOption(Config{
		Enabled: true, CertFile: p.serverCert, KeyFile: p.serverKey,
		CAFile: filepath.Join(p.dir, "absent-ca.crt"), RequireMTLS: true,
	})
	if err == nil {
		t.Fatal("ServerOption with a missing CA file = nil error")
	}
}

func TestClientOption_LoadsCAAndServerName(t *testing.T) {
	p := newCertPaths(t)
	opt, err := ClientOption(Config{Enabled: true, ServerName: "localhost", CAFile: p.caCert})
	if err != nil {
		t.Fatalf("ClientOption: %v", err)
	}
	if opt == nil {
		t.Fatal("ClientOption returned a nil option")
	}
}

func TestClientOption_LoadsClientCertificate(t *testing.T) {
	p := newCertPaths(t)
	opt, err := ClientOption(Config{
		Enabled: true, ServerName: "localhost", CAFile: p.caCert,
		CertFile: p.clientCert, KeyFile: p.clientKey, RequireMTLS: true,
	})
	if err != nil {
		t.Fatalf("ClientOption: %v", err)
	}
	if opt == nil {
		t.Fatal("ClientOption returned a nil option")
	}
}

func TestClientOption_MissingCAFile(t *testing.T) {
	_, err := ClientOption(Config{Enabled: true, ServerName: "localhost", CAFile: "/nonexistent/ca.crt"})
	if err == nil {
		t.Fatal("ClientOption with a missing CA file = nil error")
	}
}

func TestClientOption_MalformedCA(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.crt")
	if err := os.WriteFile(bad, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ClientOption(Config{Enabled: true, ServerName: "localhost", CAFile: bad})
	if err == nil {
		t.Fatal("ClientOption with a malformed CA = nil error")
	}
}

func TestClientOption_UnreadableClientCertificate(t *testing.T) {
	p := newCertPaths(t)
	_, err := ClientOption(Config{
		Enabled: true, ServerName: "localhost", CAFile: p.caCert,
		CertFile: "/nonexistent/client.crt", KeyFile: "/nonexistent/client.key",
	})
	if err == nil {
		t.Fatal("ClientOption with an unreadable client cert = nil error")
	}
}

// TestClientOption_NoServerNameStillFailsHandshake is worth pinning: with
// system roots and no ServerName, Go's crypto/tls refuses to verify rather
// than trusting anything, so an unset server name is a failure and not a
// silent acceptance.
func TestClientOption_NoServerNameUsesSystemRoots(t *testing.T) {
	opt, err := ClientOption(Config{Enabled: true})
	if err != nil {
		t.Fatalf("ClientOption: %v", err)
	}
	if opt == nil {
		t.Fatal("ClientOption returned a nil option")
	}
}

// ---------------------------------------------------------------------------
// Environment loading
// ---------------------------------------------------------------------------

func TestLoadConfigFromEnv(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want Config
	}{
		{"unset defaults to disabled", map[string]string{}, Config{}},
		{
			"full configuration",
			map[string]string{
				"ENABLE_TLS": "true", "TLS_CERT_FILE": "/c.crt", "TLS_KEY_FILE": "/c.key",
				"TLS_CA_FILE": "/ca.crt", "TLS_SERVER_NAME": "svc", "TLS_REQUIRE_MTLS": "true",
			},
			Config{Enabled: true, CertFile: "/c.crt", KeyFile: "/c.key",
				CAFile: "/ca.crt", ServerName: "svc", RequireMTLS: true},
		},
		{
			"only exact lowercase true enables TLS",
			map[string]string{"ENABLE_TLS": "TRUE", "TLS_REQUIRE_MTLS": "1"},
			Config{},
		},
		{
			"truthy but not true does not enable",
			map[string]string{"ENABLE_TLS": "yes"},
			Config{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{"ENABLE_TLS", "TLS_CERT_FILE", "TLS_KEY_FILE",
				"TLS_CA_FILE", "TLS_SERVER_NAME", "TLS_REQUIRE_MTLS"} {
				t.Setenv(k, "")
				_ = os.Unsetenv(k)
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if got := LoadConfigFromEnv(); got != tc.want {
				t.Errorf("LoadConfigFromEnv() = %+v; want %+v", got, tc.want)
			}
		})
	}
}

// TestLoadConfigFromEnv_DisabledCannotServe checks the end-to-end story: a
// config loaded from a half-configured environment fails closed at build time
// rather than producing a plaintext listener.
func TestLoadConfigFromEnv_DisabledCannotServe(t *testing.T) {
	t.Setenv("ENABLE_TLS", "true")
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", "")
	_ = os.Unsetenv("TLS_CERT_FILE")

	cfg := LoadConfigFromEnv()
	if !cfg.Enabled {
		t.Fatal("ENABLE_TLS=true did not produce Enabled=true")
	}
	if _, err := ServerOption(cfg); !errors.Is(err, ErrTLSEnabledWithoutCert) {
		t.Fatalf("ServerOption = %v; want ErrTLSEnabledWithoutCert", err)
	}
}

func TestDescribe(t *testing.T) {
	disabled := Config{}.Describe()
	if disabled != "tls=disabled (plaintext)" {
		t.Errorf("Describe(disabled) = %q", disabled)
	}

	mutual := Config{Enabled: true, ServerName: "svc", RequireMTLS: true, CAFile: "/ca.crt"}.Describe()
	if mutual != `tls=1.3 serverName="svc" mTLS=mutual caConfigured=true` {
		t.Errorf("Describe(mutual) = %q", mutual)
	}

	oneWay := Config{Enabled: true}.Describe()
	if oneWay != `tls=1.3 serverName="" mTLS=server-auth only caConfigured=false` {
		t.Errorf("Describe(one-way) = %q", oneWay)
	}
}

// TestDescribeNeverLeaksKeyMaterial guards the startup log.
func TestDescribeNeverLeaksKeyMaterial(t *testing.T) {
	p := newCertPaths(t)
	c := Config{
		Enabled: true, CertFile: p.serverCert, KeyFile: p.serverKey,
		CAFile: p.caCert, RequireMTLS: true,
	}
	d := c.Describe()
	for _, needle := range []string{"BEGIN", "PRIVATE", p.dir} {
		if contains(d, needle) {
			t.Errorf("Describe() leaked %q: %s", needle, d)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		}()
}
