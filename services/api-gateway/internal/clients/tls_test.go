package clients_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	securitytls "finger-scanner/pkg/security/tls"
	"finger-scanner/services/api-gateway/internal/clients"
)

// writeSelfSignedCert generates a throwaway CA/self-signed leaf certificate
// valid for 127.0.0.1 and writes the PEM pair plus a CA bundle to dir.
//
// A real certificate is required rather than a stub: the point of these tests
// is that the transport genuinely negotiates TLS, which a mocked credential
// cannot demonstrate.
func writeSelfSignedCert(t *testing.T, dir string) (certFile, keyFile, caFile string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "anguli-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	caFile = filepath.Join(dir, "ca.pem")
	for path, data := range map[string][]byte{certFile: certPEM, keyFile: keyPEM, caFile: certPEM} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return certFile, keyFile, caFile
}

// startHealthServerTLS runs a real gRPC server whose transport is TLS, so the
// dial under test either genuinely negotiates TLS or genuinely fails.
func startHealthServerTLS(t *testing.T, certFile, keyFile string) (addr string, stop func()) {
	t.Helper()
	opt, err := securitytls.ServerOption(securitytls.Config{
		Enabled: true, CertFile: certFile, KeyFile: keyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(opt)
	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(srv, hs)
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), func() { srv.Stop(); _ = ln.Close() }
}

// TestNewServiceClients_DialsOverTLSWhenEnabled is the regression test for the
// gateway shipping employee identities and door decisions in cleartext.
//
// The original defect was a hardcoded insecure.NewCredentials() in this file:
// the TLS package existed, was correct, was unit-tested, and was never called.
// Nothing about the plaintext path looked wrong at the call site, so nothing
// failed. This asserts the opposite end of that: with TLS enabled, a plaintext
// server is unreachable.
func TestNewServiceClients_DialsOverTLSWhenEnabled(t *testing.T) {
	dir := t.TempDir()
	_, _, caFile := writeSelfSignedCert(t, dir)

	// A plaintext server. If the client still uses insecure credentials this
	// call succeeds and the test fails, which is exactly the bug.
	plainAddr, stopPlain := startHealthServer(t, true)
	defer stopPlain()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sc, err := clients.NewServiceClients(ctx, clients.Config{
		BiometricsAddr:   plainAddr,
		AccessPolicyAddr: deadAddr(t),
		EdgeGatewayAddr:  deadAddr(t),
		TLS: securitytls.Config{
			Enabled:    true,
			CAFile:     caFile,
			ServerName: "localhost",
		},
	}, nil)
	if err != nil {
		t.Fatalf("NewServiceClients should construct lazily: %v", err)
	}
	defer sc.Close()

	statuses, allHealthy := sc.CheckHealth(ctx)
	if allHealthy {
		t.Fatal("TLS-enabled client reported a PLAINTEXT server as healthy: " +
			"the transport credentials are being ignored, so traffic is still cleartext")
	}
	if statuses["biometric-service"] != "UNAVAILABLE" {
		t.Fatalf("expected UNAVAILABLE from the TLS handshake, got %q", statuses["biometric-service"])
	}
}

// TestNewServiceClients_ConnectsToTLSServer is the positive half: TLS enabled
// against a genuine TLS server must actually work, so the test above cannot be
// satisfied by simply refusing to dial anything.
func TestNewServiceClients_ConnectsToTLSServer(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, caFile := writeSelfSignedCert(t, dir)
	tlsAddr, stopTLS := startHealthServerTLS(t, certFile, keyFile)
	defer stopTLS()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sc, err := clients.NewServiceClients(ctx, clients.Config{
		BiometricsAddr:   tlsAddr,
		AccessPolicyAddr: tlsAddr,
		EdgeGatewayAddr:  tlsAddr,
		TLS: securitytls.Config{
			Enabled:    true,
			CAFile:     caFile,
			ServerName: "localhost",
		},
	}, nil)
	if err != nil {
		t.Fatalf("NewServiceClients: %v", err)
	}
	defer sc.Close()

	statuses, allHealthy := sc.CheckHealth(ctx)
	if !allHealthy {
		t.Fatalf("expected all services healthy over mTLS-capable TLS, got %v", statuses)
	}
}

// TestNewServiceClients_TLSDisabledStaysPlaintext pins the development path:
// with TLS off the zero-value config must still dial a plaintext server, so
// single-host development and the existing tests keep working.
func TestNewServiceClients_TLSDisabledStaysPlaintext(t *testing.T) {
	plainAddr, stopPlain := startHealthServer(t, true)
	defer stopPlain()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sc, err := clients.NewServiceClients(ctx, clients.Config{
		BiometricsAddr:   plainAddr,
		AccessPolicyAddr: plainAddr,
		EdgeGatewayAddr:  plainAddr,
		// TLS zero value: Enabled false.
	}, nil)
	if err != nil {
		t.Fatalf("NewServiceClients: %v", err)
	}
	defer sc.Close()

	if _, allHealthy := sc.CheckHealth(ctx); !allHealthy {
		t.Fatal("with TLS disabled the client must still reach a plaintext server")
	}
}

// TestNewServiceClients_MisconfiguredTLSFailsClosed proves the config error is
// fatal rather than downgraded. An operator who sets ENABLE_TLS=true and gets
// the certificate path wrong must not silently get plaintext.
func TestNewServiceClients_MisconfiguredTLSFailsClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := clients.NewServiceClients(ctx, clients.Config{
		BiometricsAddr:   deadAddr(t),
		AccessPolicyAddr: deadAddr(t),
		EdgeGatewayAddr:  deadAddr(t),
		TLS: securitytls.Config{
			Enabled:     true,
			RequireMTLS: true,
			// No CAFile: mutual TLS is requested but unenforceable.
		},
	}, nil)
	if err == nil {
		t.Fatal("expected an error for unenforceable mTLS; got a client that would fall back to plaintext")
	}
}
