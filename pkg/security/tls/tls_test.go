package tls_test

import (
	"testing"

	"finger-scanner/pkg/security/tls"
)

func TestTLSConfig_InsecureFallback(t *testing.T) {
	cfg := tls.Config{Enabled: false}

	serverOpt, err := tls.ServerOption(cfg)
	if err != nil {
		t.Fatalf("unexpected error for disabled TLS server: %v", err)
	}
	if serverOpt == nil {
		t.Errorf("expected non-nil server option")
	}

	clientOpt, err := tls.ClientOption(cfg)
	if err != nil {
		t.Fatalf("unexpected error for disabled TLS client: %v", err)
	}
	if clientOpt == nil {
		t.Errorf("expected non-nil client option")
	}
}
