package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Config specifies TLS parameters for gRPC inter-service communication.
type Config struct {
	Enabled     bool
	CertFile    string
	KeyFile     string
	CAFile      string
	ServerName  string
	RequireMTLS bool
}

// LoadConfigFromEnv reads TLS configuration from environment variables.
func LoadConfigFromEnv() Config {
	enabled := os.Getenv("ENABLE_TLS") == "true"
	return Config{
		Enabled:     enabled,
		CertFile:    os.Getenv("TLS_CERT_FILE"),
		KeyFile:     os.Getenv("TLS_KEY_FILE"),
		CAFile:      os.Getenv("TLS_CA_FILE"),
		ServerName:  os.Getenv("TLS_SERVER_NAME"),
		RequireMTLS: os.Getenv("TLS_REQUIRE_MTLS") == "true",
	}
}

// ServerOption returns a grpc.ServerOption configured with TLS or insecure fallback.
func ServerOption(cfg Config) (grpc.ServerOption, error) {
	if !cfg.Enabled || cfg.CertFile == "" || cfg.KeyFile == "" {
		return grpc.EmptyServerOption{}, nil
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server key pair: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	if cfg.RequireMTLS && cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate into cert pool")
		}
		tlsConfig.ClientCAs = caPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return grpc.Creds(credentials.NewTLS(tlsConfig)), nil
}

// ClientOption returns a grpc.DialOption configured with TLS or insecure fallback.
func ClientOption(cfg Config) (grpc.DialOption, error) {
	if !cfg.Enabled {
		return grpc.WithTransportCredentials(insecure.NewCredentials()), nil
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if cfg.ServerName != "" {
		tlsConfig.ServerName = cfg.ServerName
	}

	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate into cert pool")
		}
		tlsConfig.RootCAs = caPool
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		clientCert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client key pair for mTLS: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
	}

	return grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)), nil
}
