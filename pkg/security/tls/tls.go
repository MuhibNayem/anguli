package tls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
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

var (
	// ErrTLSEnabledWithoutCert is returned when TLS is requested but no server
	// key pair was supplied.
	//
	// This used to fall back to a plaintext listener with no error. On a
	// biometric service that is a silent downgrade to cleartext: an operator
	// sets ENABLE_TLS=true, forgets a file path, and the service starts happily
	// serving unprotected. Failing closed is the only safe behaviour once the
	// operator has asked for encryption.
	ErrTLSEnabledWithoutCert = errors.New("tls: Enabled is true but CertFile/KeyFile are not both set; refusing to fall back to plaintext")

	// ErrMTLSUnenforceable is returned when mutual TLS is required but the CA
	// bundle needed to verify it is missing.
	//
	// Previously RequireMTLS with no CAFile silently produced a server that
	// accepted any client: the operator believed mutual authentication was on
	// when it was not. A security control that reports itself enabled while
	// doing nothing is worse than one that is off.
	ErrMTLSUnenforceable = errors.New("tls: RequireMTLS is true but no CAFile is set; mutual TLS cannot be enforced")

	// ErrClientCertMissing is returned when a client is configured for mutual
	// TLS without a certificate to present.
	ErrClientCertMissing = errors.New("tls: RequireMTLS is true but the client has no CertFile/KeyFile to present")
)

// ServerOption returns a grpc.ServerOption configured with TLS.
//
// When cfg.Enabled is false it returns an insecure option deliberately, and
// that is the ONLY insecure path. Once encryption is requested, a missing or
// unreadable certificate is an error rather than a silent downgrade.
func ServerOption(cfg Config) (grpc.ServerOption, error) {
	if !cfg.Enabled {
		return grpc.EmptyServerOption{}, nil
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, ErrTLSEnabledWithoutCert
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server key pair: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	// mTLS was explicitly requested, so refusing to start is correct: a server
	// that ignores the request would present itself as mutually authenticated
	// while accepting any peer.
	if cfg.RequireMTLS && cfg.CAFile == "" {
		return nil, ErrMTLSUnenforceable
	}

	if cfg.RequireMTLS {
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

// ClientOption returns a grpc.DialOption configured with TLS.
//
// When cfg.Enabled is false it returns an insecure option deliberately. When
// Enabled is true the transport is always TLS: there is no path from an
// Enabled config to a plaintext connection.
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

	// mTLS was requested, so the client must actually have an identity to
	// present. Returning an option with no certificate would look configured
	// while the server rejects every handshake.
	if cfg.RequireMTLS && (cfg.CertFile == "" || cfg.KeyFile == "") {
		return nil, ErrClientCertMissing
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

// Describe returns a short human-readable summary of how the config resolved,
// for startup logs. It never includes key material.
func (c Config) Describe() string {
	if !c.Enabled {
		return "tls=disabled (plaintext)"
	}
	mtls := "server-auth only"
	if c.RequireMTLS {
		mtls = "mutual"
	}
	return fmt.Sprintf("tls=1.3 serverName=%q mTLS=%s caConfigured=%t",
		c.ServerName, mtls, c.CAFile != "")
}
