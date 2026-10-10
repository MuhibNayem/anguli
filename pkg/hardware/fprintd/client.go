package fprintd

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// DefaultTimeout bounds a single fprintd operation. Enrollment can take many
// finger placements and is deliberately NOT bounded by this default; verify is,
// because a reader that never sees a finger must not hold a reader slot.
const DefaultTimeout = 15 * time.Second

// busConn is the seam between this package and fprintd. Everything above it is
// pure logic and fully testable; everything below is godbus. Tests substitute a
// fake here, so no session bus is needed to run the suite.
type busConn interface {
	// VerifyStart blocks until fprintd reports a result for username. It
	// returns ErrNoMatch for a clean non-match and ErrNotEnrolled when the
	// user has nothing enrolled.
	VerifyStart(ctx context.Context, username string) error
	// EnrollStart drives enrollment to completion for one finger.
	EnrollStart(ctx context.Context, username string, finger Finger) error
	// ListEnrolledFingers returns the fingers currently enrolled for username.
	ListEnrolledFingers(ctx context.Context, username string) ([]Finger, error)
	// HasFingerprintReader reports whether fprintd sees usable hardware.
	HasFingerprintReader(ctx context.Context) (bool, error)
	// Close releases the underlying connection.
	Close() error
}

// Client is the production entry point: an attestation API over fprintd.
type Client struct {
	conn busConn

	// VerifyTimeout bounds one Verify call. Zero means DefaultTimeout.
	VerifyTimeout time.Duration
	// Logger receives operational events. Nil means slog.Default.
	Logger *slog.Logger

	closeOnce sync.Once
	closeErr  error
}

// Config configures a Client.
type Config struct {
	// Conn supplies the D-Bus connection. Nil means "dial the session bus".
	Conn busConn
	// VerifyTimeout overrides DefaultTimeout for Verify.
	VerifyTimeout time.Duration
	// Logger overrides slog.Default.
	Logger *slog.Logger
	// RequireReader fails construction if no fingerprint hardware is present,
	// instead of deferring the check to the first call. Useful at service
	// startup where "no reader" is a fatal misconfiguration rather than a
	// runtime condition.
	RequireReader bool
}

// New builds a Client. With Config.Conn nil it connects to the session bus,
// which is where fprintd lives.
func New(ctx context.Context, cfg Config) (*Client, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	timeout := cfg.VerifyTimeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	conn := cfg.Conn
	if conn == nil {
		var err error
		conn, err = dialSessionBus()
		if err != nil {
			return nil, err
		}
	}

	c := &Client{conn: conn, VerifyTimeout: timeout, Logger: logger}

	if cfg.RequireReader {
		if err := c.RequireReader(ctx); err != nil {
			// Do not leak the connection we just opened on a failed construction.
			_ = conn.Close()
			return nil, err
		}
	}
	return c, nil
}

// RequireReader returns ErrNoReader when fprintd reports no usable hardware.
func (c *Client) RequireReader(ctx context.Context) error {
	ok, err := c.conn.HasFingerprintReader(ctx)
	if err != nil {
		return fmt.Errorf("fprintd: checking for hardware: %w", err)
	}
	if !ok {
		return ErrNoReader
	}
	return nil
}

// Verify asks the sensor whether the enrolled owner just touched it.
//
// It returns nil on a match. ErrNoMatch is the normal deny outcome and is not
// a fault. Cancellation and deadline errors propagate unwrapped so callers can
// tell "the person walked away" from "the reader is broken".
func (c *Client) Verify(ctx context.Context, username string) error {
	if username == "" {
		return fmt.Errorf("fprintd: verify requires a username")
	}
	ctx, cancel := context.WithTimeout(ctx, c.verifyTimeout())
	defer cancel()

	if err := c.conn.VerifyStart(ctx, username); err != nil {
		return err
	}
	c.Logger.Debug("fingerprint verified", "user", username)
	return nil
}

func (c *Client) verifyTimeout() time.Duration {
	if c.VerifyTimeout > 0 {
		return c.VerifyTimeout
	}
	return DefaultTimeout
}

// Enroll registers one finger for a user.
//
// Enrollment is intentionally not given the Verify deadline: it requires
// several deliberate placements and a timeout here would abandon a legitimate
// enrollment mid-way. The caller's own context is the bound.
func (c *Client) Enroll(ctx context.Context, username string, finger Finger) error {
	if username == "" {
		return fmt.Errorf("fprintd: enroll requires a username")
	}
	if !finger.Valid() {
		return fmt.Errorf("fprintd: finger code %d is out of range 1..10", int(finger))
	}
	if err := c.conn.EnrollStart(ctx, username, finger); err != nil {
		return err
	}
	c.Logger.Info("fingerprint enrolled", "user", username, "finger", finger.String())
	return nil
}

// Enrolled lists the fingers a user has registered.
func (c *Client) Enrolled(ctx context.Context, username string) ([]Finger, error) {
	if username == "" {
		return nil, fmt.Errorf("fprintd: listing requires a username")
	}
	f, err := c.conn.ListEnrolledFingers(ctx, username)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// Close releases the D-Bus connection. It is safe to call more than once, so a
// deferred Close alongside an explicit shutdown path is not a hazard.
func (c *Client) Close() error {
	c.closeOnce.Do(func() { c.closeErr = c.conn.Close() })
	return c.closeErr
}
