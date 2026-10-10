package fprintd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"finger-scanner/pkg/hardware/reader"
)

// ErrNoRelay is returned by StrikeRelay. There is no lock output on a
// fingerprint sensor, so there is nothing honest to do here. Returning an
// explicit error is deliberate: silently succeeding would let a deployment
// believe it had driven hardware that does not exist.
var ErrNoRelay = errors.New("fprintd: this reader has no relay output")

// TurnstileDriver adapts Client to the platform's TurnstileHardwareDriver
// interface so the existing edge loop can run against laptop fingerprint
// hardware.
//
// Read this before trusting it as a door controller. It is an attestation
// adapter, not a capture adapter:
//
//   - PollEvent returns an event whose BadgeID carries the VERIFIED IDENTITY.
//     ProbePixels is always nil. No caller can obtain a fingerprint image.
//   - The identity is whatever username was configured as Subject, and it is
//     asserted by the sensor's own firmware, not by this codebase's matcher.
//     Matching accuracy is therefore not exercised by this path at all.
//   - SignalAccessGranted and SignalAccessDenied record the decision for the
//     caller to act on; there is no hardware to signal.
//
// For a real door you want pkg/hardware/osdp, which returns pixels from a
// reader that exposes them.
type TurnstileDriver struct {
	client *Client
	// Subject is the username whose enrolled fingerprint is being verified.
	Subject string
	// Logger receives operational events. Nil means slog.Default.
	Logger *slog.Logger

	mu       sync.RWMutex
	lastVerd bool
	online   bool
}

var _ reader.TurnstileHardwareDriver = (*TurnstileDriver)(nil)

// NewTurnstileDriver wraps a Client as a TurnstileHardwareDriver verifying
// subject.
func NewTurnstileDriver(client *Client, subject string, logger *slog.Logger) (*TurnstileDriver, error) {
	if client == nil {
		return nil, fmt.Errorf("fprintd: nil client")
	}
	if subject == "" {
		return nil, fmt.Errorf("fprintd: subject is required; a verify against no identity is meaningless")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &TurnstileDriver{client: client, Subject: subject, Logger: logger}, nil
}

// PollEvent performs one verify and returns the outcome as an event.
//
// A clean non-match is returned as a nil event and a nil error only when the
// caller asked for the "no event" outcome; in practice ErrNoMatch is surfaced
// so the caller can log a deny. Either way the door must stay shut.
func (d *TurnstileDriver) PollEvent(ctx context.Context) (*reader.HardwareEvent, error) {
	err := d.client.Verify(ctx, d.Subject)

	d.mu.Lock()
	d.online = true
	d.mu.Unlock()

	if err != nil {
		if errors.Is(err, ErrNoMatch) {
			d.mu.Lock()
			d.lastVerd = false
			d.mu.Unlock()
			return nil, fmt.Errorf("%w: subject %q", ErrNoMatch, d.Subject)
		}
		if errors.Is(err, ErrNotEnrolled) {
			d.mu.Lock()
			d.lastVerd = false
			d.mu.Unlock()
			return nil, fmt.Errorf("%w: subject %q", ErrNotEnrolled, d.Subject)
		}
		return nil, err
	}

	d.mu.Lock()
	d.lastVerd = true
	d.mu.Unlock()

	return &reader.HardwareEvent{
		Type:    reader.EventFingerprintScanned,
		BadgeID: d.Subject, // verified identity, NOT a badge number
		// ProbePixels deliberately nil: this hardware cannot produce an image.
		Width:     0,
		Height:    0,
		Timestamp: time.Now().UTC(),
	}, nil
}

// StrikeRelay always fails. See ErrNoRelay.
func (d *TurnstileDriver) StrikeRelay(ctx context.Context, duration time.Duration) error {
	return ErrNoRelay
}

// SignalAccessGranted records that the caller has allowed access.
func (d *TurnstileDriver) SignalAccessGranted(ctx context.Context) error {
	d.Logger.Info("access granted (attested by sensor firmware)",
		"subject", d.Subject, "relay_signalled", false)
	return nil
}

// SignalAccessDenied records that the caller has denied access.
func (d *TurnstileDriver) SignalAccessDenied(ctx context.Context) error {
	d.Logger.Info("access denied", "subject", d.Subject, "relay_signalled", false)
	return nil
}

// IsOnline reports whether the last operation saw usable hardware. It is
// seeded from RequireReader at construction and updated on every poll, so a
// reader that disappears shows up as false after one failed cycle rather than
// never.
func (d *TurnstileDriver) IsOnline() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.online
}

// LastVerdict reports the most recent verification outcome. False before any
// verify has run, and after a deny.
func (d *TurnstileDriver) LastVerdict() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.lastVerd
}

// ProbePixelCount always returns 0, by design. It exists so a caller can log
// the distinction rather than assuming a populated HardwareEvent means a
// captured image.
func (d *TurnstileDriver) ProbePixelCount() int { return 0 }
