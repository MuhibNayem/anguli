package reader

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"finger-scanner/pkg/hardware/osdp"
)

// ReaderEventType denotes hardware reader events.
type ReaderEventType string

const (
	EventBadgePresented     ReaderEventType = "BADGE_PRESENTED"
	EventFingerprintScanned ReaderEventType = "FINGERPRINT_SCANNED"
	EventOpticalTamper      ReaderEventType = "OPTICAL_TAMPER"
)

// HardwareEvent represents a normalized event emitted by turnstile sensors.
type HardwareEvent struct {
	Type        ReaderEventType
	BadgeID     string
	ProbePixels []byte
	Width       uint32
	Height      uint32
	Timestamp   time.Time
}

// TurnstileHardwareDriver coordinates reader polling, biometrics, and relay triggers.
type TurnstileHardwareDriver interface {
	PollEvent(ctx context.Context) (*HardwareEvent, error)
	StrikeRelay(ctx context.Context, durationMs time.Duration) error
	SignalAccessGranted(ctx context.Context) error
	SignalAccessDenied(ctx context.Context) error
	IsOnline() bool
}

// OSDPTurnstileDriver implements TurnstileHardwareDriver using SIA OSDP v2.
type OSDPTurnstileDriver struct {
	osdpDriver *osdp.Driver
	logger     *slog.Logger
	// gate is a capacity-1 semaphore serialising physical-device operations.
	// A channel rather than a sync.Mutex so a caller whose context expires stops
	// waiting instead of parking behind an in-flight bus transaction.
	gate chan struct{}
}

// NewOSDPTurnstileDriver wraps an OSDP driver for door turnstiles.
func NewOSDPTurnstileDriver(driver *osdp.Driver, logger *slog.Logger) *OSDPTurnstileDriver {
	if logger == nil {
		logger = slog.Default()
	}
	d := &OSDPTurnstileDriver{
		osdpDriver: driver,
		logger:     logger,
		gate:       make(chan struct{}, 1),
	}
	d.gate <- struct{}{} // prime as "free"
	return d
}

// acquire takes the device gate, abandoning the wait if ctx expires.
func (d *OSDPTurnstileDriver) acquire(ctx context.Context) error {
	select {
	case <-d.gate:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("waiting for turnstile device: %w", ctx.Err())
	}
}

func (d *OSDPTurnstileDriver) release() { d.gate <- struct{}{} }

func (d *OSDPTurnstileDriver) PollEvent(ctx context.Context) (*HardwareEvent, error) {
	if err := d.acquire(ctx); err != nil {
		return nil, err
	}
	defer d.release()

	pkt, err := d.osdpDriver.Poll(ctx)
	if err != nil {
		return nil, fmt.Errorf("osdp poll error: %w", err)
	}

	if pkt.Command == osdp.ReplyRaw && len(pkt.Data) > 0 {
		return &HardwareEvent{
			Type:      EventBadgePresented,
			BadgeID:   fmt.Sprintf("CARD-%X", pkt.Data),
			Timestamp: time.Now(),
		}, nil
	}

	if pkt.Command == osdp.ReplyBioReadR && len(pkt.Data) > 0 {
		return &HardwareEvent{
			Type:        EventFingerprintScanned,
			ProbePixels: pkt.Data,
			Width:       200,
			Height:      200,
			Timestamp:   time.Now(),
		}, nil
	}

	return nil, nil // No pending event
}

func (d *OSDPTurnstileDriver) StrikeRelay(ctx context.Context, duration time.Duration) error {
	if err := d.acquire(ctx); err != nil {
		return err
	}
	defer d.release()

	ms := uint16(duration.Milliseconds())
	return d.osdpDriver.StrikeRelay(ctx, 0x00, ms)
}

func (d *OSDPTurnstileDriver) SignalAccessGranted(ctx context.Context) error {
	if err := d.acquire(ctx); err != nil {
		return err
	}
	defer d.release()

	// Green flash 2.5 seconds
	return d.osdpDriver.SetLED(ctx, osdp.LEDCommand{
		ReaderNumber: 0,
		LEDNumber:    0,
		TempMode:     0x02,
		TempOnTime:   25,
		TempOffTime:  0,
		TempOnColor:  2, // Green
		TempTimer:    25,
	})
}

func (d *OSDPTurnstileDriver) SignalAccessDenied(ctx context.Context) error {
	if err := d.acquire(ctx); err != nil {
		return err
	}
	defer d.release()

	// Red rapid flash 1.5 seconds
	return d.osdpDriver.SetLED(ctx, osdp.LEDCommand{
		ReaderNumber: 0,
		LEDNumber:    0,
		TempMode:     0x02,
		TempOnTime:   3,
		TempOffTime:  3,
		TempOnColor:  1, // Red
		TempTimer:    15,
	})
}

func (d *OSDPTurnstileDriver) IsOnline() bool {
	return d.osdpDriver.IsOnline()
}
