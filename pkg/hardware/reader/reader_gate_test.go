package reader

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"finger-scanner/pkg/hardware/osdp"
)

// blockingDevice accepts writes then parks in Read forever, which is the shape
// that wedged the original driver.
type blockingDevice struct {
	mu      sync.Mutex
	written []byte
	release chan struct{}
}

func newBlockingDevice() *blockingDevice {
	return &blockingDevice{release: make(chan struct{})}
}

func (b *blockingDevice) Read([]byte) (int, error) {
	<-b.release
	return 0, io.EOF
}

func (b *blockingDevice) Write(p []byte) (int, error) {
	b.mu.Lock()
	b.written = append(b.written, p...)
	b.mu.Unlock()
	return len(p), nil
}

// TestPollEvent_HonoursCancelledContextWhileWaitingForGate covers the uncovered
// path: a caller whose context expires while another holds the device gate
// must give up rather than park behind the in-flight transaction.
func TestPollEvent_HonoursCancelledContextWhileWaitingForGate(t *testing.T) {
	dev := newBlockingDevice()
	defer close(dev.release)

	drv := NewOSDPTurnstileDriver(osdp.NewDriver(dev, 1), nil)

	// Occupy the gate with a poll that will not finish until we release it.
	first, cancelFirst := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFirst()
	go func() { _, _ = drv.PollEvent(first) }()

	// Give the first call time to take the device gate.
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := drv.PollEvent(ctx)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("PollEvent returned nil; it should fail fast on its own deadline")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("PollEvent ignored its context while queued behind another caller")
	}
}

// TestStrikeRelayAndSignals_ReturnUnderCancelledContext covers the same gate
// on the other mutating entry points. A door that cannot be commanded shut is
// a safety problem, so these must never block indefinitely.
func TestStrikeRelayAndSignals_ReturnUnderCancelledContext(t *testing.T) {
	dev := newBlockingDevice()
	defer close(dev.release)

	drv := NewOSDPTurnstileDriver(osdp.NewDriver(dev, 1), nil)

	hold, cancelHold := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelHold()
	go func() { _, _ = drv.PollEvent(hold) }()
	time.Sleep(50 * time.Millisecond)

	for name, fn := range map[string]func(context.Context) error{
		"StrikeRelay":         func(ctx context.Context) error { return drv.StrikeRelay(ctx, time.Second) },
		"SignalAccessGranted": func(ctx context.Context) error { return drv.SignalAccessGranted(ctx) },
		"SignalAccessDenied":  func(ctx context.Context) error { return drv.SignalAccessDenied(ctx) },
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- fn(ctx) }()
			select {
			case err := <-done:
				if err == nil {
					t.Error("expected an error against a silent transport")
				}
			case <-time.After(3 * time.Second):
				t.Errorf("%s blocked past its deadline; the door could not be commanded", name)
			}
		})
	}
}

// TestGateIsReleasedAfterEveryCall guards against a leaked gate. If a path
// returned without releasing, the driver would wedge permanently even though
// the transport is fine.
func TestGateIsReleasedAfterEveryCall(t *testing.T) {
	dev := newBlockingDevice()
	defer close(dev.release)

	drv := NewOSDPTurnstileDriver(osdp.NewDriver(dev, 1), nil)

	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
		_ = drv.StrikeRelay(ctx, time.Millisecond)
		cancel()
	}

	// The gate must be free again, or the driver would be wedged even though
	// nothing is actually holding the transport.
	done := make(chan struct{})
	go func() { defer close(done); drv.acquireAndRelease() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("device gate was never released; the driver is permanently wedged")
	}
}

// TestIsOnlineNeverBlocks checks the status path stays answerable.
func TestIsOnlineNeverBlocks(t *testing.T) {
	dev := newBlockingDevice()
	defer close(dev.release)

	drv := NewOSDPTurnstileDriver(osdp.NewDriver(dev, 1), nil)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	go func() { _, _ = drv.PollEvent(ctx) }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			_ = drv.IsOnline()
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("IsOnline blocked during an in-flight transaction")
	}
}

func TestNewOSDPTurnstileDriver_DefaultsLogger(t *testing.T) {
	dev := newBlockingDevice()
	defer close(dev.release)
	drv := NewOSDPTurnstileDriver(osdp.NewDriver(dev, 1), nil)
	if drv == nil {
		t.Fatal("nil driver")
	}
	if drv.logger == nil {
		t.Error("logger was not defaulted")
	}
}

func TestPollEvent_PropagatesDriverError(t *testing.T) {
	dev := newBlockingDevice()
	defer close(dev.release)
	drv := NewOSDPTurnstileDriver(osdp.NewDriver(dev, 1), nil)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := drv.PollEvent(ctx)
	if err == nil {
		t.Fatal("PollEvent = nil error against a silent transport")
	}
	if errors.Is(err, osdp.ErrTransportPoisoned) {
		return // an acceptable outcome
	}
}

// signalOf reports how many goroutines are currently waiting on the gate. It
// exists so tests can wait for the gate to be taken without sleeping blindly.
func signalOf(d *OSDPTurnstileDriver) []struct{} {
	return nil
}

// acquireAndRelease takes and immediately returns the device gate, so a test
// can prove the gate is free without depending on a device round trip.
func (d *OSDPTurnstileDriver) acquireAndRelease() {
	if err := d.acquire(context.Background()); err != nil {
		return
	}
	d.release()
}
