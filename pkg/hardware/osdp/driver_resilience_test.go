package osdp

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

// silentPeripheral models the exact failure the chaos suite found: a device
// that accepts writes and then returns (0, nil) from Read forever. It has no
// deadline support, so it exercises the watchdog path rather than a transport
// that can be interrupted natively.
type silentPeripheral struct {
	mu       sync.Mutex
	writes   [][]byte
	release  chan struct{} // closed to let an in-flight read return
	reading  bool
	readDone int
}

func newSilentPeripheral() *silentPeripheral {
	return &silentPeripheral{release: make(chan struct{})}
}

func (s *silentPeripheral) Read(p []byte) (int, error) {
	s.mu.Lock()
	s.reading = true
	s.mu.Unlock()
	<-s.release
	s.mu.Lock()
	s.readDone++
	s.reading = false
	s.mu.Unlock()
	return 0, io.EOF
}

func (s *silentPeripheral) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes = append(s.writes, append([]byte(nil), p...))
	return len(p), nil
}

// bounded runs fn and fails if it has not returned within d. This is the
// assertion that actually distinguishes "fixed" from "still wedged": the old
// implementation never returns, so the helper's own timeout is the failure.
func bounded(t *testing.T, name string, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %v: the driver is still wedged", name, d)
	}
}

// TestOSDP001_SilentPeripheralRespectsContext is the regression test for
// OSDP-001: Poll must honour the caller's deadline instead of parking forever
// inside io.ReadFull on a device that returns (0, nil).
func TestOSDP001_SilentPeripheralRespectsContext(t *testing.T) {
	dev := newSilentPeripheral()
	d := NewDriver(dev, 0x01)
	defer close(dev.release)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := d.Poll(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Poll on a silent peripheral returned nil error; expected a timeout failure")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Poll error = %v; want it to wrap context.DeadlineExceeded", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Poll took %v; expected it to return near the 150ms deadline", elapsed)
	}
}

// TestOSDP002_StatusStaysResponsiveAfterWedgedTransport covers OSDP-002. The
// old driver guarded isOnline with the same mutex held across the blocking
// read, so once wedged even IsOnline() deadlocked and no caller could observe
// that the device had gone away.
func TestOSDP002_StatusStaysResponsiveAfterWedgedTransport(t *testing.T) {
	dev := newSilentPeripheral()
	d := NewDriver(dev, 0x01)
	defer close(dev.release)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := d.Poll(ctx); err == nil {
		t.Fatal("expected Poll to fail against a silent peripheral")
	}

	bounded(t, "IsOnline after a wedged transport", 2*time.Second, func() {
		if d.IsOnline() {
			t.Error("IsOnline() = true after a transport failure; it must report offline")
		}
	})
}

// TestOSDP002b_SubsequentCallsFailFastNotDeadlock proves recovery is possible:
// once the bus is abandoned, later calls must fail immediately rather than
// queueing behind a transaction that will never finish.
func TestOSDP002b_SubsequentCallsFailFastNotDeadlock(t *testing.T) {
	dev := newSilentPeripheral()
	d := NewDriver(dev, 0x01)
	defer close(dev.release)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, _ = d.Poll(ctx)

	for i := 0; i < 5; i++ {
		bounded(t, "StrikeRelay after a wedged transport", 2*time.Second, func() {
			c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := d.StrikeRelay(c, 0x00, 250); err == nil {
				t.Error("StrikeRelay on a poisoned transport returned nil; want a hard failure")
			}
		})
	}

	if !d.Poisoned() {
		t.Error("Poisoned() = false after an abandoned read; the transport should be latched unusable")
	}
}

// TestOSDP_QueuedCallerHonoursItsOwnDeadline checks the bus gate: a caller
// waiting behind an in-flight transaction must abandon when its own context
// expires, rather than inheriting the other caller's timeline.
func TestOSDP_QueuedCallerHonoursItsOwnDeadline(t *testing.T) {
	dev := newSilentPeripheral()
	d := NewDriver(dev, 0x01)
	defer close(dev.release)

	// Occupy the bus with a long-lived transaction.
	first, cancelFirst := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelFirst()
	go func() { _, _ = d.Poll(first) }()

	// Give the first call time to take the gate.
	time.Sleep(50 * time.Millisecond)

	bounded(t, "queued caller", 2*time.Second, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, err := d.Poll(ctx)
		if err == nil {
			t.Error("queued Poll returned nil; want it to give up on its own deadline")
		}
	})
}

// TestOSDP_DefaultTimeoutWhenContextHasNoDeadline ensures an unbounded caller
// still cannot pin the bus open forever. Without this, a caller that forgets
// its deadline reintroduces OSDP-001 through the back door.
func TestOSDP_DefaultTimeoutWhenContextHasNoDeadline(t *testing.T) {
	if testing.Short() {
		t.Skip("uses the 5s default transaction timeout")
	}

	dev := newSilentPeripheral()
	d := NewDriver(dev, 0x01)
	defer close(dev.release)

	// context.Background() carries no deadline at all.
	bounded(t, "Poll with an unbounded context", 20*time.Second, func() {
		_, _ = d.Poll(context.Background())
	})
}

// TestOSDP_HealthyDeviceStillWorks guards against the resilience changes
// breaking the normal path: a responsive device must still poll and strike.
func TestOSDP_HealthyDeviceStillWorks(t *testing.T) {
	dev := newEchoDevice()
	d := NewDriver(dev, 0x01)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	bounded(t, "Poll against a healthy device", 5*time.Second, func() {
		reply, err := d.Poll(ctx)
		if err != nil {
			t.Fatalf("Poll against a healthy device failed: %v", err)
		}
		if reply.Command != ReplyAck {
			t.Fatalf("reply command = 0x%02X; want ACK", reply.Command)
		}
	})

	if !d.IsOnline() {
		t.Error("IsOnline() = false after a successful poll; should report online")
	}

	bounded(t, "StrikeRelay against a healthy device", 5*time.Second, func() {
		if err := d.StrikeRelay(ctx, 0x00, 250); err != nil {
			t.Fatalf("StrikeRelay against a healthy device failed: %v", err)
		}
	})

	if d.Poisoned() {
		t.Error("Poisoned() = true after healthy traffic; the transport is fine")
	}
}

// echoDevice is a responsive duplex transport: it decodes whatever the driver
// writes and answers with a matching ACK into the read side.
type echoDevice struct {
	mu  sync.Mutex
	out []byte
}

func newEchoDevice() *echoDevice { return &echoDevice{} }

func (e *echoDevice) Read(p []byte) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.out) == 0 {
		return 0, io.EOF
	}
	n := copy(p, e.out)
	e.out = e.out[n:]
	return n, nil
}

func (e *echoDevice) Write(p []byte) (int, error) {
	pkt, err := DecodePacket(p)
	if err != nil {
		return 0, err
	}
	reply, err := (&Packet{
		Address:  pkt.Address,
		Sequence: pkt.Sequence,
		UseCRC:   true,
		Command:  ReplyAck,
	}).Encode()
	if err != nil {
		return 0, err
	}
	e.mu.Lock()
	e.out = append(e.out, reply...)
	e.mu.Unlock()
	return len(p), nil
}

// TestOSDP_IsOnlineNeverBlocksUnderConcurrency exercises the status path while
// a transaction is mid-flight, which is where the original single-mutex design
// deadlocked.
func TestOSDP_IsOnlineNeverBlocksUnderConcurrency(t *testing.T) {
	dev := newSilentPeripheral()
	d := NewDriver(dev, 0x01)
	defer close(dev.release)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	go func() { _, _ = d.Poll(ctx) }()
	time.Sleep(20 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			_ = d.IsOnline()
		}
	}()
	bounded(t, "concurrent IsOnline during an in-flight transaction", 2*time.Second, func() {
		<-done
	})
}
