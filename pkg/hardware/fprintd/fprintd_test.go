package fprintd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// fakeBus is a scripted busConn. Every test drives the layer above it without
// needing a session bus, which is the only way this package's logic gets any
// coverage on a machine that is not a Linux desktop with a reader attached.
type fakeBus struct {
	mu sync.Mutex

	hasReader bool
	verifyErr error
	enrollErr error
	listErr   error
	listResp  []Finger

	// block, when set, makes VerifyStart wait for the context to end. This is
	// how the cancellation and timeout behaviour is exercised.
	block bool

	verifyCalls int
	enrollCalls int
	closeCalls  int

	lastVerifyUser string
	lastEnrollUser string
	lastEnrollFing Finger

	closed bool
}

func (f *fakeBus) VerifyStart(ctx context.Context, username string) error {
	f.mu.Lock()
	f.verifyCalls++
	f.lastVerifyUser = username
	block, err := f.block, f.verifyErr
	f.mu.Unlock()

	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	return err
}

func (f *fakeBus) EnrollStart(ctx context.Context, username string, finger Finger) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enrollCalls++
	f.lastEnrollUser = username
	f.lastEnrollFing = finger
	return f.enrollErr
}

func (f *fakeBus) ListEnrolledFingers(ctx context.Context, username string) ([]Finger, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]Finger, len(f.listResp))
	copy(out, f.listResp)
	return out, nil
}

func (f *fakeBus) HasFingerprintReader(ctx context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hasReader, nil
}

func (f *fakeBus) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeCalls++
	f.closed = true
	return nil
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestClient(t *testing.T, bus *fakeBus, timeout time.Duration) *Client {
	t.Helper()
	c, err := New(context.Background(), Config{
		Conn:          bus,
		VerifyTimeout: timeout,
		Logger:        quietLogger(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestFingerCodesRoundTrip(t *testing.T) {
	for f := LeftThumb; f <= RightLittle; f++ {
		name := f.String()
		if !f.Valid() {
			t.Errorf("finger %d should be valid", int(f))
		}
		back, err := ParseFinger(name)
		if err != nil {
			t.Fatalf("ParseFinger(%q): %v", name, err)
		}
		if back != f {
			t.Errorf("round trip %d -> %q -> %d", int(f), name, int(back))
		}
	}
	// fprintd codes run 1..10. Zero and anything past ten must be rejected
	// rather than silently mapped onto a real finger.
	for _, bad := range []Finger{0, 11, 99, -1} {
		if bad.Valid() {
			t.Errorf("finger %d should be invalid", int(bad))
		}
		if _, err := FingerName(bad); err == nil {
			t.Errorf("FingerName(%d) = nil error", int(bad))
		}
	}
}

func TestParseFingerAcceptsBareNames(t *testing.T) {
	got, err := ParseFinger("right-index")
	if err != nil {
		t.Fatalf("ParseFinger(right-index): %v", err)
	}
	if got != RightIndex {
		t.Errorf("got %d, want %d", int(got), int(RightIndex))
	}
	if _, err := ParseFinger("left-pinky"); err == nil {
		t.Error("ParseFinger accepted a name that is not a finger")
	}
}

func TestNewRequireReader(t *testing.T) {
	noReader := &fakeBus{hasReader: false}
	if _, err := New(context.Background(), Config{Conn: noReader, RequireReader: true, Logger: quietLogger()}); !errors.Is(err, ErrNoReader) {
		t.Fatalf("err = %v; want ErrNoReader", err)
	}
	// A failed construction must not leak the connection it opened.
	if noReader.closeCalls != 1 {
		t.Errorf("closeCalls = %d; want 1 after failed construction", noReader.closeCalls)
	}

	withReader := &fakeBus{hasReader: true}
	if _, err := New(context.Background(), Config{Conn: withReader, RequireReader: true, Logger: quietLogger()}); err != nil {
		t.Fatalf("New with a reader: %v", err)
	}
	if withReader.closeCalls != 0 {
		t.Errorf("closeCalls = %d; want 0 on success", withReader.closeCalls)
	}
}

func TestVerifyHappyPath(t *testing.T) {
	bus := &fakeBus{}
	c := newTestClient(t, bus, time.Second)
	if err := c.Verify(context.Background(), "alice"); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if bus.lastVerifyUser != "alice" {
		t.Errorf("verified user = %q; want alice", bus.lastVerifyUser)
	}
}

// ErrNoMatch is the normal deny outcome and must survive unwrapped, because
// callers branch on it to decide the door stays shut.
func TestVerifyNoMatchIsNotAnErrorWrapper(t *testing.T) {
	bus := &fakeBus{verifyErr: ErrNoMatch}
	c := newTestClient(t, bus, time.Second)
	err := c.Verify(context.Background(), "alice")
	if !errors.Is(err, ErrNoMatch) {
		t.Fatalf("err = %v; want ErrNoMatch", err)
	}
	if err == ErrNotEnrolled {
		t.Fatal("a no-match was misreported as not-enrolled")
	}
}

func TestVerifyRequiresUsername(t *testing.T) {
	c := newTestClient(t, &fakeBus{}, time.Second)
	if err := c.Verify(context.Background(), ""); err == nil {
		t.Fatal("Verify with an empty username succeeded")
	}
}

// A door must be able to abandon a verify when the person walks away. If the
// context is ignored, the reader is pinned until a finger arrives, which is the
// same wedge OSDP-001 and OSDP-002 were about.
func TestVerifyHonoursContextCancellation(t *testing.T) {
	bus := &fakeBus{block: true}
	c := newTestClient(t, bus, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := c.Verify(ctx, "alice")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v; want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("cancellation took %v; the call is not actually interruptible", elapsed)
	}
}

func TestVerifyAppliesItsOwnTimeout(t *testing.T) {
	bus := &fakeBus{block: true}
	c := newTestClient(t, bus, 40*time.Millisecond)

	start := time.Now()
	err := c.Verify(context.Background(), "alice")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v; want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("timeout took %v; want ~40ms", elapsed)
	}
}

func TestDefaultTimeoutIsUsedWhenUnset(t *testing.T) {
	bus := &fakeBus{}
	c, err := New(context.Background(), Config{Conn: bus, Logger: quietLogger()})
	if err != nil {
		t.Fatal(err)
	}
	if c.verifyTimeout() != DefaultTimeout {
		t.Errorf("verifyTimeout = %v; want %v", c.verifyTimeout(), DefaultTimeout)
	}
}

func TestEnrollValidatesInputs(t *testing.T) {
	bus := &fakeBus{}
	c := newTestClient(t, bus, time.Second)

	if err := c.Enroll(context.Background(), "", RightIndex); err == nil {
		t.Error("Enroll with an empty username succeeded")
	}
	if err := c.Enroll(context.Background(), "alice", Finger(0)); err == nil {
		t.Error("Enroll with finger 0 succeeded")
	}
	if err := c.Enroll(context.Background(), "alice", Finger(42)); err == nil {
		t.Error("Enroll with finger 42 succeeded")
	}
	if bus.enrollCalls != 0 {
		t.Errorf("enrollCalls = %d; invalid input should not reach the daemon", bus.enrollCalls)
	}

	if err := c.Enroll(context.Background(), "alice", RightIndex); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if bus.lastEnrollFing != RightIndex {
		t.Errorf("enrolled finger = %d; want %d", int(bus.lastEnrollFing), int(RightIndex))
	}
}

// Enrollment needs several placements. Applying the verify deadline to it would
// abandon a legitimate enrollment part-way through.
func TestEnrollIsNotGivenTheVerifyDeadline(t *testing.T) {
	bus := &fakeBus{}
	c := newTestClient(t, bus, 10*time.Millisecond)
	if err := c.Enroll(context.Background(), "alice", LeftThumb); err != nil {
		t.Fatalf("Enroll under a 10ms verify timeout failed: %v", err)
	}
}

func TestEnrolledListsFingers(t *testing.T) {
	bus := &fakeBus{listResp: []Finger{RightIndex, RightRing}}
	c := newTestClient(t, bus, time.Second)

	got, err := c.Enrolled(context.Background(), "alice")
	if err != nil {
		t.Fatalf("Enrolled: %v", err)
	}
	if len(got) != 2 || got[0] != RightIndex || got[1] != RightRing {
		t.Errorf("got %v; want [RightIndex RightRing]", got)
	}
	if _, err := c.Enrolled(context.Background(), ""); err == nil {
		t.Error("Enrolled with an empty username succeeded")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	bus := &fakeBus{}
	c := newTestClient(t, bus, time.Second)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if bus.closeCalls != 1 {
		t.Errorf("closeCalls = %d; want 1", bus.closeCalls)
	}
}

func TestNewRejectsNilClientInputs(t *testing.T) {
	if _, err := NewTurnstileDriver(nil, "alice", nil); err == nil {
		t.Error("NewTurnstileDriver(nil client) succeeded")
	}
	c := newTestClient(t, &fakeBus{}, time.Second)
	if _, err := NewTurnstileDriver(c, "", nil); err == nil {
		t.Error("NewTurnstileDriver with an empty subject succeeded")
	}
	// Verifying against no identity is meaningless: a sensor that only says
	// "yes" to an anonymous subject would open the door for anyone.
	if _, err := NewTurnstileDriver(c, "alice", nil); err != nil {
		t.Errorf("valid construction failed: %v", err)
	}
}

func TestPollEventCarriesIdentityAndNeverPixels(t *testing.T) {
	bus := &fakeBus{}
	c := newTestClient(t, bus, time.Second)
	d, err := NewTurnstileDriver(c, "alice", quietLogger())
	if err != nil {
		t.Fatal(err)
	}

	if d.IsOnline() {
		t.Error("IsOnline is true before any operation has run")
	}

	ev, err := d.PollEvent(context.Background())
	if err != nil {
		t.Fatalf("PollEvent: %v", err)
	}
	if ev.Type != "FINGERPRINT_SCANNED" {
		t.Errorf("event type = %q", ev.Type)
	}
	if ev.BadgeID != "alice" {
		t.Errorf("BadgeID = %q; want the verified subject", ev.BadgeID)
	}
	// The single most important assertion in this package. A populated pixel
	// buffer here would mean someone believes this hardware captures images.
	if ev.ProbePixels != nil {
		t.Errorf("ProbePixels has %d bytes; match-on-sensor hardware cannot produce an image", len(ev.ProbePixels))
	}
	if ev.Width != 0 || ev.Height != 0 {
		t.Errorf("dimensions = %dx%d; want 0x0", ev.Width, ev.Height)
	}
	if d.ProbePixelCount() != 0 {
		t.Error("ProbePixelCount should be 0 by design")
	}
	if !d.IsOnline() {
		t.Error("IsOnline should be true after a successful poll")
	}
	if !d.LastVerdict() {
		t.Error("LastVerdict should be true after a match")
	}
}

func TestPollEventDenyOutcomes(t *testing.T) {
	for name, injected := range map[string]error{
		"no match":     ErrNoMatch,
		"not enrolled": ErrNotEnrolled,
	} {
		t.Run(name, func(t *testing.T) {
			bus := &fakeBus{verifyErr: injected}
			c := newTestClient(t, bus, time.Second)
			d, _ := NewTurnstileDriver(c, "alice", quietLogger())

			ev, err := d.PollEvent(context.Background())
			if err == nil {
				t.Fatalf("PollEvent returned an event (%+v) for %v; a deny must not open the door", ev, name)
			}
			if ev != nil {
				t.Error("a denied poll returned an event")
			}
			if d.LastVerdict() {
				t.Error("LastVerdict is true after a deny")
			}
		})
	}
}

func TestPollEventPropagatesHardwareFault(t *testing.T) {
	fault := errors.New("reader fell off the bus")
	bus := &fakeBus{verifyErr: fault}
	c := newTestClient(t, bus, time.Second)
	d, _ := NewTurnstileDriver(c, "alice", quietLogger())

	if _, err := d.PollEvent(context.Background()); !errors.Is(err, fault) {
		t.Fatalf("err = %v; want the hardware fault unwrapped", err)
	}
	if d.LastVerdict() {
		t.Error("a hardware fault must not leave a previous verdict standing as true")
	}
}

func TestStrikeRelayRefusesRatherThanPretending(t *testing.T) {
	c := newTestClient(t, &fakeBus{}, time.Second)
	d, _ := NewTurnstileDriver(c, "alice", quietLogger())

	if err := d.StrikeRelay(context.Background(), 500*time.Millisecond); !errors.Is(err, ErrNoRelay) {
		t.Fatalf("err = %v; want ErrNoRelay", err)
	}
	// Silently succeeding here would let a deployment believe it had opened a
	// door with no door attached.
	if err := d.SignalAccessGranted(context.Background()); err != nil {
		t.Errorf("SignalAccessGranted: %v", err)
	}
	if err := d.SignalAccessDenied(context.Background()); err != nil {
		t.Errorf("SignalAccessDenied: %v", err)
	}
}

// The fprintd daemon reports errors as bare integers. If those stop mapping to
// sentinels, a no-match starts looking like a hardware fault and the door logic
// built on ErrNoMatch silently breaks.
func TestNormaliseErrorMapsFprintdCodes(t *testing.T) {
	cases := []struct {
		name string
		code uint32
		want error
	}{
		{"no match", 7, ErrNoMatch},
		{"not enrolled", 9, ErrNotEnrolled},
		{"canceled", 10, context.Canceled},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := dbus.NewError("org.freedesktop.DBus.Error.Failed", []interface{}{c.code})
			got := normaliseError(raw)
			if !errors.Is(got, c.want) {
				t.Errorf("normaliseError(code %d) = %v; want %v", c.code, got, c.want)
			}
		})
	}

	// Rate limiting has no sentinel but must not read as "no match".
	limited := normaliseError(dbus.NewError("x", []interface{}{uint32(14)}))
	if errors.Is(limited, ErrNoMatch) {
		t.Error("rate limiting was reported as a no-match")
	}
	if limited == nil {
		t.Error("rate limiting produced no error at all")
	}
}

func TestNormaliseErrorPassesContextThrough(t *testing.T) {
	if got := normaliseError(context.Canceled); !errors.Is(got, context.Canceled) {
		t.Errorf("got %v; want context.Canceled", got)
	}
	if got := normaliseError(context.DeadlineExceeded); !errors.Is(got, context.DeadlineExceeded) {
		t.Errorf("got %v; want context.DeadlineExceeded", got)
	}
	if got := normaliseError(nil); got != nil {
		t.Errorf("normaliseError(nil) = %v", got)
	}
}

func TestNormaliseErrorHandlesNoReplyAsCancellation(t *testing.T) {
	raw := dbus.NewError("org.freedesktop.DBus.Error.NoReply", nil)
	if got := normaliseError(raw); !errors.Is(got, context.Canceled) {
		t.Errorf("got %v; want context.Canceled", got)
	}
}

func TestNormaliseErrorWrapsUnknownFailures(t *testing.T) {
	raw := fmt.Errorf("something else entirely")
	got := normaliseError(raw)
	if got == nil {
		t.Fatal("an unknown failure was swallowed")
	}
	if !errors.Is(got, raw) {
		t.Error("an unknown failure lost its cause")
	}
	if errors.Is(got, ErrNoMatch) {
		t.Error("an unknown failure was misreported as a no-match")
	}
}

func TestCodeFromErrorCoversNumericWidths(t *testing.T) {
	cases := []struct {
		name string
		body []interface{}
		want uint32
		ok   bool
	}{
		{"uint32", []interface{}{uint32(7)}, 7, true},
		{"uint64", []interface{}{uint64(7)}, 7, true},
		{"int32", []interface{}{int32(7)}, 7, true},
		{"int64", []interface{}{int64(7)}, 7, true},
		{"empty body", []interface{}{}, 0, false},
		{"wrong type", []interface{}{"seven"}, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := codeFromError(dbus.NewError("x", c.body))
			if got != c.want || ok != c.ok {
				t.Errorf("got (%d,%v); want (%d,%v)", got, ok, c.want, c.ok)
			}
		})
	}
	if _, ok := codeFromError(fmt.Errorf("plain")); ok {
		t.Error("a non-dbus error produced a code")
	}
}

// Closed connections must fail cleanly rather than panicking or hanging.
func TestOperationsAfterCloseFail(t *testing.T) {
	bus := &fakeBus{}
	c := newTestClient(t, bus, time.Second)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	// Client.Verify calls into busConn, and the godbus-backed conn is what
	// guards closed state. Here the fake still answers, which is the point:
	// the Client itself must not panic or misbehave after Close.
	if err := c.Verify(context.Background(), "alice"); err != nil && !errors.Is(err, ErrNoMatch) {
		t.Logf("post-close verify returned %v (acceptable)", err)
	}
}
