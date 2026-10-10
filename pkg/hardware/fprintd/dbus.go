package fprintd

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/godbus/dbus/v5"
)

// fprintd's well-known names and paths.
const (
	busName    = "net.reactivated.Fprint"
	objectPath = dbus.ObjectPath("/net/reactivated/Fprint")

	deviceIface  = "net.reactivated.Fprint.Device"
	managerIface = "net.reactivated.Fprint.Manager"
)

// fprintd raises errors as bare integer codes rather than named D-Bus errors.
// These are the ones worth distinguishing; anything else is opaque.
const (
	fpErrNoMatch               uint32 = 7  // finger does not belong to the user
	fpErrNoMatchedEnrolledFing uint32 = 9  // nothing enrolled for this user
	fpErrCanceled              uint32 = 10 // cancelled by the client
	fpErrTooManyAttempts       uint32 = 14 // rate limited
)

// dbusConn is the godbus-backed busConn.
type dbusConn struct {
	conn *dbus.Conn
	obj  dbus.BusObject

	// mu guards the closed flag so Close can race safely with in-flight calls.
	mu     sync.Mutex
	closed bool
}

func dialSessionBus() (busConn, error) {
	// SessionBus fails for a system service, an SSH session, or a container.
	// That is the most common deployment mistake with fprintd, so it gets a
	// named error rather than a raw godbus one.
	conn, err := dbus.SessionBus()
	if err != nil {
		return nil, fmt.Errorf("%w: fprintd is a per-session service (%v)", ErrNoSubject, err)
	}
	return &dbusConn{conn: conn, obj: conn.Object(busName, objectPath)}, nil
}

func (d *dbusConn) ensureOpen() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return errors.New("fprintd: connection closed")
	}
	return nil
}

func (d *dbusConn) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	return d.conn.Close()
}

func (d *dbusConn) methodCall(ctx context.Context, method string, args ...interface{}) *dbus.Call {
	if ctx == nil {
		return d.obj.Call(method, 0, args...)
	}
	// CallWithContext registers the call with the bus, so a caller that gives
	// up actually interrupts fprintd rather than leaving it mid-operation to be
	// picked up by an unrelated later verify.
	return d.obj.CallWithContext(ctx, method, 0, args...)
}

func (d *dbusConn) VerifyStart(ctx context.Context, username string) error {
	if err := d.ensureOpen(); err != nil {
		return err
	}
	return normaliseError(d.methodCall(ctx, deviceIface+".VerifyStart", username).Err)
}

func (d *dbusConn) EnrollStart(ctx context.Context, username string, finger Finger) error {
	if err := d.ensureOpen(); err != nil {
		return err
	}
	return normaliseError(d.methodCall(ctx, deviceIface+".EnrollStart", username, finger.String()).Err)
}

func (d *dbusConn) ListEnrolledFingers(ctx context.Context, username string) ([]Finger, error) {
	if err := d.ensureOpen(); err != nil {
		return nil, err
	}
	call := d.methodCall(ctx, deviceIface+".ListEnrolledFingers", username)
	if call.Err != nil {
		return nil, normaliseError(call.Err)
	}

	// fprintd returns a list of structs carrying both the numeric code and its
	// name. Only the name is stable across releases, so it is what we key on.
	var raw []struct {
		Finger       string
		FingerString string
	}
	if err := call.Store(&raw); err != nil {
		return nil, fmt.Errorf("fprintd: decoding finger list: %w", err)
	}

	out := make([]Finger, 0, len(raw))
	for _, r := range raw {
		f, err := ParseFinger(r.FingerString)
		if err != nil {
			// A finger this build does not recognise must not abort the whole
			// listing. Skip it; the caller still sees everything understood.
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

func (d *dbusConn) HasFingerprintReader(ctx context.Context) (bool, error) {
	if err := d.ensureOpen(); err != nil {
		return false, err
	}
	v, err := d.obj.GetProperty(managerIface + ".HasFingerprintReader")
	if err != nil {
		return false, normaliseError(err)
	}
	b, ok := v.Value().(bool)
	if !ok {
		return false, fmt.Errorf("fprintd: HasFingerprintReader was %T, want bool", v.Value())
	}
	return b, nil
}

// asDBusError extracts a godbus error from a chain.
//
// It checks both the value and the pointer form. godbus's NewError returns a
// *Error while its own decode path produces a value, and errors.As only
// matches the exact type its target names. Handling only one form means a
// no-match silently degrades into an opaque error, which is precisely the bug
// this mapping exists to prevent.
func asDBusError(err error) (dbus.Error, bool) {
	var value dbus.Error
	if errors.As(err, &value) {
		return value, true
	}
	var pointer *dbus.Error
	if errors.As(err, &pointer) && pointer != nil {
		return *pointer, true
	}
	return dbus.Error{}, false
}

// normaliseError maps fprintd's numeric codes onto sentinels and passes
// context errors through untouched, so cancellation stays distinguishable from
// a hardware fault.
//
// It is deliberately a pure function of the error so it can be tested without
// a session bus, which is the only way this package's error handling gets any
// coverage on a developer machine.
func normaliseError(err error) error {
	if err == nil {
		return nil
	}
	// Cancellation first: it is the one case a caller must be able to act on,
	// and wrapping it would hide it behind a driver error.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}

	if code, ok := codeFromError(err); ok {
		switch code {
		case fpErrNoMatch:
			return ErrNoMatch
		case fpErrNoMatchedEnrolledFing:
			return ErrNotEnrolled
		case fpErrCanceled:
			return context.Canceled
		case fpErrTooManyAttempts:
			return fmt.Errorf("fprintd: rate limited by the daemon (code %d)", code)
		}
	}

	// fprintd reports a client-side cancellation as NoReply.
	if derr, ok := asDBusError(err); ok && derr.Name == "org.freedesktop.DBus.Error.NoReply" {
		return context.Canceled
	}

	return fmt.Errorf("fprintd: %w", err)
}

// codeFromError extracts fprintd's numeric error code.
//
// fprintd does not use named D-Bus errors; it raises a bare integer, so the
// code survives only as the first element of the error body. Reading the number
// rather than matching "No match" as text matters because the numbers are the
// daemon's contract and the wording has changed between releases.
func codeFromError(err error) (uint32, bool) {
	derr, ok := asDBusError(err)
	if !ok || len(derr.Body) == 0 {
		return 0, false
	}
	switch v := derr.Body[0].(type) {
	case uint32:
		return v, true
	case uint64:
		return uint32(v), true
	case int32:
		return uint32(v), true
	case int64:
		return uint32(v), true
	}
	return 0, false
}
