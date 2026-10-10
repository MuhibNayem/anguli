package osdp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrDeviceOffline = errors.New("OSDP peripheral device not responding to poll")
	ErrCommandNAK    = errors.New("OSDP peripheral device returned NAK")

	// ErrTransportPoisoned is returned when the underlying transport has been
	// abandoned mid-transaction. OSDP is a strict request/response protocol on a
	// shared bus: once a reply has been partially consumed we can no longer tell
	// frame boundaries apart, so every later call would misparse the stream.
	// Rather than attempt recovery we fail fast until the transport is rebuilt.
	ErrTransportPoisoned = errors.New("OSDP transport poisoned by an abandoned transaction; rebuild the driver")

	// ErrNoDeadlineTransport is a diagnostic sentinel describing the degraded
	// path taken when a transport cannot carry an I/O deadline.
	ErrNoDeadlineTransport = errors.New("transport does not support read deadlines; using context watchdog")
)

// BiometricFormat specifies format of biometric data requested.
type BiometricFormat byte

const (
	BioFormatRawMinutiae BiometricFormat = 0x01
	BioFormatRawImage    BiometricFormat = 0x02
	BioFormatCylinders   BiometricFormat = 0x03
)

// LEDCommand configures visual indicator state on reader.
type LEDCommand struct {
	ReaderNumber uint8
	LEDNumber    uint8
	TempMode     uint8 // 0x00=NOP, 0x01=Cancel temp, 0x02=Set temp
	TempOnTime   uint8 // in 100ms units
	TempOffTime  uint8
	TempOnColor  uint8 // 1=Red, 2=Green, 3=Amber, 4=Blue
	TempOffColor uint8
	TempTimer    uint16 // duration in 100ms units
	PermMode     uint8
	PermOnTime   uint8
	PermOffTime  uint8
	PermOnColor  uint8
	PermOffColor uint8
}

// defaultIOTimeout bounds a single transaction when the caller's context has
// no deadline of its own. A physical peripheral that never answers must not be
// able to hold the bus open indefinitely.
//
// Two seconds matches the reply window SIA OSDP deployments normally use, and
// keeps a door from feeling unresponsive when a reader drops off the bus. It is
// a backstop only: any caller that supplies its own deadline gets that instead.
const defaultIOTimeout = 2 * time.Second

// deadlineSetter is implemented by transports that can bound an I/O operation
// (net.Conn, os.File, and anything wrapping them). Preferring this over a
// watchdog goroutine means an abandoned read actually stops.
type deadlineSetter interface {
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// Driver manages an active RS-485 or serial connection to an OSDP reader.
//
// Concurrency model, and why it is this way:
//
//   - ioGate serialises transactions. OSDP is request/response on a shared bus,
//     so two concurrent commands would interleave and corrupt framing. It is a
//     channel rather than a sync.Mutex so waiters honour their own context
//     instead of piling up behind a slow device.
//   - statusMu guards isOnline only and is never held across I/O. Status
//     reporting must stay answerable even when the bus is wedged; previously
//     IsOnline() took the same mutex as the blocking read, so a single silent
//     peripheral froze the health check too.
//   - Every read and write is bounded by the caller's context. A peripheral that
//     returns (0, nil) forever can no longer wedge the driver.
type Driver struct {
	rw   io.ReadWriter
	addr byte

	// seq is guarded by ioGate.
	seq byte

	// ioGate is a capacity-1 semaphore serialising bus transactions.
	ioGate chan struct{}

	// statusMu guards isOnline and must never be held across I/O.
	statusMu sync.RWMutex
	isOnline bool

	// poisoned latches once the transport state is unrecoverable.
	poisoned atomic.Bool
}

// NewDriver creates an OSDP v2 peripheral controller on an underlying transport.
func NewDriver(rw io.ReadWriter, peripheralAddress byte) *Driver {
	d := &Driver{
		rw:       rw,
		addr:     peripheralAddress,
		seq:      0,
		isOnline: true,
		ioGate:   make(chan struct{}, 1),
	}
	d.ioGate <- struct{}{} // prime the semaphore as "free"
	return d
}

// setOnline records reachability without ever blocking on I/O.
func (d *Driver) setOnline(v bool) {
	d.statusMu.Lock()
	d.isOnline = v
	d.statusMu.Unlock()
}

// IsOnline reports the last observed reachability of the physical reader.
//
// This never blocks on the bus, so it stays answerable while a transaction is
// in flight or after the transport has been poisoned.
func (d *Driver) IsOnline() bool {
	d.statusMu.RLock()
	defer d.statusMu.RUnlock()
	return d.isOnline
}

// Poisoned reports whether the transport was abandoned mid-transaction.
func (d *Driver) Poisoned() bool { return d.poisoned.Load() }

// deadlineFor returns the deadline governing this transaction: the caller's if
// it set one, otherwise defaultIOTimeout so an unbounded context cannot pin the
// bus open forever. The returned cancel is always non-nil and must be called.
func deadlineFor(ctx context.Context) (deadline time.Time, bounded context.Context, cancel func()) {
	if dl, ok := ctx.Deadline(); ok {
		return dl, ctx, func() {}
	}
	c, cancelFn := context.WithTimeout(ctx, defaultIOTimeout)
	return time.Time{}, c, cancelFn
}

// writeFull writes the whole buffer, bounded by ctx.
func (d *Driver) writeFull(ctx context.Context, buf []byte) error {
	dl, bounded, cancel := deadlineFor(ctx)
	defer cancel()
	if ds, ok := d.rw.(deadlineSetter); ok && !dl.IsZero() {
		if err := ds.SetWriteDeadline(dl); err == nil {
			defer func() { _ = ds.SetWriteDeadline(time.Time{}) }()
		}
	}
	_, err := d.rw.Write(buf)
	if err != nil {
		return err
	}
	if _, ok := d.rw.(deadlineSetter); ok {
		return nil // the write was bounded by a real transport deadline
	}
	// No deadline support: confirm completion through the watchdog so a wedged
	// write cannot pin the bus.
	select {
	case <-bounded.Done():
		d.poisoned.Store(true)
		d.setOnline(false)
		return bounded.Err()
	default:
		return nil
	}
}

// readFull reads exactly len(buf), bounded by ctx.
//
// Transports that support deadlines are interrupted for real. Everything else
// falls back to a watchdog goroutine; in that case an abandoned read can leave
// the goroutine blocked, so the caller must poison the transport.
func (d *Driver) readFull(ctx context.Context, buf []byte) error {
	dl, bounded, cancel := deadlineFor(ctx)
	defer cancel()
	if ds, ok := d.rw.(deadlineSetter); ok {
		if !dl.IsZero() {
			if err := ds.SetReadDeadline(dl); err == nil {
				defer func() { _ = ds.SetReadDeadline(time.Time{}) }()
			}
		}
		_, err := io.ReadFull(d.rw, buf)
		return err
	}
	return d.watchdog(ctx, bounded, func() error {
		_, err := io.ReadFull(d.rw, buf)
		return err
	})
}

// watchdog runs fn on another goroutine and abandons it if ctx expires first.
// It reports whether the operation actually completed.
func (d *Driver) watchdog(ctx context.Context, bounded context.Context, fn func() error) error {
	type result struct{ err error }
	ch := make(chan result, 1)
	go func() { ch <- result{fn()} }()
	select {
	case r := <-ch:
		return r.err
	case <-bounded.Done():
		// The goroutine is still parked inside the transport. Since it may
		// resume at any moment and consume bytes from the bus, framing can no
		// longer be trusted.
		d.poisoned.Store(true)
		d.setOnline(false)
		return fmt.Errorf("%w (ctx: %v)", ctx.Err(), bounded.Err())
	}
}

// SendCommand sends an OSDP command packet and reads the peripheral device's reply.
//
// It always returns within the transaction deadline, even if the peripheral has
// stopped responding entirely.
func (d *Driver) SendCommand(ctx context.Context, cmd byte, data []byte) (*Packet, error) {
	if d.poisoned.Load() {
		return nil, ErrTransportPoisoned
	}

	// Serialise the transaction, but let a cancelled caller give up waiting.
	select {
	case <-d.ioGate:
	case <-ctx.Done():
		return nil, fmt.Errorf("waiting for OSDP bus: %w", ctx.Err())
	}
	defer func() { d.ioGate <- struct{}{} }()

	// Re-check under the gate: another caller may have poisoned while we queued.
	if d.poisoned.Load() {
		return nil, ErrTransportPoisoned
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	d.seq = (d.seq + 1) % 4
	pkt := &Packet{
		Address:  d.addr,
		Sequence: d.seq,
		UseCRC:   true,
		Command:  cmd,
		Data:     data,
	}

	raw, err := pkt.Encode()
	if err != nil {
		return nil, fmt.Errorf("packet encode failed: %w", err)
	}

	if err := d.writeFull(ctx, raw); err != nil {
		d.setOnline(false)
		return nil, fmt.Errorf("transport write failed: %w", err)
	}

	// Read reply frame.
	hdrBuf := make([]byte, 8)
	if err := d.readFull(ctx, hdrBuf); err != nil {
		d.setOnline(false)
		return nil, fmt.Errorf("reply read header failed: %w", err)
	}

	if hdrBuf[0] != SOM {
		d.setOnline(false)
		return nil, ErrInvalidSOM
	}

	pktLen := int(binary.LittleEndian.Uint16(hdrBuf[2:4]))
	if pktLen < 8 || pktLen > 1500 {
		return nil, fmt.Errorf("invalid reply length: %d", pktLen)
	}

	fullBuf := make([]byte, pktLen)
	copy(fullBuf[:8], hdrBuf)

	if pktLen > 8 {
		if err := d.readFull(ctx, fullBuf[8:]); err != nil {
			d.setOnline(false)
			return nil, fmt.Errorf("reply read payload failed: %w", err)
		}
	}

	reply, err := DecodePacket(fullBuf)
	if err != nil {
		return nil, fmt.Errorf("reply decode failed: %w", err)
	}

	if reply.Command == ReplyNak {
		return nil, ErrCommandNAK
	}

	d.setOnline(true)
	return reply, nil
}

// Poll sends an osdp_POLL keepalive and reads pending card/finger events.
func (d *Driver) Poll(ctx context.Context) (*Packet, error) {
	return d.SendCommand(ctx, CmdPoll, nil)
}

// StrikeRelay activates the turnstile output strike solenoid for durationMs milliseconds.
func (d *Driver) StrikeRelay(ctx context.Context, outputIndex byte, durationMs uint16) error {
	// osdp_OUT payload: output number (1), control code (1: 0x01=NOP, 0x02=Set/On, 0x05=Timed Set), timer (2)
	payload := make([]byte, 4)
	payload[0] = outputIndex
	payload[1] = 0x05                                           // Timed momentary pulse
	binary.LittleEndian.PutUint16(payload[2:4], durationMs/100) // 100ms units

	reply, err := d.SendCommand(ctx, CmdOut, payload)
	if err != nil {
		return err
	}
	if reply.Command != ReplyAck {
		return fmt.Errorf("unexpected reply to strike relay: 0x%02X", reply.Command)
	}
	return nil
}

// SetLED sets the biometric turnstile LED color and flash pattern.
func (d *Driver) SetLED(ctx context.Context, cmd LEDCommand) error {
	payload := make([]byte, 14)
	payload[0] = cmd.ReaderNumber
	payload[1] = cmd.LEDNumber
	payload[2] = cmd.TempMode
	payload[3] = cmd.TempOnTime
	payload[4] = cmd.TempOffTime
	payload[5] = cmd.TempOnColor
	payload[6] = cmd.TempOffColor
	binary.LittleEndian.PutUint16(payload[7:9], cmd.TempTimer)
	payload[9] = cmd.PermMode
	payload[10] = cmd.PermOnTime
	payload[11] = cmd.PermOffTime
	payload[12] = cmd.PermOnColor
	payload[13] = cmd.PermOffColor

	reply, err := d.SendCommand(ctx, CmdLed, payload)
	if err != nil {
		return err
	}
	if reply.Command != ReplyAck {
		return fmt.Errorf("unexpected reply to set LED: 0x%02X", reply.Command)
	}
	return nil
}

// RequestBiometricScan commands the reader to scan a fingerprint (osdp_BIOREAD).
func (d *Driver) RequestBiometricScan(ctx context.Context, readerNumber byte, bioType byte, format BiometricFormat) ([]byte, error) {
	payload := []byte{
		readerNumber,
		bioType, // 0x01 = Right thumb, 0x02 = Right index, etc.
		byte(format),
		0x00, // Quality threshold (0 = any)
	}

	reply, err := d.SendCommand(ctx, CmdBioRead, payload)
	if err != nil {
		return nil, err
	}

	if reply.Command == ReplyBioReadR {
		return reply.Data, nil
	}

	return nil, fmt.Errorf("unexpected reply to BIOREAD: 0x%02X", reply.Command)
}
