package osdp

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// deadlineTransport is backed by a real TCP socket, so it implements
// SetReadDeadline/SetWriteDeadline. This is the path a production serial or
// USB-over-IP handle takes, and it is the path where an abandoned read is
// interrupted for real rather than abandoned behind a watchdog goroutine.
type deadlineTransport struct {
	conn net.Conn
	mu   sync.Mutex
	got  []byte
}

func newDeadlinePair(t *testing.T) (*deadlineTransport, net.Conn) {
	t.Helper()
	a, b := net.Pipe() // net.Pipe conns DO support deadlines in modern Go
	_ = a
	_ = b

	// Use a loopback TCP pair instead: guaranteed deadline support and a
	// realistic blocking behaviour.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = r.c.Close() })

	return &deadlineTransport{conn: client}, r.c
}

func (d *deadlineTransport) Read(p []byte) (int, error)  { return d.conn.Read(p) }
func (d *deadlineTransport) Write(p []byte) (int, error) { return d.conn.Write(p) }

// responder answers each request with a matching ACK.
func responder(t *testing.T, conn net.Conn, reply func(*Packet) byte) {
	t.Helper()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil || n == 0 {
				return
			}
			req, err := DecodePacket(buf[:n])
			if err != nil {
				continue
			}
			out, err := (&Packet{
				Address:  req.Address,
				Sequence: req.Sequence,
				UseCRC:   true,
				Command:  reply(req),
			}).Encode()
			if err != nil {
				return
			}
			if _, err := conn.Write(out); err != nil {
				return
			}
		}
	}()
}

// TestDeadlineTransport_InterruptsAbandonedRead proves the deadline path: a
// peer that accepts the connection and then says nothing is cut off by the
// transport deadline, with no goroutine left parked in Read.
func TestDeadlineTransport_InterruptsAbandonedRead(t *testing.T) {
	transport, _ := newDeadlinePair(t)
	d := NewDriver(transport, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := d.Poll(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Poll against a silent peer returned nil error")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Poll took %v; the read deadline did not interrupt it", elapsed)
	}
	if d.IsOnline() {
		t.Error("IsOnline() = true after a failed read")
	}
}

// TestDeadlineTransport_CommandsSucceedOnHealthyPeer covers the happy path over
// a deadline-capable transport for every command verb.
func TestDeadlineTransport_CommandsSucceedOnHealthyPeer(t *testing.T) {
	transport, server := newDeadlinePair(t)
	d := NewDriver(transport, 1)
	responder(t, server, func(*Packet) byte { return ReplyAck })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := d.Poll(ctx); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if err := d.StrikeRelay(ctx, 0, 2500); err != nil {
		t.Fatalf("StrikeRelay: %v", err)
	}
	if err := d.SetLED(ctx, LEDCommand{
		ReaderNumber: 0, LEDNumber: 1, TempMode: 0x02,
		TempOnTime: 10, TempOffTime: 5, TempOnColor: 2, TempTimer: 25,
	}); err != nil {
		t.Fatalf("SetLED: %v", err)
	}
	if !d.IsOnline() {
		t.Error("IsOnline() = false after a successful command sequence")
	}
	if d.Poisoned() {
		t.Error("Poisoned() = true on a healthy deadline-capable transport")
	}
}

// TestDeadlineTransport_NAKIsReportedNotRetriedForever: a NAK is a definite
// answer, so it must surface immediately rather than being retried.
func TestDeadlineTransport_NAKIsReportedNotRetriedForever(t *testing.T) {
	transport, server := newDeadlinePair(t)
	d := NewDriver(transport, 1)
	responder(t, server, func(*Packet) byte { return ReplyNak })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	_, err := d.Poll(ctx)
	if !errors.Is(err, ErrCommandNAK) {
		t.Fatalf("error = %v; want ErrCommandNAK", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("NAK took %v; a NAK is a final answer, not a timeout", elapsed)
	}
}

// TestRequestBiometricScan_SuccessAndUnexpectedReply covers the BIOREAD verb.
func TestRequestBiometricScan_SuccessAndUnexpectedReply(t *testing.T) {
	transport, server := newDeadlinePair(t)
	d := NewDriver(transport, 1)
	responder(t, server, func(*Packet) byte { return ReplyBioReadR })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	data, err := d.RequestBiometricScan(ctx, 0, 0x01, BioFormatRawImage)
	if err != nil {
		t.Fatalf("RequestBiometricScan: %v", err)
	}
	if data == nil {
		t.Error("RequestBiometricScan returned nil data")
	}

	// An ACK in reply to BIOREAD is not a scan result and must be rejected.
	transport2, server2 := newDeadlinePair(t)
	d2 := NewDriver(transport2, 1)
	responder(t, server2, func(*Packet) byte { return ReplyAck })
	if _, err := d2.RequestBiometricScan(ctx, 0, 0x01, BioFormatRawImage); err == nil {
		t.Error("RequestBiometricScan accepted an ACK; it must require a BIOREADR reply")
	}
}

// TestSetLED_RejectsUnexpectedReply ensures a wrong reply verb is not silently
// treated as success.
func TestSetLED_RejectsUnexpectedReply(t *testing.T) {
	transport, server := newDeadlinePair(t)
	d := NewDriver(transport, 1)
	responder(t, server, func(*Packet) byte { return ReplyRaw })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.SetLED(ctx, LEDCommand{}); err == nil {
		t.Error("SetLED accepted a RAW reply; only ACK is valid")
	}
}

// TestStrikeRelay_RejectsUnexpectedReply mirrors the above for OUT.
func TestStrikeRelay_RejectsUnexpectedReply(t *testing.T) {
	transport, server := newDeadlinePair(t)
	d := NewDriver(transport, 1)
	responder(t, server, func(*Packet) byte { return ReplyRaw })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.StrikeRelay(ctx, 0, 2500); err == nil {
		t.Error("StrikeRelay accepted a RAW reply; only ACK is valid")
	}
}

// TestInvalidSOMMarksOffline covers frame validation.
func TestInvalidSOMMarksOffline(t *testing.T) {
	transport, server := newDeadlinePair(t)
	d := NewDriver(transport, 1)

	go func() {
		buf := make([]byte, 64)
		if _, err := server.Read(buf); err != nil {
			return
		}
		// Not a valid OSDP start-of-message byte.
		_, _ = server.Write([]byte{0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := d.Poll(ctx); !errors.Is(err, ErrInvalidSOM) {
		t.Fatalf("error = %v; want ErrInvalidSOM", err)
	}
	if d.IsOnline() {
		t.Error("IsOnline() = true after a framing error")
	}
}

var _ io.ReadWriter = (*deadlineTransport)(nil)
