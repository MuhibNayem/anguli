package osdp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

var (
	ErrDeviceOffline = errors.New("OSDP peripheral device not responding to poll")
	ErrCommandNAK    = errors.New("OSDP peripheral device returned NAK")
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

// Driver manages an active RS-485 or serial connection to an OSDP reader.
type Driver struct {
	rw       io.ReadWriter
	addr     byte
	seq      byte
	mu       sync.Mutex
	isOnline bool
}

// NewDriver creates an OSDP v2 peripheral controller on an underlying transport.
func NewDriver(rw io.ReadWriter, peripheralAddress byte) *Driver {
	return &Driver{
		rw:       rw,
		addr:     peripheralAddress,
		seq:      0,
		isOnline: true,
	}
}

// SendCommand sends an OSDP command packet and reads the peripheral device's reply.
func (d *Driver) SendCommand(ctx context.Context, cmd byte, data []byte) (*Packet, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

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

	if _, err := d.rw.Write(raw); err != nil {
		d.isOnline = false
		return nil, fmt.Errorf("transport write failed: %w", err)
	}

	// Read reply frame
	hdrBuf := make([]byte, 8)
	if _, err := io.ReadFull(d.rw, hdrBuf); err != nil {
		d.isOnline = false
		return nil, fmt.Errorf("reply read header failed: %w", err)
	}

	if hdrBuf[0] != SOM {
		d.isOnline = false
		return nil, ErrInvalidSOM
	}

	pktLen := int(binary.LittleEndian.Uint16(hdrBuf[2:4]))
	if pktLen < 8 || pktLen > 1500 {
		return nil, fmt.Errorf("invalid reply length: %d", pktLen)
	}

	fullBuf := make([]byte, pktLen)
	copy(fullBuf[:8], hdrBuf)

	if pktLen > 8 {
		if _, err := io.ReadFull(d.rw, fullBuf[8:]); err != nil {
			d.isOnline = false
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

	d.isOnline = true
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
	payload[1] = 0x05 // Timed momentary pulse
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

// IsOnline returns the live connection status of the physical reader.
func (d *Driver) IsOnline() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.isOnline
}
