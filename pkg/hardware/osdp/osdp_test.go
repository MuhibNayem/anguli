package osdp_test

import (
	"bytes"
	"context"
	"testing"

	"finger-scanner/pkg/hardware/osdp"
)

// simulatedDevice emulates an OSDP v2 peripheral device over an in-memory duplex channel.
type simulatedDevice struct {
	inBuf  *bytes.Buffer
	outBuf *bytes.Buffer
}

func (s *simulatedDevice) Read(p []byte) (n int, err error) {
	return s.outBuf.Read(p)
}

func (s *simulatedDevice) Write(p []byte) (n int, err error) {
	pkt, err := osdp.DecodePacket(p)
	if err != nil {
		return 0, err
	}

	var replyCmd byte = osdp.ReplyAck
	var replyData []byte

	switch pkt.Command {
	case osdp.CmdPoll:
		replyCmd = osdp.ReplyAck
	case osdp.CmdOut:
		replyCmd = osdp.ReplyAck
	case osdp.CmdLed:
		replyCmd = osdp.ReplyAck
	case osdp.CmdBioRead:
		replyCmd = osdp.ReplyBioReadR
		replyData = []byte{0xDE, 0xAD, 0xBE, 0xEF} // Synthetic scan payload
	}

	replyPkt := &osdp.Packet{
		Address:  pkt.Address,
		Sequence: pkt.Sequence,
		UseCRC:   true,
		Command:  replyCmd,
		Data:     replyData,
	}

	encoded, err := replyPkt.Encode()
	if err != nil {
		return 0, err
	}

	return s.outBuf.Write(encoded)
}

func TestOSDPPacketEncodingAndCRC(t *testing.T) {
	pkt := &osdp.Packet{
		Address:  0x00,
		Sequence: 0x01,
		UseCRC:   true,
		Command:  osdp.CmdPoll,
		Data:     nil,
	}

	encoded, err := pkt.Encode()
	if err != nil {
		t.Fatalf("failed to encode packet: %v", err)
	}

	if encoded[0] != osdp.SOM {
		t.Errorf("expected SOM byte 0x53, got 0x%02X", encoded[0])
	}

	decoded, err := osdp.DecodePacket(encoded)
	if err != nil {
		t.Fatalf("failed to decode valid packet: %v", err)
	}

	if decoded.Command != osdp.CmdPoll {
		t.Errorf("expected CmdPoll 0x60, got 0x%02X", decoded.Command)
	}
	if decoded.Sequence != 0x01 {
		t.Errorf("expected sequence 0x01, got 0x%02X", decoded.Sequence)
	}
}

func TestOSDPDriver_PollAndRelayStrike(t *testing.T) {
	ctx := context.Background()
	dev := &simulatedDevice{
		inBuf:  &bytes.Buffer{},
		outBuf: &bytes.Buffer{},
	}

	driver := osdp.NewDriver(dev, 0x00)

	// Test Poll
	pollReply, err := driver.Poll(ctx)
	if err != nil {
		t.Fatalf("poll failed: %v", err)
	}
	if pollReply.Command != osdp.ReplyAck {
		t.Errorf("expected ReplyAck, got 0x%02X", pollReply.Command)
	}

	// Test Relay Strike (2500ms)
	if err := driver.StrikeRelay(ctx, 0x00, 2500); err != nil {
		t.Fatalf("strike relay failed: %v", err)
	}

	// Test Biometric Acquisition
	bioData, err := driver.RequestBiometricScan(ctx, 0x00, 0x02, osdp.BioFormatRawMinutiae)
	if err != nil {
		t.Fatalf("biometric scan failed: %v", err)
	}
	if len(bioData) != 4 || bioData[0] != 0xDE {
		t.Errorf("unexpected biometric scan data: %v", bioData)
	}
}
