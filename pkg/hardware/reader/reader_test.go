package reader_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"finger-scanner/pkg/hardware/osdp"
	"finger-scanner/pkg/hardware/reader"
)

type mockDuplex struct {
	out *bytes.Buffer
}

func (m *mockDuplex) Read(p []byte) (n int, err error) {
	return m.out.Read(p)
}

func (m *mockDuplex) Write(p []byte) (n int, err error) {
	pkt, _ := osdp.DecodePacket(p)
	reply := &osdp.Packet{
		Address:  pkt.Address,
		Sequence: pkt.Sequence,
		UseCRC:   true,
		Command:  osdp.ReplyAck,
	}
	enc, _ := reply.Encode()
	return m.out.Write(enc)
}

func TestTurnstileHardwareDriver_VisualAndRelay(t *testing.T) {
	ctx := context.Background()
	dev := &mockDuplex{out: &bytes.Buffer{}}
	osdpDrv := osdp.NewDriver(dev, 0x00)
	turnstile := reader.NewOSDPTurnstileDriver(osdpDrv, nil)

	if !turnstile.IsOnline() {
		t.Errorf("expected turnstile to report online")
	}

	if err := turnstile.StrikeRelay(ctx, 2500*time.Millisecond); err != nil {
		t.Fatalf("failed to strike relay: %v", err)
	}

	if err := turnstile.SignalAccessGranted(ctx); err != nil {
		t.Fatalf("failed to signal granted: %v", err)
	}

	if err := turnstile.SignalAccessDenied(ctx); err != nil {
		t.Fatalf("failed to signal denied: %v", err)
	}
}
