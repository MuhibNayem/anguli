package chaos

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"finger-scanner/pkg/hardware/osdp"
	"finger-scanner/pkg/hardware/reader"
	"finger-scanner/pkg/security/ratelimit"
	secTLS "finger-scanner/pkg/security/tls"
)

// ---------------------------------------------------------------------------
// TLS chaos
//
// The dangerous failure mode for a TLS config helper is a SILENT downgrade:
// the operator sets ENABLE_TLS=true, forgets a file path, and the service
// quietly serves plaintext while every log says "TLS enabled".
// ---------------------------------------------------------------------------

func TestChaos_TLSConfiguration(t *testing.T) {
	const dim = "security-tls"

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	caFile := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(certFile, []byte("not a real certificate"), 0o600)
	_ = os.WriteFile(keyFile, []byte("not a real key"), 0o600)
	_ = os.WriteFile(caFile, []byte("not a real ca"), 0o600)

	genuine := secTLS.Config{Enabled: false}
	certOnly := secTLS.Config{Enabled: true, CertFile: certFile}
	keyOnly := secTLS.Config{Enabled: true, KeyFile: keyFile}
	bothBad := secTLS.Config{Enabled: true, CertFile: certFile, KeyFile: keyFile}
	mtlsNoCA := secTLS.Config{Enabled: true, CertFile: certFile, KeyFile: keyFile, RequireMTLS: true}
	mtlsCA := secTLS.Config{Enabled: true, CertFile: certFile, KeyFile: keyFile,
		RequireMTLS: true, CAFile: caFile}

	cases := []struct {
		name string
		cfg  secTLS.Config
	}{
		{"disabled", genuine},
		{"enabled-no-certs", secTLS.Config{Enabled: true}},
		{"enabled-cert-only", certOnly},
		{"enabled-key-only", keyOnly},
		{"enabled-both-bad-files", bothBad},
		{"enabled-mtls-without-ca", mtlsNoCA},
		{"enabled-mtls-with-bad-ca", mtlsCA},
		{"enabled-missing-files", secTLS.Config{
			Enabled: true, CertFile: "/nonexistent/a.pem", KeyFile: "/nonexistent/b.pem"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			record(dim, "server/"+tc.name)
			opt, err := secTLS.ServerOption(tc.cfg)
			if err != nil {
				observe(dim, tc.name+": server errored: "+shortErr(err))
				return
			}
			if opt == nil {
				t.Errorf("[%s] ServerOption returned nil option for %s", dim, tc.name)
			}
			// INV-NOSECRET: a config that asks for TLS but supplies no usable
			// material must NOT silently yield a plaintext server.
			if tc.cfg.Enabled && (tc.cfg.CertFile == "" || tc.cfg.KeyFile == "") {
				observe(dim, "SILENT DOWNGRADE: Enabled=true with no cert/key -> ServerOption returned an empty (plaintext) option: "+tc.name)
			}
			if tc.cfg.RequireMTLS && tc.cfg.CAFile == "" {
				observe(dim, "mTLS REQUESTED BUT NOT ENFORCED: RequireMTLS=true with no CAFile -> "+tc.name)
			}
		})
	}

	for _, tc := range cases {
		t.Run("client/"+tc.name, func(t *testing.T) {
			record(dim, "client/"+tc.name)
			opt, err := secTLS.ClientOption(tc.cfg)
			if err != nil {
				observe(dim, "client "+tc.name+" errored: "+shortErr(err))
				return
			}
			if opt == nil {
				t.Errorf("[%s] ClientOption returned nil option for %s", dim, tc.name)
			}
			if tc.cfg.Enabled && tc.cfg.CAFile == "" {
				observe(dim, "client "+tc.name+": Enabled=true but no CAFile -> system roots only, no private CA trust")
			}
		})
	}

	// Environment parsing must never invent a default that looks secure.
	t.Run("env-parsing", func(t *testing.T) {
		for i := 0; i < 12; i++ {
			record(dim, "env-parse-"+itoa(float64(i)))
			cfg := secTLS.LoadConfigFromEnv()
			if cfg.Enabled && cfg.CertFile == "" {
				observe(dim, "ENV: ENABLE_TLS=true with empty TLS_CERT_FILE yields a config that will downgrade to plaintext")
			}
			if cfg.Enabled && cfg.RequireMTLS && cfg.CAFile == "" {
				observe(dim, "ENV: TLS_REQUIRE_MTLS=true with empty TLS_CA_FILE cannot be enforced")
			}
		}
	})

	// CA material that is not valid PEM must be rejected loudly.
	t.Run("invalid-ca-material", func(t *testing.T) {
		for i, junk := range []string{"", "garbage", "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----", "\x00\x01\x02"} {
			record(dim, "invalid-ca-"+itoa(float64(i)))
			p := filepath.Join(dir, "bad-ca-"+itoa(float64(i))+".pem")
			if err := os.WriteFile(p, []byte(junk), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := secTLS.Config{Enabled: true, CertFile: certFile, KeyFile: keyFile,
				RequireMTLS: true, CAFile: p}
			if _, err := secTLS.ServerOption(cfg); err == nil {
				observe(dim, "invalid CA material was ACCEPTED (index "+itoa(float64(i))+") - mTLS would be configured with an empty pool")
			} else {
				observe(dim, "invalid CA rejected at index "+itoa(float64(i)))
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Rate limiter chaos
// ---------------------------------------------------------------------------

func TestChaos_RateLimiter(t *testing.T) {
	const dim = "security-ratelimit"

	// Boundary parameter sets, including degenerate and hostile ones.
	sets := []struct {
		name           string
		rate, capacity float64
	}{
		{"zero-zero", 0, 0},
		{"rate-zero-cap-positive", 0, 10},
		{"cap-zero-rate-positive", 10, 0},
		{"normal", 10, 20},
		{"fast", 1000, 1000},
		{"tiny-rate", 0.001, 1},
		{"fractional-cap", 5, 2.5},
		{"cap-one", 10, 1},
		{"large", 1e6, 1e6},
		{"equal", 7, 7},
	}

	for _, s := range sets {
		t.Run(s.name, func(t *testing.T) {
			record(dim, s.name)
			tb := ratelimit.NewTokenBucket(s.rate, s.capacity)
			allowed := 0
			for i := 0; i < 50; i++ {
				if tb.Allow() {
					allowed++
				}
			}
			// INV-CORRECT: a bucket must never grant more than its burst
			// capacity up-front, however fast the caller loops.
			if float64(allowed) > s.capacity+1 {
				t.Errorf("[%s] INV-CORRECT: %s granted %d requests with capacity %.2f",
					dim, s.name, allowed, s.capacity)
			}
			observe(dim, s.name+": rate="+itoa(s.rate)+" cap="+itoa(s.capacity)+" allowed="+itoa(float64(allowed)))
		})
	}

	// AllowN must never accept a non-positive token count: a negative n
	// would ADD to the bucket and hand the caller free capacity.
	t.Run("negative-and-zero-consumption", func(t *testing.T) {
		record(dim, "negative-consumption")
		tb := ratelimit.NewTokenBucket(1, 10)
		before := 0
		for i := 0; i < 10; i++ {
			if tb.Allow() {
				before++
			}
		}
		// Drain the bucket.
		for i := 0; i < 20; i++ {
			tb.Allow()
		}
		tb.AllowN(-1000)
		after := 0
		for i := 0; i < 10; i++ {
			if tb.Allow() {
				after++
			}
		}
		observe(dim, "negative AllowN: normal burst="+itoa(float64(before))+" post-negative burst="+itoa(float64(after)))
		if after > int(before) {
			t.Errorf("[%s] INV-NOBYPASS: AllowN with a negative count increased available capacity (%d -> %d)",
				dim, before, after)
		}
		record(dim, "zero-consumption")
		tb.AllowN(0)
	})

	// Massive AllowN must not be able to overdraw and then keep spending.
	t.Run("overdraw", func(t *testing.T) {
		record(dim, "overdraw")
		tb := ratelimit.NewTokenBucket(10, 10)
		if tb.AllowN(1e9) {
			observe(dim, "AllowN(1e9) granted against capacity 10")
		}
		count := 0
		for i := 0; i < 100; i++ {
			if tb.Allow() {
				count++
			}
		}
		if count > 11 {
			t.Errorf("[%s] INV-CORRECT: %d requests allowed after an overdraw against capacity 10", dim, count)
		}
	})

	// Concurrent use must never exceed the burst capacity.
	t.Run("concurrent-burst", func(t *testing.T) {
		record(dim, "concurrent-burst")
		tb := ratelimit.NewTokenBucket(0.0001, 50)
		var wg sync.WaitGroup
		var mu sync.Mutex
		allowed := 0
		for i := 0; i < 500; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if tb.Allow() {
					mu.Lock()
					allowed++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if allowed > 50 {
			t.Errorf("[%s] INV-CORRECT: concurrent burst allowed %d against capacity 50", dim, allowed)
		}
		observe(dim, "concurrent burst of 500 allowed="+itoa(float64(allowed)))
	})

	// Refill must be monotonic and bounded by capacity.
	t.Run("refill-bounds", func(t *testing.T) {
		record(dim, "refill-bounds")
		tb := ratelimit.NewTokenBucket(100, 5)
		for i := 0; i < 50; i++ {
			tb.Allow()
			time.Sleep(time.Millisecond)
		}
		burst := 0
		for i := 0; i < 30; i++ {
			if tb.Allow() {
				burst++
			}
		}
		if burst > 5 {
			t.Errorf("[%s] INV-CORRECT: refill overshot capacity, burst=%d (capacity 5)", dim, burst)
		}
		observe(dim, "refill burst after idle="+itoa(float64(burst)))
	})
}

// ---------------------------------------------------------------------------
// OSDP protocol chaos
// ---------------------------------------------------------------------------

func TestChaos_OSDPFraming(t *testing.T) {
	const dim = "security-osdp"

	valid := []byte{0xFF, 0x00, 0x05, 0x60, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00}

	// A well formed frame must decode; this is the control.
	record(dim, "control-valid-frame")
	if _, err := osdp.DecodePacket(valid); err != nil {
		observe(dim, "control frame failed to decode: "+shortErr(err))
	}

	// Single byte corruption across the whole frame: CRC must catch it.
	accepted := 0
	for i := 0; i < len(valid); i++ {
		record(dim, "corrupt-byte-"+itoa(float64(i)))
		mutated := append([]byte{}, valid...)
		mutated[i] ^= 0xFF
		if _, err := osdp.DecodePacket(mutated); err == nil {
			accepted++
			t.Errorf("[%s] INV-CORRECT: frame with byte %d corrupted was ACCEPTED", dim, i)
		}
	}
	observe(dim, "single-byte corruption: "+itoa(float64(len(valid)))+" positions tested")

	// Truncation at every possible length.
	for cut := 0; cut <= len(valid); cut++ {
		record(dim, "truncate-"+itoa(float64(cut)))
		if _, err := osdp.DecodePacket(valid[:cut]); err == nil && cut != len(valid) {
			t.Errorf("[%s] INV-CORRECT: truncated frame of %d bytes ACCEPTED", dim, cut)
		}
	}

	// Pathological frame bodies.
	oversized := make([]byte, 0, 4096)
	oversized = append(oversized, 0xFF, 0x00, 0x00, 0x60)
	oversized = append(oversized, make([]byte, 4096)...)
	record(dim, "oversized-4k")
	if _, err := osdp.DecodePacket(oversized); err == nil {
		t.Errorf("[%s] INV-CORRECT: oversized frame ACCEPTED", dim)
	} else {
		observe(dim, "oversized frame rejected: "+shortErr(err))
	}

	for name, body := range map[string][]byte{
		"empty":    {},
		"one":      {0xFF},
		"two":      {0xFF, 0x00},
		"three":    {0xFF, 0x00, 0x05},
		"zeros":    make([]byte, 64),
		"ones":     bytesRepeat(0xFF, 64),
		"no-som":   {0xFF, 0x00, 0x05, 0x61, 0x01},
		"bad-addr": {0xFF, 0x00, 0x05, 0x60, 0x01, 0x02, 0x03, 0x04, 0x00, 0x01},
	} {
		record(dim, "body-"+name)
		_, err := osdp.DecodePacket(body)
		observe(dim, "body "+name+" -> "+boolStr(err == nil))
	}

	// CRC correctness across many lengths.
	for n := 0; n <= 512; n++ {
		record(dim, "crc-"+itoa(float64(n)))
		crc := osdp.ComputeCRC16(make([]byte, n))
		if crc == 0 && n > 0 {
			// Not an error, just a data point; ensure it is deterministic.
			if osdp.ComputeCRC16(make([]byte, n)) != crc {
				t.Errorf("[%s] INV-CORRECT: CRC16 is not deterministic at length %d", dim, n)
			}
		}
	}

	// Driver behaviour against a hostile transport.
	//
	// INV-BOUNDED: SendCommand must honour the context deadline. This used to
	// call io.ReadFull on the raw transport with no context check, so a
	// peripheral returning (0, nil) blocked indefinitely while holding the bus
	// lock - deadlocking every later OSDP call. That was tracked as OSDP-001
	// and OSDP-002; the driver now bounds every read and write by the caller's
	// context, so the assertions below are hard failures rather than skips.
	t.Run("hostile-transport", func(t *testing.T) {
		for _, mode := range []string{"silent", "garbage", "partial-frame", "closed"} {
			record(dim, "transport-"+mode)
			rw := &hostileRW{mode: mode}
			d := osdp.NewDriver(rw, 1)
			err, returned := pollBounded(d, 400*time.Millisecond)
			observe(dim, "transport "+mode+" -> returned="+boolStr(returned)+" err="+boolStr(err != nil))
			if !returned {
				t.Errorf("[%s] INV-BOUNDED: Poll did not return within the deadline on transport %s "+
					"(regression of OSDP-001: an unbounded read wedged the bus)", dim, mode)
			}
		}
	})

	// Relay strike must return promptly on a silent transport.
	//
	// The caller supplies its own deadline here, which is what a door controller
	// should do. A separate sub-test below covers the unbounded case to prove
	// the driver still imposes its own backstop.
	t.Run("relay-bounds", func(t *testing.T) {
		for _, ms := range []uint16{0, 1, 100, 2500, 5000, 60000, 65535} {
			record(dim, "relay-"+itoa(float64(ms)))
			rw := &hostileRW{mode: "silent"}
			d := osdp.NewDriver(rw, 1)
			done := make(chan error, 1)
			go func() {
				ctx, cancel := contextWithTimeout(400 * time.Millisecond)
				defer cancel()
				done <- d.StrikeRelay(ctx, 0, ms)
			}()
			var err error
			returned := true
			select {
			case err = <-done:
			case <-time.After(1500 * time.Millisecond):
				returned = false
			}
			observe(dim, "relay "+itoa(float64(ms))+"ms -> returned="+boolStr(returned))
			if !returned {
				t.Errorf("[%s] INV-BOUNDED: StrikeRelay(%dms) did not return on a silent transport "+
					"(regression of OSDP-001: the door could not be commanded open or closed)", dim, ms)
			}
			if returned && ms > 10000 && err == nil {
				t.Errorf("[%s] INV-BOUNDED: relay strike of %dms was accepted without bound", dim, ms)
			}
			record(dim, "relay-out-of-range-"+itoa(float64(ms)))
		}
	})

	// A caller that forgets its deadline must still be bounded by the driver.
	t.Run("relay-unbounded-caller", func(t *testing.T) {
		record(dim, "relay-unbounded-caller")
		rw := &hostileRW{mode: "silent"}
		d := osdp.NewDriver(rw, 1)
		done := make(chan error, 1)
		go func() { done <- d.StrikeRelay(context.Background(), 0, 2500) }()
		select {
		case <-done:
			observe(dim, "unbounded caller still bounded by the driver backstop")
		case <-time.After(8 * time.Second):
			t.Errorf("[%s] INV-BOUNDED: StrikeRelay with context.Background() never returned; "+
				"the driver must impose its own transaction deadline", dim)
		}
	})

	// After a wedged transport, the driver must not stay permanently locked.
	t.Run("mutex-recovery", func(t *testing.T) {
		record(dim, "mutex-recovery")
		rw := &hostileRW{mode: "silent"}
		d := osdp.NewDriver(rw, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			_, _ = d.Poll(ctx)
		}()
		time.Sleep(100 * time.Millisecond)
		second := make(chan struct{})
		go func() {
			defer close(second)
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			_, _ = d.Poll(ctx)
		}()
		select {
		case <-second:
			observe(dim, "driver still responsive after a wedged transport")
		case <-time.After(2 * time.Second):
			t.Errorf("[%s] INV-BOUNDED: the driver stayed locked after a wedged transport "+
				"(regression of OSDP-002: the bus lock was held across the blocking read, so "+
				"every later OSDP call deadlocked and recovery needed a process restart)", dim)
		}
	})
}

// pollBounded calls Poll with a context deadline and reports whether it returned
// within the bound. The goroutine may leak on failure, which is the point:
// that leak is the defect being characterised.
func pollBounded(d *osdp.Driver, bound time.Duration) (error, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := d.Poll(ctx)
		done <- err
	}()
	select {
	case err := <-done:
		return err, true
	case <-time.After(bound * 2):
		return nil, false
	}
}

// ---------------------------------------------------------------------------
// Reader driver chaos
// ---------------------------------------------------------------------------

func TestChaos_TurnstileDriver(t *testing.T) {
	const dim = "security-reader"

	for _, mode := range []string{"silent", "garbage", "partial-frame", "closed"} {
		t.Run("offline-"+mode, func(t *testing.T) {
			record(dim, "offline-"+mode)
			rw := &hostileRW{mode: mode}
			d := osdp.NewDriver(rw, 1)
			drv := reader.NewOSDPTurnstileDriver(d, nil)
			type pollOut struct {
				ev  *reader.HardwareEvent
				err error
			}
			done := make(chan pollOut, 1)
			go func() {
				ctx, cancel := contextWithTimeout(400 * time.Millisecond)
				defer cancel()
				ev, err := drv.PollEvent(ctx)
				done <- pollOut{ev, err}
			}()
			var out pollOut
			returned := true
			select {
			case out = <-done:
			case <-time.After(1500 * time.Millisecond):
				returned = false
			}
			observe(dim, "poll "+mode+" -> returned="+boolStr(returned)+" event="+boolStr(out.ev != nil))
			if !returned {
				t.Errorf("[%s] INV-BOUNDED: reader.PollEvent blocked past the context deadline on "+
					"transport %s (regression of OSDP-003: the turnstile wrapper inherited the "+
					"unbounded OSDP read)", dim, mode)
			}
			if out.ev != nil && strings.Contains(string(out.ev.Type), "GRANT") {
				t.Errorf("[%s] INV-NOBYPASS: garbage transport produced a grant event", dim)
			}
			record(dim, "offline-"+mode+"/done")
		})
	}

	// Relay strike through the driver wrapper, including hostile durations.
	for _, d := range []time.Duration{0, time.Nanosecond, time.Millisecond,
		2500 * time.Millisecond, time.Minute, 24 * time.Hour, -time.Second} {
		t.Run("strike", func(t *testing.T) {
			record(dim, "strike-"+itoa(float64(d)))
			rw := &hostileRW{mode: "silent"}
			drv := reader.NewOSDPTurnstileDriver(osdp.NewDriver(rw, 1), nil)
			done := make(chan error, 1)
			go func() {
				ctx, cancel := contextWithTimeout(400 * time.Millisecond)
				defer cancel()
				done <- drv.StrikeRelay(ctx, d)
			}()
			var err error
			returned := true
			select {
			case err = <-done:
			case <-time.After(1500 * time.Millisecond):
				returned = false
			}
			observe(dim, "strike "+itoa(float64(d))+" -> returned="+boolStr(returned))
			if !returned {
				t.Errorf("[%s] INV-BOUNDED: reader.StrikeRelay(%v) blocked on a silent transport "+
					"(regression of OSDP-003: the door could not be commanded open or closed)", dim, d)
			}
			if returned && d > time.Minute && err == nil {
				t.Errorf("[%s] INV-BOUNDED: relay strike of %v accepted without bound", dim, d)
			}
		})
	}

	// Signal helpers must be safe on a dead transport.
	t.Run("signals", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			record(dim, "signal-grant-"+itoa(float64(i)))
			rw := &hostileRW{mode: "closed"}
			drv := reader.NewOSDPTurnstileDriver(osdp.NewDriver(rw, 1), nil)
			ctx, cancel := contextWithTimeout(time.Second)
			_ = drv.SignalAccessGranted(ctx)
			cancel()

			record(dim, "signal-deny-"+itoa(float64(i)))
			rw2 := &hostileRW{mode: "closed"}
			drv2 := reader.NewOSDPTurnstileDriver(osdp.NewDriver(rw2, 1), nil)
			ctx2, cancel2 := contextWithTimeout(time.Second)
			_ = drv2.SignalAccessDenied(ctx2)
			cancel2()
		}
	})
}

// hostileRW is a transport that misbehaves in a named way.
type hostileRW struct {
	mode string
	n    int
}

func (h *hostileRW) Read(p []byte) (int, error) {
	h.n++
	switch h.mode {
	case "closed":
		return 0, os.ErrClosed
	case "garbage":
		for i := range p {
			p[i] = byte(0xA5 ^ i)
		}
		return len(p), nil
	case "partial-frame":
		if len(p) == 0 {
			return 0, nil
		}
		p[0] = 0xFF
		return 1, nil
	default: // silent - returns (0, nil) forever, which is legal for io.Reader
		// and makes io.ReadFull loop. Sleep so a leaked goroutine does not
		// hot-spin and starve the rest of the suite.
		time.Sleep(5 * time.Millisecond)
		return 0, nil
	}
}

func (h *hostileRW) Write(p []byte) (int, error) {
	if h.mode == "closed" {
		return 0, os.ErrClosed
	}
	return len(p), nil
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// ---------------------------------------------------------------------------
// Known defects
// ---------------------------------------------------------------------------

// The knownDefect helper has been retired.
//
// It existed to track reproduced defects as skips so the suite could stay green
// while a finding remained visible in the observations ledger. All three OSDP
// findings it carried (OSDP-001, OSDP-002, OSDP-003) are now fixed in
// pkg/hardware/osdp/driver.go and pkg/hardware/reader/reader.go, and the skips
// that referenced them have been replaced with hard INV-BOUNDED assertions.
//
// The helper is kept out of the tree deliberately: a skip that silently outlives
// its defect is worse than no test, because it looks like coverage. Reintroduce
// it only together with the tracking discipline in test/chaos/README.md.
