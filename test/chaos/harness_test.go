// Package chaos contains cross-service robustness (chaos) testing for the
// AegisBiometrics platform.
//
// These tests deliberately abuse the system: malformed images, degraded
// fingerprints, hostile inputs, dependency outages and extreme concurrency.
// The goal is NOT to assert ideal behaviour on every input. The goal is to
// assert a small set of hard invariants that must never break:
//
//  1. INV-NOPANIC   - no RPC or algorithm may panic on any input.
//  2. INV-BOUNDED   - no unbounded memory or time consumption.
//  3. INV-NOSECRET  - templates must never be returned in plaintext.
//  4. INV-NOBYPASS  - no input may produce an unauthorized grant.
//  5. INV-CORRECT   - malformed input must be rejected, not silently accepted.
//
// Accuracy characteristics (monotonicity of match scores, FAR/FRR behaviour)
// are measured and reported through the findings ledger rather than asserted,
// because several are known to be imperfect and are tracked separately.
package chaos

import (
	"context"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
	biometricsv1 "finger-scanner/pkg/api/v1/biometrics"
	edgegatewayv1 "finger-scanner/pkg/api/v1/edgegateway"
	accesspolicyservice "finger-scanner/services/access-policy-service"
	biometricservice "finger-scanner/services/biometric-service"
	edgegatewayservice "finger-scanner/services/edge-gateway-service"
)

// ---------------------------------------------------------------------------
// Case counter / findings ledger
// ---------------------------------------------------------------------------

type ledger struct {
	mu      sync.Mutex
	byDim   map[string]int
	total   atomic.Int64
	finding map[string][]string
}

var L = &ledger{
	byDim:   make(map[string]int),
	finding: make(map[string][]string),
}

// record registers that one chaos case was executed.
func record(dim, name string) {
	L.mu.Lock()
	L.byDim[dim]++
	L.mu.Unlock()
	L.total.Add(1)
	_ = name
}

// observe records a non-fatal finding (an accuracy or robustness observation
// that is tracked rather than asserted).
func observe(dim, msg string) {
	L.mu.Lock()
	defer L.mu.Unlock()
	if len(L.finding[dim]) < 40 {
		L.finding[dim] = append(L.finding[dim], msg)
	}
}

// CaseCount returns the number of chaos cases executed so far.
func CaseCount() int { return int(L.total.Load()) }

func dimensionCounts() map[string]int {
	L.mu.Lock()
	defer L.mu.Unlock()
	out := make(map[string]int, len(L.byDim))
	for k, v := range L.byDim {
		out[k] = v
	}
	return out
}

// dumpLedgerW writes the full dimension breakdown and findings to w.
func dumpLedgerW(w io.Writer) {
	dims := dimensionCounts()
	keys := make([]string, 0, len(dims))
	for k := range dims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintln(w, "---- CHAOS DIMENSION BREAKDOWN ----")
	for _, k := range keys {
		fmt.Fprintf(w, "  %-34s %5d cases\n", k, dims[k])
	}
	fmt.Fprintf(w, "  %-34s %5d TOTAL\n", "ALL DIMENSIONS", CaseCount())

	L.mu.Lock()
	defer L.mu.Unlock()
	fkeys := make([]string, 0, len(L.finding))
	for k := range L.finding {
		fkeys = append(fkeys, k)
	}
	sort.Strings(fkeys)
	if len(fkeys) > 0 {
		fmt.Fprintln(w, "---- OBSERVATIONS (tracked, not asserted) ----")
		for _, k := range fkeys {
			fmt.Fprintf(w, "  [%s]\n", k)
			for _, m := range L.finding[k] {
				fmt.Fprintf(w, "     - %s\n", m)
			}
		}
	}
}

// dumpLedger writes the ledger through the test log.
func dumpLedger(t *testing.T) {
	dumpLedgerW(log.Writer())
}

// ---------------------------------------------------------------------------
// Service cluster fixture
// ---------------------------------------------------------------------------

// Cluster holds in-process gRPC servers standing in for the three backend
// services. Using real gRPC servers (rather than direct struct calls) means
// every chaos case exercises the actual transport, codec and handler layer.
type Cluster struct {
	Bio    biometricsv1.BiometricsServiceClient
	Policy accesscontrolv1.AccessPolicyServiceClient
	Edge   edgegatewayv1.EdgeGatewayServiceClient
}

// grpcServer creates a listener and a gRPC server WITHOUT starting Serve, so
// that services can be registered first (grpc forbids registering after Serve).
func grpcServer(t *testing.T) (*grpc.Server, net.Listener) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return grpc.NewServer(), ln
}

// serve starts the gRPC server in the background.
func serve(t *testing.T, s *grpc.Server, ln net.Listener) {
	t.Helper()
	go func() { _ = s.Serve(ln) }()
}

func dial(t *testing.T, addr string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	return conn
}

// NewBioCluster starts an isolated biometric service.
func NewBioCluster(t *testing.T) *Cluster {
	t.Helper()
	srv, ln := grpcServer(t)
	if err := biometricservice.RegisterService(srv, []byte(TestMasterKey), nil); err != nil {
		t.Fatalf("register biometric: %v", err)
	}
	serve(t, srv, ln)
	conn := dial(t, ln.Addr().String())
	t.Cleanup(func() { conn.Close(); srv.Stop() })
	return &Cluster{Bio: biometricsv1.NewBiometricsServiceClient(conn)}
}

// NewPolicyCluster starts an isolated access policy service.
func NewPolicyCluster(t *testing.T) *Cluster {
	t.Helper()
	srv, ln := grpcServer(t)
	accesspolicyservice.RegisterService(srv, nil)
	serve(t, srv, ln)
	conn := dial(t, ln.Addr().String())
	t.Cleanup(func() { conn.Close(); srv.Stop() })
	return &Cluster{Policy: accesscontrolv1.NewAccessPolicyServiceClient(conn)}
}

// NewFullCluster starts biometric + policy + edge (edge wired to policy).
func NewFullCluster(t *testing.T) *Cluster {
	t.Helper()
	psrv, pln := grpcServer(t)
	accesspolicyservice.RegisterService(psrv, nil)
	serve(t, psrv, pln)
	pconn := dial(t, pln.Addr().String())

	esrv, eln := grpcServer(t)
	edgegatewayservice.RegisterServiceWithPolicy(
		esrv, accesscontrolv1.NewAccessPolicyServiceClient(pconn), nil)
	serve(t, esrv, eln)
	econn := dial(t, eln.Addr().String())

	bsrv, bln := grpcServer(t)
	if err := biometricservice.RegisterService(bsrv, []byte(TestMasterKey), nil); err != nil {
		t.Fatalf("register biometric: %v", err)
	}
	serve(t, bsrv, bln)
	bconn := dial(t, bln.Addr().String())

	t.Cleanup(func() {
		bconn.Close()
		econn.Close()
		pconn.Close()
		bsrv.Stop()
		esrv.Stop()
		psrv.Stop()
	})
	return &Cluster{
		Bio:    biometricsv1.NewBiometricsServiceClient(bconn),
		Policy: accesscontrolv1.NewAccessPolicyServiceClient(pconn),
		Edge:   edgegatewayv1.NewEdgeGatewayServiceClient(econn),
	}
}

// TestMasterKey is a 32-byte key used only by tests.
const TestMasterKey = "0123456789abcdef0123456789abcdef"

// ctxFor returns a bounded context so no chaos case can hang the suite.
func ctxFor(t *testing.T, d time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), d)
}

// ---------------------------------------------------------------------------
// Synthetic print generation
// ---------------------------------------------------------------------------

// SyntheticPrint produces a deterministic ridge pattern.
func SyntheticPrint(w, h int, seed int64) []byte {
	pix := make([]byte, w*h)
	for i := range pix {
		pix[i] = 200
	}
	rng := rand.New(rand.NewSource(seed))
	spacing := 5 + rng.Intn(3)
	for r := spacing; r < h-spacing; r += spacing {
		for c := spacing; c < w-spacing; c++ {
			if (c+int(seed))%29 == 0 {
				continue
			}
			if (r+c+int(seed))%47 == 0 && r+2 < h-spacing {
				pix[(r+2)*w+c] = 45
			}
			pix[r*w+c] = 45
			if r+1 < h {
				pix[(r+1)*w+c] = 55
			}
		}
	}
	return pix
}

// LoopPrint generates a fingerprint-like print that carries genuine spatial
// structure: a core with radiating ridge flow, angular radius modulation and a
// per-angle phase offset, so minutiae land in characteristic positions.
//
// This matters for chaos testing. A naive "uniform parallel ridges" generator
// is DEGENERATE: every local neighbourhood looks identical, every MCC cylinder
// looks alike, and the matcher reports 100% matched pairs for structurally
// different inputs. That produces false alarms that train people to ignore the
// suite. LoopPrint keeps the local neighbourhoods distinguishable so that a
// rejected probe means something.
func LoopPrint(w, h int, cx, cy, period float64, seed int64) []byte {
	pix := make([]byte, w*h)
	for i := range pix {
		pix[i] = 205
	}
	rng := rand.New(rand.NewSource(seed))
	phase := make([]float64, 360)
	for i := range phase {
		phase[i] = rng.Float64() * period
	}
	ratioX := 1.0 + 0.35*rng.Float64()
	ratioY := 1.0 + 0.35*rng.Float64()
	tilt := rng.Float64() * 2 * math.Pi

	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			dx := (float64(x) - cx) / ratioX
			dy := (float64(y) - cy) / ratioY
			xx := dx*math.Cos(tilt) - dy*math.Sin(tilt)
			yy := dx*math.Sin(tilt) + dy*math.Cos(tilt)
			r := math.Hypot(xx, yy)
			th := math.Atan2(yy, xx)
			if th < 0 {
				th += 2 * math.Pi
			}
			mod := 1.0 + 0.22*math.Sin(3*th+float64(seed))
			rr := r * mod
			idx := int(th/math.Pi*180) % 360
			v := math.Mod(rr, period) + phase[idx]
			if math.Mod(v, period) < period*0.5 {
				pix[y*w+x] = 45
			}
		}
	}
	return pix
}

// LoopCorpus builds n structurally distinct fingerprint-like prints that can
// legitimately be used as an imposter cohort.
func LoopCorpus(w, h, n int) [][]byte {
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		s := int64(100 + i*37)
		cx := float64(w) * (0.30 + 0.40*rng01(s))
		cy := float64(h) * (0.30 + 0.40*rng01(s+1))
		per := 7.0 + 4.0*rng01(s+2)
		out[i] = LoopPrint(w, h, cx, cy, per, s)
	}
	return out
}

func rng01(seed int64) float64 {
	r := rand.New(rand.NewSource(seed))
	return r.Float64()
}

// ImpPrint produces a structurally different print (orthogonal ridge flow).
// NOTE: this is a DEGENERATE pattern - see TestChaos_DegeneratePatterns for the
// characterised saturation behaviour it provokes.
func ImpPrint(w, h int, seed int64) []byte {
	pix := make([]byte, w*h)
	for i := range pix {
		pix[i] = 195
	}
	for c := 18; c < w-18; c += 7 {
		for r := 18; r < h-18; r++ {
			if (r+int(seed))%31 == 0 {
				continue
			}
			pix[r*w+c] = 45
			if c+1 < w {
				pix[r*w+c+1] = 55
			}
		}
	}
	return pix
}

// ---------------------------------------------------------------------------
// Image degradation operators (all are pure, all preserve w*h length)
// ---------------------------------------------------------------------------

func clamp8(v float64) uint8 {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return uint8(v)
}

// GaussianBlur applies a separable Gaussian blur.
func GaussianBlur(src []byte, w, h int, sigma float64) []byte {
	if sigma <= 0 || len(src) == 0 {
		return src
	}
	r := int(math.Ceil(sigma * 3))
	if r < 1 {
		r = 1
	}
	k := make([]float64, 2*r+1)
	var sum float64
	for i := -r; i <= r; i++ {
		k[i+r] = math.Exp(-float64(i*i) / (2 * sigma * sigma))
		sum += k[i+r]
	}
	for i := range k {
		k[i] /= sum
	}
	tmp := make([]float64, w*h)
	out := make([]byte, w*h)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			var s float64
			for i := -r; i <= r; i++ {
				xx := x + i
				if xx < 0 {
					xx = 0
				}
				if xx >= w {
					xx = w - 1
				}
				s += k[i+r] * float64(src[y*w+xx])
			}
			tmp[y*w+x] = s
		}
	}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			var s float64
			for i := -r; i <= r; i++ {
				yy := y + i
				if yy < 0 {
					yy = 0
				}
				if yy >= h {
					yy = h - 1
				}
				s += k[i+r] * tmp[yy*w+x]
			}
			out[y*w+x] = clamp8(s)
		}
	}
	return out
}

// MotionBlur applies horizontal directional blur.
func MotionBlur(src []byte, w, h, span int) []byte {
	out := make([]byte, len(src))
	copy(out, src)
	if span < 2 {
		return out
	}
	half := span / 2
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			var s float64
			n := 0
			for i := -half; i <= half; i++ {
				xx := x + i
				if xx < 0 || xx >= w {
					continue
				}
				s += float64(src[y*w+xx])
				n++
			}
			if n > 0 {
				out[y*w+x] = clamp8(s / float64(n))
			}
		}
	}
	return out
}

// Oily simulates reduced ridge contrast from a greasy finger. The pipeline's
// Normalize stage is expected to absorb global contrast loss.
func Oily(src []byte, w, h int, sigma, contrast float64) []byte {
	b := GaussianBlur(src, w, h, sigma)
	var sum float64
	for _, v := range b {
		sum += float64(v)
	}
	if len(b) == 0 {
		return b
	}
	mean := sum / float64(len(b))
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = clamp8(mean + (float64(v)-mean)*contrast)
	}
	return out
}

// Wet simulates a wet finger: blur plus a specular highlight blob.
func Wet(src []byte, w, h int, sigma float64, cx, cy, rad float64) []byte {
	b := GaussianBlur(src, w, h, sigma)
	out := make([]byte, len(b))
	copy(out, b)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			d := math.Hypot(float64(x)-cx, float64(y)-cy)
			if d < rad {
				out[y*w+x] = clamp8(float64(out[y*w+x]) + (1-d/rad)*150)
			}
		}
	}
	return out
}

// Dry simulates a dry finger: random ridge erosion breaking ridges apart.
func Dry(src []byte, threshold uint8, prob float64, seed int64) []byte {
	out := make([]byte, len(src))
	copy(out, src)
	rng := rand.New(rand.NewSource(seed))
	for i, v := range src {
		if v < threshold && rng.Float64() < prob {
			out[i] = clamp8(170 + float64(rng.Intn(50)))
		}
	}
	return out
}

// Partial crops a fraction of the image, leaving the remainder background.
// The result is always the same buffer length.
func Partial(src []byte, w, h int, frac float64) []byte {
	out := make([]byte, w*h)
	for i := range out {
		out[i] = 200
	}
	w2 := int(float64(w) * frac)
	if w2 > w {
		w2 = w
	}
	copy(out[:w2*h], src[:w2*h])
	return out
}

// GaussianNoise adds zero-mean Gaussian noise.
func GaussianNoise(src []byte, sigma float64, seed int64) []byte {
	rng := rand.New(rand.NewSource(seed))
	out := make([]byte, len(src))
	for i, v := range src {
		out[i] = clamp8(float64(v) + rng.NormFloat64()*sigma)
	}
	return out
}

// Rotate rotates the image about its centre (nearest neighbour).
func Rotate(src []byte, w, h int, deg float64) []byte {
	if deg == 0 {
		out := make([]byte, len(src))
		copy(out, src)
		return out
	}
	rad := deg * math.Pi / 180
	cs, sn := math.Cos(rad), math.Sin(rad)
	cx, cy := float64(w)/2, float64(h)/2
	out := make([]byte, w*h)
	for i := range out {
		out[i] = 200
	}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			fx, fy := float64(x)-cx, float64(y)-cy
			sx := int(math.Round(fx*cs + fy*sn + cx))
			sy := int(math.Round(-fx*sn + fy*cs + cy))
			if sx < 0 || sx >= w || sy < 0 || sy >= h {
				continue
			}
			out[y*w+x] = src[sy*w+sx]
		}
	}
	return out
}

// Shift translates the image by (dx,dy).
func Shift(src []byte, w, h, dx, dy int) []byte {
	out := make([]byte, w*h)
	for i := range out {
		out[i] = 200
	}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			sx, sy := x+dx, y+dy
			if sx < 0 || sx >= w || sy < 0 || sy >= h {
				continue
			}
			out[y*w+x] = src[sy*w+sx]
		}
	}
	return out
}

// Contrast rescales around the mean.
func Contrast(src []byte, factor float64) []byte {
	if len(src) == 0 {
		return src
	}
	var sum float64
	for _, v := range src {
		sum += float64(v)
	}
	mean := sum / float64(len(src))
	out := make([]byte, len(src))
	for i, v := range src {
		out[i] = clamp8(mean + (float64(v)-mean)*factor)
	}
	return out
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

// hostileStrings returns a corpus of adversarial string payloads used for
// injection, encoding and boundary testing.
func hostileStrings() []struct{ name, val string } {
	return []struct{ name, val string }{
		{"empty", ""},
		{"single space", " "},
		{"null byte", "EM\x00P"},
		{"newline", "EMP\n90214"},
		{"crlf", "EMP\r\n90214"},
		{"tab", "EMP\t90214"},
		{"sql drop", "EMP'; DROP TABLE templates;--"},
		{"sql union", "EMP' UNION SELECT * FROM pass_events--"},
		{"nosql", `{"$ne": null}`},
		{"mongo gt", `{"$gt": ""}`},
		{"path traversal", "../../../etc/passwd"},
		{"windows path", `..\..\windows\system32`},
		{"template expr", "{{.Env}}"},
		{"proto injection", "EMP\x12\x0aEMBEDDED"},
		{"json brace", `{"nested":"json"}`},
		{"quote", `EMP"90214`},
		{"backslash", `EMP\90214`},
		{"unicode emoji", "EMP\U0001F600"},
		{"rtl override", "EMP\u202E0912"},
		{"zero width", "EMP\u200B\u200B"},
		{"combining", "ÉṀ90214"},
		{"cjk", "员工90214"},
		{"long 1024", longString(1024)},
		{"long 4096", longString(4096)},
		{"long 65536", longString(65536)},
		{"format verb", "%s%s%s%s%n%n"},
		{"shell", "$(rm -rf /)"},
		{"semicolon chain", "a;b;c;"},
		{"nul flood", "\x00\x00\x00\x00"},
		{"high bytes", "\xff\xfe\xfd\xfc"},
		{"space name", "EMP 90214"},
	}
}

func longString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'A'
	}
	return string(b)
}

// tempWAL returns a per-test WAL path inside the test temp dir.
func tempWAL(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), fmt.Sprintf("chaos-%d.wal", time.Now().UnixNano()))
}

var _ = os.Getenv

// contextWithDeadline builds a context that expires almost immediately, used to
// verify deadlines are honoured rather than ignored.
func contextWithDeadline(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
