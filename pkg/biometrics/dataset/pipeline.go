package dataset

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"sync"

	"finger-scanner/pkg/biometrics/image"
	"finger-scanner/pkg/biometrics/iso19794b"
	"finger-scanner/pkg/biometrics/mcc"
	"finger-scanner/pkg/biometrics/minutiae"
)

// newRand returns a deterministic source. math/rand's global source is
// deliberately avoided: two evaluations in one process must not share state.
func newRand(seed int64) *rand.Rand { return rand.New(rand.NewSource(seed)) }

func shuffle(t []Trial, r *rand.Rand) []Trial {
	r.Shuffle(len(t), func(i, j int) { t[i], t[j] = t[j], t[i] })
	return t
}

// ErrNoPixels means a sample needed the image pipeline but carries no image.
var ErrNoPixels = errors.New("dataset: sample has no pixels")

// ErrInsufficientMinutiae mirrors the pipeline's own rejection threshold. A
// print that yields too few minutiae is not a match failure, it is a
// quality-gate rejection, and conflating the two would distort FRR.
var ErrInsufficientMinutiae = errors.New("dataset: too few minutiae after extraction")

// minMinutiae is the same gate the biometric service applies.
const minMinutiae = 8

// Matcher scores trials by running the platform's real pipeline and then the
// real matcher. It is the reason this package is worth having: it exercises
// exactly the code a deployment runs, rather than a simplified stand-in.
//
// Templates are cached per sample because an evaluation of N trials re-derives
// the same samples over and over, and extraction dominates the cost.
type Matcher struct {
	extractor *minutiae.Extractor
	matcher   *mcc.Matcher
	logger    *slog.Logger

	mu        sync.Mutex
	templates map[string]*mcc.Template
	errs      map[string]error
}

// NewMatcher builds a scorer around the platform's MCC matcher.
// operatingThreshold sets the accept/reject point reported by Evaluate.
func NewMatcher(operatingThreshold float64, logger *slog.Logger) *Matcher {
	if logger == nil {
		logger = slog.Default()
	}
	return &Matcher{
		extractor: minutiae.NewExtractor(),
		matcher:   mcc.NewMatcher(0.35, operatingThreshold, logger),
		logger:    logger,
		templates: make(map[string]*mcc.Template),
		errs:      make(map[string]error),
	}
}

// Score implements ScoreFunc.
func (m *Matcher) Score(ctx context.Context, probe, target *Sample) (float64, error) {
	pt, err := m.templateFor(probe)
	if err != nil {
		return 0, fmt.Errorf("probe %s: %w", probe.ID, err)
	}
	tt, err := m.templateFor(target)
	if err != nil {
		return 0, fmt.Errorf("target %s: %w", target.ID, err)
	}

	res, err := m.matcher.Verify(ctx, pt, tt)
	if err != nil {
		return 0, err
	}
	return res.Score, nil
}

// templateFor derives and caches the MCC template for a sample.
func (m *Matcher) templateFor(s *Sample) (*mcc.Template, error) {
	m.mu.Lock()
	if t, ok := m.templates[s.ID]; ok {
		m.mu.Unlock()
		return t, nil
	}
	if err, ok := m.errs[s.ID]; ok {
		m.mu.Unlock()
		return nil, err
	}
	m.mu.Unlock()

	t, err := m.buildTemplate(s)

	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		// Cache the failure too: re-extracting a print that cannot be
		// extracted is the most expensive possible no-op.
		m.errs[s.ID] = err
		return nil, err
	}
	m.templates[s.ID] = t
	return t, nil
}

func (m *Matcher) buildTemplate(s *Sample) (*mcc.Template, error) {
	var points []minutiae.Minutia

	switch s.Kind {
	case KindMinutiae:
		points = convertMinutiae(s.Minutiae)
		if len(points) < minMinutiae {
			return nil, fmt.Errorf("%w: %s has %d", ErrInsufficientMinutiae, s.ID, len(points))
		}
	case KindImage:
		if !s.HasPixels() {
			return nil, ErrNoPixels
		}
		img, err := image.NewGrayImage(s.Width, s.Height, s.Pixels)
		if err != nil {
			return nil, fmt.Errorf("building gray image: %w", err)
		}
		norm := img.Normalize(128, 2000)
		bin := norm.AdaptiveBinarize(15)
		skel := image.ZhangSuenThinning(bin, s.Width, s.Height)
		orientations := norm.OrientationField(16)
		points = m.extractor.Extract(skel, s.Width, s.Height, orientations, 16)
		if len(points) < minMinutiae {
			return nil, fmt.Errorf("%w: %s has %d", ErrInsufficientMinutiae, s.ID, len(points))
		}
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownFormat, s.ID)
	}

	return mcc.BuildTemplate(s.ID, points), nil
}

// convertMinutiae maps the 19794-2 wire representation onto the internal one.
// ISO type 0 means "other", which has no internal equivalent, so it is kept as
// unspecified rather than guessed at.
func convertMinutiae(in []iso19794b.MinutiaFormat) []minutiae.Minutia {
	out := make([]minutiae.Minutia, 0, len(in))
	for _, m := range in {
		var t minutiae.MinutiaType
		switch m.Type {
		case 1:
			t = minutiae.TypeEnding
		case 2:
			t = minutiae.TypeBifurcation
		default:
			t = minutiae.TypeUnspecified
		}
		// The 19794-2 quality field is 1..100, which is the same range the
		// internal type uses, so this is a straight pass-through.
		q := m.Quality
		if q > 100 {
			q = 100
		}
		out = append(out, minutiae.Minutia{
			X: m.X, Y: m.Y, Angle: m.Orientation,
			Type: t, Quality: q,
		})
	}
	return out
}
