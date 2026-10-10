package dataset

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"
)

// TrialConfig controls how trials are generated.
type TrialConfig struct {
	// Seed makes trial generation deterministic. The same Set and the same
	// config always yield the same trials in the same order.
	Seed int64
	// MaxGenuine caps genuine pairs. Zero means unlimited.
	MaxGenuine int
	// MaxImpostor caps impostor pairs. Zero means unlimited.
	MaxImpostor int
}

// ErrNoTrials means the set cannot produce trials, usually because it holds a
// single subject (so every pair is genuine) or fewer than two subjects (so
// none can be impostor).
var ErrNoTrials = errors.New("dataset: not enough samples to build trials")

// Trial is one probe/target comparison with its ground truth.
type Trial struct {
	Probe  *Sample
	Target *Sample
	// Genuine is ground truth: true when both samples are the same subject and
	// the same finger.
	Genuine bool
}

// Trials builds genuine and impostor comparisons from the set.
//
// Genuine pairs are same subject AND same finger, since two impressions of
// different fingers are impostors as far as a finger matcher is concerned.
// Impostor pairs are different subjects.
//
// Both kinds are capped and shuffled with a seeded source, so results are
// reproducible and no ordering artefact favours either class.
func (s *Set) Trials(cfg TrialConfig) ([]Trial, error) {
	if len(s.Samples) < 2 {
		return nil, fmt.Errorf("%w: %d samples", ErrNoTrials, len(s.Samples))
	}

	bySubject := map[string][]*Sample{}
	for _, smp := range s.Samples {
		bySubject[smp.Subject] = append(bySubject[smp.Subject], smp)
	}
	if len(bySubject) < 2 {
		return nil, fmt.Errorf("%w: %d subject(s); impostor trials need at least 2", ErrNoTrials, len(bySubject))
	}

	rng := newRand(cfg.Seed)

	var genuine, impostor []Trial

	// Subjects are visited in sorted order, and fingers within each subject are
	// sorted too. Ranging over the maps directly would leak Go's randomised map
	// iteration order into the trial list, and the seeded shuffle could not undo
	// it - the same seed would then produce different trials on different runs,
	// which silently breaks run-to-run comparison of matcher scores.
	subjects := make([]string, 0, len(bySubject))
	for k := range bySubject {
		subjects = append(subjects, k)
	}
	sort.Strings(subjects)

	// Genuine: same subject, same finger.
	for _, subject := range subjects {
		group := bySubject[subject]
		byFinger := map[string][]*Sample{}
		var fingers []string
		for _, smp := range group {
			if _, seen := byFinger[smp.Finger]; !seen {
				fingers = append(fingers, smp.Finger)
			}
			byFinger[smp.Finger] = append(byFinger[smp.Finger], smp)
		}
		sort.Strings(fingers)
		for _, finger := range fingers {
			set := byFinger[finger]
			for i := 0; i < len(set); i++ {
				for j := i + 1; j < len(set); j++ {
					genuine = append(genuine, Trial{Probe: set[i], Target: set[j], Genuine: true})
				}
			}
		}
	}

	// Impostor: different subjects. Compare each subject's samples against the
	// first sample of every other subject, which keeps the set O(subjects^2)
	// rather than O(samples^2) and gives a balanced impostor load per subject.
	for _, a := range subjects {
		for _, b := range subjects {
			if a == b {
				continue
			}
			for _, probe := range bySubject[a] {
				target := bySubject[b][0]
				impostor = append(impostor, Trial{Probe: probe, Target: target, Genuine: false})
			}
		}
	}

	genuine = shuffle(genuine, rng)
	impostor = shuffle(impostor, rng)

	if cfg.MaxGenuine > 0 && len(genuine) > cfg.MaxGenuine {
		genuine = genuine[:cfg.MaxGenuine]
	}
	if cfg.MaxImpostor > 0 && len(impostor) > cfg.MaxImpostor {
		impostor = impostor[:cfg.MaxImpostor]
	}

	trials := append(append([]Trial{}, genuine...), impostor...)
	if len(trials) == 0 {
		return nil, fmt.Errorf("%w: no same-finger repeats and fewer than 2 subjects", ErrNoTrials)
	}
	return trials, nil
}

// ScoreFunc scores one trial. The returned score must increase with genuine
// similarity: higher means more likely to be the same finger.
type ScoreFunc func(ctx context.Context, probe, target *Sample) (float64, error)

// Point is one point on an ROC curve.
type Point struct {
	// FAR is the false accept rate: impostor pairs accepted, 0..1.
	FAR float64
	// FRR is the false reject rate: genuine pairs rejected, 0..1.
	FRR float64
	// Threshold is the score at which this point occurs.
	Threshold float64
}

// TrialFailure records a trial that could not be scored, so a partial run is
// never mistaken for a complete one.
type TrialFailure struct {
	Probe, Target string
	Err           error
}

// Report is an evaluation result.
type Report struct {
	Total    int
	Genuine  int
	Impostor int

	// OperatingThreshold is the matcher's own accept point.
	OperatingThreshold float64

	// Counts at the operating point, named by what HAPPENED to the pair.
	// "ImpostorTrue" would have meant the same thing as ImpostorAccepted while
	// reading as its opposite, which is how the CLI once printed an accept
	// rate of 1.0 directly beside a line reading "0 accepted".
	GenuineAccepted, GenuineRejected   int
	ImpostorAccepted, ImpostorRejected int

	// FalseAcceptRate is impostor pairs wrongly accepted, 0..1.
	FalseAcceptRate float64
	// FalseRejectRate is genuine pairs wrongly rejected, 0..1.
	FalseRejectRate float64

	// EER is the equal error rate: the single threshold where FAR and FRR
	// cross. It is the standard way-summarised measure of matcher quality.
	EER          float64
	EERThreshold float64
	// ROC is the full curve, ordered by ascending FAR.
	ROC []Point

	// Failures lists trials that errored rather than scored.
	Failures []TrialFailure
	// Duration is the wall-clock time spent scoring.
	Duration time.Duration
}

// Scored pairs the trial with its outcome.
type Scored struct {
	Trial
	Score float64
}

// Score runs fn over every trial and returns the raw scores. Split out from
// Evaluate so a caller can cache, parallelise or persist them.
func Score(ctx context.Context, trials []Trial, fn ScoreFunc) ([]Scored, []TrialFailure, error) {
	if fn == nil {
		return nil, nil, errors.New("dataset: nil ScoreFunc")
	}
	out := make([]Scored, 0, len(trials))
	var failures []TrialFailure

	for _, t := range trials {
		if err := ctx.Err(); err != nil {
			return out, failures, err
		}
		s, err := fn(ctx, t.Probe, t.Target)
		if err != nil {
			failures = append(failures, TrialFailure{Probe: t.Probe.ID, Target: t.Target.ID, Err: err})
			continue
		}
		if math.IsNaN(s) || math.IsInf(s, 0) {
			// A non-finite score would silently poison the curve.
			failures = append(failures, TrialFailure{
				Probe: t.Probe.ID, Target: t.Target.ID,
				Err: fmt.Errorf("scorer returned a non-finite score: %v", s),
			})
			continue
		}
		out = append(out, Scored{Trial: t, Score: s})
	}
	return out, failures, nil
}

// Evaluate scores trials with fn and computes the full operating picture.
//
// The operating point uses the matcher's own GlobalScoreThreshold when one is
// supplied; otherwise it reports at 0, which for a 0..1 score means "accept
// everything" and is not a meaningful deployment point. Pass the real
// threshold.
func Evaluate(ctx context.Context, trials []Trial, fn ScoreFunc, operatingThreshold float64) (*Report, error) {
	start := time.Now()

	scored, failures, err := Score(ctx, trials, fn)
	if err != nil {
		return nil, err
	}

	rep := &Report{
		Total:              len(scored),
		Failures:           failures,
		OperatingThreshold: operatingThreshold,
	}

	for _, s := range scored {
		accepted := s.Score >= operatingThreshold
		if s.Genuine {
			rep.Genuine++
			if accepted {
				rep.GenuineAccepted++
			} else {
				rep.GenuineRejected++
			}
		} else {
			rep.Impostor++
			if accepted {
				rep.ImpostorAccepted++
			} else {
				rep.ImpostorRejected++
			}
		}
	}

	if rep.Genuine > 0 {
		rep.FalseRejectRate = float64(rep.GenuineRejected) / float64(rep.Genuine)
	}
	if rep.Impostor > 0 {
		rep.FalseAcceptRate = float64(rep.ImpostorAccepted) / float64(rep.Impostor)
	}

	rep.ROC = roc(scored)
	rep.EER, rep.EERThreshold = eer(rep.ROC)
	rep.Duration = time.Since(start)
	return rep, nil
}

// roc builds the curve by sweeping a threshold from +inf down to the lowest
// observed score. At each threshold a pair is accepted when score >= threshold.
//
// Walking the sorted scores makes that natural: everything processed so far
// scores at or above the current threshold and is therefore ACCEPTED, and
// everything still to come scores below it and is therefore REJECTED. So
//
//	FRR = (genuine not yet processed) / genuine total
//	FAR = (impostor already processed) / impostor total
//
// Getting that backwards is easy and looks plausible: a perfect separator would
// still report FRR 1 at every threshold, and the EER would come out as 1.
func roc(scored []Scored) []Point {
	if len(scored) == 0 {
		return nil
	}
	sorted := make([]Scored, len(scored))
	copy(sorted, scored)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Score > sorted[j].Score })

	var nGenuine, nImpostor int
	for _, s := range sorted {
		if s.Genuine {
			nGenuine++
		} else {
			nImpostor++
		}
	}
	if nGenuine == 0 || nImpostor == 0 {
		return nil
	}

	var processedGenuine, processedImpostor int
	points := make([]Point, 0, len(sorted)+1)

	// Start above every score: nothing accepted, FAR 0, FRR 1.
	points = append(points, Point{
		FAR: 0, FRR: 1, Threshold: math.Inf(1),
	})

	for i := 0; i < len(sorted); {
		threshold := sorted[i].Score
		// Consume the whole run of equal scores before emitting, so the curve
		// has one vertex per distinct threshold rather than one per trial.
		for i < len(sorted) && sorted[i].Score == threshold {
			if sorted[i].Genuine {
				processedGenuine++
			} else {
				processedImpostor++
			}
			i++
		}
		points = append(points, Point{
			FAR:       float64(processedImpostor) / float64(nImpostor),
			FRR:       float64(nGenuine-processedGenuine) / float64(nGenuine),
			Threshold: threshold,
		})
	}

	// Ordered by ascending FAR so the curve reads left to right.
	sort.Slice(points, func(i, j int) bool { return points[i].FAR < points[j].FAR })
	return points
}

// eer returns the smallest |FAR-FRR| on the curve and its threshold. That is
// the standard definition of the equal error operating point.
func eer(points []Point) (rate, threshold float64) {
	if len(points) == 0 {
		return 0, 0
	}
	best := math.Inf(1)
	for _, p := range points {
		d := math.Abs(p.FAR - p.FRR)
		if d < best {
			best = d
			rate = (p.FAR + p.FRR) / 2
			threshold = p.Threshold
		}
	}
	return rate, threshold
}
