package dataset

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"finger-scanner/pkg/biometrics/iso19794"
	"finger-scanner/pkg/biometrics/iso19794b"
)

// writeRecord writes raw bytes into a temp dataset directory.
func writeRecord(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}

// imageRecord builds a valid ISO/IEC 19794-4 image record.
func imageRecord(t *testing.T, w, h int) []byte {
	t.Helper()
	pix := make([]uint8, w*h)
	for i := range pix {
		pix[i] = uint8(i * 7 % 251)
	}
	raw, err := iso19794.BuildImage(pix, w, h, 500)
	if err != nil {
		t.Fatalf("BuildImage: %v", err)
	}
	return raw
}

// minutiaeRecord builds a valid ISO/IEC 19794-2:2005 minutiae record with a
// deterministic ridge pattern so matching has something real to work on.
func minutiaeRecord(t *testing.T, n, phase int) []byte {
	t.Helper()
	mins := make([]iso19794b.MinutiaFormat, 0, n)
	for i := 0; i < n; i++ {
		mins = append(mins, iso19794b.MinutiaFormat{
			Type:        uint8(1 + (i+phase)%2), // alternate ending / bifurcation
			X:           uint16(200 + (i*37+phase*11)%1200),
			Y:           uint16(200 + (i*53+phase*17)%1200),
			Quality:     uint8(50 + (i+phase)%50),
			Orientation: float64((i+phase)%64) / 64.0 * 2 * math.Pi,
		})
	}
	raw, err := iso19794b.Build(256, 256, uint8(phase%10+1), 0, 90, mins)
	if err != nil {
		t.Fatalf("Build 19794-2: %v", err)
	}
	return raw
}

func TestLoadReadsBothRecordFormats(t *testing.T) {
	dir := t.TempDir()
	writeRecord(t, dir, "s01_left-index_01.iso", imageRecord(t, 16, 16))
	writeRecord(t, dir, "s01_left-index_02.iso", imageRecord(t, 16, 16))
	writeRecord(t, dir, "s02_right-index_01.fmr", minutiaeRecord(t, 40, 0))

	set, err := Load(dir, Options{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(set.Samples) != 3 {
		t.Fatalf("loaded %d samples; want 3", len(set.Samples))
	}
	if len(set.Rejected) != 0 {
		t.Errorf("unexpected rejections: %v", set.Rejected)
	}

	byKind := map[Kind]int{}
	for _, s := range set.Samples {
		byKind[s.Kind]++
		if s.Subject == "" {
			t.Errorf("sample %s has no subject", s.ID)
		}
	}
	if byKind[KindImage] != 2 || byKind[KindMinutiae] != 1 {
		t.Errorf("kinds = %v; want 2 images and 1 minutiae record", byKind)
	}

	for _, s := range set.Samples {
		if s.Kind == KindImage && !s.HasPixels() {
			t.Errorf("image record %s parsed but has no pixels", s.ID)
		}
		if s.Kind == KindMinutiae && len(s.Minutiae) == 0 {
			t.Errorf("minutiae record %s parsed but has no minutiae", s.ID)
		}
	}
}

func TestLoadIsDeterministicAndSorted(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"s03", "s01", "s02"} {
		for i := 1; i <= 2; i++ {
			writeRecord(t, dir, fmt.Sprintf("%s_left-index_%02d.iso", n, i), imageRecord(t, 8, 8))
		}
	}
	first, err := Load(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Load(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Samples) != len(second.Samples) {
		t.Fatalf("load sizes differ: %d vs %d", len(first.Samples), len(second.Samples))
	}
	for i := range first.Samples {
		if first.Samples[i].ID != second.Samples[i].ID {
			t.Fatalf("sample %d differs between loads: %s vs %s",
				i, first.Samples[i].ID, second.Samples[i].ID)
		}
	}
	// Sorted by subject then finger then ID.
	for i := 1; i < len(first.Samples); i++ {
		a, b := first.Samples[i-1], first.Samples[i]
		if a.Subject > b.Subject {
			t.Errorf("not sorted by subject: %s before %s", a.Subject, b.Subject)
		}
	}
}

func TestLoadUsesManifest(t *testing.T) {
	dir := t.TempDir()
	writeRecord(t, dir, "aaa.iso", imageRecord(t, 8, 8))
	writeRecord(t, dir, "bbb.iso", imageRecord(t, 8, 8))

	manifest := "# file\tsubject\tfinger\naaa.iso\tsubject-one\tleft-ring\nbbb.iso\tsubject-two\tright-little\n"
	if err := os.WriteFile(filepath.Join(dir, DefaultManifest), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}

	set, err := Load(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string][2]string{}
	for _, s := range set.Samples {
		found[s.Subject] = [2]string{s.Subject, s.Finger}
	}
	if got := found["subject-one"]; got[1] != "left-ring" {
		t.Errorf("finger = %q; want left-ring from the manifest", got[1])
	}
}

func TestLoadRejectsMalformedManifest(t *testing.T) {
	dir := t.TempDir()
	writeRecord(t, dir, "a.iso", imageRecord(t, 8, 8))
	if err := os.WriteFile(filepath.Join(dir, DefaultManifest), []byte("only-one-field\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, Options{}); err == nil {
		t.Fatal("a manifest with too few fields was accepted")
	}
}

func TestLoadIsolatesBadFilesInsteadOfFailing(t *testing.T) {
	dir := t.TempDir()
	writeRecord(t, dir, "s01_left-index_01.iso", imageRecord(t, 8, 8))
	writeRecord(t, dir, "s01_left-index_02.iso", []byte("this is not a record"))
	writeRecord(t, dir, "s02_left-index_01.iso", imageRecord(t, 8, 8))
	// Documentation that must be ignored rather than rejected as junk.
	writeRecord(t, dir, "notes.txt", []byte("scratch"))

	set, err := Load(dir, Options{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// One bad record must not cost us the run, but it must be reported.
	if len(set.Samples) != 2 {
		t.Errorf("loaded %d samples; want 2", len(set.Samples))
	}
	if len(set.Rejected) != 1 {
		t.Fatalf("rejections = %v; want exactly 1", set.Rejected)
	}
	if !strings.Contains(set.Rejected[0].Path, "s01_left-index_02.iso") {
		t.Errorf("wrong file rejected: %s", set.Rejected[0].Path)
	}
	for _, s := range set.Samples {
		if strings.Contains(s.ID, "notes") {
			t.Error("a .txt file was loaded as a sample")
		}
	}
}

// A manifest entry with no subject leaves a sample with no identity, and a
// sample with no identity can take part in neither a genuine nor an impostor
// trial. Guessing one would corrupt every measurement downstream, so it must
// be refused.
func TestLoadRefusesSamplesWithoutASubject(t *testing.T) {
	dir := t.TempDir()
	writeRecord(t, dir, "s01_left-index_01.iso", imageRecord(t, 8, 8))
	// Field present but blank.
	manifest := "s01_left-index_01.iso\t\tleft-index\n"
	if err := os.WriteFile(filepath.Join(dir, DefaultManifest), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(dir, Options{})
	if !errors.Is(err, ErrNoSamples) {
		t.Fatalf("err = %v; want ErrNoSamples", err)
	}
}

// A single-token file name is still a usable identity: the whole base name
// becomes the subject. That is the documented fallback when there is no
// manifest, so it is pinned rather than left to chance.
func TestLoadFallsBackToTheFileNameForSubject(t *testing.T) {
	dir := t.TempDir()
	writeRecord(t, dir, "subject7.iso", imageRecord(t, 8, 8))
	set, err := Load(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Samples) != 1 {
		t.Fatalf("loaded %d samples", len(set.Samples))
	}
	if set.Samples[0].Subject != "subject7" {
		t.Errorf("subject = %q; want subject7", set.Samples[0].Subject)
	}
	if set.Samples[0].Finger != "" {
		t.Errorf("finger = %q; want empty for a single-token name", set.Samples[0].Finger)
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope"), Options{}); err == nil {
		t.Error("Load of a missing directory succeeded")
	}
	file := filepath.Join(t.TempDir(), "f.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(file, Options{}); err == nil {
		t.Error("Load of a file succeeded")
	}

	empty := t.TempDir()
	if _, err := Load(empty, Options{}); !errors.Is(err, ErrNoSamples) {
		t.Errorf("err = %v; want ErrNoSamples on an empty directory", err)
	}
}

func TestLoadRespectsMaxSamples(t *testing.T) {
	dir := t.TempDir()
	for i := 1; i <= 10; i++ {
		writeRecord(t, dir, fmt.Sprintf("s%02d_left-index_01.iso", i), imageRecord(t, 8, 8))
	}
	set, err := Load(dir, Options{MaxSamples: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Samples) != 4 {
		t.Fatalf("loaded %d; want 4", len(set.Samples))
	}
	// The cap must pick the same samples every time, not an arbitrary four.
	again, err := Load(dir, Options{MaxSamples: 4})
	if err != nil {
		t.Fatal(err)
	}
	for i := range set.Samples {
		if set.Samples[i].ID != again.Samples[i].ID {
			t.Errorf("MaxSamples is not deterministic at %d: %s vs %s",
				i, set.Samples[i].ID, again.Samples[i].ID)
		}
	}
}

// buildTwoSubjectSet lays out a small dataset: two subjects, two fingers, two
// impressions each, plus one subject with an extra impression so the genuine
// trial count is not accidentally symmetric.
func buildTwoSubjectSet(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, subject := range []string{"s01", "s02"} {
		for _, finger := range []string{"left-index", "right-index"} {
			for i := 1; i <= 2; i++ {
				name := fmt.Sprintf("%s_%s_%02d.fmr", subject, finger, i)
				writeRecord(t, dir, name, minutiaeRecord(t, 40, i))
			}
		}
	}
	return dir
}

func TestTrialsAreReproducible(t *testing.T) {
	dir := buildTwoSubjectSet(t)
	set, err := Load(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}

	a, err := set.Trials(TrialConfig{Seed: 42})
	if err != nil {
		t.Fatal(err)
	}
	b, err := set.Trials(TrialConfig{Seed: 42})
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != len(b) {
		t.Fatalf("same seed produced %d and %d trials", len(a), len(b))
	}
	for i := range a {
		if a[i].Probe.ID != b[i].Probe.ID || a[i].Target.ID != b[i].Target.ID {
			t.Fatalf("trial %d differs between identical seeds", i)
		}
	}

	c, err := set.Trials(TrialConfig{Seed: 99})
	if err != nil {
		t.Fatal(err)
	}
	same := len(a) == len(c)
	if same {
		for i := range a {
			if a[i].Probe.ID != c[i].Probe.ID {
				same = false
				break
			}
		}
	}
	if same {
		t.Error("different seeds produced an identical trial order; the shuffle is not applied")
	}
}

func TestTrialsSeparateGenuineFromImpostor(t *testing.T) {
	dir := buildTwoSubjectSet(t)
	set, err := Load(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	trials, err := set.Trials(TrialConfig{Seed: 7})
	if err != nil {
		t.Fatal(err)
	}

	var genuine, impostor int
	for _, tr := range trials {
		if tr.Genuine {
			genuine++
			if tr.Probe.Subject != tr.Target.Subject {
				t.Errorf("trial labelled genuine crosses subjects: %s vs %s",
					tr.Probe.Subject, tr.Target.Subject)
			}
			if tr.Probe.Finger != tr.Target.Finger {
				t.Errorf("trial labelled genuine crosses fingers: %s vs %s",
					tr.Probe.Finger, tr.Target.Finger)
			}
		} else {
			impostor++
			if tr.Probe.Subject == tr.Target.Subject {
				t.Errorf("trial labelled impostor shares subject %s", tr.Probe.Subject)
			}
		}
	}
	// Two subjects x two fingers x one pair each = 4 genuine.
	if genuine != 4 {
		t.Errorf("genuine trials = %d; want 4", genuine)
	}
	if impostor == 0 {
		t.Error("no impostor trials were generated")
	}
}

func TestTrialsRespectsCaps(t *testing.T) {
	dir := buildTwoSubjectSet(t)
	set, err := Load(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	trials, err := set.Trials(TrialConfig{Seed: 1, MaxGenuine: 2, MaxImpostor: 3})
	if err != nil {
		t.Fatal(err)
	}
	var g, i int
	for _, tr := range trials {
		if tr.Genuine {
			g++
		} else {
			i++
		}
	}
	if g != 2 || i != 3 {
		t.Errorf("got %d genuine and %d impostor; want 2 and 3", g, i)
	}
}

func TestTrialsRejectsUnusableSets(t *testing.T) {
	dir := t.TempDir()
	writeRecord(t, dir, "s01_left-index_01.iso", imageRecord(t, 8, 8))
	set, err := Load(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	// A single subject cannot produce an impostor trial at all.
	if _, err := set.Trials(TrialConfig{}); !errors.Is(err, ErrNoTrials) {
		t.Errorf("err = %v; want ErrNoTrials", err)
	}

	empty := &Set{}
	if _, err := empty.Trials(TrialConfig{}); !errors.Is(err, ErrNoTrials) {
		t.Errorf("err = %v; want ErrNoTrials on an empty set", err)
	}
}

func TestTrialsRejectsDifferentFingersOfOneSubject(t *testing.T) {
	// Same subject, different fingers, no repeats: nothing is genuine and
	// nothing is impostor either, because impostor requires two subjects.
	dir := t.TempDir()
	writeRecord(t, dir, "s01_left-index_01.iso", imageRecord(t, 8, 8))
	writeRecord(t, dir, "s01_right-index_01.iso", imageRecord(t, 8, 8))
	set, err := Load(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Trials(TrialConfig{}); !errors.Is(err, ErrNoTrials) {
		t.Errorf("err = %v; want ErrNoTrials", err)
	}
}

// The whole point of the package: a matcher that separates the classes must
// report a low error rate, and one that does not must not.
//
// A ScoreFunc only ever sees the two samples, never the trial's ground-truth
// label, so the label is encoded in the sample IDs here rather than being read
// off the Trial. That mirrors reality: a matcher cannot cheat.
func TestEvaluateComputesTheStandardMetrics(t *testing.T) {
	trials := []Trial{
		{Probe: &Sample{ID: "g1"}, Target: &Sample{ID: "t1"}, Genuine: true},
		{Probe: &Sample{ID: "g2"}, Target: &Sample{ID: "t2"}, Genuine: true},
		{Probe: &Sample{ID: "i1"}, Target: &Sample{ID: "t3"}, Genuine: false},
		{Probe: &Sample{ID: "i2"}, Target: &Sample{ID: "t4"}, Genuine: false},
	}
	isGenuine := func(probe *Sample) bool { return strings.HasPrefix(probe.ID, "g") }

	// A perfect matcher: genuine above the threshold, impostor below.
	perfect := func(ctx context.Context, a, b *Sample) (float64, error) {
		if isGenuine(a) {
			return 0.9, nil
		}
		return 0.1, nil
	}
	rep, err := Evaluate(context.Background(), trials, perfect, 0.5)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Genuine != 2 || rep.Impostor != 2 {
		t.Fatalf("counts = %d genuine, %d impostor", rep.Genuine, rep.Impostor)
	}
	if rep.FalseAcceptRate != 0 || rep.FalseRejectRate != 0 {
		t.Errorf("FAR = %v, FRR = %v; want 0, 0", rep.FalseAcceptRate, rep.FalseRejectRate)
	}
	if rep.EER != 0 {
		t.Errorf("EER = %v; want 0 for a perfect separation", rep.EER)
	}
	if len(rep.ROC) < 2 {
		t.Errorf("ROC has %d points; want at least 2", len(rep.ROC))
	}

	// An inverted matcher must look bad, or the metric is not measuring anything.
	inverted := func(ctx context.Context, a, b *Sample) (float64, error) {
		if isGenuine(a) {
			return 0.1, nil
		}
		return 0.9, nil
	}
	bad, err := Evaluate(context.Background(), trials, inverted, 0.5)
	if err != nil {
		t.Fatal(err)
	}
	if bad.FalseAcceptRate != 1 || bad.FalseRejectRate != 1 {
		t.Errorf("inverted matcher got FAR = %v, FRR = %v; want 1, 1",
			bad.FalseAcceptRate, bad.FalseRejectRate)
	}
	if bad.EER <= 0 {
		t.Errorf("EER = %v for an inverted matcher; it must be worse than chance", bad.EER)
	}
}

func TestEvaluateROCIsMonotonicInFAR(t *testing.T) {
	trials := make([]Trial, 0, 40)
	for i := 0; i < 20; i++ {
		trials = append(trials, Trial{
			Probe:   &Sample{ID: fmt.Sprintf("g%d", i)},
			Target:  &Sample{ID: "gt"},
			Genuine: true,
		})
	}
	for i := 0; i < 20; i++ {
		trials = append(trials, Trial{
			Probe:   &Sample{ID: fmt.Sprintf("i%d", i)},
			Target:  &Sample{ID: "it"},
			Genuine: false,
		})
	}
	fn := func(ctx context.Context, a, b *Sample) (float64, error) {
		genuine := a.ID[0] == 'g'
		if genuine {
			return 0.4 + 0.6*float64(len(a.ID)-1)/20.0, nil
		}
		return 0.2 * float64(len(a.ID)-1) / 20.0, nil
	}

	rep, err := Evaluate(context.Background(), trials, fn, 0.5)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.ROC) < 3 {
		t.Fatalf("ROC has %d points", len(rep.ROC))
	}
	for i := 1; i < len(rep.ROC); i++ {
		if rep.ROC[i].FAR < rep.ROC[i-1].FAR {
			t.Errorf("ROC is not sorted by FAR at %d: %v then %v",
				i, rep.ROC[i-1].FAR, rep.ROC[i].FAR)
		}
	}
	if rep.ROC[0].FAR != 0 {
		t.Errorf("ROC starts at FAR %v; want 0", rep.ROC[0].FAR)
	}
}

// A broken scorer must not be silently averaged into a report that looks clean.
func TestEvaluateReportsFailuresInsteadOfHidingThem(t *testing.T) {
	trials := []Trial{
		{Probe: &Sample{ID: "ok"}, Target: &Sample{ID: "t1"}, Genuine: true},
		{Probe: &Sample{ID: "boom"}, Target: &Sample{ID: "t2"}, Genuine: true},
		{Probe: &Sample{ID: "nan"}, Target: &Sample{ID: "t3"}, Genuine: false},
	}
	fn := func(ctx context.Context, a, b *Sample) (float64, error) {
		switch a.ID {
		case "boom":
			return 0, errors.New("extraction failed")
		case "nan":
			return math.NaN(), nil
		}
		return 0.9, nil
	}

	rep, err := Evaluate(context.Background(), trials, fn, 0.5)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Total != 1 {
		t.Errorf("scored %d trials; want 1", rep.Total)
	}
	if len(rep.Failures) != 2 {
		t.Fatalf("failures = %v; want 2", rep.Failures)
	}
	if rep.Genuine != 1 || rep.Impostor != 0 {
		t.Errorf("counts = %d genuine, %d impostor", rep.Genuine, rep.Impostor)
	}
}

func TestEvaluateRejectsNilScorer(t *testing.T) {
	if _, err := Evaluate(context.Background(), nil, nil, 0.5); err == nil {
		t.Fatal("Evaluate with a nil scorer succeeded")
	}
}

func TestScoreStopsOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	trials := []Trial{{Probe: &Sample{ID: "p"}, Target: &Sample{ID: "t"}, Genuine: true}}
	_, _, err := Score(ctx, trials, func(context.Context, *Sample, *Sample) (float64, error) {
		return 0.5, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v; want context.Canceled", err)
	}
}

// End to end over real ISO records: load, build trials, run the platform's own
// matcher. A record whose minutiae never came from an image still exercises
// the template conversion and the MCC scoring path.
func TestMatcherScoresRealRecords(t *testing.T) {
	dir := buildTwoSubjectSet(t)
	set, err := Load(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	trials, err := set.Trials(TrialConfig{Seed: 3})
	if err != nil {
		t.Fatal(err)
	}

	m := NewMatcher(60.0, nil)
	rep, err := Evaluate(context.Background(), trials, m.Score, 60.0)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Total == 0 {
		t.Fatal("no trials were scored")
	}
	if len(rep.Failures) != 0 {
		t.Fatalf("unexpected scoring failures: %v", rep.Failures)
	}
	for i := 0; i < len(rep.ROC); i++ {
		if rep.ROC[i].FAR < 0 || rep.ROC[i].FAR > 1 {
			t.Fatalf("ROC FAR out of range: %v", rep.ROC[i].FAR)
		}
	}
	if rep.EER < 0 || rep.EER > 1 {
		t.Errorf("EER out of range: %v", rep.EER)
	}
}

func TestMatcherRejectsBadSamples(t *testing.T) {
	m := NewMatcher(60.0, nil)
	ctx := context.Background()

	if _, err := m.Score(ctx, &Sample{ID: "no-pixels", Kind: KindImage}, &Sample{ID: "t", Kind: KindImage}); !errors.Is(err, ErrNoPixels) {
		t.Errorf("err = %v; want ErrNoPixels", err)
	}
	if _, err := m.Score(ctx, &Sample{ID: "weird", Kind: "nonsense"}, &Sample{ID: "t", Kind: KindImage}); !errors.Is(err, ErrUnknownFormat) {
		t.Errorf("err = %v; want ErrUnknownFormat", err)
	}
	// Too few minutiae is a quality rejection, not a match failure. Conflating
	// the two would quietly inflate the measured reject rate.
	thin := &Sample{ID: "thin", Kind: KindMinutiae, Minutiae: []iso19794b.MinutiaFormat{{Type: 1, X: 1, Y: 1, Quality: 50}}}
	if _, err := m.Score(ctx, thin, &Sample{ID: "t", Kind: KindMinutiae}); !errors.Is(err, ErrInsufficientMinutiae) {
		t.Errorf("err = %v; want ErrInsufficientMinutiae", err)
	}
}

// The template cache is the difference between an evaluation that finishes and
// one that does not, since trials re-derive the same samples many times over.
func TestMatcherCachesTemplatesAndErrors(t *testing.T) {
	m := NewMatcher(60.0, nil)
	good := &Sample{ID: "g", Kind: KindMinutiae, Minutiae: makeMany(40)}
	thin := &Sample{ID: "t-thin", Kind: KindMinutiae, Minutiae: makeMany(2)}

	for i := 0; i < 3; i++ {
		if _, err := m.templateFor(good); err != nil {
			t.Fatalf("templateFor %d: %v", i, err)
		}
		if _, err := m.templateFor(thin); !errors.Is(err, ErrInsufficientMinutiae) {
			t.Fatalf("templateFor(thin) %d = %v; want ErrInsufficientMinutiae", i, err)
		}
	}
	if len(m.templates) != 1 {
		t.Errorf("cached %d templates; want only the good one", len(m.templates))
	}
	if len(m.errs) != 1 {
		t.Errorf("cached %d errors; want 1", len(m.errs))
	}
}

func TestConvertMinutiaePreservesTypeAndClampsQuality(t *testing.T) {
	in := []iso19794b.MinutiaFormat{
		{Type: 1, X: 10, Y: 20, Quality: 80, Orientation: 1.0},
		{Type: 2, X: 30, Y: 40, Quality: 5, Orientation: 2.0},
		{Type: 0, X: 50, Y: 60, Quality: 100, Orientation: 3.0}, // "other"
		{Type: 1, X: 70, Y: 80, Quality: 255, Orientation: 4.0}, // out of range
	}
	got := convertMinutiae(in)
	if len(got) != len(in) {
		t.Fatalf("converted %d of %d", len(got), len(in))
	}
	if got[0].Type != 1 || got[1].Type != 2 {
		t.Errorf("types = %v,%v; want ending,bifurcation", got[0].Type, got[1].Type)
	}
	// ISO type 0 is "other minutia", which has no internal equivalent. Mapping
	// it to unspecified is honest; mapping it to an ending would not be.
	if got[2].Type != 0 {
		t.Errorf("ISO type 0 became %v; want unspecified", got[2].Type)
	}
	if got[3].Quality != 100 {
		t.Errorf("quality 255 became %v; want a clamp to 100", got[3].Quality)
	}
}

func TestParseNameConvention(t *testing.T) {
	cases := []struct {
		name    string
		subject string
		finger  string
	}{
		{"s01_left-index_01.iso", "s01", "left-index"},
		{"subject.fmr", "subject", ""},
		{"a_b_c_d.iso", "a", "b"},
	}
	for _, c := range cases {
		subject, finger := parseNameConvention(c.name)
		if subject != c.subject || finger != c.finger {
			t.Errorf("parseNameConvention(%q) = (%q,%q); want (%q,%q)",
				c.name, subject, finger, c.subject, c.finger)
		}
	}
}

func makeMany(n int) []iso19794b.MinutiaFormat {
	out := make([]iso19794b.MinutiaFormat, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, iso19794b.MinutiaFormat{
			Type: 1, X: uint16(100 + i), Y: uint16(200 + i), Quality: 90,
		})
	}
	return out
}

// The MCC score is NOT normalised to 0..1. It accumulates matched-cylinder
// contribution and production compares it against 60. A dataset harness that
// assumed a 0..1 scale would accept nearly every impostor and report a false
// accept rate of 1.0 while appearing to run normally, so the scale is pinned
// here rather than left to whoever wires up the next caller.
func TestMatcherUsesTheProductionScoreScale(t *testing.T) {
	const productionGlobalThreshold = 60.0

	m := NewMatcher(productionGlobalThreshold, nil)
	if m.matcher.GlobalScoreThreshold != productionGlobalThreshold {
		t.Fatalf("global score threshold = %v; want %v",
			m.matcher.GlobalScoreThreshold, productionGlobalThreshold)
	}
	if productionGlobalThreshold <= 1.0 {
		t.Fatal("the production threshold is <= 1.0, which would mean the score is normalised; update this test")
	}

	// Scores from real records must therefore exceed 1, or the threshold is
	// meaningless.
	dir := buildTwoSubjectSet(t)
	set, err := Load(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	trials, err := set.Trials(TrialConfig{Seed: 11, MaxGenuine: 4, MaxImpostor: 8})
	if err != nil {
		t.Fatal(err)
	}
	scored, failures, err := Score(context.Background(), trials, m.Score)
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 0 {
		t.Fatalf("scoring failures: %v", failures)
	}
	for _, s := range scored {
		if s.Score <= 1.0 {
			t.Fatalf("trial %s/%s scored %v; that is inside 0..1, so the assumed scale is wrong",
				s.Probe.ID, s.Target.ID, s.Score)
		}
	}
}
