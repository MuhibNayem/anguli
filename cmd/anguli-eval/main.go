// Command anguli-eval measures the fingerprint matcher against a real dataset.
//
// It exists because every accuracy number this project has produced so far came
// from synthetic images. This runs the platform's actual pipeline - normalise,
// binarise, thin, extract minutiae, build MCC templates, match - over records
// on disk and reports the standard open-set measures: false accept rate, false
// reject rate, equal error rate and the full ROC.
//
// Usage:
//
//	anguli-eval -dir ./dataset [flags]
//
// The directory should contain ISO/IEC 19794-4 image records and/or
// ISO/IEC 19794-2:2005 minutiae records, plus an optional manifest.tsv mapping
// each file to a subject and a finger:
//
//	# file<TAB>subject<TAB>finger
//	s01_left-index_01.iso	s01	left-index
//
// Without a manifest, subject and finger are taken from the file name
// <subject>_<finger>_<n>.
//
// A genuine trial is two impressions of the same finger. An impostor trial is
// two different people. Trials are seeded, so the same dataset and the same
// seed always produce the same comparison set.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"finger-scanner/pkg/biometrics/dataset"
)

// defaultGlobalThreshold mirrors the value the biometric and edge services
// actually run with. The MCC score is NOT normalised to 0..1: it accumulates
// matched-cylinder contribution, and production compares it against 60. Passing
// a 0..1 threshold here accepts nearly everything and reports a false accept
// rate of 1.0 while looking like a working run.
const defaultGlobalThreshold = 60.0

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "anguli-eval: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		dir          = flag.String("dir", "", "directory holding fingerprint records (required)")
		manifest     = flag.String("manifest", dataset.DefaultManifest, "metadata file inside -dir")
		maxSamples   = flag.Int("max-samples", 0, "cap the number of samples loaded, for a quick run")
		seed         = flag.Int64("seed", 20260101, "trial generation seed; fix it to compare runs")
		maxGenuine   = flag.Int("max-genuine", 500, "cap on genuine trials")
		maxImpostor  = flag.Int("max-impostor", 2000, "cap on impostor trials")
		threshold    = flag.Float64("threshold", defaultGlobalThreshold, "matcher accept threshold for the operating point")
		showROC      = flag.Bool("roc", false, "print the full ROC curve")
		maxRejection = flag.Float64("max-rejection", 0.02, "exit non-zero if the reject rate exceeds this")
	)
	flag.Parse()

	if *dir == "" {
		flag.Usage()
		return errors.New("-dir is required")
	}

	// Ctrl-C cancels in-flight trials rather than orphaning them: extraction is
	// slow enough that a half-finished evaluation is worth aborting cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	set, err := dataset.Load(*dir, dataset.Options{Manifest: *manifest, MaxSamples: *maxSamples})
	if err != nil && !errors.Is(err, dataset.ErrNoSamples) {
		return err
	}
	if errors.Is(err, dataset.ErrNoSamples) {
		// Report why every file was refused; an empty directory and a directory
		// of the wrong format look identical otherwise.
		for _, r := range set.Rejected {
			fmt.Fprintf(os.Stderr, "  rejected %s: %v\n", r.Path, r.Err)
		}
		return fmt.Errorf("no usable samples in %s (of %d files rejected)", *dir, len(set.Rejected))
	}

	describe(set)

	trials, err := set.Trials(dataset.TrialConfig{
		Seed:        *seed,
		MaxGenuine:  *maxGenuine,
		MaxImpostor: *maxImpostor,
	})
	if err != nil {
		return err
	}

	matcher := dataset.NewMatcher(*threshold, logger)
	report, err := dataset.Evaluate(ctx, trials, matcher.Score, *threshold)
	if err != nil {
		return err
	}

	printReport(report, *showROC)

	if len(report.Failures) > 0 {
		fmt.Printf("\n%d trial(s) could not be scored and are EXCLUDED from these rates:\n", len(report.Failures))
		shown := report.Failures
		if len(shown) > 10 {
			shown = shown[:10]
		}
		for _, f := range shown {
			fmt.Printf("  %s vs %s: %v\n", f.Probe, f.Target, f.Err)
		}
		if len(report.Failures) > len(shown) {
			fmt.Printf("  ... and %d more\n", len(report.Failures)-len(shown))
		}
		fmt.Println("  A dataset with many rejected prints has an optimistic-biased score.")
	}

	if report.FalseRejectRate > *maxRejection {
		fmt.Printf("\nFAIL: reject rate %.4f exceeds the %.4f ceiling\n", report.FalseRejectRate, *maxRejection)
		return fmt.Errorf("matcher reject rate too high")
	}
	return nil
}

func describe(set *dataset.Set) {
	bySubject := map[string]bool{}
	byKind := map[dataset.Kind]int{}
	images := 0
	minutiaeRecords := 0
	for _, s := range set.Samples {
		bySubject[s.Subject] = true
		byKind[s.Kind]++
		if s.HasPixels() {
			images++
		}
		if len(s.Minutiae) > 0 {
			minutiaeRecords++
		}
	}
	fmt.Printf("Loaded %d samples from %s\n", len(set.Samples), set.Root)
	fmt.Printf("  subjects: %d\n", len(bySubject))
	fmt.Printf("  %s records: %d\n", dataset.KindImage, byKind[dataset.KindImage])
	fmt.Printf("  %s records: %d\n", dataset.KindMinutiae, byKind[dataset.KindMinutiae])
	fmt.Printf("  records carrying pixels: %d\n", images)
	fmt.Printf("  records carrying minutiae: %d\n", minutiaeRecords)
	if n := len(set.Rejected); n > 0 {
		fmt.Printf("  REJECTED %d file(s) - these are excluded, see below\n", n)
	}
	fmt.Println()
}

func printReport(r *dataset.Report, showROC bool) {
	fmt.Printf("Operating point (threshold %.4f)\n", r.OperatingThreshold)
	fmt.Printf("  genuine:  %d scored, %d accepted, %d rejected\n", r.Genuine, r.GenuineAccepted, r.GenuineRejected)
	fmt.Printf("  impostor: %d scored, %d accepted, %d rejected\n", r.Impostor, r.ImpostorAccepted, r.ImpostorRejected)
	fmt.Printf("  false accept rate: %.4f\n", r.FalseAcceptRate)
	fmt.Printf("  false reject rate: %.4f\n", r.FalseRejectRate)

	fmt.Printf("\nEqual error point\n")
	fmt.Printf("  EER:        %.4f\n", r.EER)
	fmt.Printf("  threshold:  %.6f\n", r.EERThreshold)

	fmt.Printf("\nelapsed: %s\n", r.Duration.Round(time.Millisecond))

	if !showROC || len(r.ROC) == 0 {
		return
	}
	fmt.Printf("\nROC curve (%d points)\n", len(r.ROC))
	fmt.Printf("  %-12s %-12s %s\n", "FAR", "FRR", "threshold")
	// The raw curve can run to thousands of points. Print an evenly spaced
	// sample so the output stays readable while keeping both ends.
	step := len(r.ROC) / 40
	if step < 1 {
		step = 1
	}
	for i := 0; i < len(r.ROC); i += step {
		p := r.ROC[i]
		fmt.Printf("  %-12.4f %-12.4f %.6f\n", p.FAR, p.FRR, p.Threshold)
	}
	last := r.ROC[len(r.ROC)-1]
	fmt.Printf("  %-12.4f %-12.4f %.6f\n", last.FAR, last.FRR, last.Threshold)
}
