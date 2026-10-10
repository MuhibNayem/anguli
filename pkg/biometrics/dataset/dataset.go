// Package dataset loads real fingerprint data and evaluates a matcher against
// it.
//
// # Why this exists
//
// Every number this repository has produced so far came from synthetic,
// generated-on-the-spot images. That can prove a pipeline does not crash, that
// a parser round-trips, and that a breaker opens under load. It cannot tell you
// whether the matcher recognises a finger it has seen once. Those are different
// claims, and only real data supports the second one.
//
// This package is the route to real data:
//
//   - Load reads a directory of ISO/IEC 19794-4 image records (and 19794-2
//     minutiae records, which need no extraction) plus the subject/finger
//     metadata that those formats do not carry.
//   - Trials turns a loaded set into genuine and impostor pairs.
//   - Evaluate scores those pairs and reports FAR, FRR, EER and an ROC.
//
// # Determinism
//
// Trial generation is seeded. The same Set with the same TrialConfig always
// produces the same trials in the same order, so a score change between two
// runs is a real change and not a reshuffle.
//
// # What this does not do
//
// It does not parse ISO/IEC 19794-5 CBEFF containers. That is a separate
// container format with its own registry of identifiers, and it is deliberately
// absent rather than guessed - a container parser written from memory produces
// records that parse cleanly and match nothing. Point this package at the
// extracted records instead.
//
// It also does not download anything. Datasets such as FVC and NIST SD4 are
// distributed under their own licences and are large; this package reads what
// is already on disk.
package dataset

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"finger-scanner/pkg/biometrics/iso19794"
	"finger-scanner/pkg/biometrics/iso19794b"
)

// Errors returned by this package.
var (
	// ErrNoSamples means the load produced nothing usable. Every file was
	// rejected, which usually means the wrong directory or the wrong format.
	ErrNoSamples = errors.New("dataset: no usable samples were loaded")

	// ErrUnknownFormat means a file is neither a 19794-4 image record nor a
	// 19794-2 minutiae record.
	ErrUnknownFormat = errors.New("dataset: unrecognised record format")
)

// Kind distinguishes the two record shapes this package understands.
type Kind string

const (
	// KindImage is an ISO/IEC 19794-4 finger image record. It must go through
	// the image pipeline before it can be matched.
	KindImage Kind = "iso19794-4"
	// KindMinutiae is an ISO/IEC 19794-2:2005 minutiae record. It is already
	// in template form and skips extraction.
	KindMinutiae Kind = "iso19794-2"
)

// Sample is one impression from one finger of one person.
type Sample struct {
	// ID is stable and unique within a Set. It defaults to the file's base
	// name and is replaced by the manifest ID when one is supplied.
	ID string
	// Subject is the person. Trials use it to decide genuine vs impostor, so a
	// wrong value here silently corrupts every measurement downstream.
	Subject string
	// Finger is a human-readable finger name, e.g. "left-index".
	Finger string
	// Kind records which of the two supported formats this is.
	Kind Kind

	// raw is the record exactly as read from disk.
	raw []byte

	// Pixels is populated for KindImage records only.
	Pixels []uint8
	Width  int
	Height int

	// Minutiae is populated for KindMinutiae records only.
	Minutiae []iso19794b.MinutiaFormat

	// path is where this came from, for diagnostics.
	path string
}

// Path is the file the sample was read from.
func (s *Sample) Path() string { return s.path }

// HasPixels reports whether the sample carries image data.
func (s *Sample) HasPixels() bool { return len(s.Pixels) > 0 }

// Rejected records one file that could not be loaded, and why.
//
// A dataset is assembled from files by other people. One malformed record must
// not abort a run of ten thousand, but silently skipping it would make a
// measured FAR or FRR quietly wrong. So failures are collected and returned
// alongside the data.
type Rejected struct {
	Path string
	Err  error
}

// Set is a loaded dataset.
type Set struct {
	Samples []*Sample
	// Rejected lists every file that failed to load. Non-empty is a warning
	// worth acting on, not a fatal condition.
	Rejected []Rejected
	// Root is the directory the set was loaded from.
	Root string
}

// Options controls loading.
type Options struct {
	// Manifest names the metadata file inside the directory. When empty,
	// Load looks for "manifest.tsv". If neither exists, subject and finger are
	// parsed from the file name.
	Manifest string
	// MaxSamples caps how many samples are loaded, for previewing a large
	// dataset. Zero means no cap. The cap is applied after sorting, so the
	// same subset is produced every time.
	MaxSamples int
	// SkipExtensions lists file suffixes to ignore. Compared case-insensitively
	// against the lowercased extension, with or without a leading dot.
	SkipExtensions []string
}

// DefaultManifest is the metadata file name Load looks for.
const DefaultManifest = "manifest.tsv"

var defaultSkip = map[string]bool{
	".md": true, ".txt": true, ".tsv": true, ".csv": true,
	".json": true, ".jpg": true, ".png": true, ".gitkeep": true,
}

// Load reads every supported record in dir.
//
// Records are ISO/IEC 19794-4 or 19794-2 files. Subject and finger metadata
// come from the manifest when present, otherwise from the file name following
// the convention <subject>_<finger>_<index>, e.g. "s01_left-index_01.iso".
func Load(dir string, opts Options) (*Set, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("dataset: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("dataset: %s is not a directory", dir)
	}

	meta, err := loadManifest(dir, opts)
	if err != nil {
		return nil, err
	}

	set := &Set{Root: dir}

	for _, name := range listRecordFiles(dir, opts) {
		path := filepath.Join(dir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			set.Rejected = append(set.Rejected, Rejected{Path: path, Err: err})
			continue
		}
		sample, err := parseRecord(raw, name, meta)
		if err != nil {
			set.Rejected = append(set.Rejected, Rejected{Path: path, Err: err})
			continue
		}
		set.Samples = append(set.Samples, sample)
	}

	// Deterministic order: by subject, then finger, then ID. Two runs over the
	// same directory must produce byte-identical trial sets.
	sort.Slice(set.Samples, func(i, j int) bool {
		a, b := set.Samples[i], set.Samples[j]
		if a.Subject != b.Subject {
			return a.Subject < b.Subject
		}
		if a.Finger != b.Finger {
			return a.Finger < b.Finger
		}
		return a.ID < b.ID
	})

	if opts.MaxSamples > 0 && len(set.Samples) > opts.MaxSamples {
		set.Samples = set.Samples[:opts.MaxSamples]
	}

	if len(set.Samples) == 0 {
		return set, ErrNoSamples
	}
	return set, nil
}

// listRecordFiles returns candidate file names in a deterministic order.
func listRecordFiles(dir string, opts Options) []string {
	skip := make(map[string]bool, len(defaultSkip)+len(opts.SkipExtensions))
	for k, v := range defaultSkip {
		skip[k] = v
	}
	for _, e := range opts.SkipExtensions {
		e = strings.ToLower(e)
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		skip[e] = true
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if skip[strings.ToLower(filepath.Ext(e.Name()))] {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

type recordMeta struct {
	Subject string
	Finger  string
}

// loadManifest reads the optional manifest. A missing manifest is not an
// error; it just means names have to carry the metadata.
func loadManifest(dir string, opts Options) (map[string]recordMeta, error) {
	name := opts.Manifest
	if name == "" {
		name = DefaultManifest
	}
	path := filepath.Join(dir, name)

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("dataset: opening manifest: %w", err)
	}
	defer f.Close()

	out := make(map[string]recordMeta)
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Split(text, "\t")
		if len(fields) < 3 {
			return nil, fmt.Errorf("dataset: manifest line %d has %d fields, want at least 3 (file, subject, finger)", line, len(fields))
		}
		file := strings.TrimSpace(fields[0])
		out[file] = recordMeta{
			Subject: strings.TrimSpace(fields[1]),
			Finger:  strings.TrimSpace(fields[2]),
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("dataset: reading manifest: %w", err)
	}
	return out, nil
}

func parseRecord(raw []byte, name string, meta map[string]recordMeta) (*Sample, error) {
	s := &Sample{
		ID:      strings.TrimSuffix(name, filepath.Ext(name)),
		path:    name,
		Subject: "",
		Finger:  "",
		raw:     raw,
	}

	// Prefer the manifest; fall back to the file name.
	if m, ok := meta[name]; ok {
		s.Subject = m.Subject
		s.Finger = m.Finger
	} else {
		subject, finger := parseNameConvention(name)
		s.Subject = subject
		s.Finger = finger
	}

	switch {
	case iso19794.IsFingerImageRecord(raw):
		rec, err := iso19794.ParseImage(raw)
		if err != nil {
			return nil, fmt.Errorf("parsing 19794-4 image record: %w", err)
		}
		s.Kind = KindImage
		s.Pixels = rec.Pixels
		s.Width = rec.Width
		s.Height = rec.Height

	case isMinutiaeRecord(raw):
		rec, err := iso19794b.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("parsing 19794-2 minutiae record: %w", err)
		}
		s.Kind = KindMinutiae
		// A 19794-2 record may carry more than one view; take the first and
		// say so rather than merging fingers into one template.
		if len(rec.Views) == 0 {
			return nil, fmt.Errorf("%w: record has no finger views", ErrUnknownFormat)
		}
		s.Finger = firstNonEmpty(s.Finger, viewFingerName(rec.Views[0]))
		s.Minutiae = rec.Views[0].Minutiae

	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownFormat, name)
	}

	if s.Subject == "" {
		return nil, fmt.Errorf("subject is unknown for %s and the file name does not follow <subject>_<finger>_<n>; add a %s", name, DefaultManifest)
	}
	return s, nil
}

// isMinutiaeRecord distinguishes a 19794-2 record from anything else. The
// parsers themselves are the authority, so this only asks whether either
// could plausibly read the bytes.
func isMinutiaeRecord(raw []byte) bool {
	if len(raw) < iso19794b.RecordHeaderLen {
		return false
	}
	if iso19794.IsFingerImageRecord(raw) {
		return false
	}
	// 19794-2 starts with the ASCII "FMR\0"; 19794-4 starts with a numeric
	// format code that is never 0x464D5200.
	return string(raw[0:3]) == "FMR"
}

// parseNameConvention reads <subject>_<finger>_<index>. The subject is the
// first field; the finger is the second. Extra fields are ignored.
func parseNameConvention(name string) (subject, finger string) {
	base := strings.TrimSuffix(name, filepath.Ext(name))
	parts := strings.Split(base, "_")
	if len(parts) < 2 {
		return base, ""
	}
	return parts[0], parts[1]
}

func viewFingerName(v iso19794b.View) string {
	return fmt.Sprintf("pos%d-view%d-type%d", v.FingerPosition, v.ViewNumber, v.ImpressionType)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
