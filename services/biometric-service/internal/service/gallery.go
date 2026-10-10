package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"runtime"
	"sort"
	"sync"
	"time"

	"finger-scanner/pkg/biometrics/crypto"
	"finger-scanner/pkg/biometrics/mcc"
	"finger-scanner/pkg/biometrics/minutiae"
	"finger-scanner/services/biometric-service/internal/domain"
	"finger-scanner/services/biometric-service/internal/ports"
)

// galleryTTL bounds how long a decrypted gallery is trusted before being
// rebuilt from the repository.
//
// The TTL exists because the cache is per-process. Enrolling an employee on
// replica A cannot invalidate replica B's in-memory gallery, so a fresh
// enrollment is invisible to 1:N search on every other replica until their
// caches expire. Invalidating on local writes covers the single-node case
// exactly; the TTL is what covers the rest, trading a bounded window of
// staleness for not rebuilding a multi-gigabyte gallery on every walk-up.
const galleryTTL = 30 * time.Second

// galleryMinutiaeTolerance is the fractional difference in minutiae count
// allowed between probe and candidate before the candidate is discarded.
//
// This is the cheapest possible filter and it runs before any decryption,
// matching or Hough voting, so it is the only lever that reduces the constant
// factor rather than the asymptotics. +-25% is deliberately wide: extraction is
// noisy on real prints and a narrow bound would reject true matches at the
// boundary, turning a performance win into a false-negative for exactly the
// employees whose fingers gave a marginal read.
const galleryMinutiaeTolerance = 0.25

// galleryEntry is one enrolled finger, decrypted once and kept matcher-ready.
type galleryEntry struct {
	employeeID string
	position   int32
	template   *mcc.Template
	minutiae   int
	// points and grid back the spatial-consensus prefilter. They are derived
	// from the same payload as the cylinders, so they cannot drift apart.
	points []minutiae.Minutia
	grid   spatialGrid
}

// spatialGrid buckets minutiae into square cells so a proximity test costs a
// couple of map lookups instead of a scan of every enrolled point.
//
// The matcher itself is the expensive thing in 1:N search - profiling a 2000
// finger gallery put over 90% of CPU inside Cylinder.SimilarityWithShift and its
// callers, which run once per probe/gallery cylinder pair. This grid does not
// make matching cheaper; it makes it possible to throw away candidates without
// matching them.
type spatialGrid struct {
	cell    float64
	buckets map[[2]int][]minutiae.Minutia
}

func newSpatialGrid(points []minutiae.Minutia, cell float64) spatialGrid {
	g := spatialGrid{cell: cell, buckets: make(map[[2]int][]minutiae.Minutia, len(points))}
	for _, p := range points {
		key := g.key(p)
		g.buckets[key] = append(g.buckets[key], p)
	}
	return g
}

func (g spatialGrid) keyOf(p minutiae.Minutia) (int, int) {
	return int(float64(p.X) / g.cell), int(float64(p.Y) / g.cell)
}

func (g spatialGrid) key(p minutiae.Minutia) [2]int {
	cx, cy := g.keyOf(p)
	return [2]int{cx, cy}
}

// hasNeighbourWithin reports whether any indexed point lies within tol of p.
func (g spatialGrid) hasNeighbourWithin(p minutiae.Minutia, tol float64) bool {
	cx, cy := g.keyOf(p)
	tolSq := tol * tol
	for dx := -1; dx <= 1; dx++ {
		for dy := -1; dy <= 1; dy++ {
			for _, q := range g.buckets[[2]int{cx + dx, cy + dy}] {
				ddx := float64(p.X) - float64(q.X)
				ddy := float64(p.Y) - float64(q.Y)
				if ddx*ddx+ddy*ddy <= tolSq {
					return true
				}
			}
		}
	}
	return false
}

// spatialFilterTolerance is how far apart a probe minutia may sit from an
// enrolled one and still count as the same feature.
//
// The matcher tolerates translation up to transTol (14px) when clustering its
// own inliers, so 20px leaves headroom over what a true match is willing to
// accept rather than cutting inside it.
const spatialFilterTolerance = 20.0

// spatialFilterMinFraction is the share of probe minutiae that must find a
// neighbouring enrolled minutia for a candidate to survive.
//
// Deliberately low. A genuine match from a different finger placement can lose
// a large share of its minutiae to extraction noise, so requiring a high
// overlap would reject true matches - and a false negative here means a real
// person does not get through the door. The filter's job is only to discard
// candidates that share almost nothing with the probe, which is what the
// overwhelming majority of a large gallery looks like.
const spatialFilterMinFraction = 0.30

// spatialPreFilter discards candidates that share almost no spatial structure
// with the probe, before any cylinder comparison happens.
//
// Measured result: it removes very little, and that is a property of
// fingerprints rather than a tuning mistake. Minutiae are concentrated in the
// centre of every print, so two different people have systematically similar
// minutiae distributions and a spatial test passes almost everything. It is
// kept because it costs almost nothing, not because it carries the load.
func (e galleryEntry) spatialPreFilter(probe []minutiae.Minutia) bool {
	if len(probe) == 0 {
		return false
	}
	needed := int(float64(len(probe)) * spatialFilterMinFraction)
	if needed < 1 {
		needed = 1
	}
	hits := 0
	for _, p := range probe {
		if e.grid.hasNeighbourWithin(p, spatialFilterTolerance) {
			hits++
			if hits >= needed {
				return true
			}
		}
	}
	return false
}

// gallery caches decrypted templates so 1:N search does not re-read and
// re-decrypt the entire enrolment table on every walk-up.
//
// What this replaces: ListAll followed by a per-record AES-GCM decrypt, JSON
// unmarshal and matcher invocation, all serial, on the request path. At campus
// scale that is tens of thousands of decryptions per swipe, and the cost grows
// with the number of employees rather than staying flat.
type gallery struct {
	mu        sync.RWMutex
	entries   []galleryEntry
	loadedAt  time.Time
	populated bool
}

// invalidate marks the cache stale so the next search rebuilds it.
//
// Called after a local write. It drops the entries immediately rather than
// waiting for the TTL, because the writer knows the table changed and there is
// no reason to serve a gallery that is known to be missing it.
func (g *gallery) invalidate() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.entries = nil
	g.populated = false
	g.loadedAt = time.Time{}
}

// snapshot returns the current gallery, rebuilding it if stale or empty.
//
// The rebuild runs under a write lock, so concurrent walk-ups arriving during a
// reload wait for one rebuild rather than each starting their own. That is
// deliberate: without it, a morning rush of simultaneous scans on a cold cache
// would issue one full table scan and decryption pass per waiting reader.
func (g *gallery) snapshot(
	ctx context.Context,
	repo ports.TemplateRepository,
	vault *crypto.Vault,
	logger *slog.Logger,
) ([]galleryEntry, bool, error) {
	g.mu.RLock()
	fresh := g.populated && time.Since(g.loadedAt) < galleryTTL
	entries := g.entries
	g.mu.RUnlock()

	if fresh {
		return entries, false, nil
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	// Re-check: another goroutine may have rebuilt while we waited.
	if g.populated && time.Since(g.loadedAt) < galleryTTL {
		return g.entries, false, nil
	}

	built, err := buildGallery(ctx, repo, vault, logger)
	if err != nil {
		return nil, false, err
	}

	g.entries = built
	g.populated = true
	g.loadedAt = time.Now()
	return built, true, nil
}

// buildGallery reads every enrolled template and decrypts it once.
func buildGallery(
	ctx context.Context,
	repo ports.TemplateRepository,
	vault *crypto.Vault,
	logger *slog.Logger,
) ([]galleryEntry, error) {
	all, err := repo.ListAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list templates: %w", err)
	}

	built := make([]galleryEntry, 0, len(all))
	skipped := 0
	for _, item := range all {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		decrypted, err := vault.DecryptTemplate(item.EncryptedPayload)
		if err != nil {
			// A single unreadable record must not blind the whole gallery: the
			// employee is simply not searchable until it is re-enrolled.
			skipped++
			continue
		}
		var payload domain.DecryptedTemplatePayload
		if err := json.Unmarshal(decrypted, &payload); err != nil {
			skipped++
			continue
		}

		tmpl := &mcc.Template{
			ID:        item.TemplateID,
			Cylinders: payload.Cylinders,
		}
		if len(tmpl.Cylinders) == 0 {
			skipped++
			continue
		}

		built = append(built, galleryEntry{
			employeeID: item.EmployeeID,
			position:   item.Position,
			template:   tmpl,
			points:     payload.Minutiae,
			grid:       newSpatialGrid(payload.Minutiae, spatialFilterTolerance),
			// One cylinder per minutia, so the length is an exact count and
			// needs no separate bookkeeping that could drift from the data.
			minutiae: len(tmpl.Cylinders),
		})
	}

	if skipped > 0 {
		logger.WarnContext(ctx, "gallery rebuild skipped unreadable templates",
			slog.Int("skipped", skipped),
			slog.Int("loaded", len(built)),
		)
	}
	logger.InfoContext(ctx, "gallery loaded", slog.Int("templates", len(built)))
	return built, nil
}

// search evaluates the probe against the gallery and returns the best matches.
//
// Caching removed the database and decryption cost; this removes the remaining
// serial constraint. The matcher is pure - it holds only read-only thresholds
// and allocates everything it needs per call - so survivors are verified across
// a bounded worker pool instead of one at a time on a single goroutine.
//
// The honest limit of this approach: it reduces wall-clock by the core count,
// not by the asymptotic cost. The matcher still compares every probe cylinder
// against every gallery cylinder for each surviving candidate, and that inner
// loop is still over 90% of CPU. Three rounds of output-identical optimisation
// have made it about 22x cheaper and moved the 200 ms SLA from roughly 100
// enrolled fingers to roughly 3100, but the growth is still linear and the
// next order of magnitude needs a different algorithm. See the throughput note
// in the README before sizing a gallery.
func (g *gallery) search(
	ctx context.Context,
	probe *mcc.Template,
	probePoints []minutiae.Minutia,
	matcher *mcc.Matcher,
	topK uint32,
	logger *slog.Logger,
) []CandidateResult {
	probeMinutiae := len(probe.Cylinders)

	g.mu.RLock()
	entries := g.entries
	g.mu.RUnlock()

	tolerance := int(float64(probeMinutiae)*galleryMinutiaeTolerance) + 1
	candidates := make([]galleryEntry, 0, len(entries))
	byCount := 0
	for _, e := range entries {
		if diff := e.minutiae - probeMinutiae; diff > tolerance || diff < -tolerance {
			continue
		}
		byCount++
		if !e.spatialPreFilter(probePoints) {
			continue
		}
		candidates = append(candidates, e)
	}

	logger.DebugContext(ctx, "gallery pre-filter applied",
		slog.Int("gallery", len(entries)),
		slog.Int("after_count_filter", byCount),
		slog.Int("after_spatial_filter", len(candidates)),
		slog.Int("probe_minutiae", probeMinutiae),
	)
	if len(candidates) == 0 {
		return nil
	}

	workers := runtime.GOMAXPROCS(0)
	if workers > len(candidates) {
		workers = len(candidates)
	}

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		hits []CandidateResult
	)
	jobs := make(chan galleryEntry)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for e := range jobs {
				// The matcher is pure, so a shared instance is safe here.
				res, err := matcher.Verify(ctx, probe, e.template)
				if err != nil || !res.IsMatch {
					continue
				}
				mu.Lock()
				hits = append(hits, CandidateResult{
					EmployeeID: e.employeeID,
					Position:   e.position,
					Score:      res.Score,
				})
				mu.Unlock()
			}
		}()
	}

feed:
	for _, e := range candidates {
		select {
		case <-ctx.Done():
			break feed
		case jobs <- e:
		}
	}
	close(jobs)
	wg.Wait()

	sort.Slice(hits, func(i, j int) bool { return hits[i].Score > hits[j].Score })

	if topK > 0 && len(hits) > int(topK) {
		hits = hits[:topK]
	}
	return hits
}
