package service

import (
	"context"
	"log/slog"
	"time"
)

// DefaultOfflineReplayInterval is how often the edge tries to flush its offline
// audit WAL to central storage when nothing else has asked it to.
const DefaultOfflineReplayInterval = 30 * time.Second

// RunOfflineReplayLoop periodically forwards buffered door decisions upstream
// until ctx is cancelled.
//
// This exists because the control was unreachable in practice. ReplayEvents was
// correct, and a gRPC endpoint invoked it, but nothing in the running edge
// process ever called that endpoint. So during an outage the edge buffered every
// door decision to its durable WAL, and when the WAN came back the events just
// sat on one machine's disk until an operator happened to make the RPC by hand.
// Central storage had no access trail at all, which is the same failure mode as
// building a revocation control nobody can invoke: the code being correct and
// tested is not the same as the control existing.
//
// It replays once immediately rather than waiting a full interval, so a node
// that reboots after an outage flushes its backlog instead of holding it for
// another period.
//
// Failures are logged once at Warn and thereafter at Debug until a success. A
// WAN outage spans many ticks, and logging every one at Warn turns a known
// condition into alarm fatigue that trains operators to ignore this line.
func RunOfflineReplayLoop(ctx context.Context, svc EdgeUseCase, interval time.Duration, logger *slog.Logger) {
	if svc == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	if interval <= 0 {
		interval = DefaultOfflineReplayInterval
	}

	// failing is true once a replay has errored and no later attempt has
	// succeeded. It gates the log level so a long outage stays quiet.
	failing := false

	attempt := func() {
		replayed, err := svc.ReplayEvents(ctx)
		if err != nil {
			if ctx.Err() != nil {
				// Shutting down; an aborted replay is not an incident.
				return
			}
			if failing {
				logger.DebugContext(ctx, "offline audit replay still failing",
					slog.String("error", err.Error()))
			} else {
				logger.WarnContext(ctx, "offline audit replay failed; events retained on the edge and will be retried",
					slog.String("error", err.Error()))
				failing = true
			}
			return
		}
		if len(replayed) > 0 {
			logger.InfoContext(ctx, "offline audit events flushed to central storage",
				slog.Int("events", len(replayed)))
		}
		if failing {
			logger.InfoContext(ctx, "offline audit replay recovered")
			failing = false
		}
	}

	attempt()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			attempt()
		}
	}
}
