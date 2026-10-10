package ratelimit

import "errors"

// ErrInvalidRate is returned by NewKeyedLimiter for a non-positive rate.
//
// This is deliberately an error rather than a silently-clamped default. A rate
// of zero on a door endpoint does not degrade gracefully - it stops every
// employee getting through - so a bad value must stop the process at startup,
// which is what the other gateway configuration does.
var ErrInvalidRate = errors.New("ratelimit: rate must be positive")
