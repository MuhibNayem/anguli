//go:build race

package service

// raceLatencyFactor scales the absolute latency guard when the race detector
// is enabled.
//
// Measured on the development machine: 138 ms without -race, 3.52 s with it -
// about 25x. The detector instruments every memory access, and the matcher's
// inner loop is exactly the kind of code it penalises. Without this the guard
// would fail every CI run while telling nobody anything about the code.
//
// The guard's purpose is to catch a regression - a lost cache, an accidental
// quadratic - not to certify a machine. TestSearchScalingIsReported covers the
// shape of the growth, which is the part that should not move.
const raceLatencyFactor = 40
