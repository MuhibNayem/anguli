//go:build !race

package service

// raceLatencyFactor is 1 outside a race-enabled build; see racemode_on_test.go.
const raceLatencyFactor = 1
