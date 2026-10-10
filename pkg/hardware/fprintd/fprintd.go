// Package fprintd drives Linux fingerprint hardware through fprintd, the
// distribution's fingerprint daemon, over D-Bus.
//
// # What this is for
//
// This package exists because a match-in-sensor reader - which is what most
// laptop fingerprint hardware is - CANNOT supply a fingerprint image to any
// program. The sensor has its own MCU, does its own matching, and returns only
// a verdict. libfprint classifies these as match-on-chip: matching happens in
// device firmware and templates live in on-device flash.
//
// So this is an ATTESTATION driver, not a capture driver. It can answer "did
// the enrolled owner of this machine just touch the sensor?" with a real
// biometric event behind it. It cannot produce pixels, and therefore cannot
// feed the image pipeline: minutiae extraction, MCC matching and NFIQ quality
// scoring all have no input from here.
//
// On a Mac there is no equivalent option at all: Touch ID never releases the
// image from the Secure Enclave, so there is nothing for an application to
// read.
//
// # Scope and deployment caveats
//
// fprintd runs per user session on the SESSION bus, not as a system service.
// That shapes where this can be deployed:
//
//   - It suits a kiosk, a developer workstation, or a per-terminal daemon that
//     already runs as a logged-in user.
//   - It does NOT suit a headless door-controller daemon running as a system
//     service, because there is no session bus for it to attach to and no
//     enrolled user identity to verify against.
//
// A production door controller needs hardware that speaks a protocol the host
// can read - see package driver in pkg/hardware/osdp for that path. This
// package is deliberately honest about being the weaker of the two.
//
// # Cancellability
//
// Every operation here is long-running: a finger placement can take seconds,
// or never complete. All calls take a context and the underlying D-Bus method
// calls are issued with CallWithContext, so cancelling the context sends an
// org.freedesktop.DBus.Cancel to fprintd and releases the call. That matters
// for a door: an abandoned verify must not pin a reader hostage, the same
// failure mode that OSDP-001/002 were about.
//
// # Pure Go
//
// The D-Bus client is github.com/godbus/dbus/v5, which is pure Go. There is no
// cgo, no libfprint dependency, and no requirement that libfprint be present
// on the target. This matters because the runtime images in deploy/ are Alpine
// with CGO deliberately disabled.
package fprintd

import (
	"errors"
	"fmt"
)

// Error values returned by this package.
var (
	// ErrNoReader means fprintd is reachable but reports no fingerprint
	// hardware, either because there is none or because its driver is missing.
	ErrNoReader = errors.New("fprintd: no fingerprint reader available")

	// ErrNoMatch means the verify completed and the finger presented does not
	// belong to the enrolled owner. This is an expected outcome, not a fault:
	// callers should treat it as a deny decision rather than an error.
	ErrNoMatch = errors.New("fprintd: no match")

	// ErrNotEnrolled means the user has no fingerprint enrolled, so a verify
	// cannot return a meaningful result.
	ErrNotEnrolled = errors.New("fprintd: no fingerprint enrolled for user")

	// ErrNoSubject means the platform exposes no session bus. fprintd is a
	// per-session service, so a process without a session (a system daemon,
	// an SSH session, a container) cannot reach it at all.
	ErrNoSubject = errors.New("fprintd: no session bus available")
)

// Finger identifies a finger using the codes fprintd itself uses, so the
// values can be passed straight through rather than translated.
type Finger int

// The finger codes fprintd accepts.
const (
	LeftThumb Finger = iota + 1
	LeftIndex
	LeftMiddle
	LeftRing
	LeftLittle
	RightThumb
	RightIndex
	RightMiddle
	RightRing
	RightLittle
)

var fingerNames = map[Finger]string{
	LeftThumb:   "left-thumb-finger",
	LeftIndex:   "left-index-finger",
	LeftMiddle:  "left-middle-finger",
	LeftRing:    "left-ring-finger",
	LeftLittle:  "left-little-finger",
	RightThumb:  "right-thumb-finger",
	RightIndex:  "right-index-finger",
	RightMiddle: "right-middle-finger",
	RightRing:   "right-ring-finger",
	RightLittle: "right-little-finger",
}

// String renders the finger as the name fprintd expects on the wire.
func (f Finger) String() string {
	if n, ok := fingerNames[f]; ok {
		return n
	}
	return "unknown-finger"
}

// Valid reports whether f is one of the ten codes fprintd defines.
func (f Finger) Valid() bool {
	_, ok := fingerNames[f]
	return ok
}

// ParseFinger resolves a fprintd finger name back to its code. It accepts the
// dashed form fprintd uses and is case-insensitive.
func ParseFinger(name string) (Finger, error) {
	for f, n := range fingerNames {
		if equalFold(n, name) {
			return f, nil
		}
	}
	// fprintd also accepts a few bare spellings in older releases.
	for f, n := range fingerNames {
		if equalFold(trimFingerSuffix(n), name) {
			return f, nil
		}
	}
	return 0, fmt.Errorf("fprintd: %q is not a known finger", name)
}

// FingerName returns the wire name for a finger code.
func FingerName(f Finger) (string, error) {
	if !f.Valid() {
		return "", fmt.Errorf("fprintd: finger code %d is out of range 1..10", int(f))
	}
	return f.String(), nil
}

func trimFingerSuffix(n string) string {
	for _, suffix := range []string{"-finger"} {
		if len(n) > len(suffix) && n[len(n)-len(suffix):] == suffix {
			return n[:len(n)-len(suffix)]
		}
	}
	return n
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
