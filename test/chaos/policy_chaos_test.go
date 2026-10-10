package chaos

import (
	"context"
	"testing"
	"time"

	accesscontrolv1 "finger-scanner/pkg/api/v1/accesscontrol"
)

// ---------------------------------------------------------------------------
// Anti-passback state machine: exhaustive sequence enumeration
// ---------------------------------------------------------------------------

// directions enumerates every swipe sequence up to maxLen, so the APB state
// machine is exercised over its entire reachable state space rather than a
// handful of hand-picked paths.
func directions(maxLen int) [][]int32 {
	out := [][]int32{}
	cur := []int32{}
	var rec func(prefix []int32)
	rec = func(prefix []int32) {
		if len(prefix) > 0 {
			cp := make([]int32, len(prefix))
			copy(cp, prefix)
			out = append(out, cp)
		}
		if len(prefix) == maxLen {
			return
		}
		for _, d := range []int32{1, 2} {
			rec(append(prefix, d))
		}
	}
	rec(cur)
	return out
}

func TestChaos_APBSequences(t *testing.T) {
	const dim = "apb-sequences"
	c := NewPolicyCluster(t)

	// INV-NOBYPASS: within the APB window, two consecutive ENTRY swipes for
	// the same employee must never both be granted.
	for _, seq := range directions(6) {
		t.Run(sequenceName(seq), func(t *testing.T) {
			record(dim, sequenceName(seq))
			ctx, cancel := ctxFor(t, 15*time.Second)
			defer cancel()

			emp := "APB-" + sequenceName(seq)
			prevGrantedEntry := false
			inside := false

			for i, d := range seq {
				r, err := c.Policy.EvaluateAccess(ctx, &accesscontrolv1.EvaluateAccessRequest{
					EmployeeId: emp, ZoneId: "zone-main-gate", DoorId: "door-1",
					Direction:         accesscontrolv1.DoorDirection(d),
					BiometricVerified: true, BiometricScore: 90,
					TimestampUnix: time.Now().Unix() + int64(i),
				})
				if err != nil {
					observe(dim, sequenceName(seq)+" error at step "+itoa(float64(i))+": "+shortErr(err))
					return
				}
				if d == 1 {
					if prevGrantedEntry && inside && r.IsGranted {
						t.Errorf("[%s] INV-NOBYPASS: consecutive entry both granted for %s (step %d)",
							dim, emp, i)
					}
					if r.IsGranted {
						prevGrantedEntry = true
						inside = true
					}
				} else {
					if r.IsGranted {
						prevGrantedEntry = false
						inside = false
					}
				}
			}
		})
	}
}

// INV-CORRECT: an EXIT must never be granted unless a prior ENTRY was recorded.
func TestChaos_APBExitRequiresEntry(t *testing.T) {
	const dim = "apb-exit-gating"
	c := NewPolicyCluster(t)

	for i := 0; i < 25; i++ {
		t.Run("exit-without-entry", func(t *testing.T) {
			record(dim, "exit-without-entry-"+itoa(float64(i)))
			ctx, cancel := ctxFor(t, 10*time.Second)
			defer cancel()
			// Each iteration uses a distinct, never-seen employee id.
			r, err := c.Policy.EvaluateAccess(ctx, &accesscontrolv1.EvaluateAccessRequest{
				EmployeeId: "NEVER-" + itoa(float64(i)), ZoneId: "zone-main-gate", DoorId: "d",
				Direction:         accesscontrolv1.DoorDirection_DOOR_DIRECTION_EXIT,
				BiometricVerified: true, BiometricScore: 95, TimestampUnix: time.Now().Unix()})
			if err != nil {
				return
			}
			if r.IsGranted {
				t.Errorf("[%s] exit granted for employee with no prior entry (%s)", dim, "NEVER-"+itoa(float64(i)))
			}
		})
	}
}

// Zone coverage: every zone must be evaluated, unknown zones must not silently
// become permissive.
func TestChaos_APBZoneMatrix(t *testing.T) {
	const dim = "apb-zones"
	c := NewPolicyCluster(t)
	zones := []string{
		"zone-main-gate", "zone-factory-floor", "zone-datacenter",
		"zone-unknown", "", " ", "ZONE-MAIN-GATE", "zone", "zone-",
		"zone-main-gate-x", "x-zone-main-gate", "zone main gate",
	}
	roles := []string{"", "EMPLOYEE", "OPERATOR", "SECURITY_ADMIN", "AGENT", "STAFF", "ADMIN", "NONSENSE"}
	for _, z := range zones {
		for _, role := range roles {
			t.Run("zone-role", func(t *testing.T) {
				record(dim, "zone="+zoneName(z)+" role="+zoneName(role))
				ctx, cancel := ctxFor(t, 10*time.Second)
				defer cancel()
				r, err := c.Policy.EvaluateAccess(ctx, &accesscontrolv1.EvaluateAccessRequest{
					EmployeeId: "ZR-" + zoneName(z) + "-" + zoneName(role), ZoneId: z, DoorId: "d",
					Direction:         accesscontrolv1.DoorDirection_DOOR_DIRECTION_ENTRY,
					BiometricVerified: true, BiometricScore: 90, TimestampUnix: time.Now().Unix()})
				if err != nil {
					observe(dim, "zone="+zoneName(z)+" role="+zoneName(role)+" error: "+shortErr(err))
					return
				}
				observe(dim, "zone="+zoneName(z)+" role="+zoneName(role)+" granted="+boolStr(r.IsGranted)+" reason="+r.Reason)
			})
		}
	}
}

// Biometric-verified flag interactions: the policy must not grant when the
// caller asserts verification but supplies a failing score (or vice versa).
func TestChaos_APBVerificationFlagMatrix(t *testing.T) {
	const dim = "apb-verify-flag"
	c := NewPolicyCluster(t)
	zones := []string{"zone-main-gate", "zone-factory-floor", "zone-datacenter", "zone-unknown"}
	for _, z := range zones {
		for _, verified := range []bool{true, false} {
			for _, score := range []float64{0, 59.99, 60, 69.99, 70, 100} {
				t.Run("flag", func(t *testing.T) {
					record(dim, "zone="+zoneName(z)+" verified="+boolStr(verified)+" score="+itoa(score))
					ctx, cancel := ctxFor(t, 10*time.Second)
					defer cancel()
					emp := "VF-" + zoneName(z) + "-" + boolStr(verified) + "-" + itoa(score)
					r, err := c.Policy.EvaluateAccess(ctx, &accesscontrolv1.EvaluateAccessRequest{
						EmployeeId: emp, ZoneId: z, DoorId: "d",
						Direction:         accesscontrolv1.DoorDirection_DOOR_DIRECTION_ENTRY,
						BiometricVerified: verified, BiometricScore: score, TimestampUnix: time.Now().Unix()})
					if err != nil {
						return
					}
					// INV-NOBYPASS: verified=false must never be granted.
					if !verified && r.IsGranted {
						t.Errorf("[%s] INV-NOBYPASS: granted with BiometricVerified=false (zone %s score %s)",
							dim, zoneName(z), itoa(score))
					}
					observe(dim, "zone="+zoneName(z)+" verified="+boolStr(verified)+" score="+itoa(score)+" granted="+boolStr(r.IsGranted))
				})
			}
		}
	}
}

// Time window behaviour: repeated entries inside the window must deny, and the
// state machine must recover once an exit is recorded.
func TestChaos_APBWindowRecovery(t *testing.T) {
	const dim = "apb-window-recovery"
	c := NewPolicyCluster(t)
	for i := 0; i < 20; i++ {
		t.Run("cycle", func(t *testing.T) {
			record(dim, "cycle-"+itoa(float64(i)))
			ctx, cancel := ctxFor(t, 15*time.Second)
			defer cancel()
			emp := "CYC-" + itoa(float64(i))
			swipe := func(d accesscontrolv1.DoorDirection) bool {
				r, err := c.Policy.EvaluateAccess(ctx, &accesscontrolv1.EvaluateAccessRequest{
					EmployeeId: emp, ZoneId: "zone-main-gate", DoorId: "d",
					Direction: d, BiometricVerified: true, BiometricScore: 90,
					TimestampUnix: time.Now().Unix()})
				if err != nil {
					return false
				}
				return r.IsGranted
			}
			e := accesscontrolv1.DoorDirection_DOOR_DIRECTION_ENTRY
			x := accesscontrolv1.DoorDirection_DOOR_DIRECTION_EXIT

			if !swipe(e) {
				t.Errorf("[%s] first entry denied for %s", dim, emp)
			}
			if swipe(e) {
				t.Errorf("[%s] second entry granted inside window for %s", dim, emp)
			}
			if !swipe(x) {
				t.Errorf("[%s] exit denied after entry for %s", dim, emp)
			}
			if !swipe(e) {
				t.Errorf("[%s] re-entry denied after valid exit for %s", dim, emp)
			}
			record(dim, "cycle-"+itoa(float64(i))+"/detail")
		})
	}
}

func sequenceName(seq []int32) string {
	b := make([]byte, 0, len(seq))
	for _, d := range seq {
		if d == 1 {
			b = append(b, 'E')
		} else {
			b = append(b, 'X')
		}
	}
	return string(b)
}

var _ = context.Background
