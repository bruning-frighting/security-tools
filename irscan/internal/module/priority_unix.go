//go:build unix

package module

import (
	"syscall"

	"irscan/internal/safety"
)

// applyLowPriority lowers scheduling priority so the scan does not compete with the
// customer's production workload.
//
// Failure is deliberately ignored: being unable to renice is not a reason to refuse to
// scan, and on most systems lowering (but never raising) priority is permitted even
// unprivileged.
func applyLowPriority(l safety.Limits) {
	if !l.LowPriority {
		return
	}
	_ = syscall.Setpriority(syscall.PRIO_PROCESS, 0, 10)
}
