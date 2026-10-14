//go:build windows

package module

import (
	"syscall"
	"unsafe"

	"irscan/internal/safety"
)

var (
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procSetPriorityClass      = kernel32.NewProc("SetPriorityClass")
	procGetCurrentProcessHndl = kernel32.NewProc("GetCurrentProcess")
)

// PROCESS_MODE_BACKGROUND_BEGIN lowers both CPU and I/O priority for the process, which is
// exactly the "low CPU and IO priority" production-safety requirement. It is preferred over
// BELOW_NORMAL_PRIORITY_CLASS because the latter does not affect I/O scheduling.
const processModeBackgroundBegin = 0x00100000

// applyLowPriority is best-effort; a failure is not a reason to refuse to scan.
//
// VERIFICATION STATUS: compile- and vet-verified only. No Windows build of irscan can be
// executed in the environment that produced it (DECISIONS.md B-001).
func applyLowPriority(l safety.Limits) {
	if !l.LowPriority {
		return
	}
	h, _, _ := procGetCurrentProcessHndl.Call()
	_, _, _ = procSetPriorityClass.Call(h, uintptr(processModeBackgroundBegin))
	_ = unsafe.Pointer(nil)
}
