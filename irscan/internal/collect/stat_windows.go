//go:build windows

package collect

import (
	"os"
	"syscall"
)

// fillOwner on Windows.
//
// POSIX UID/GID do not exist, so they stay -1 and checks must not rely on them. What IS
// available cheaply is the hidden/system attribute, which matters for T1564.001 (hidden
// files) -- on Windows "hidden" is an attribute bit, not a leading dot.
//
// Resolving the actual security-descriptor owner requires GetNamedSecurityInfo plus SID
// translation. That is deliberately not done per-file during a walk: it is expensive, and
// this build cannot be executed on a Windows host in this environment to measure the cost
// (DECISIONS.md B-001). Owner resolution is therefore left to checks that need it for a
// bounded set of paths.
func fillOwner(fi *FileInfo, st os.FileInfo) {
	sys, ok := st.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return
	}
	const (
		attrHidden = 0x2
		attrSystem = 0x4
	)
	if sys.FileAttributes&attrHidden != 0 || sys.FileAttributes&attrSystem != 0 {
		fi.Hidden = true
	}
}
