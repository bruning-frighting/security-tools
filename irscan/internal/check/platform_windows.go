//go:build windows

package check

import (
	"os"
	"os/user"

	"irscan/internal/collect"
)

func currentUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "unknown"
}

// isElevated reports whether the process holds the Administrators group in its token.
//
// Implemented by attempting a read that only an elevated token can perform, rather than by
// shelling out. A false result is reported in the scan header so that "nothing found" is
// read in the light of a limited scan.
func isElevated() bool {
	// \\.\PHYSICALDRIVE0 can only be opened by an elevated token. A failure here is
	// treated as "not elevated", which is the conservative direction: over-reporting
	// elevation would make an under-privileged scan look authoritative.
	f, err := os.Open(`\\.\PHYSICALDRIVE0`)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func liveRegistry() collect.Registry { return collect.NewWindowsRegistry() }

func liveWindowsTelemetry() collect.TelemetrySource {
	// Windows event log collection is not implemented in this phase. Returning a source
	// that reports every channel absent WITH A REASON is the honest behaviour: checks will
	// emit INSUFFICIENT_DATA naming this gap, instead of NOT_DETECTED.
	return collect.NoTelemetry{
		Reason: "Windows event log collection is not implemented in this build " +
			"(irscan does not yet bind wevtapi); no event-based evidence was examined",
	}
}
