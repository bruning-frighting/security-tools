//go:build !windows

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

// isElevated on Unix means effective uid 0.
//
// This matters for honesty, not for capability: an unprivileged scan cannot read
// /etc/shadow, /var/log/audit or other users' ~/.ssh, and the report must say the scan was
// unprivileged so that "nothing found" is read correctly.
func isElevated() bool { return os.Geteuid() == 0 }

// liveRegistry is never reachable on Unix (NewEnv only calls it when TargetOS == "windows"
// and the root is live), but the symbol must exist for the package to build.
func liveRegistry() collect.Registry {
	return collect.UnavailableRegistry{
		Reason: "this binary was built for a non-Windows OS; it cannot read a Windows registry",
	}
}

func liveWindowsTelemetry() collect.TelemetrySource {
	return collect.NoTelemetry{
		Reason: "this binary was built for a non-Windows OS; it cannot read Windows event logs",
	}
}
