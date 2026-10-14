package check

import (
	"os"
	"path/filepath"
	"runtime"
	"time"

	"irscan/internal/collect"
	"irscan/internal/model"
	"irscan/internal/safety"
)

// EnvOptions configures environment construction.
type EnvOptions struct {
	// FSRoot relocates the filesystem view. Empty means the live filesystem.
	FSRoot string
	// Synthetic marks FSRoot as a fixture tree rather than a mounted real root.
	Synthetic bool
	TargetOS  string
	ScanID    string
	Limits    safety.Limits
	Allowlist Allowlister
	// Now is injected for deterministic time-window logic in tests.
	Now func() time.Time
	// Registry / Telemetry override the defaults, which is how fixture and replay runs
	// supply Windows registry and event data on a Linux build.
	Registry  collect.Registry
	Telemetry collect.TelemetrySource
}

// BuildHostInfo is the single source of truth for host identification, shared by NewEnv and
// by the CLI's scan-manifest construction (cmd/irscan). Without this sharing, the manifest
// header and the per-check Env can silently disagree about who ran the scan and whether it
// was elevated -- which happened during development: the manifest's Host block was built
// independently and simply never populated ScanUser or Elevated, so the report printed
// "scanned as ``" even on a real run.
func BuildHostInfo(targetOS, fsRoot string, synthetic bool) model.HostInfo {
	host := model.HostInfo{
		OS:            targetOS,
		Arch:          runtime.GOARCH,
		FSRoot:        fsRoot,
		SyntheticRoot: synthetic,
		Attributes:    map[string]string{},
	}
	if synthetic {
		host.Hostname = "fixture-" + filepath.Base(fsRoot)
		host.ScanUser = "(fixture)"
	} else {
		if hn, err := os.Hostname(); err == nil {
			host.Hostname = hn
		}
		host.ScanUser = currentUser()
		host.Elevated = isElevated()
	}
	return host
}

// NewEnv builds a check Env.
//
// Defaults are chosen so that an unsupplied source reports itself unavailable WITH A REASON
// rather than silently behaving as empty. That is the difference between a report saying
// "the registry could not be read on this host" and one implying the registry was clean.
func NewEnv(opts EnvOptions) Env {
	if opts.TargetOS == "" {
		opts.TargetOS = runtime.GOOS
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Allowlist == nil {
		opts.Allowlist = NoAllowlist{}
	}
	if opts.Limits == (safety.Limits{}) {
		opts.Limits = safety.DefaultLimits()
	}

	budget := safety.NewBudget(opts.Limits)
	fs := collect.NewRootFS(opts.FSRoot, opts.TargetOS, budget, opts.Synthetic)

	reg := opts.Registry
	if reg == nil {
		reg = defaultRegistry(opts)
	}
	tel := opts.Telemetry
	if tel == nil {
		tel = defaultTelemetry(opts, fs)
	}

	host := BuildHostInfo(opts.TargetOS, opts.FSRoot, opts.Synthetic)

	return Env{
		Host:      host,
		ScanID:    opts.ScanID,
		FS:        fs,
		Registry:  reg,
		Telemetry: tel,
		Budget:    budget,
		Limits:    opts.Limits,
		Allowlist: opts.Allowlist,
		Now:       opts.Now,
		TargetOS:  opts.TargetOS,
	}
}

func defaultRegistry(opts EnvOptions) collect.Registry {
	if opts.TargetOS != "windows" {
		return collect.UnavailableRegistry{
			Reason: "target OS is " + opts.TargetOS + "; there is no Windows registry to read",
		}
	}
	if opts.Synthetic || opts.FSRoot != "" {
		// A fixture tree cannot supply a live registry. Callers that need registry data in
		// a fixture run must pass a FakeRegistry; defaulting to "unavailable with a reason"
		// prevents a fixture run from looking like a clean registry scan.
		return collect.UnavailableRegistry{
			Reason: "scanning a relocated filesystem root; the live Windows registry is not " +
				"part of that root and no fixture registry was supplied",
		}
	}
	return liveRegistry()
}

func defaultTelemetry(opts EnvOptions, fs collect.FileSystem) collect.TelemetrySource {
	switch opts.TargetOS {
	case "linux":
		return collect.DefaultLinuxTelemetry(fs)
	case "windows":
		if opts.Synthetic || opts.FSRoot != "" {
			return collect.NoTelemetry{
				Reason: "scanning a relocated filesystem root; Windows event channels are " +
					"not part of that root and no fixture telemetry was supplied",
			}
		}
		return liveWindowsTelemetry()
	default:
		return collect.NoTelemetry{Reason: "no telemetry source for target OS " + opts.TargetOS}
	}
}

// FixtureEnv builds an Env rooted at a fixture directory.
//
// This is the single entry point used by the generic gate test runner, so every check is
// tested through exactly the same construction path a real scan uses -- only the FS root and
// the injected sources differ.
func FixtureEnv(fixtureDir, targetOS string) (Env, error) {
	if _, err := os.Stat(fixtureDir); err != nil {
		return Env{}, err
	}
	abs, err := filepath.Abs(fixtureDir)
	if err != nil {
		return Env{}, err
	}
	fixed := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	return NewEnv(EnvOptions{
		FSRoot:    abs,
		Synthetic: true,
		TargetOS:  targetOS,
		ScanID:    "fixture-scan",
		Now:       func() time.Time { return fixed },
	}), nil
}
