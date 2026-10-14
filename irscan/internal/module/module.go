// Package module defines the pluggable scanner module interface and the module registry.
//
// The repository was inspected and contains no malware-scanning module (DECISIONS.md D-007).
// Rather than invent one, this package provides the interface a real module would implement
// and registers an explicitly NOT-IMPLEMENTED malware command, so the CLI shape is honest
// about what does and does not exist.
package module

import (
	"context"
	"fmt"
	"sort"

	"irscan/internal/model"
)

// Options are the operator-supplied inputs common to every module.
type Options struct {
	ScanID    string
	OutputDir string
	TargetOS  string
	FSRoot    string
	Synthetic bool
	// Filters
	Techniques []string
	Tactics    []string
	Only       []string
	DryRun     bool
	Allowlist  string
	Scope      string
}

// Result is what a module returns to the runner.
type Result struct {
	Module    string
	Results   []model.CheckResult
	Findings  []model.Finding
	Inventory []model.InventoryItem
	Errors    []string
}

// Module is one scanner capability.
type Module interface {
	Name() string
	Description() string
	// Available reports whether the module can run, and why not when it cannot. A module
	// that is registered but unavailable is visible in --dry-run and in reports, which is
	// the point: the operator sees what was NOT run.
	Available() (bool, string)
	// DryRun lists the collectors that would run and the privileges each needs, without
	// touching the host.
	DryRun(opts Options) []DryRunEntry
	Run(ctx context.Context, opts Options) (Result, error)
}

// DryRunEntry describes one collector that would run.
type DryRunEntry struct {
	Check      string
	Title      string
	OS         []string
	Source     string
	Privilege  string
	Optional   bool
	Techniques []string
	// WouldRun is false when a filter or the target OS excludes this check.
	WouldRun bool
	SkipWhy  string
}

// modules is the registry of available modules. Named `modules` rather than `registry` to
// avoid shadowing the imported irscan/internal/registry package.
var modules = map[string]Module{}

func Register(m Module) { modules[m.Name()] = m }

func Get(name string) (Module, bool) { m, ok := modules[name]; return m, ok }

func All() []Module {
	out := make([]Module, 0, len(modules))
	for _, m := range modules {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// ---------------------------------------------------------------------------------------
// Malware module: registered, deliberately not implemented
// ---------------------------------------------------------------------------------------

// NotImplementedMalware is a placeholder, not a stub that pretends to work.
//
// Run returns an error and the CLI exits non-zero. It does not return an empty result set,
// because an empty result set is indistinguishable from "scanned and found nothing" and
// would be read as a clean malware scan.
type NotImplementedMalware struct{}

func (NotImplementedMalware) Name() string { return "malware" }

func (NotImplementedMalware) Description() string {
	return "Malware scanning -- NOT IMPLEMENTED in this build"
}

func (NotImplementedMalware) Available() (bool, string) {
	return false, "No malware-scanning module exists in this repository. The unified CLI " +
		"and the module interface are built so that a real module can be integrated, but " +
		"no scanner has been written and none is bundled. See DECISIONS.md D-007."
}

func (NotImplementedMalware) DryRun(Options) []DryRunEntry { return nil }

func (m NotImplementedMalware) Run(context.Context, Options) (Result, error) {
	_, why := m.Available()
	return Result{Module: "malware"}, fmt.Errorf("malware module is NOT IMPLEMENTED: %s", why)
}

func init() { Register(NotImplementedMalware{}) }
