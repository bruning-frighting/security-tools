// Command irscan is a read-only, retrospective MITRE ATT&CK host artifact scanner.
//
// Deployment model: an operator drops a portable folder onto a live customer server and
// runs one binary. No installation, no runtime dependencies, no network access at scan
// time. The ATT&CK registry is embedded at build time.
//
// The tool never writes outside --output, never deletes, quarantines, kills or modifies
// anything, and never opens sensitive process memory such as LSASS.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"irscan/internal/check"
	"irscan/internal/coverage"
	"irscan/internal/model"
	"irscan/internal/module"
	"irscan/internal/registry"
	"irscan/internal/report"
	"irscan/internal/safety"
)

// Set at build time via -ldflags (see build/go.sh dist).
var (
	version = "0.0.0-dev"
	commit  = "unknown"
)

const usage = `irscan -- read-only MITRE ATT&CK host artifact scanner

USAGE
  irscan attack  [flags]           run the ATT&CK host artifact checks
  irscan all     --scope S [flags] run every available module
  irscan malware                   NOT IMPLEMENTED (registered so its absence is visible)
  irscan modules                   list modules and their availability
  irscan version                   print version, commit and binary hash

COMMON FLAGS
  --os <windows|linux>   target OS (default: this host's OS)
  --output <dir>         output directory; the ONLY place irscan writes
  --technique <IDs>      comma-separated ATT&CK IDs to restrict to (e.g. T1547.001)
  --tactic <names>       comma-separated tactic shortnames (e.g. persistence)
  --check <IDs>          comma-separated check IDs
  --allowlist <file>     scoped, expiring suppression entries
  --root <path>          treat <path> as the filesystem root (for offline/triage images)
  --synthetic            mark --root as a fixture tree, not a mounted real root
  --dry-run              list the collectors that would run and the privileges each needs
  --report coverage      print the coverage and gaps report; does not scan

SAFETY
  Read-only. Low CPU and I/O priority. Per-collector timeouts. File count and size limits.
  Network filesystems skipped by default. Nothing is written outside --output.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "attack":
		err = runScan("attack", args)
	case "all":
		err = runScan("all", args)
	case "malware":
		err = runMalware()
	case "modules":
		err = listModules()
	case "version":
		err = printVersion()
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "irscan: %v\n", err)
		os.Exit(1)
	}
}

type opts struct {
	targetOS   string
	output     string
	techniques string
	tactics    string
	checks     string
	allowlist  string
	root       string
	synthetic  bool
	dryRun     bool
	reportKind string
	scope      string
}

func parseFlags(name string, args []string) (*opts, error) {
	o := &opts{}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&o.targetOS, "os", runtime.GOOS, "target OS (windows|linux)")
	fs.StringVar(&o.output, "output", "", "output directory")
	fs.StringVar(&o.techniques, "technique", "", "comma-separated ATT&CK technique IDs")
	fs.StringVar(&o.tactics, "tactic", "", "comma-separated tactic shortnames")
	fs.StringVar(&o.checks, "check", "", "comma-separated check IDs")
	fs.StringVar(&o.allowlist, "allowlist", "", "allowlist file")
	fs.StringVar(&o.root, "root", "", "filesystem root to scan")
	fs.BoolVar(&o.synthetic, "synthetic", false, "treat --root as a fixture tree")
	fs.BoolVar(&o.dryRun, "dry-run", false, "list collectors and privileges; do not scan")
	fs.StringVar(&o.reportKind, "report", "", "report to print without scanning (coverage)")
	fs.StringVar(&o.scope, "scope", "", "approved engagement scope identifier")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	o.targetOS = strings.ToLower(o.targetOS)
	if o.targetOS != "windows" && o.targetOS != "linux" {
		return nil, fmt.Errorf("--os must be windows or linux, got %q", o.targetOS)
	}
	return o, nil
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func runScan(command string, args []string) error {
	o, err := parseFlags(command, args)
	if err != nil {
		return err
	}

	reg, err := registry.Load()
	if err != nil {
		return err
	}

	// --report coverage: static, does not scan, needs no output directory.
	if o.reportKind == "coverage" {
		cov := coverage.Compute(reg, check.All(), nil)
		fmt.Print(report.RenderCoverage(cov, nil))
		return nil
	}
	if o.reportKind != "" {
		return fmt.Errorf("unknown --report %q (supported: coverage)", o.reportKind)
	}

	// `all` requires an explicit approved scope so a broad run is always deliberate.
	if command == "all" && strings.TrimSpace(o.scope) == "" {
		return fmt.Errorf("`irscan all` requires --scope <approved-scope-identifier>; " +
			"running every module against a customer host must be an explicit decision")
	}

	scanID := newScanID()
	mopts := module.Options{
		ScanID:     scanID,
		OutputDir:  o.output,
		TargetOS:   o.targetOS,
		FSRoot:     o.root,
		Synthetic:  o.synthetic,
		Techniques: splitList(o.techniques),
		Tactics:    splitList(o.tactics),
		Only:       splitList(o.checks),
		DryRun:     o.dryRun,
		Allowlist:  o.allowlist,
		Scope:      o.scope,
	}

	var mods []module.Module
	if command == "all" {
		mods = module.All()
	} else {
		m, ok := module.Get("attack")
		if !ok {
			return fmt.Errorf("attack module not registered")
		}
		mods = []module.Module{m}
	}

	if o.dryRun {
		return printDryRun(mods, mopts)
	}

	if strings.TrimSpace(o.output) == "" {
		return fmt.Errorf("--output <dir> is required for a scan (it is the only location " +
			"irscan writes to)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	started := time.Now().UTC()
	var (
		allResults   []model.CheckResult
		allFindings  []model.Finding
		allInventory []model.InventoryItem
		errs         []string
		enabled      []string
	)

	for _, m := range mods {
		ok, why := m.Available()
		if !ok {
			// An unavailable module is recorded, not silently skipped: the operator must
			// be able to see what did NOT run.
			errs = append(errs, fmt.Sprintf("module %q unavailable: %s", m.Name(), why))
			continue
		}
		enabled = append(enabled, m.Name())
		r, err := m.Run(ctx, mopts)
		if err != nil {
			errs = append(errs, fmt.Sprintf("module %q failed: %v", m.Name(), err))
			continue
		}
		allResults = append(allResults, r.Results...)
		allFindings = append(allFindings, r.Findings...)
		allInventory = append(allInventory, r.Inventory...)
		errs = append(errs, r.Errors...)
	}
	ended := time.Now().UTC()

	// Split reportable findings from suppressed ones. Suppressed items are counted and
	// listed in an appendix, never dropped.
	var reportable, suppressed []model.Finding
	for _, f := range allFindings {
		switch {
		case f.Suppressed:
			suppressed = append(suppressed, f)
		case f.Level.Reportable():
			reportable = append(reportable, f)
		}
	}

	_, skipped := moduleSelection(mopts)
	manifest := buildManifest(scanID, o, mopts, reg, started, ended, allResults,
		enabled, skipped, errs, len(suppressed))

	cov := coverage.Compute(reg, check.All(), allResults)

	w, err := report.NewWriter(o.output)
	if err != nil {
		return err
	}
	written, err := w.WriteAll(report.Bundle{
		Manifest:   manifest,
		Findings:   reportable,
		Inventory:  allInventory,
		Coverage:   cov,
		Results:    allResults,
		Suppressed: suppressed,
		Checks:     check.All(),
	})
	if err != nil {
		return err
	}

	// Console summary.
	fmt.Printf("irscan %s  scan_id=%s  target=%s\n", version, scanID, o.targetOS)
	fmt.Printf("  checks executed      : %d\n", len(allResults))
	fmt.Printf("  findings (reportable): %d\n", len(reportable))
	fmt.Printf("  suppressed           : %d\n", len(suppressed))
	fmt.Printf("  inventory items      : %d\n", len(allInventory))
	counts := map[model.Outcome]int{}
	for _, r := range allResults {
		counts[r.Outcome]++
	}
	fmt.Printf("  outcomes             :")
	for _, oc := range model.AllOutcomes() {
		if counts[oc] > 0 {
			fmt.Printf(" %s=%d", oc, counts[oc])
		}
	}
	fmt.Println()
	if m6, ok := cov.Metric("M6"); ok {
		fmt.Printf("  M6 data availability : %s\n", m6.String())
	}
	for _, e := range errs {
		fmt.Printf("  ! %s\n", e)
	}
	fmt.Printf("  output               : %s\n", o.output)
	for _, f := range written {
		fmt.Printf("      %s\n", f)
	}
	fmt.Printf("\n%s\n", report.TamperNotice)
	return nil
}

// moduleSelection recomputes which checks were skipped, for the manifest.
func moduleSelection(o module.Options) ([]string, map[string]string) {
	skipped := map[string]string{}
	var ran []string
	m, ok := module.Get("attack")
	if !ok {
		return ran, skipped
	}
	for _, e := range m.DryRun(o) {
		if e.WouldRun {
			ran = append(ran, e.Check)
		} else {
			skipped[e.Check] = e.SkipWhy
		}
	}
	return ran, skipped
}

func buildManifest(scanID string, o *opts, mopts module.Options, reg *registry.Registry,
	started, ended time.Time, results []model.CheckResult, enabled []string,
	skipped map[string]string, errs []string, suppressedCount int) report.ScanManifest {

	exe, _ := os.Executable()
	m := report.ScanManifest{
		ScanID:        scanID,
		Tool:          "irscan",
		Version:       version,
		Commit:        commit,
		BinarySHA256:  selfHash(exe),
		BinaryPath:    exe,
		StartedAt:     started,
		EndedAt:       ended,
		DurationMS:    ended.Sub(started).Milliseconds(),
		TargetOS:      o.targetOS,
		EnabledModules: enabled,
		Scope:         o.scope,
		ChecksSkipped: skipped,
		ATTACKVersion: reg.Source.Version,
		ATTACKSHA256:  reg.Source.SHA256,
		Attribution:   reg.Source.Attribution,
		Limits:        safety.DefaultLimits(),
		Errors:        errs,
		SuppressedCount: suppressedCount,
	}

	// Shared with every check's own Env construction (internal/check.BuildHostInfo), so the
	// manifest header and the per-check environment can never disagree about who ran the
	// scan or whether it was elevated.
	m.Host = check.BuildHostInfo(o.targetOS, o.root, o.synthetic)

	for _, r := range results {
		m.ChecksRun = append(m.ChecksRun, r.CheckID)
		for _, s := range r.Sources {
			rec := report.SourceRecord{
				Check: r.CheckID, Source: s.Name, Reason: s.Reason,
				ItemsSeen: s.ItemsSeen, Truncated: s.Truncated, Incomplete: s.Incomplete,
				Privilege: s.Privilege, Optional: s.Optional,
			}
			if s.Available {
				m.CollectedSources = append(m.CollectedSources, rec)
			} else {
				m.UnavailableSources = append(m.UnavailableSources, rec)
			}
		}
		if r.Err != "" {
			m.Errors = append(m.Errors, fmt.Sprintf("%s: %s", r.CheckID, r.Err))
		}
	}
	sort.Strings(m.ChecksRun)

	m.SelfTag = report.SelfTag{
		ScanID:      scanID,
		ProcessName: filepath.Base(exe),
		PID:         os.Getpid(),
		User:        currentUserName(),
		OutputDir:   o.output,
		Note: "irscan reads artifacts and logs; it does not modify them. When reviewing " +
			"file-access or process telemetry for the scan window, exclude this process " +
			"to avoid attributing the scanner's own reads to an adversary.",
	}
	return m
}

func printDryRun(mods []module.Module, o module.Options) error {
	fmt.Printf("irscan %s -- DRY RUN (no host data is read)\n\n", version)
	for _, m := range mods {
		ok, why := m.Available()
		status := "available"
		if !ok {
			status = "UNAVAILABLE: " + why
		}
		fmt.Printf("module %s -- %s\n  %s\n\n", m.Name(), m.Description(), status)
		if !ok {
			continue
		}
		entries := m.DryRun(o)
		fmt.Printf("  %-28s %-46s %s\n", "CHECK", "SOURCE", "PRIVILEGE REQUIRED")
		fmt.Printf("  %s\n", strings.Repeat("-", 110))
		for _, e := range entries {
			if !e.WouldRun {
				continue
			}
			opt := ""
			if e.Optional {
				opt = " (optional)"
			}
			fmt.Printf("  %-28s %-46s %s%s\n", e.Check, e.Source, e.Privilege, opt)
		}
		fmt.Println()
		var skippedShown bool
		for _, e := range entries {
			if e.WouldRun {
				continue
			}
			if !skippedShown {
				fmt.Printf("  NOT RUN:\n")
				skippedShown = true
			}
			fmt.Printf("    %-28s %s\n", e.Check, e.SkipWhy)
		}
		if skippedShown {
			fmt.Println()
		}
	}
	fmt.Println("No host data was read and nothing was written.")
	return nil
}

func runMalware() error {
	m, ok := module.Get("malware")
	if !ok {
		return fmt.Errorf("malware module not registered")
	}
	_, why := m.Available()
	fmt.Fprintf(os.Stderr, "irscan malware: NOT IMPLEMENTED\n\n%s\n", why)
	return fmt.Errorf("malware module is not implemented in this build")
}

func listModules() error {
	fmt.Printf("irscan %s modules:\n\n", version)
	for _, m := range module.All() {
		ok, why := m.Available()
		state := "AVAILABLE"
		if !ok {
			state = "NOT AVAILABLE"
		}
		fmt.Printf("  %-10s %-12s %s\n", m.Name(), state, m.Description())
		if !ok {
			fmt.Printf("             reason: %s\n", why)
		}
	}
	return nil
}

func printVersion() error {
	exe, _ := os.Executable()
	fmt.Printf("irscan %s (commit %s, %s/%s)\n", version, commit, runtime.GOOS, runtime.GOARCH)
	fmt.Printf("binary: %s\n", exe)
	fmt.Printf("binary sha256: %s\n", selfHash(exe))
	reg, err := registry.Load()
	if err != nil {
		return err
	}
	fmt.Printf("ATT&CK: %s\n", reg.Provenance())
	fmt.Printf("checks registered: %d\n", len(check.All()))
	return nil
}

// selfHash hashes the running binary so every report can state exactly what produced it.
func selfHash(path string) string {
	if path == "" {
		return "unknown"
	}
	f, err := os.Open(path)
	if err != nil {
		return "unknown"
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(h.Sum(nil))
}

// newScanID is derived from the start time and the pid. It does not need to be
// cryptographically random: its purpose is to let an analyst correlate and exclude this
// scan's own activity, not to be unguessable.
func newScanID() string {
	now := time.Now().UTC()
	seed := fmt.Sprintf("%s|%d|%s", now.Format("20060102T150405.000000Z"), os.Getpid(), version)
	sum := sha256.Sum256([]byte(seed))
	return fmt.Sprintf("irscan-%s-%s", now.Format("20060102T150405Z"),
		hex.EncodeToString(sum[:4]))
}
