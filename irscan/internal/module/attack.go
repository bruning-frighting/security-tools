package module

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"irscan/internal/allowlist"
	"irscan/internal/check"
	"irscan/internal/model"
	"irscan/internal/registry"
	"irscan/internal/safety"

	_ "irscan/internal/checks" // registers the checks
)

// AttackModule runs the ATT&CK host-artifact checks.
type AttackModule struct{}

func (AttackModule) Name() string { return "attack" }

func (AttackModule) Description() string {
	return "MITRE ATT&CK host artifact and technique checks (persistence, stealth, " +
		"defense impairment, credential access)"
}

func (AttackModule) Available() (bool, string) {
	if _, err := registry.Load(); err != nil {
		return false, "embedded ATT&CK registry failed to load: " + err.Error()
	}
	if len(check.All()) == 0 {
		return false, "no checks are registered in this build"
	}
	return true, ""
}

func init() { Register(AttackModule{}) }

// selected resolves which checks run, and why the others do not.
func selected(opts Options) (run []check.Check, skipped map[string]string) {
	skipped = map[string]string{}
	targetOS := opts.TargetOS
	if targetOS == "" {
		targetOS = runtime.GOOS
	}

	wantTech := map[string]bool{}
	for _, t := range opts.Techniques {
		wantTech[strings.ToUpper(strings.TrimSpace(t))] = true
	}
	wantTactic := map[string]bool{}
	for _, t := range opts.Tactics {
		wantTactic[strings.ToLower(strings.TrimSpace(t))] = true
	}
	wantOnly := map[string]bool{}
	for _, t := range opts.Only {
		wantOnly[strings.ToUpper(strings.TrimSpace(t))] = true
	}

	for _, c := range check.All() {
		m := c.Meta()
		switch {
		case !m.AppliesTo(targetOS):
			skipped[m.ID] = fmt.Sprintf("targets %v, scan target OS is %s", m.OS, targetOS)
		case len(wantOnly) > 0 && !wantOnly[strings.ToUpper(m.ID)]:
			skipped[m.ID] = "excluded by --check filter"
		case len(wantTech) > 0 && !matchesAny(m.TechniqueIDs(), wantTech):
			skipped[m.ID] = "excluded by --technique filter"
		case len(wantTactic) > 0 && !matchesAnyLower(m.Tactics, wantTactic):
			skipped[m.ID] = "excluded by --tactic filter"
		default:
			run = append(run, c)
		}
	}
	return run, skipped
}

func matchesAny(have []string, want map[string]bool) bool {
	for _, h := range have {
		if want[strings.ToUpper(h)] {
			return true
		}
	}
	return false
}

func matchesAnyLower(have []string, want map[string]bool) bool {
	for _, h := range have {
		if want[strings.ToLower(h)] {
			return true
		}
	}
	return false
}

func (a AttackModule) DryRun(opts Options) []DryRunEntry {
	run, skipped := selected(opts)
	var out []DryRunEntry

	for _, c := range run {
		m := c.Meta()
		for _, s := range m.Sources {
			out = append(out, DryRunEntry{
				Check: m.ID, Title: m.Title, OS: m.OS,
				Source: s.Name, Privilege: s.Privilege, Optional: s.Optional,
				Techniques: m.TechniqueIDs(), WouldRun: true,
			})
		}
	}
	for _, c := range check.All() {
		m := c.Meta()
		why, isSkipped := skipped[m.ID]
		if !isSkipped {
			continue
		}
		out = append(out, DryRunEntry{
			Check: m.ID, Title: m.Title, OS: m.OS,
			Techniques: m.TechniqueIDs(), WouldRun: false, SkipWhy: why,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Check != out[j].Check {
			return out[i].Check < out[j].Check
		}
		return out[i].Source < out[j].Source
	})
	return out
}

func (a AttackModule) Run(ctx context.Context, opts Options) (Result, error) {
	res := Result{Module: a.Name()}

	targetOS := opts.TargetOS
	if targetOS == "" {
		targetOS = runtime.GOOS
	}

	var al check.Allowlister = allowlist.Empty{}
	if opts.Allowlist != "" {
		set, err := allowlist.Load(opts.Allowlist, time.Now)
		if err != nil {
			// A malformed allowlist is fatal: silently suppressing the wrong things is
			// worse than refusing to run.
			return res, fmt.Errorf("allowlist: %w", err)
		}
		al = set
		for _, e := range set.Expired {
			res.Errors = append(res.Errors, fmt.Sprintf(
				"allowlist entry %q expired on %s and was IGNORED", e.ID, e.Expires))
		}
	}

	limits := safety.DefaultLimits()
	applyLowPriority(limits)

	run, _ := selected(opts)

	for _, c := range run {
		m := c.Meta()
		if err := ctx.Err(); err != nil {
			res.Errors = append(res.Errors, "scan cancelled: "+err.Error())
			break
		}

		// Each check gets its own Env, and therefore its own budget: one expensive check
		// must not consume the file allowance of the next.
		env := check.NewEnv(check.EnvOptions{
			FSRoot:    opts.FSRoot,
			Synthetic: opts.Synthetic,
			TargetOS:  targetOS,
			ScanID:    opts.ScanID,
			Limits:    limits,
			Allowlist: al,
		})

		cctx, cancel := context.WithTimeout(ctx, limits.CollectorTimeout)
		r := runOne(cctx, c, env)
		cancel()

		if err := r.Validate(); err != nil {
			// A contract violation is a defect in the check, not something to paper over.
			res.Errors = append(res.Errors, fmt.Sprintf(
				"check %s produced a result violating the data contract: %v", m.ID, err))
		}
		res.Results = append(res.Results, r)
		res.Inventory = append(res.Inventory, r.Inventory...)
		res.Findings = append(res.Findings, r.Findings...)
	}

	// Cross-check deduplication: one artifact is one finding, carrying every technique and
	// check that matched it.
	res.Findings = check.MergeFindings(res.Findings)
	return res, nil
}

// runOne isolates a check so a panic in one cannot abort the scan. On a live customer
// server, a crash midway through is worse than a recorded ERROR for one check.
func runOne(ctx context.Context, c check.Check, env check.Env) (r model.CheckResult) {
	m := c.Meta()
	started := time.Now()
	defer func() {
		if p := recover(); p != nil {
			r = model.CheckResult{
				CheckID:   m.ID,
				Outcome:   model.Error,
				Reason:    fmt.Sprintf("check panicked: %v", p),
				Err:       fmt.Sprintf("panic: %v", p),
				StartedAt: started,
				Duration:  time.Since(started),
			}
		}
	}()
	return c.Run(ctx, env)
}
