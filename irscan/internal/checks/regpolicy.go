package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"irscan/internal/check"
	"irscan/internal/collect"
	"irscan/internal/model"
)

// regPolicyCheck is a reusable implementation for the defence-impairment family whose
// artifact is "a registry value that should say protection is ON but says OFF".
//
// Defender, the host firewall and event-log channel configuration are all exactly that
// shape: a named value, a documented secure default, and a numeric state meaning disabled.
// Sharing the implementation is honest because the collection and the reasoning are
// identical; what is NOT shared is the documentation, the ATT&CK mapping or the fixtures.
//
// Attribution is per artifact: each policy value carries the specific technique its own
// registry value evidences, and a finding cites only that technique and its parent.
type regPolicyCheck struct {
	id      string
	title   string
	tactics []string

	techniques []check.TechniqueMapping

	sourceName      string
	sourcePrivilege string
	sourceFailures  []string

	criteria []model.Criterion

	values     []policyValue
	exclusions []exclusionKey

	escalation     string
	fpHandling     string
	overlay        check.Overlay
	artifactType   string
	inventoryGroup string

	fixtureDir     string
	wantTechniques []string
	minFindings    int
	positiveReg    func() *collect.FakeRegistry
	negativeReg    func() *collect.FakeRegistry
	positiveWhy    string
	negativeWhy    string
}

// policyValue is one protection toggle.
type policyValue struct {
	Hive, Path, Value string
	// What describes the protection in analyst language.
	What string
	// DisabledWhen lists the numeric values that mean "protection off".
	DisabledWhen []uint64
	// AbsentMeans is "enabled", "disabled" or "neutral" and says how to read the value (or
	// its whole key) being absent. Getting this wrong in either direction is how a policy
	// check either misses a disabled protection or screams about an unmanaged default.
	AbsentMeans string
	// Criterion is the criterion ID this value's disabled state satisfies.
	Criterion string
	// Technique is the specific ATT&CK ID this value evidences.
	Technique string
}

// exclusionKey is a registry key whose every value is an exclusion entry.
type exclusionKey struct {
	Hive, Path string
	What       string
	Criterion  string
	Technique  string
	// Kind distinguishes path/extension/process exclusions in the report.
	Kind string
}

func (c *regPolicyCheck) Meta() check.Meta {
	return check.Meta{
		ID:         c.id,
		Title:      c.title,
		OS:         []string{"windows"},
		Tactics:    c.tactics,
		Techniques: c.techniques,
		Sources: []check.SourceRequirement{{
			Name:         c.sourceName,
			Privilege:    c.sourcePrivilege,
			FailureModes: c.sourceFailures,
		}},
		Criteria:              c.criteria,
		EscalationCriteria:    c.escalation,
		FalsePositiveHandling: c.fpHandling,
		Overlay:               c.overlay,
		Validation:            model.FixtureTested,
		FixtureProvenance:     model.Synthetic,
	}
}

func (c *regPolicyCheck) Run(ctx context.Context, env check.Env) model.CheckResult {
	started := env.Now()
	m := c.Meta()

	src := collect.SourceResult{Name: c.sourceName, Privilege: c.sourcePrivilege}
	if ok, reason := env.Registry.Available(); !ok {
		src.Available = false
		src.Reason = reason
		return check.Result(m.ID, started, env.Now,
			[]model.DataSourceStatus{check.SourceStatus(m.Sources[0], src)}, nil, nil)
	}
	src.Available = true

	byID := map[string]model.Criterion{}
	for _, cr := range c.criteria {
		byID[cr.ID] = cr
	}

	var findings []model.Finding
	var inventory []model.InventoryItem

	// ---- protection toggles -----------------------------------------------------------
	for _, pv := range c.values {
		if err := ctx.Err(); err != nil {
			return check.ErrorResult(m.ID, started, env.Now, err)
		}
		state, raw, found := c.readPolicy(env, pv, &src)
		src.ItemsSeen++

		inventory = append(inventory, model.InventoryItem{
			Group:        c.inventoryGroup,
			ArtifactType: c.artifactType,
			ArtifactID:   pv.Hive + `\` + pv.Path + `\` + pv.Value,
			Attributes: map[string]string{
				"what":         pv.What,
				"state":        state,
				"raw_value":    Truncate(raw, 120),
				"value_present": fmt.Sprintf("%t", found),
				"absent_means": pv.AbsentMeans,
				"technique":    pv.Technique,
			},
			TechniqueIDs: []string{pv.Technique, parentOf(pv.Technique)},
			CheckIDs:     []string{m.ID},
		})

		if state != "disabled" {
			continue
		}

		artifactID := pv.Hive + `\` + pv.Path + `\` + pv.Value
		detail := fmt.Sprintf("%s = %s (value present: %t; absence would mean %s)",
			artifactID, defaultStr(raw, "(absent)"), found, pv.AbsentMeans)

		findings = append(findings, check.NewFinding(env, m.ID, check.FindingSpec{
			ArtifactType: c.artifactType,
			ArtifactID:   artifactID,
			Level:        model.SuspiciousIndicator,
			TechniqueIDs: []string{pv.Technique, parentOf(pv.Technique)},
			Title:        fmt.Sprintf("%s is DISABLED", pv.What),
			WhatAndWhere: fmt.Sprintf("%s. Registry state: %s", pv.What, detail),
			Criteria:     []model.Criterion{byID[pv.Criterion]},
			Benign: append([]string{
				"Administrators and group policy legitimately disable individual " +
					"protections, often to accommodate a third-party product.",
				"A host managed by a third-party EDR commonly has the built-in " +
					"equivalent switched off by design.",
			}, c.overlay.FalsePositives...),
			NextPivot: []string{
				"Establish whether this setting is managed by group policy or was set " +
					"locally -- a locally set value on a GPO-managed estate is the " +
					"interesting case.",
				"Check the key's last-write time to bound when the change happened, and " +
					"compare it against other suspicious activity.",
				"Confirm with the customer whether the change was authorised and when.",
				"Treat any detection gap from the period it was disabled as a blind spot " +
					"when reasoning about other checks' NOT_DETECTED results.",
			},
			Evidence: []model.EvidenceRef{{
				ID:        "ev-pol-" + collect.SHA256Hex([]byte(artifactID))[:12],
				Kind:      "registry_value",
				Source:    artifactID,
				SHA256:    collect.SHA256Hex([]byte(detail)),
				HashScope: "full_object",
				Excerpt:   Truncate(detail, env.Limits.MaxExcerptBytes),
				SizeBytes: int64(len(detail)),
			}},
			Context: map[string]string{
				"technique":    pv.Technique,
				"absent_means": pv.AbsentMeans,
				"note": "This is a CONFIGURATION observation. It shows a protection is " +
					"off; it does not by itself show who turned it off or when.",
			},
		}))
	}

	// ---- exclusion lists --------------------------------------------------------------
	for _, ex := range c.exclusions {
		if err := ctx.Err(); err != nil {
			return check.ErrorResult(m.ID, started, env.Now, err)
		}
		info, err := env.Registry.OpenKey(ex.Hive, ex.Path)
		if err != nil {
			if strings.Contains(err.Error(), "permission denied") {
				src.Errors = append(src.Errors,
					fmt.Sprintf("access denied reading %s\\%s", ex.Hive, ex.Path))
			}
			// An absent exclusions key means no exclusions are configured, which is the
			// secure default and not a visibility gap.
			continue
		}
		src.ItemsSeen++
		var entries []string
		for _, v := range info.Values {
			if strings.TrimSpace(v.Name) == "" {
				continue
			}
			entries = append(entries, v.Name)
		}
		sort.Strings(entries)

		inventory = append(inventory, model.InventoryItem{
			Group:        c.inventoryGroup,
			ArtifactType: c.artifactType,
			ArtifactID:   info.Path,
			Attributes: map[string]string{
				"what":      ex.What,
				"kind":      ex.Kind,
				"count":     fmt.Sprintf("%d", len(entries)),
				"entries":   Truncate(strings.Join(entries, " ; "), 400),
				"technique": ex.Technique,
			},
			TechniqueIDs: []string{ex.Technique, parentOf(ex.Technique)},
			CheckIDs:     []string{m.ID},
		})

		if len(entries) == 0 {
			continue
		}

		// ONE finding per exclusion list, aggregating every entry. Emitting one finding per
		// exclusion would bury an analyst on any host with a legitimately long list.
		var risky []string
		for _, e := range entries {
			if _, hit := InWindowsTransientDir(e); hit {
				risky = append(risky, e)
				continue
			}
			// A bare drive root or a whole-volume exclusion defeats the product entirely.
			q := strings.ToLower(strings.TrimSpace(e))
			if q == `c:\` || q == `c:` || q == `*` || q == `*.*` || q == `\` {
				risky = append(risky, e)
			}
		}

		crit := []model.Criterion{byID[ex.Criterion]}
		level := model.SuspiciousIndicator
		detail := fmt.Sprintf("%s: %d entr%s configured: %s", ex.What, len(entries),
			map[bool]string{true: "y", false: "ies"}[len(entries) == 1],
			strings.Join(entries, " ; "))
		if len(risky) > 0 {
			detail += fmt.Sprintf(" | entries covering user-writable or whole-volume "+
				"locations: %s", strings.Join(risky, " ; "))
		}

		findings = append(findings, check.NewFinding(env, m.ID, check.FindingSpec{
			ArtifactType: c.artifactType,
			ArtifactID:   info.Path,
			Level:        level,
			TechniqueIDs: []string{ex.Technique, parentOf(ex.Technique)},
			Title: fmt.Sprintf("%s configured (%d entries, %d covering writable or whole-volume paths)",
				ex.What, len(entries), len(risky)),
			WhatAndWhere: detail,
			Criteria:     crit,
			Benign: []string{
				"Vendor guidance for databases, mail servers, hypervisors and build agents " +
					"routinely requires antivirus exclusions, and large estates have long, " +
					"legitimate exclusion lists.",
				"Developer and CI hosts are commonly excluded to avoid build-time scanning " +
					"overhead.",
				"Backup and imaging products publish required exclusion paths.",
			},
			NextPivot: []string{
				"Compare this exclusion list against the organisation's documented, " +
					"approved exclusions -- that comparison, not this check, is what " +
					"separates authorised from planted.",
				"Inspect the contents of each excluded path: an excluded directory that " +
					"contains executables is the case worth pursuing.",
				"Check the key's last-write time to bound when entries were added.",
				"Treat excluded paths as unscanned by the endpoint product when reasoning " +
					"about any other NOT_DETECTED result.",
			},
			Aggregate: &model.Aggregate{
				Entity:     info.Path,
				EventCount: len(entries),
				TopSources: countedEntries(entries, env.Limits.MaxSampleEvents),
				Truncated:  len(entries) > env.Limits.MaxSampleEvents,
			},
			Evidence: []model.EvidenceRef{{
				ID:        "ev-exc-" + collect.SHA256Hex([]byte(info.Path))[:12],
				Kind:      "registry_key",
				Source:    info.Path,
				SHA256:    collect.SHA256Hex([]byte(strings.Join(entries, "\n"))),
				HashScope: "full_object",
				Excerpt:   Truncate(strings.Join(entries, " ; "), env.Limits.MaxExcerptBytes),
				SizeBytes: int64(len(strings.Join(entries, "\n"))),
			}},
			Context: map[string]string{
				"technique":      ex.Technique,
				"entry_count":    fmt.Sprintf("%d", len(entries)),
				"risky_entries":  fmt.Sprintf("%d", len(risky)),
				"note": "A long exclusion list is not by itself evidence of compromise. " +
					"Vendor-required exclusions are common and legitimate.",
			},
		}))
	}

	return check.Result(m.ID, started, env.Now,
		[]model.DataSourceStatus{check.SourceStatus(m.Sources[0], src)}, findings, inventory)
}

// readPolicy returns ("enabled"|"disabled"|"neutral"|"unknown", rawRendered, valuePresent).
func (c *regPolicyCheck) readPolicy(env check.Env, pv policyValue,
	src *collect.SourceResult) (string, string, bool) {

	info, err := env.Registry.OpenKey(pv.Hive, pv.Path)
	if err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			src.Errors = append(src.Errors,
				fmt.Sprintf("access denied reading %s\\%s", pv.Hive, pv.Path))
			// Denied is not absent: returning "unknown" stops the check inferring a
			// protection state it was not allowed to observe.
			return "unknown", "", false
		}
		return absentState(pv), "", false
	}
	for _, v := range info.Values {
		if !strings.EqualFold(v.Name, pv.Value) {
			continue
		}
		for _, d := range pv.DisabledWhen {
			if v.Number == d {
				return "disabled", v.String, true
			}
		}
		return "enabled", v.String, true
	}
	return absentState(pv), "", false
}

func absentState(pv policyValue) string {
	switch pv.AbsentMeans {
	case "disabled":
		return "disabled"
	case "enabled":
		return "enabled"
	default:
		return "neutral"
	}
}

func countedEntries(entries []string, limit int) []model.CountedItem {
	if limit <= 0 {
		limit = 5
	}
	out := make([]model.CountedItem, 0, limit)
	for i, e := range entries {
		if i >= limit {
			break
		}
		out = append(out, model.CountedItem{Name: e, Count: 1})
	}
	return out
}

func (c *regPolicyCheck) Cases() []check.FixtureCase {
	base := func(root, name string) string { return filepath.Join(root, c.fixtureDir, name) }
	return []check.FixtureCase{
		{
			Name:  "protections disabled",
			Kind:  check.CasePositive,
			Why:   c.positiveWhy,
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(base(root, "positive"), "windows")
				if err != nil {
					return env, err
				}
				env.Registry = c.positiveReg()
				return env, nil
			},
			WantOutcome:      model.Detected,
			MinFindings:      c.minFindings,
			WantTechniqueIDs: c.wantTechniques,
		},
		{
			Name:  "stock secure configuration",
			Kind:  check.CaseNegative,
			Why:   c.negativeWhy,
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(base(root, "negative"), "windows")
				if err != nil {
					return env, err
				}
				env.Registry = c.negativeReg()
				return env, nil
			},
			WantOutcome: model.NotDetected,
		},
		{
			Name: "registry unavailable",
			Kind: check.CaseNoData,
			Why: "Without a registry no protection state can be observed; the honest " +
				"outcome is INSUFFICIENT_DATA, never 'protections are fine'.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(base(root, "nodata"), "windows")
				if err != nil {
					return env, err
				}
				env.Registry = collect.UnavailableRegistry{
					Reason: "target is not a Windows host; there is no registry to read",
				}
				return env, nil
			},
			WantOutcome: model.InsufficientData,
		},
		{
			Name: "policy keys access-denied",
			Kind: check.CasePermissionDenied,
			Why: "Denied keys must yield 'unknown', not an inferred protection state. " +
				"Reporting a locked-down host as securely configured would be the worst " +
				"possible error for a defence-impairment check.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(base(root, "nodata"), "windows")
				if err != nil {
					return env, err
				}
				r := collect.NewFakeRegistry()
				for _, pv := range c.values {
					r.Set(pv.Hive, pv.Path, collect.RegKeyInfo{})
					r.Deny(pv.Hive, pv.Path)
				}
				for _, ex := range c.exclusions {
					r.Set(ex.Hive, ex.Path, collect.RegKeyInfo{})
					r.Deny(ex.Hive, ex.Path)
				}
				env.Registry = r
				return env, nil
			},
			WantOutcome: model.PartialData,
			AlsoAccept:  []model.Outcome{model.PermissionDenied, model.InsufficientData},
		},
	}
}
