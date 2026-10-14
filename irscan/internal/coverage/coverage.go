// Package coverage computes the six coverage metrics.
//
// Three rules govern everything here:
//
//  1. Each metric keeps its own numerator and denominator and is NEVER merged with another
//     into a single score.
//  2. A technique is counted ONCE in every global denominator even when it belongs to
//     several tactics; the (technique, OS) view is reported separately.
//  3. A technique may only be counted IMPLEMENTED when a check that maps to it passes the
//     full per-check quality gate. The registry baseline cannot assert IMPLEMENTED, and the
//     check's own declaration is not taken at face value -- check.EvaluateGate decides.
package coverage

import (
	"fmt"
	"sort"

	"irscan/internal/check"
	"irscan/internal/model"
	"irscan/internal/registry"
)

// Metric is one coverage number, always carrying both parts and the name of its universe.
type Metric struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Definition      string `json:"definition"`
	Numerator       int    `json:"numerator"`
	Denominator     int    `json:"denominator"`
	DenominatorName string `json:"denominator_name"`
	Note            string `json:"note,omitempty"`
	// Companions are numerators over the SAME denominator that must be reported beside
	// this metric but never added into it (e.g. FIXTURE_TESTED beside LAB_VERIFIED).
	Companions []Companion `json:"companions,omitempty"`
}

type Companion struct {
	Name      string `json:"name"`
	Numerator int    `json:"numerator"`
}

// String always states the denominator inline, as required.
func (m Metric) String() string {
	if m.Denominator == 0 {
		return fmt.Sprintf("%d/%d (%s; undefined, denominator is zero)",
			m.Numerator, m.Denominator, m.DenominatorName)
	}
	return fmt.Sprintf("%d/%d = %.1f%% (denominator: %s = %d)",
		m.Numerator, m.Denominator,
		100*float64(m.Numerator)/float64(m.Denominator),
		m.DenominatorName, m.Denominator)
}

// TechniqueStatus is the resolved per-technique view that feeds M3/M4 and the gaps report.
type TechniqueStatus struct {
	TechniqueID      string                     `json:"technique_id"`
	Name             string                     `json:"name"`
	Tactics          []string                   `json:"tactics"`
	OSScope          []string                   `json:"os_scope"`
	TestabilityClass string                     `json:"testability_class"`
	Baseline         string                     `json:"baseline_status"`
	Effective        model.ImplementationStatus `json:"effective_status"`
	Rationale        string                     `json:"rationale"`
	// Checks that map to this technique, with whether each passes the gate.
	Checks []CheckRef `json:"checks,omitempty"`
}

type CheckRef struct {
	CheckID     string `json:"check_id"`
	GatePassing bool   `json:"gate_passing"`
	Partial     bool   `json:"partial_mapping"`
	Validation  string `json:"validation_status"`
	GateFailures []string `json:"gate_failures,omitempty"`
}

// Report is the full coverage computation.
type Report struct {
	ATTACKVersion string `json:"attack_version"`
	ATTACKSHA256  string `json:"attack_stix_sha256"`
	Attribution   string `json:"attribution"`

	Metrics []Metric `json:"metrics"`

	// PerTactic and PerOS break M3 down without changing the global denominator.
	PerTactic map[string]Metric `json:"m3_per_tactic"`
	PerOS     map[string]Metric `json:"m3_per_technique_os_pair"`

	Techniques []TechniqueStatus `json:"techniques"`

	// Inconsistencies are registry/check disagreements. A non-empty list is a defect.
	Inconsistencies []string `json:"inconsistencies"`

	// ReconstructionNotice is printed with every coverage output.
	ReconstructionNotice string `json:"reconstruction_notice"`
}

const reconstructionNotice = "" +
	"The six metrics below are a RECONSTRUCTION. The authoritative specification document " +
	"was not available in the session that produced this tool, so the metric set was " +
	"derived from the task's stated requirements (separate metrics, each with an explicit " +
	"numerator and denominator, never merged). See PLAN.md section 4 and DECISIONS.md " +
	"D-001. If the original specification is supplied, these definitions must be " +
	"re-checked against it."

// Compute builds the coverage report.
//
// results may be nil: M1-M5 are static properties of the registry and the check inventory,
// so they can be reported without running a scan. M6 is per-scan and is omitted (denominator
// zero, clearly labelled) when no results are supplied.
func Compute(reg *registry.Registry, checks []check.Check, results []model.CheckResult) *Report {
	rep := &Report{
		ATTACKVersion:        reg.Source.Version,
		ATTACKSHA256:         reg.Source.SHA256,
		Attribution:          reg.Source.Attribution,
		PerTactic:            map[string]Metric{},
		PerOS:                map[string]Metric{},
		ReconstructionNotice: reconstructionNotice,
	}

	// --- index checks by technique, recording gate results -----------------------------
	gates := map[string]check.GateResult{}
	byTechnique := map[string][]CheckRef{}
	for _, c := range checks {
		m := c.Meta()
		g := check.EvaluateGate(c)
		gates[m.ID] = g
		for _, tm := range m.Techniques {
			byTechnique[tm.TechniqueID] = append(byTechnique[tm.TechniqueID], CheckRef{
				CheckID:      m.ID,
				GatePassing:  g.Passes(),
				Partial:      tm.Partial,
				Validation:   string(m.Validation),
				GateFailures: g.Failures,
			})
		}
	}

	// --- per-technique effective status ------------------------------------------------
	host := reg.HostScope()
	for _, t := range host {
		st := TechniqueStatus{
			TechniqueID:      t.ID,
			Name:             t.Name,
			Tactics:          t.Tactics,
			OSScope:          t.OSScope,
			TestabilityClass: t.TestabilityClass,
			Baseline:         t.BaselineStatus,
			Checks:           byTechnique[t.ID],
		}
		st.Effective, st.Rationale = effectiveStatus(t, byTechnique[t.ID])
		rep.Techniques = append(rep.Techniques, st)

		// Consistency: the registry baseline and the check inventory must not disagree.
		if len(byTechnique[t.ID]) > 0 &&
			(t.BaselineStatus == "UNSUPPORTED" || t.BaselineStatus == "NOT_APPLICABLE") {
			rep.Inconsistencies = append(rep.Inconsistencies, fmt.Sprintf(
				"%s: registry baseline says %s but %d check(s) map to it; either the "+
					"baseline classification or the mapping is wrong",
				t.ID, t.BaselineStatus, len(byTechnique[t.ID])))
		}
	}
	sort.Slice(rep.Techniques, func(i, j int) bool {
		return registry.SortKey(rep.Techniques[i].TechniqueID) <
			registry.SortKey(rep.Techniques[j].TechniqueID)
	})

	statusOf := map[string]model.ImplementationStatus{}
	for _, s := range rep.Techniques {
		statusOf[s.TechniqueID] = s.Effective
	}

	// --- M1 registry completeness -------------------------------------------------------
	m1num := 0
	for i := range reg.Techniques {
		t := &reg.Techniques[i]
		ok := t.ID != "" && t.Name != "" && len(t.Platforms) > 0
		if t.Active && len(t.Tactics) == 0 {
			ok = false
		}
		if t.IsSubtechnique && t.ParentID == "" {
			ok = false
		}
		if ok {
			m1num++
		}
	}
	rep.Metrics = append(rep.Metrics, Metric{
		ID:   "M1",
		Name: "Registry completeness",
		Definition: "Techniques parsed from the pinned STIX bundle with all required " +
			"fields resolved (ID, name, tactics for active objects, parent for " +
			"sub-techniques), over every attack-pattern in the bundle.",
		Numerator: m1num, Denominator: len(reg.Techniques),
		DenominatorName: "U_bundle (all attack-patterns in the pinned bundle)",
	})

	// --- M2 classification completeness --------------------------------------------------
	m2num := 0
	for _, t := range host {
		if t.TestabilityClass != "" && t.TestabilityClass != "UNDETERMINED" &&
			t.BaselineStatus != "" {
			m2num++
		}
	}
	rep.Metrics = append(rep.Metrics, Metric{
		ID:   "M2",
		Name: "Classification completeness",
		Definition: "In-scope techniques carrying both a resolved testability class (not " +
			"UNDETERMINED) and a baseline implementation status, over all in-scope " +
			"techniques. The Phase 2d gate requires this to be 100%.",
		Numerator: m2num, Denominator: len(host),
		DenominatorName: "U_host (active techniques applicable to Windows or Linux)",
	})

	// --- M3 / M4 over U_impl --------------------------------------------------------------
	impl := reg.ImplementationScope()
	m3num, m4num := 0, 0
	for _, t := range impl {
		switch statusOf[t.ID] {
		case model.Implemented:
			m3num++
		case model.Partial:
			m4num++
		}
	}
	rep.Metrics = append(rep.Metrics, Metric{
		ID:   "M3",
		Name: "Implementation coverage",
		Definition: "Techniques with at least one non-partial mapping from a check that " +
			"PASSES the full per-check quality gate, over techniques in the " +
			"implementation scope. A check that fails any gate item is excluded.",
		Numerator: m3num, Denominator: len(impl),
		DenominatorName: "U_impl (in-scope techniques in persistence, stealth, " +
			"defense-impairment or credential-access)",
		Note: "A technique belonging to several tactics is counted ONCE here.",
	})
	rep.Metrics = append(rep.Metrics, Metric{
		ID:   "M4",
		Name: "Partial coverage",
		Definition: "Techniques whose best available check is PARTIAL -- a check exists " +
			"but fails a gate item, or maps only partially. Explicitly NOT added to M3.",
		Numerator: m4num, Denominator: len(impl),
		DenominatorName: "U_impl",
	})

	// M3 per tactic. A technique in two scope tactics contributes to both breakdowns but
	// still only once to the global M3 above.
	for _, tac := range reg.ImplementationTactics() {
		num, den := 0, 0
		for _, t := range impl {
			if !t.HasTactic(tac) {
				continue
			}
			den++
			if statusOf[t.ID] == model.Implemented {
				num++
			}
		}
		rep.PerTactic[tac] = Metric{
			ID: "M3." + tac, Name: "Implementation coverage: " + reg.TacticName(tac),
			Numerator: num, Denominator: den,
			DenominatorName: "U_impl techniques in tactic " + tac,
			Note: "Techniques in more than one scope tactic appear in each tactic's " +
				"breakdown; the global M3 counts them once.",
		}
	}

	// M3 as (technique, OS) pairs.
	for _, os := range []string{"linux", "windows"} {
		num, den := 0, 0
		for _, t := range impl {
			if !t.SupportsOS(os) {
				continue
			}
			den++
			if statusOf[t.ID] != model.Implemented {
				continue
			}
			// The technique only counts for this OS if a gate-passing check actually
			// targets this OS.
			for _, cr := range byTechnique[t.ID] {
				if !cr.GatePassing || cr.Partial {
					continue
				}
				for _, c := range checks {
					if c.Meta().ID == cr.CheckID && c.Meta().AppliesTo(os) {
						num++
						goto nextTechnique
					}
				}
			}
		nextTechnique:
		}
		rep.PerOS[os] = Metric{
			ID: "M3.os." + os, Name: "Implementation coverage: " + os + " (technique,OS pairs)",
			Numerator: num, Denominator: den,
			DenominatorName: "U_impl techniques applicable to " + os,
		}
	}

	// --- M5 validation coverage -------------------------------------------------------
	lab, fixture, untested := 0, 0, 0
	for _, c := range checks {
		switch c.Meta().Validation {
		case model.LabVerified:
			lab++
		case model.FixtureTested:
			fixture++
		default:
			untested++
		}
	}
	rep.Metrics = append(rep.Metrics, Metric{
		ID:   "M5",
		Name: "Validation coverage (LAB_VERIFIED only)",
		Definition: "Checks observed running against a real OS of the right kind, over all " +
			"defined checks. FIXTURE_TESTED is reported beside it and is NEVER added in.",
		Numerator: lab, Denominator: len(checks),
		DenominatorName: "all defined checks",
		Note: "Windows checks cannot reach LAB_VERIFIED in the environment that produced " +
			"this build: Smart App Control blocks execution of unsigned binaries " +
			"(DECISIONS.md B-001).",
		Companions: []Companion{
			{Name: "FIXTURE_TESTED", Numerator: fixture},
			{Name: "UNTESTED", Numerator: untested},
		},
	})

	// --- M6 runtime data availability (per scan) ---------------------------------------
	determinate, executed := 0, 0
	for _, r := range results {
		if r.Outcome == model.NotTested {
			continue
		}
		executed++
		if r.Outcome.Determinate() {
			determinate++
		}
	}
	m6 := Metric{
		ID:   "M6",
		Name: "Runtime data availability (this scan)",
		Definition: "Checks that returned a determinate outcome (DETECTED or NOT_DETECTED), " +
			"over checks actually executed in this scan. The complement is the share of " +
			"checks that could not answer because data, privileges or both were missing.",
		Numerator: determinate, Denominator: executed,
		DenominatorName: "checks executed in this scan",
	}
	if executed == 0 {
		m6.Note = "No scan results supplied; this metric is undefined rather than zero."
	}
	rep.Metrics = append(rep.Metrics, m6)

	return rep
}

// effectiveStatus resolves the registry baseline against the real check inventory.
//
// This is the only place IMPLEMENTED can be produced, and it requires a gate-passing check
// with a non-partial mapping.
func effectiveStatus(t *registry.Technique, refs []CheckRef) (model.ImplementationStatus, string) {
	if !t.Active {
		return model.NotApplicable, "ATT&CK object is revoked or deprecated."
	}
	if len(refs) == 0 {
		return model.ImplementationStatus(t.BaselineStatus), t.BaselineRationale
	}

	var passing, partial, failing []string
	for _, r := range refs {
		switch {
		case r.GatePassing && !r.Partial:
			passing = append(passing, r.CheckID)
		case r.GatePassing && r.Partial:
			partial = append(partial, r.CheckID)
		default:
			failing = append(failing, r.CheckID)
		}
	}
	switch {
	case len(passing) > 0:
		return model.Implemented, fmt.Sprintf(
			"Covered by gate-passing check(s): %v.", passing)
	case len(partial) > 0:
		return model.Partial, fmt.Sprintf(
			"Only partial mappings exist (%v): the check covers part of this technique. "+
				"Excluded from implementation coverage.", partial)
	default:
		return model.Partial, fmt.Sprintf(
			"Check(s) %v map to this technique but fail the per-check quality gate, so the "+
				"technique is NOT counted as implemented.", failing)
	}
}

// Gaps returns every technique that is not IMPLEMENTED, for the Coverage and Gaps report.
func (r *Report) Gaps() []TechniqueStatus {
	var out []TechniqueStatus
	for _, t := range r.Techniques {
		if t.Effective != model.Implemented {
			out = append(out, t)
		}
	}
	return out
}

// Metric looks a metric up by ID.
func (r *Report) Metric(id string) (Metric, bool) {
	for _, m := range r.Metrics {
		if m.ID == id {
			return m, true
		}
	}
	return Metric{}, false
}
