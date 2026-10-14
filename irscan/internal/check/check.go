// Package check defines what a check is, what it is allowed to see, and the quality gate it
// must pass before it may count toward implementation coverage.
//
// The central design decision: a check SUPPLIES its four required test cases as data
// (Cases()). A single generic test runs them. That makes the per-check quality gate
// machine-verified rather than self-certified -- a check cannot claim IMPLEMENTED by setting
// a boolean, it has to actually have a passing positive, negative, no-data and
// permission-denied case.
package check

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"irscan/internal/collect"
	"irscan/internal/model"
	"irscan/internal/registry"
	"irscan/internal/safety"
)

// ---------------------------------------------------------------------------------------
// Env: everything a check may touch
// ---------------------------------------------------------------------------------------

// Env is the check's entire world. There is no other way for a check to reach the host: no
// os package, no exec, no network. Swapping these interfaces is what makes every check
// runnable against fixtures.
type Env struct {
	Host      model.HostInfo
	ScanID    string
	FS        collect.FileSystem
	Registry  collect.Registry
	Telemetry collect.TelemetrySource
	Budget    *safety.Budget
	Limits    safety.Limits
	Allowlist Allowlister
	// Now is injected so time-window logic is deterministic in tests.
	Now func() time.Time
	// TargetOS is "windows" or "linux".
	TargetOS string
}

// Allowlister decides whether an artifact is suppressed. Suppressed items are counted and
// listed in an appendix -- never silently dropped.
type Allowlister interface {
	// Match returns the matching entry ID and reason, or ("", "") if not allowlisted.
	Match(artifactType, artifactID string, attrs map[string]string) (entryID, reason string)
}

// NoAllowlist is the default.
type NoAllowlist struct{}

func (NoAllowlist) Match(string, string, map[string]string) (string, string) { return "", "" }

// ---------------------------------------------------------------------------------------
// Technique mapping
// ---------------------------------------------------------------------------------------

// TechniqueMapping is one edge of the explicit many-to-many check<->technique table.
//
// Justification is mandatory. It is what stops a generic check from being stapled onto
// unrelated techniques to inflate coverage: if you cannot write why this check is evidence
// for this technique, the mapping does not belong.
type TechniqueMapping struct {
	TechniqueID string
	// Justification states why this check's evidence bears on this technique.
	Justification string
	// Partial marks a mapping that covers only part of the technique. A technique mapped
	// only by Partial edges can never reach IMPLEMENTED via this check alone.
	Partial bool
}

// ---------------------------------------------------------------------------------------
// Overlay: the analyst-facing documentation required by the gate
// ---------------------------------------------------------------------------------------

type Reference struct {
	Title string
	URL   string
}

// Overlay is gate item 1. Every field is required; EmptyFields reports what is missing.
type Overlay struct {
	// Behavior: what the adversary actually does.
	Behavior string
	// Artifacts: what that leaves behind on the host.
	Artifacts []string
	// Logic: how this check decides, in words an analyst can audit.
	Logic string
	// FalsePositives: the legitimate causes that produce the same artifact.
	FalsePositives []string
	// Limitations: what this check cannot see. Required, because a check that claims no
	// limitations is a check whose author has not thought about evasion.
	Limitations []string
	References  []Reference
}

func (o Overlay) EmptyFields() []string {
	var missing []string
	if strings.TrimSpace(o.Behavior) == "" {
		missing = append(missing, "Behavior")
	}
	if len(o.Artifacts) == 0 {
		missing = append(missing, "Artifacts")
	}
	if strings.TrimSpace(o.Logic) == "" {
		missing = append(missing, "Logic")
	}
	if len(o.FalsePositives) == 0 {
		missing = append(missing, "FalsePositives")
	}
	if len(o.Limitations) == 0 {
		missing = append(missing, "Limitations")
	}
	if len(o.References) == 0 {
		missing = append(missing, "References")
	}
	return missing
}

// ---------------------------------------------------------------------------------------
// Collector requirements
// ---------------------------------------------------------------------------------------

// SourceRequirement documents one data source a check needs, its privilege, and how it fails.
// This is gate item 2 and it is also what --dry-run prints.
type SourceRequirement struct {
	Name string
	// Privilege needed, in plain words ("root", "Administrator", "none").
	Privilege string
	// FailureModes: how this source fails and what the check does about it.
	FailureModes []string
	// Optional sources do not force INSUFFICIENT_DATA when absent.
	Optional bool
}

// ---------------------------------------------------------------------------------------
// Meta
// ---------------------------------------------------------------------------------------

type Meta struct {
	ID    string
	Title string
	// OS lists the target operating systems this check applies to.
	OS []string
	// Tactics is informational, for grouping in reports.
	Tactics []string

	Techniques []TechniqueMapping
	Sources    []SourceRequirement
	Overlay    Overlay

	// Criteria are the documented matching rules. Findings cite these by ID; a finding may
	// not cite a criterion that is not declared here.
	Criteria []model.Criterion
	// EscalationCriteria states, in words, what second independent signal is required to go
	// above observed_artifact. Gate item 4.
	EscalationCriteria string
	// FalsePositiveHandling states what the check does about the known-noisy cases. Gate
	// item 5. Required for the noisy areas the spec names (Run keys, services, scheduled
	// tasks, systemd units, cron, Defender exclusions, log clearing).
	FalsePositiveHandling string

	// Validation is the author's claim, cross-checked by tests and the review pass.
	Validation model.ValidationStatus
	// FixtureProvenance qualifies FIXTURE_TESTED (DECISIONS.md D-004).
	FixtureProvenance model.FixtureProvenance
	// LabEvidence must be non-empty when Validation is LAB_VERIFIED: it names the exact
	// environment the check was observed running in. VerifyLabClaims enforces this.
	LabEvidence string

	// Telemetry marks a check whose evidence is log-based rather than current-state. Such
	// checks must aggregate by entity rather than emit one finding per event.
	Telemetry bool
}

// AppliesTo reports whether the check runs for a target OS.
func (m Meta) AppliesTo(os string) bool {
	for _, o := range m.OS {
		if o == os {
			return true
		}
	}
	return false
}

// TechniqueIDs returns the mapped ATT&CK IDs.
func (m Meta) TechniqueIDs() []string {
	out := make([]string, 0, len(m.Techniques))
	for _, t := range m.Techniques {
		out = append(out, t.TechniqueID)
	}
	sort.Strings(out)
	return out
}

// FullyCoveredTechniqueIDs returns only non-partial mappings: the techniques this check can
// actually carry to IMPLEMENTED.
func (m Meta) FullyCoveredTechniqueIDs() []string {
	var out []string
	for _, t := range m.Techniques {
		if !t.Partial {
			out = append(out, t.TechniqueID)
		}
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------------------
// Test cases: the machine-verified half of the gate
// ---------------------------------------------------------------------------------------

type CaseKind string

const (
	// CasePositive: the artifact is present and the check must report DETECTED.
	CasePositive CaseKind = "positive"
	// CaseNegative: a fixture reflecting common LEGITIMATE software. Must be NOT_DETECTED.
	// This is the case that proves the check is not just matching on existence.
	CaseNegative CaseKind = "negative"
	// CaseNoData: the required source does not exist. Must be INSUFFICIENT_DATA, never
	// NOT_DETECTED.
	CaseNoData CaseKind = "no_data"
	// CasePermissionDenied: the source exists but is unreadable. Must be PERMISSION_DENIED
	// or PARTIAL_DATA, never NOT_DETECTED.
	CasePermissionDenied CaseKind = "permission_denied"
)

// RequiredCaseKinds is the gate's test requirement.
func RequiredCaseKinds() []CaseKind {
	return []CaseKind{CasePositive, CaseNegative, CaseNoData, CasePermissionDenied}
}

// FixtureCase is one executable test case supplied by the check itself.
type FixtureCase struct {
	Name string
	Kind CaseKind
	// Build constructs the Env for this case. fixtureRoot is the absolute path of
	// testdata/fixtures.
	Build func(fixtureRoot string) (Env, error)
	// WantOutcome is the required outcome.
	WantOutcome model.Outcome
	// AlsoAccept lists additional acceptable outcomes (e.g. PARTIAL_DATA for a
	// permission-denied case where some sources remain readable).
	AlsoAccept []model.Outcome
	// MinFindings is the minimum number of reportable findings expected.
	MinFindings int
	// WantTechniqueIDs, when set, must all appear across the findings.
	WantTechniqueIDs []string
	// Why documents what this case is actually proving.
	Why string
}

// Accepts reports whether an observed outcome satisfies the case.
func (c FixtureCase) Accepts(got model.Outcome) bool {
	if got == c.WantOutcome {
		return true
	}
	for _, o := range c.AlsoAccept {
		if got == o {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------------------
// Check
// ---------------------------------------------------------------------------------------

type Check interface {
	Meta() Meta
	Run(ctx context.Context, env Env) model.CheckResult
	// Cases supplies the gate's test cases. A check returning fewer than the four required
	// kinds cannot pass the gate and is excluded from implementation coverage.
	Cases() []FixtureCase
}

// ---------------------------------------------------------------------------------------
// Gate evaluation
// ---------------------------------------------------------------------------------------

// GateResult explains, item by item, whether a check may count as IMPLEMENTED.
type GateResult struct {
	CheckID string
	// Items maps gate item name -> pass.
	Items map[string]bool
	// Failures explains each failed item.
	Failures []string
}

func (g GateResult) Passes() bool { return len(g.Failures) == 0 }

// EvaluateGate applies the six per-check gate items from PLAN.md section 8.
//
// It is deliberately static: it inspects declarations and the supplied case kinds. Whether
// those cases actually PASS is proven separately by the generic test runner, and the two
// together are what justify IMPLEMENTED.
func EvaluateGate(c Check) GateResult {
	m := c.Meta()
	g := GateResult{CheckID: m.ID, Items: map[string]bool{}}

	fail := func(item, msg string) {
		g.Items[item] = false
		g.Failures = append(g.Failures, item+": "+msg)
	}
	pass := func(item string) { g.Items[item] = true }

	// 1. Overlay entry.
	if missing := m.Overlay.EmptyFields(); len(missing) > 0 {
		fail("overlay", "missing "+strings.Join(missing, ", "))
	} else {
		pass("overlay")
	}

	// 2. Collector privileges and failure modes documented.
	switch {
	case len(m.Sources) == 0:
		fail("sources_documented", "no source requirements declared")
	default:
		ok := true
		for _, s := range m.Sources {
			if strings.TrimSpace(s.Privilege) == "" || len(s.FailureModes) == 0 {
				fail("sources_documented", fmt.Sprintf(
					"source %q missing privilege or failure modes", s.Name))
				ok = false
				break
			}
		}
		if ok {
			pass("sources_documented")
		}
	}

	// 3. All four test cases present.
	have := map[CaseKind]bool{}
	for _, cs := range c.Cases() {
		have[cs.Kind] = true
	}
	var missingCases []string
	for _, k := range RequiredCaseKinds() {
		if !have[k] {
			missingCases = append(missingCases, string(k))
		}
	}
	if len(missingCases) > 0 {
		fail("four_test_cases", "missing "+strings.Join(missingCases, ", "))
	} else {
		pass("four_test_cases")
	}

	// 4. Escalation criteria.
	if strings.TrimSpace(m.EscalationCriteria) == "" {
		fail("escalation_criteria", "not documented")
	} else {
		pass("escalation_criteria")
	}

	// 5. False-positive handling.
	if strings.TrimSpace(m.FalsePositiveHandling) == "" {
		fail("false_positive_handling", "not documented")
	} else {
		pass("false_positive_handling")
	}

	// 6. Honest validation status.
	switch m.Validation {
	case model.LabVerified:
		if strings.TrimSpace(m.LabEvidence) == "" {
			fail("honest_validation",
				"claims LAB_VERIFIED without naming the environment it was observed in")
		} else {
			pass("honest_validation")
		}
	case model.FixtureTested:
		if m.FixtureProvenance == model.NoFixtures {
			fail("honest_validation", "FIXTURE_TESTED without a fixture provenance")
		} else {
			pass("honest_validation")
		}
	case model.Untested:
		fail("honest_validation", "UNTESTED checks cannot count as implemented")
	default:
		fail("honest_validation", "unknown validation status "+string(m.Validation))
	}

	// Criteria must be declared, since findings may only cite declared criteria.
	if len(m.Criteria) == 0 {
		fail("criteria_declared", "no documented criteria")
	} else {
		pass("criteria_declared")
	}

	return g
}

// ValidateMapping enforces that every cited ATT&CK ID exists in the registry, is in scope,
// and carries a justification.
//
// This is the code-level guard against inventing ATT&CK IDs and against stapling a generic
// check onto unrelated techniques.
func ValidateMapping(c Check, reg *registry.Registry) []string {
	m := c.Meta()
	var problems []string
	if len(m.Techniques) == 0 {
		problems = append(problems, m.ID+": no technique mappings")
	}
	seen := map[string]bool{}
	for _, tm := range m.Techniques {
		if seen[tm.TechniqueID] {
			problems = append(problems, fmt.Sprintf("%s: duplicate mapping for %s",
				m.ID, tm.TechniqueID))
		}
		seen[tm.TechniqueID] = true

		t := reg.Get(tm.TechniqueID)
		if t == nil {
			problems = append(problems, fmt.Sprintf(
				"%s: ATT&CK ID %s does not exist in the pinned registry (v%s)",
				m.ID, tm.TechniqueID, reg.Source.Version))
			continue
		}
		if !t.Active {
			problems = append(problems, fmt.Sprintf(
				"%s: %s is revoked/deprecated (superseded by %q); map to the successor",
				m.ID, tm.TechniqueID, t.RevokedByID))
		}
		if strings.TrimSpace(tm.Justification) == "" {
			problems = append(problems, fmt.Sprintf(
				"%s: mapping to %s has no justification", m.ID, tm.TechniqueID))
		}
		// The check's OS list must overlap the technique's.
		overlap := false
		for _, o := range m.OS {
			if t.SupportsOS(o) {
				overlap = true
			}
		}
		if !overlap {
			problems = append(problems, fmt.Sprintf(
				"%s: check targets %v but %s applies to %v",
				m.ID, m.OS, tm.TechniqueID, t.OSScope))
		}
	}
	return problems
}

// VerifyLabClaims returns a problem for every check claiming LAB_VERIFIED without naming a
// concrete environment. The review pass runs this; so does the test suite.
func VerifyLabClaims(checks []Check) []string {
	var problems []string
	for _, c := range checks {
		m := c.Meta()
		if m.Validation != model.LabVerified {
			continue
		}
		if strings.TrimSpace(m.LabEvidence) == "" {
			problems = append(problems, m.ID+": LAB_VERIFIED with no LabEvidence")
			continue
		}
		// A lab claim must name an OS kind consistent with the check's targets.
		ev := strings.ToLower(m.LabEvidence)
		matched := false
		for _, o := range m.OS {
			if strings.Contains(ev, strings.ToLower(o)) {
				matched = true
			}
		}
		if !matched {
			problems = append(problems, fmt.Sprintf(
				"%s: LAB_VERIFIED evidence %q does not name any of the check's target OSes %v",
				m.ID, m.LabEvidence, m.OS))
		}
	}
	return problems
}

// ---------------------------------------------------------------------------------------
// Check registry
// ---------------------------------------------------------------------------------------

var registered []Check

// Register adds a check to the global inventory. Called from init() in the checks package.
func Register(c ...Check) { registered = append(registered, c...) }

// All returns every registered check, ordered by ID for deterministic reports.
func All() []Check {
	out := append([]Check{}, registered...)
	sort.Slice(out, func(i, j int) bool { return out[i].Meta().ID < out[j].Meta().ID })
	return out
}

// ForOS returns checks applicable to a target OS.
func ForOS(os string) []Check {
	var out []Check
	for _, c := range All() {
		if c.Meta().AppliesTo(os) {
			out = append(out, c)
		}
	}
	return out
}
