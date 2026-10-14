// Package model holds the data contracts shared by collectors, checks and reports.
//
// These types are the spec's contracts rendered in Go. Two rules are enforced structurally
// rather than left to reviewer discipline:
//
//  1. Missing logs or missing privileges can never produce NOT_DETECTED. CheckResult.Validate
//     rejects it, and OutcomeFromSources is where the rule is actually implemented.
//  2. Raw host data is never persisted. A Finding carries EvidenceRef values holding a
//     bounded, redacted excerpt plus a hash -- never the whole object.
package model

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------------------
// Scan outcomes
// ---------------------------------------------------------------------------------------

type Outcome string

const (
	// Detected: the check's documented criteria matched.
	Detected Outcome = "DETECTED"
	// NotDetected: the check ran with ALL required data present and found nothing.
	// Never valid when data or privileges were missing.
	NotDetected Outcome = "NOT_DETECTED"
	// InsufficientData: a required source was absent, disabled or empty.
	InsufficientData Outcome = "INSUFFICIENT_DATA"
	// PartialData: some required sources were present, others were not.
	PartialData Outcome = "PARTIAL_DATA"
	// PermissionDenied: the collector was denied access.
	PermissionDenied Outcome = "PERMISSION_DENIED"
	// NotTested: the check was not run (filtered out, wrong OS, dry run).
	NotTested Outcome = "NOT_TESTED"
	// Error: the check failed unexpectedly.
	Error Outcome = "ERROR"
)

// Determinate reports whether the outcome actually answers the question. Only determinate
// outcomes count in the numerator of coverage metric M6.
func (o Outcome) Determinate() bool { return o == Detected || o == NotDetected }

// AllOutcomes is the authoritative list, used to validate report completeness.
func AllOutcomes() []Outcome {
	return []Outcome{Detected, NotDetected, InsufficientData, PartialData,
		PermissionDenied, NotTested, Error}
}

// ---------------------------------------------------------------------------------------
// Finding levels
// ---------------------------------------------------------------------------------------

type FindingLevel string

const (
	// ObservedArtifact: the artifact exists. NOT a claim of badness. Goes to the Inventory
	// report, never to Findings.
	ObservedArtifact FindingLevel = "observed_artifact"
	// SuspiciousIndicator: documented criteria matched beyond mere existence.
	SuspiciousIndicator FindingLevel = "suspicious_indicator"
	// Corroborated: a second independent signal named in the check's criteria also matched.
	Corroborated FindingLevel = "corroborated"
	// ConfirmedTestDetection: matched a controlled benign simulation.
	ConfirmedTestDetection FindingLevel = "confirmed_test_detection"
)

// Reportable reports whether a finding belongs in the Findings output. Observed artifacts
// belong in Inventory; mixing them is what makes host-scan output unreadable.
func (l FindingLevel) Reportable() bool { return l != ObservedArtifact }

// Rank orders levels for merge and escalation logic. -1 means invalid.
func (l FindingLevel) Rank() int {
	switch l {
	case ObservedArtifact:
		return 0
	case SuspiciousIndicator:
		return 1
	case Corroborated:
		return 2
	case ConfirmedTestDetection:
		return 3
	}
	return -1
}

// ---------------------------------------------------------------------------------------
// Status enums
// ---------------------------------------------------------------------------------------

type ImplementationStatus string

const (
	Implemented   ImplementationStatus = "IMPLEMENTED"
	Partial       ImplementationStatus = "PARTIAL"
	Planned       ImplementationStatus = "PLANNED"
	Unsupported   ImplementationStatus = "UNSUPPORTED"
	NotApplicable ImplementationStatus = "NOT_APPLICABLE"
)

type ValidationStatus string

const (
	Untested ValidationStatus = "UNTESTED"
	// FixtureTested: exercised only against fixtures. Reported separately from, and never
	// summed into, validation coverage.
	FixtureTested ValidationStatus = "FIXTURE_TESTED"
	// LabVerified: the check ran against a real OS of the right kind and was observed.
	// Claiming this falsely is the worst available failure mode; check.VerifyLabClaims and
	// the review pass both exist to catch it.
	LabVerified ValidationStatus = "LAB_VERIFIED"
)

// FixtureProvenance qualifies FIXTURE_TESTED without inventing a fourth validation status
// (DECISIONS.md D-004).
type FixtureProvenance string

const (
	NoFixtures FixtureProvenance = ""
	// Synthetic: fixtures hand-built by the check author.
	Synthetic FixtureProvenance = "synthetic"
	// CapturedRealHost: fixtures captured from a real host and replayed. Still
	// FIXTURE_TESTED -- the collector did not run, so its privilege, API, error and timeout
	// paths remain unexercised.
	CapturedRealHost FixtureProvenance = "captured_real_host"
)

type AnalystDisposition string

const (
	Unreviewed    AnalystDisposition = "unreviewed"
	Actionable    AnalystDisposition = "actionable"
	Benign        AnalystDisposition = "benign"
	NeedsMoreData AnalystDisposition = "needs_more_data"
)

// ---------------------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------------------

// EvidenceRef is what gets persisted: a bounded excerpt plus a hash. The full host object is
// never written to the output directory.
type EvidenceRef struct {
	ID string `json:"id"`
	// Kind is the shape of the evidence: file_excerpt, registry_value, log_event,
	// directory_listing, service_config, unit_file.
	Kind string `json:"kind"`
	// Source is the logical location on the scanned host, not the fixture root.
	Source string `json:"source"`
	// SHA256 of the bytes identified by HashScope.
	SHA256 string `json:"sha256"`
	// HashScope records what SHA256 covers: "full_object" when the whole artifact was
	// hashed, "excerpt" when only the retained excerpt was. Without this an analyst cannot
	// tell whether the hash is comparable against a reference copy.
	HashScope string `json:"hash_scope"`
	// Excerpt is bounded by safety limits and redacted where required.
	Excerpt string `json:"excerpt,omitempty"`
	// SizeBytes is the full object's size even when the excerpt is shorter.
	SizeBytes int64 `json:"size_bytes"`
	Truncated bool  `json:"truncated"`
	// Redacted is true when secret material was removed. Credential checks must set this.
	Redacted bool `json:"redacted"`
	// RedactionNote explains what was removed, without revealing it.
	RedactionNote string    `json:"redaction_note,omitempty"`
	ModTime       time.Time `json:"mod_time,omitempty"`
}

// ---------------------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------------------

// Criterion is one documented matching rule. Findings cite criteria by ID so "why did this
// fire" is answerable from the report alone, and so nothing implies severity without stated
// criteria.
type Criterion struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

// Aggregate carries telemetry-check results. Telemetry checks aggregate by entity -- count,
// window, top sources, bounded samples -- instead of emitting one finding per event.
type Aggregate struct {
	Entity       string        `json:"entity"`
	EventCount   int           `json:"event_count"`
	WindowStart  time.Time     `json:"window_start"`
	WindowEnd    time.Time     `json:"window_end"`
	TopSources   []CountedItem `json:"top_sources,omitempty"`
	SampleEvents []EvidenceRef `json:"sample_events,omitempty"`
	Truncated    bool          `json:"truncated"`
}

type CountedItem struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// Finding is one artifact, not one event and not one technique. The dedup key is
// host + artifact identity, and a single finding carries every technique and check that
// matched it.
type Finding struct {
	DedupKey     string `json:"dedup_key"`
	Host         string `json:"host"`
	ArtifactType string `json:"artifact_type"`
	ArtifactID   string `json:"artifact_id"`

	Level FindingLevel `json:"level"`

	// Many-to-many: all techniques and checks that matched this one artifact.
	TechniqueIDs []string `json:"technique_ids"`
	CheckIDs     []string `json:"check_ids"`

	Title string `json:"title"`
	// WhatAndWhere is the triage header: what the artifact is and where it lives.
	WhatAndWhere string `json:"what_and_where"`
	// CriteriaMatched are the documented criteria that fired. Required above
	// observed_artifact.
	CriteriaMatched []Criterion `json:"criteria_matched"`
	// BenignExplanations are the legitimate causes an analyst must rule out first.
	BenignExplanations []string `json:"benign_explanations"`
	// NextPivot is what to look at next.
	NextPivot []string `json:"next_pivot"`

	Evidence  []EvidenceRef `json:"evidence"`
	Aggregate *Aggregate    `json:"aggregate,omitempty"`

	// Suppression is counted and listed in an appendix, never silently hidden.
	Suppressed        bool   `json:"suppressed"`
	SuppressedBy      string `json:"suppressed_by,omitempty"`
	SuppressionReason string `json:"suppression_reason,omitempty"`

	// Context holds facts that are explicitly NOT proof of benign -- package ownership, a
	// valid signature. Named "context" so no consumer treats it as a verdict.
	Context map[string]string `json:"context,omitempty"`

	AnalystDisposition AnalystDisposition `json:"analyst_disposition"`

	FirstSeen time.Time `json:"first_seen,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
}

// Validate enforces the contract rules the noise-reduction design depends on. The report
// writers call it, so a malformed finding fails tests rather than reaching an analyst.
func (f *Finding) Validate() error {
	if f.DedupKey == "" {
		return fmt.Errorf("finding %q: empty dedup key", f.Title)
	}
	if len(f.TechniqueIDs) == 0 {
		return fmt.Errorf("finding %s: no technique IDs", f.DedupKey)
	}
	if len(f.CheckIDs) == 0 {
		return fmt.Errorf("finding %s: no check IDs", f.DedupKey)
	}
	if f.Level.Rank() < 0 {
		return fmt.Errorf("finding %s: invalid level %q", f.DedupKey, f.Level)
	}
	if f.Level.Reportable() {
		if len(f.CriteriaMatched) == 0 {
			return fmt.Errorf("finding %s: level %s requires documented criteria",
				f.DedupKey, f.Level)
		}
		if len(f.BenignExplanations) == 0 {
			return fmt.Errorf("finding %s: level %s requires benign explanations to rule out",
				f.DedupKey, f.Level)
		}
		if len(f.NextPivot) == 0 {
			return fmt.Errorf("finding %s: level %s requires a next pivot", f.DedupKey, f.Level)
		}
		if len(f.Evidence) == 0 && f.Aggregate == nil {
			return fmt.Errorf("finding %s: level %s requires evidence or an aggregate",
				f.DedupKey, f.Level)
		}
	}
	// Escalation to corroborated or above needs a second independent signal, expressed as at
	// least two distinct documented criteria.
	if f.Level.Rank() >= Corroborated.Rank() && len(f.CriteriaMatched) < 2 {
		return fmt.Errorf("finding %s: level %s claims corroboration but cites %d criterion; "+
			"escalation requires a second independent signal",
			f.DedupKey, f.Level, len(f.CriteriaMatched))
	}
	for i, e := range f.Evidence {
		if e.SHA256 == "" {
			return fmt.Errorf("finding %s: evidence[%d] has no hash", f.DedupKey, i)
		}
		if e.HashScope != "full_object" && e.HashScope != "excerpt" {
			return fmt.Errorf("finding %s: evidence[%d] invalid hash_scope %q",
				f.DedupKey, i, e.HashScope)
		}
	}
	return nil
}

// Merge folds another finding for the SAME artifact into this one, unioning technique and
// check attribution and keeping the highest level. This is what makes "one artifact is one
// finding" true across checks.
func (f *Finding) Merge(o Finding) {
	f.TechniqueIDs = Union(f.TechniqueIDs, o.TechniqueIDs)
	f.CheckIDs = Union(f.CheckIDs, o.CheckIDs)
	f.CriteriaMatched = mergeCriteria(f.CriteriaMatched, o.CriteriaMatched)
	f.BenignExplanations = Union(f.BenignExplanations, o.BenignExplanations)
	f.NextPivot = Union(f.NextPivot, o.NextPivot)
	f.Evidence = append(f.Evidence, o.Evidence...)
	if o.Aggregate != nil && f.Aggregate == nil {
		f.Aggregate = o.Aggregate
	}
	if o.Level.Rank() > f.Level.Rank() {
		f.Level = o.Level
	}
	if len(o.Context) > 0 {
		if f.Context == nil {
			f.Context = map[string]string{}
		}
		for k, v := range o.Context {
			f.Context[k] = v
		}
	}
}

// ---------------------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------------------

// InventoryItem is a grouped observed artifact. Inventory answers "what is on this host";
// Findings answers "what should I look at". They are never mixed.
type InventoryItem struct {
	Group        string            `json:"group"`
	ArtifactType string            `json:"artifact_type"`
	ArtifactID   string            `json:"artifact_id"`
	Attributes   map[string]string `json:"attributes,omitempty"`
	TechniqueIDs []string          `json:"technique_ids"`
	CheckIDs     []string          `json:"check_ids"`
	Evidence     []EvidenceRef     `json:"evidence,omitempty"`
}

// ---------------------------------------------------------------------------------------
// Data source availability
// ---------------------------------------------------------------------------------------

// DataSourceStatus records, per check run, whether each required source was actually there.
// This is what lets a report distinguish "clean" from "blind", and it feeds metric M6.
type DataSourceStatus struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	// Reason is mandatory when Available is false.
	Reason    string `json:"reason,omitempty"`
	ItemsSeen int    `json:"items_seen"`
	// Truncated is set when a SAFETY LIMIT stopped collection early (file count, file size,
	// event cap). A truncated source can never justify NOT_DETECTED.
	Truncated bool `json:"truncated"`
	// Incomplete is set when the source answered but some of it could not be read -- most
	// often a permission denial on part of the tree. Kept distinct from Truncated because
	// an analyst reading "truncated by safety limit" when the real cause was "denied on
	// /var/spool/cron" has been told the wrong thing about their visibility gap.
	Incomplete bool `json:"incomplete,omitempty"`
	// IncompleteReason explains Incomplete.
	IncompleteReason string `json:"incomplete_reason,omitempty"`
	// Privilege records the privilege the collector needed, for the --dry-run listing.
	Privilege string `json:"privilege,omitempty"`
	// Optional marks a source whose mere absence does not reduce confidence (for example
	// the Windows Startup folder, which simply may not exist). An optional source that is
	// DENIED or TRUNCATED still reduces confidence -- not being allowed to read something
	// is different from it not being there.
	Optional bool `json:"optional,omitempty"`
}

// ---------------------------------------------------------------------------------------
// Check results
// ---------------------------------------------------------------------------------------

type CheckResult struct {
	CheckID string  `json:"check_id"`
	Outcome Outcome `json:"outcome"`
	// Reason is mandatory for every non-determinate outcome: an analyst must be able to tell
	// why a check could not answer.
	Reason string `json:"reason,omitempty"`

	Findings  []Finding          `json:"findings,omitempty"`
	Inventory []InventoryItem    `json:"inventory,omitempty"`
	Sources   []DataSourceStatus `json:"sources"`

	StartedAt time.Time     `json:"started_at"`
	Duration  time.Duration `json:"duration_ns"`
	Err       string        `json:"error,omitempty"`
}

// Validate enforces the "missing data must never read as clean" rule.
func (r *CheckResult) Validate() error {
	if r.CheckID == "" {
		return fmt.Errorf("check result with empty check ID")
	}
	if !r.Outcome.Determinate() && r.Reason == "" {
		return fmt.Errorf("check %s: outcome %s requires a reason", r.CheckID, r.Outcome)
	}
	if r.Outcome == NotDetected {
		for _, s := range r.Sources {
			// An optional source that is simply absent is the one permitted exception:
			// a Windows host with no all-users Startup folder has nothing to miss.
			// An optional source that was DENIED is not an exception.
			if !s.Available && s.Optional && !IsPermissionReason(s.Reason) {
				continue
			}
			if !s.Available {
				return fmt.Errorf("check %s: reported NOT_DETECTED while source %q was "+
					"unavailable (%s); must be INSUFFICIENT_DATA or PARTIAL_DATA",
					r.CheckID, s.Name, s.Reason)
			}
			if s.Truncated {
				return fmt.Errorf("check %s: reported NOT_DETECTED while source %q was "+
					"truncated by a safety limit; must be PARTIAL_DATA", r.CheckID, s.Name)
			}
			if s.Incomplete {
				return fmt.Errorf("check %s: reported NOT_DETECTED while source %q was only "+
					"partially readable (%s); must be PARTIAL_DATA",
					r.CheckID, s.Name, s.IncompleteReason)
			}
		}
	}
	if r.Outcome == Detected && len(r.Findings) == 0 {
		return fmt.Errorf("check %s: DETECTED with no findings", r.CheckID)
	}
	for i := range r.Findings {
		if err := r.Findings[i].Validate(); err != nil {
			return fmt.Errorf("check %s: %w", r.CheckID, err)
		}
	}
	return nil
}

// ReportableFindings returns only findings at suspicious_indicator or above, excluding
// suppressed ones. Used by the Findings report.
func (r *CheckResult) ReportableFindings() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Level.Reportable() && !f.Suppressed {
			out = append(out, f)
		}
	}
	return out
}

// OutcomeFromSources derives the correct outcome from source availability and whether
// anything matched. Checks must use this rather than hand-rolling the logic: it is where the
// "never NOT_DETECTED on missing data" rule is implemented.
func OutcomeFromSources(sources []DataSourceStatus, matched bool) (Outcome, string) {
	// Mandatory sources decide whether the question could be answered at all. Optional
	// sources can only degrade a clean answer to partial, never rescue a blind one:
	// an absent optional source must not let "I saw nothing at all" masquerade as
	// "I saw most things and found nothing".
	var mandatory int
	var mMissing, mDenied, oDenied, truncated, incomplete []string

	for _, s := range sources {
		if !s.Optional {
			mandatory++
		}
		switch {
		case !s.Available && IsPermissionReason(s.Reason):
			if s.Optional {
				oDenied = append(oDenied, s.Name)
			} else {
				mDenied = append(mDenied, s.Name)
			}
		case !s.Available:
			if !s.Optional {
				mMissing = append(mMissing, s.Name)
			}
			// An optional source that is merely absent has no effect on the outcome.
		default:
			// Available, but possibly not in full. Truncation (a safety limit) and
			// incompleteness (usually a permission denial) are reported separately so the
			// analyst is told the real cause of the visibility gap.
			if s.Truncated {
				truncated = append(truncated, s.Name)
			}
			if s.Incomplete {
				incomplete = append(incomplete, s.Name)
			}
		}
	}

	switch {
	case matched:
		// A positive match stands even on partial data: finding something is not weakened
		// by not having seen everything.
		return Detected, ""

	case len(sources) == 0:
		return InsufficientData, "check declared no data sources, so nothing was examined"

	case mandatory == 0:
		// Every source was optional. There is no mandatory evidence base, so a clean
		// answer cannot be justified.
		return InsufficientData,
			"check declared no mandatory data source, so no determinate answer is possible"

	case len(mMissing)+len(mDenied) == mandatory && len(mDenied) > 0:
		return PermissionDenied, "access denied to required source(s): " +
			strings.Join(append(append([]string{}, mDenied...), mMissing...), ", ")

	case len(mMissing)+len(mDenied) == mandatory:
		return InsufficientData, "no required source was available: " +
			strings.Join(mMissing, ", ")

	case len(mMissing) > 0 || len(mDenied) > 0 || len(oDenied) > 0 ||
		len(truncated) > 0 || len(incomplete) > 0:
		var parts []string
		if len(mMissing) > 0 {
			parts = append(parts, "unavailable: "+strings.Join(mMissing, ", "))
		}
		if d := append(append([]string{}, mDenied...), oDenied...); len(d) > 0 {
			parts = append(parts, "denied: "+strings.Join(d, ", "))
		}
		if len(incomplete) > 0 {
			parts = append(parts, "partially readable: "+strings.Join(incomplete, ", "))
		}
		if len(truncated) > 0 {
			parts = append(parts, "truncated by safety limit: "+strings.Join(truncated, ", "))
		}
		return PartialData, "scanned with incomplete data (" + strings.Join(parts, "; ") +
			"); absence of a finding is not evidence of absence"

	default:
		return NotDetected, ""
	}
}

// IsPermissionReason distinguishes "denied" from "absent", which decides between
// PERMISSION_DENIED and INSUFFICIENT_DATA.
func IsPermissionReason(reason string) bool {
	r := strings.ToLower(reason)
	for _, needle := range []string{
		"permission denied", "access is denied", "access denied", "eacces", "eperm",
		"not elevated", "requires administrator", "requires elevation", "privilege",
		"operation not permitted",
	} {
		if strings.Contains(r, needle) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------------------
// Host info
// ---------------------------------------------------------------------------------------

type HostInfo struct {
	Hostname   string            `json:"hostname"`
	OS         string            `json:"os"`
	OSVersion  string            `json:"os_version"`
	Arch       string            `json:"arch"`
	Elevated   bool              `json:"elevated"`
	ScanUser   string            `json:"scan_user"`
	FSRoot     string            `json:"fs_root"`
	Attributes map[string]string `json:"attributes,omitempty"`
	// SyntheticRoot is true when the filesystem root is a fixture tree rather than a live
	// host. Reports must say so, so fixture output is never mistaken for a real scan.
	SyntheticRoot bool `json:"synthetic_root"`
}

// ---------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------

// Union returns the sorted, deduplicated union. Sorted so report output is deterministic.
func Union(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, v := range a {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	for _, v := range b {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func mergeCriteria(a, b []Criterion) []Criterion {
	seen := map[string]bool{}
	out := make([]Criterion, 0, len(a)+len(b))
	for _, c := range a {
		if !seen[c.ID] {
			seen[c.ID] = true
			out = append(out, c)
		}
	}
	for _, c := range b {
		if !seen[c.ID] {
			seen[c.ID] = true
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
