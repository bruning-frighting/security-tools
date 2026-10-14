// Package report writes the three separate analyst outputs plus the evidence and scan
// manifests.
//
// The separation is the point. Mixing "here is every autostart entry on the box" with "here
// is the thing you should look at" is what makes host-scan output unreadable, so:
//
//	findings.*            suspicious_indicator and above, NOT suppressed
//	inventory.*           grouped observed artifacts
//	coverage_and_gaps.*   every non-detected / insufficient / unsupported / untested / error row
//	evidence_manifest.*   bounded excerpts plus hashes (never raw host data)
//	scan_manifest.json    provenance, sources, errors, timings
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"irscan/internal/check"
	"irscan/internal/coverage"
	"irscan/internal/model"
	"irscan/internal/safety"
)

// TamperNotice appears in every report. It is not boilerplate: it is the single most
// important caveat about retrospective host scanning, and omitting it would let a reader
// treat a clean report as proof of a clean host.
const TamperNotice = "" +
	"These results were collected from a host that may itself be compromised. An adversary " +
	"with sufficient privilege can alter or delete the artifacts and logs this tool reads, " +
	"including after the fact. Absence of a finding is NOT evidence of absence, and the " +
	"content of any artifact shown here may have been tampered with. Treat this report as " +
	"one input to an investigation, corroborated against off-host evidence wherever possible."

// ScanManifest records what ran, against what, with what visibility.
type ScanManifest struct {
	ScanID        string `json:"scan_id"`
	Tool          string `json:"tool"`
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	BinarySHA256  string `json:"binary_sha256"`
	BinaryPath    string `json:"binary_path"`
	StartedAt     time.Time `json:"started_at"`
	EndedAt       time.Time `json:"ended_at"`
	DurationMS    int64     `json:"duration_ms"`

	Host     model.HostInfo `json:"host"`
	TargetOS string         `json:"target_os"`

	EnabledModules []string `json:"enabled_modules"`
	Scope          string   `json:"scope"`

	ChecksRun     []string          `json:"checks_run"`
	ChecksSkipped map[string]string `json:"checks_skipped"`

	CollectedSources   []SourceRecord `json:"collected_sources"`
	UnavailableSources []SourceRecord `json:"unavailable_sources"`

	Errors []string `json:"errors"`

	ATTACKVersion string `json:"attack_version"`
	ATTACKSHA256  string `json:"attack_stix_sha256"`
	Attribution   string `json:"attack_attribution"`

	Limits safety.Limits `json:"limits"`

	// SuppressedCount is surfaced at the top of every report, never hidden.
	SuppressedCount int `json:"suppressed_count"`
	// ExpiredAllowlistEntries are entries that were ignored because they had expired.
	ExpiredAllowlistEntries []string `json:"expired_allowlist_entries,omitempty"`

	// SelfTag lets an analyst exclude this tool's own activity from log review.
	SelfTag SelfTag `json:"self_identification"`

	TamperNotice string `json:"tamper_notice"`
}

// SelfTag describes how to recognise the scanner's own footprint.
type SelfTag struct {
	ScanID       string   `json:"scan_id"`
	ProcessName  string   `json:"process_name"`
	PID          int      `json:"pid"`
	User         string   `json:"user"`
	OutputDir    string   `json:"output_dir"`
	Note         string   `json:"note"`
	ReadPathHint []string `json:"read_path_hint,omitempty"`
}

type SourceRecord struct {
	Check     string `json:"check"`
	Source    string `json:"source"`
	Reason    string `json:"reason,omitempty"`
	ItemsSeen int    `json:"items_seen"`
	// Truncated: a safety limit stopped collection. Incomplete: part of the source could
	// not be read, usually a permission denial. Kept distinct so the manifest states the
	// real cause of a visibility gap.
	Truncated  bool   `json:"truncated"`
	Incomplete bool   `json:"incomplete,omitempty"`
	Privilege  string `json:"privilege,omitempty"`
	Optional   bool   `json:"optional,omitempty"`
}

// Bundle is everything a scan produced.
type Bundle struct {
	Manifest  ScanManifest
	Findings  []model.Finding
	Inventory []model.InventoryItem
	Coverage  *coverage.Report
	Results   []model.CheckResult
	// Suppressed findings are listed in an appendix.
	Suppressed []model.Finding
	// Checks is the inventory used for the dry-run / coverage documentation.
	Checks []check.Check
}

// Writer writes into, and only into, the operator's output directory.
type Writer struct {
	guard *safety.OutputGuard
}

func NewWriter(outputDir string) (*Writer, error) {
	g, err := safety.NewOutputGuard(outputDir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(g.Root(), 0o700); err != nil {
		return nil, fmt.Errorf("creating output dir: %w", err)
	}
	return &Writer{guard: g}, nil
}

func (w *Writer) write(name string, data []byte) error {
	p := filepath.Join(w.guard.Root(), name)
	// Every write passes the guard. The tool has no other write path: no quarantine, no
	// remediation, no deletion.
	if err := w.guard.Check(p); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o600)
}

func (w *Writer) writeJSON(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return w.write(name, append(b, '\n'))
}

// WriteAll emits every output. Returns the list of files written.
func (w *Writer) WriteAll(b Bundle) ([]string, error) {
	var written []string
	emit := func(name string, fn func() error) error {
		if err := fn(); err != nil {
			return fmt.Errorf("writing %s: %w", name, err)
		}
		written = append(written, name)
		return nil
	}

	b.Manifest.TamperNotice = TamperNotice

	if err := emit("scan_manifest.json", func() error {
		return w.writeJSON("scan_manifest.json", b.Manifest)
	}); err != nil {
		return written, err
	}

	// --- Findings: suspicious_indicator and above, not suppressed ---------------------
	if err := emit("findings.json", func() error {
		return w.writeJSON("findings.json", map[string]any{
			"scan_id":          b.Manifest.ScanID,
			"tamper_notice":    TamperNotice,
			"suppressed_count": len(b.Suppressed),
			"findings":         b.Findings,
		})
	}); err != nil {
		return written, err
	}
	if err := emit("findings.md", func() error {
		return w.write("findings.md", []byte(renderFindings(b)))
	}); err != nil {
		return written, err
	}

	// --- Inventory: grouped observed artifacts ----------------------------------------
	if err := emit("inventory.json", func() error {
		return w.writeJSON("inventory.json", map[string]any{
			"scan_id":   b.Manifest.ScanID,
			"inventory": b.Inventory,
		})
	}); err != nil {
		return written, err
	}
	if err := emit("inventory.md", func() error {
		return w.write("inventory.md", []byte(renderInventory(b)))
	}); err != nil {
		return written, err
	}

	// --- Coverage and gaps -------------------------------------------------------------
	if b.Coverage != nil {
		if err := emit("coverage_and_gaps.json", func() error {
			return w.writeJSON("coverage_and_gaps.json", b.Coverage)
		}); err != nil {
			return written, err
		}
		if err := emit("coverage_and_gaps.md", func() error {
			return w.write("coverage_and_gaps.md", []byte(RenderCoverage(b.Coverage, b.Results)))
		}); err != nil {
			return written, err
		}
	}

	// --- Evidence manifest --------------------------------------------------------------
	if err := emit("evidence_manifest.json", func() error {
		return w.writeJSON("evidence_manifest.json", buildEvidenceManifest(b))
	}); err != nil {
		return written, err
	}

	return written, nil
}

// buildEvidenceManifest collects every evidence reference. Only excerpts and hashes are
// persisted -- raw host data never is.
func buildEvidenceManifest(b Bundle) map[string]any {
	type item struct {
		model.EvidenceRef
		FromFinding string   `json:"from_finding"`
		Checks      []string `json:"checks"`
	}
	var items []item
	seen := map[string]bool{}
	add := func(f model.Finding, evs []model.EvidenceRef) {
		for _, e := range evs {
			key := e.ID + "|" + e.SHA256
			if seen[key] {
				continue
			}
			seen[key] = true
			items = append(items, item{EvidenceRef: e, FromFinding: f.DedupKey,
				Checks: f.CheckIDs})
		}
	}
	for _, f := range append(append([]model.Finding{}, b.Findings...), b.Suppressed...) {
		add(f, f.Evidence)
		if f.Aggregate != nil {
			add(f, f.Aggregate.SampleEvents)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })

	return map[string]any{
		"scan_id": b.Manifest.ScanID,
		"note": "Only bounded, redacted excerpts and SHA-256 hashes are retained. Raw host " +
			"data is never written to the output directory. hash_scope states whether the " +
			"hash covers the full object or only the retained excerpt; only full_object " +
			"hashes are comparable against a reference copy.",
		"tamper_notice": TamperNotice,
		"count":         len(items),
		"evidence":      items,
	}
}

// ---------------------------------------------------------------------------------------
// Markdown rendering
// ---------------------------------------------------------------------------------------

func renderFindings(b Bundle) string {
	var s strings.Builder
	m := b.Manifest
	fmt.Fprintf(&s, "# irscan Findings\n\n")
	writeHeader(&s, m)

	fmt.Fprintf(&s, "## Summary\n\n")
	fmt.Fprintf(&s, "- Reportable findings (suspicious_indicator and above): **%d**\n",
		len(b.Findings))
	fmt.Fprintf(&s, "- Suppressed by allowlist (listed in the appendix, not hidden): **%d**\n",
		len(b.Suppressed))
	fmt.Fprintf(&s, "- Observed artifacts are NOT here; see `inventory.md` (%d items)\n",
		len(b.Inventory))
	fmt.Fprintf(&s, "- Checks that could not answer are NOT here; see `coverage_and_gaps.md`\n\n")

	if len(b.Findings) == 0 {
		fmt.Fprintf(&s, "No findings at suspicious_indicator or above.\n\n")
		fmt.Fprintf(&s, "> This is **not** a clean bill of health. Read "+
			"`coverage_and_gaps.md` to see what could not be examined: on a host where the "+
			"relevant logs or privileges were unavailable, an empty findings list mostly "+
			"reflects lack of visibility.\n\n")
	}

	byLevel := map[model.FindingLevel][]model.Finding{}
	for _, f := range b.Findings {
		byLevel[f.Level] = append(byLevel[f.Level], f)
	}
	for _, lvl := range []model.FindingLevel{
		model.ConfirmedTestDetection, model.Corroborated, model.SuspiciousIndicator,
	} {
		fs := byLevel[lvl]
		if len(fs) == 0 {
			continue
		}
		fmt.Fprintf(&s, "## %s (%d)\n\n", lvl, len(fs))
		for i, f := range fs {
			renderFinding(&s, i+1, f)
		}
	}

	if len(b.Suppressed) > 0 {
		fmt.Fprintf(&s, "## Appendix: suppressed findings (%d)\n\n", len(b.Suppressed))
		fmt.Fprintf(&s, "These matched a check but were suppressed by an allowlist entry. "+
			"They are listed so suppression is auditable.\n\n")
		for _, f := range b.Suppressed {
			fmt.Fprintf(&s, "- `%s` -- %s\n  - suppressed by: **%s** -- %s\n",
				f.ArtifactID, f.Title, f.SuppressedBy, f.SuppressionReason)
		}
		fmt.Fprintf(&s, "\n")
	}
	return s.String()
}

func renderFinding(s *strings.Builder, n int, f model.Finding) {
	fmt.Fprintf(s, "### %d. %s\n\n", n, f.Title)
	fmt.Fprintf(s, "- **What and where:** %s\n", f.WhatAndWhere)
	fmt.Fprintf(s, "- **Artifact:** `%s` (`%s`)\n", f.ArtifactID, f.ArtifactType)
	fmt.Fprintf(s, "- **ATT&CK:** %s\n", strings.Join(f.TechniqueIDs, ", "))
	fmt.Fprintf(s, "- **Checks:** %s\n", strings.Join(f.CheckIDs, ", "))
	fmt.Fprintf(s, "- **Analyst disposition:** %s\n", f.AnalystDisposition)

	fmt.Fprintf(s, "\n**Criteria matched** (the documented rules that fired):\n\n")
	for _, c := range f.CriteriaMatched {
		fmt.Fprintf(s, "- `%s` -- %s\n", c.ID, c.Text)
	}
	fmt.Fprintf(s, "\n**Benign explanations to rule out first:**\n\n")
	for _, e := range f.BenignExplanations {
		fmt.Fprintf(s, "- %s\n", e)
	}
	fmt.Fprintf(s, "\n**Next pivot:**\n\n")
	for _, p := range f.NextPivot {
		fmt.Fprintf(s, "- %s\n", p)
	}
	if f.Aggregate != nil && f.Aggregate.EventCount > 0 {
		a := f.Aggregate
		fmt.Fprintf(s, "\n**Telemetry aggregate** (entity `%s`): %d events",
			a.Entity, a.EventCount)
		if !a.WindowStart.IsZero() {
			fmt.Fprintf(s, " between %s and %s",
				a.WindowStart.Format(time.RFC3339), a.WindowEnd.Format(time.RFC3339))
		}
		if a.Truncated {
			fmt.Fprintf(s, " (truncated by a safety limit)")
		}
		fmt.Fprintf(s, "\n")
		for _, t := range a.TopSources {
			fmt.Fprintf(s, "  - %s: %d\n", t.Name, t.Count)
		}
	}
	if len(f.Evidence) > 0 {
		fmt.Fprintf(s, "\n**Evidence:**\n\n")
		for _, e := range f.Evidence {
			fmt.Fprintf(s, "- `%s` sha256:`%s` (scope: %s", e.Source, e.SHA256, e.HashScope)
			if e.Redacted {
				fmt.Fprintf(s, ", REDACTED: %s", e.RedactionNote)
			}
			if e.Truncated {
				fmt.Fprintf(s, ", truncated")
			}
			fmt.Fprintf(s, ")\n")
		}
	}
	if len(f.Context) > 0 {
		fmt.Fprintf(s, "\n**Context** (never proof of benign):\n\n")
		keys := make([]string, 0, len(f.Context))
		for k := range f.Context {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(s, "- %s: %s\n", k, f.Context[k])
		}
	}
	fmt.Fprintf(s, "\n---\n\n")
}

func renderInventory(b Bundle) string {
	var s strings.Builder
	fmt.Fprintf(&s, "# irscan Inventory\n\n")
	writeHeader(&s, b.Manifest)
	fmt.Fprintf(&s, "Observed artifacts, grouped. **Presence here is not suspicion.** "+
		"This is the \"what is on this host\" view; findings live in `findings.md`.\n\n")

	groups := map[string][]model.InventoryItem{}
	for _, it := range b.Inventory {
		groups[it.Group] = append(groups[it.Group], it)
	}
	names := make([]string, 0, len(groups))
	for g := range groups {
		names = append(names, g)
	}
	sort.Strings(names)

	if len(names) == 0 {
		fmt.Fprintf(&s, "_No artifacts were collected. See `coverage_and_gaps.md` for why._\n")
		return s.String()
	}

	for _, g := range names {
		items := groups[g]
		sort.Slice(items, func(i, j int) bool { return items[i].ArtifactID < items[j].ArtifactID })
		fmt.Fprintf(&s, "## %s (%d)\n\n", g, len(items))
		attrKeys := map[string]bool{}
		for _, it := range items {
			for k := range it.Attributes {
				attrKeys[k] = true
			}
		}
		keys := make([]string, 0, len(attrKeys))
		for k := range attrKeys {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		fmt.Fprintf(&s, "| artifact | %s | ATT&CK |\n", strings.Join(keys, " | "))
		// Columns are: artifact, each attribute key, ATT&CK -- len(keys)+2 total.
		// A previous version wrote "|---|" + strings.Repeat(...) + "|---|", which double
		// counts the separator between the last attribute and the ATT&CK column and
		// renders a stray "||" that some Markdown viewers misalign.
		fmt.Fprintf(&s, "|%s\n", strings.Repeat("---|", len(keys)+2))
		for _, it := range items {
			cells := make([]string, 0, len(keys))
			for _, k := range keys {
				cells = append(cells, mdEscape(it.Attributes[k]))
			}
			fmt.Fprintf(&s, "| `%s` | %s | %s |\n",
				mdEscape(it.ArtifactID), strings.Join(cells, " | "),
				strings.Join(it.TechniqueIDs, ", "))
		}
		fmt.Fprintf(&s, "\n")
	}
	return s.String()
}

// RenderCoverage renders the coverage and gaps report. Exported so `irscan attack
// --report coverage` can print it without running a scan.
func RenderCoverage(c *coverage.Report, results []model.CheckResult) string {
	var s strings.Builder
	fmt.Fprintf(&s, "# irscan Coverage and Gaps\n\n")
	fmt.Fprintf(&s, "ATT&CK Enterprise v%s (STIX sha256 `%s`)\n\n", c.ATTACKVersion, c.ATTACKSHA256)
	fmt.Fprintf(&s, "> %s\n\n", c.Attribution)
	fmt.Fprintf(&s, "> **On these metrics.** %s\n\n", c.ReconstructionNotice)

	fmt.Fprintf(&s, "## The six metrics\n\n")
	fmt.Fprintf(&s, "Each is reported with its own numerator and denominator and is never "+
		"merged with another into a single score.\n\n")
	for _, m := range c.Metrics {
		fmt.Fprintf(&s, "### %s -- %s\n\n", m.ID, m.Name)
		fmt.Fprintf(&s, "**%s**\n\n", m.String())
		fmt.Fprintf(&s, "%s\n\n", m.Definition)
		if m.Note != "" {
			fmt.Fprintf(&s, "_%s_\n\n", m.Note)
		}
		for _, comp := range m.Companions {
			fmt.Fprintf(&s, "- Reported beside %s, **not added into it**: %s = %d/%d\n",
				m.ID, comp.Name, comp.Numerator, m.Denominator)
		}
		if len(m.Companions) > 0 {
			fmt.Fprintf(&s, "\n")
		}
	}

	fmt.Fprintf(&s, "## M3 broken down by tactic\n\n")
	fmt.Fprintf(&s, "A technique belonging to two scope tactics appears in both rows below "+
		"but is counted **once** in the global M3.\n\n")
	fmt.Fprintf(&s, "| tactic | implemented / in scope |\n|---|---|\n")
	tacs := make([]string, 0, len(c.PerTactic))
	for t := range c.PerTactic {
		tacs = append(tacs, t)
	}
	sort.Strings(tacs)
	for _, t := range tacs {
		m := c.PerTactic[t]
		fmt.Fprintf(&s, "| %s | %d / %d |\n", t, m.Numerator, m.Denominator)
	}

	fmt.Fprintf(&s, "\n## M3 as (technique, OS) pairs\n\n")
	fmt.Fprintf(&s, "| OS | implemented / applicable |\n|---|---|\n")
	oss := make([]string, 0, len(c.PerOS))
	for o := range c.PerOS {
		oss = append(oss, o)
	}
	sort.Strings(oss)
	for _, o := range oss {
		m := c.PerOS[o]
		fmt.Fprintf(&s, "| %s | %d / %d |\n", o, m.Numerator, m.Denominator)
	}

	if len(c.Inconsistencies) > 0 {
		fmt.Fprintf(&s, "\n## Inconsistencies (defects)\n\n")
		fmt.Fprintf(&s, "The registry baseline and the check inventory disagree. "+
			"A non-empty list here is a defect, not a nuance.\n\n")
		for _, p := range c.Inconsistencies {
			fmt.Fprintf(&s, "- %s\n", p)
		}
	}

	// Per-scan outcome breakdown.
	if len(results) > 0 {
		fmt.Fprintf(&s, "\n## This scan: outcome by check\n\n")
		fmt.Fprintf(&s, "| check | outcome | why |\n|---|---|---|\n")
		rs := append([]model.CheckResult{}, results...)
		sort.Slice(rs, func(i, j int) bool { return rs[i].CheckID < rs[j].CheckID })
		for _, r := range rs {
			fmt.Fprintf(&s, "| %s | **%s** | %s |\n",
				r.CheckID, r.Outcome, mdEscape(r.Reason))
		}
		counts := map[model.Outcome]int{}
		for _, r := range results {
			counts[r.Outcome]++
		}
		fmt.Fprintf(&s, "\n| outcome | count |\n|---|---|\n")
		for _, o := range model.AllOutcomes() {
			fmt.Fprintf(&s, "| %s | %d |\n", o, counts[o])
		}
	}

	// Gaps.
	gaps := c.Gaps()
	fmt.Fprintf(&s, "\n## Gaps: every in-scope technique not implemented (%d)\n\n", len(gaps))
	fmt.Fprintf(&s, "Techniques remain visible here whether they are planned, unsupported "+
		"or inapplicable. Nothing is dropped from the report to improve a number.\n\n")

	byStatus := map[model.ImplementationStatus][]coverage.TechniqueStatus{}
	for _, g := range gaps {
		byStatus[g.Effective] = append(byStatus[g.Effective], g)
	}
	for _, st := range []model.ImplementationStatus{
		model.Partial, model.Planned, model.Unsupported, model.NotApplicable,
	} {
		rows := byStatus[st]
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(&s, "### %s (%d)\n\n", st, len(rows))
		fmt.Fprintf(&s, "| technique | name | tactics | OS | evidence class | why |\n")
		fmt.Fprintf(&s, "|---|---|---|---|---|---|\n")
		for _, g := range rows {
			fmt.Fprintf(&s, "| %s | %s | %s | %s | %s | %s |\n",
				g.TechniqueID, mdEscape(g.Name), strings.Join(g.Tactics, ", "),
				strings.Join(g.OSScope, ", "), g.TestabilityClass,
				mdEscape(truncate(g.Rationale, 260)))
		}
		fmt.Fprintf(&s, "\n")
	}
	return s.String()
}

func writeHeader(s *strings.Builder, m ScanManifest) {
	fmt.Fprintf(s, "scan_id: `%s`  \n", m.ScanID)
	fmt.Fprintf(s, "tool: %s %s (commit %s, binary sha256 `%s`)  \n",
		m.Tool, m.Version, m.Commit, m.BinarySHA256)
	fmt.Fprintf(s, "host: `%s` (%s), scanned as `%s`, elevated: %t  \n",
		m.Host.Hostname, m.TargetOS, m.Host.ScanUser, m.Host.Elevated)
	if m.Host.SyntheticRoot {
		fmt.Fprintf(s, "**filesystem root is a FIXTURE TREE (`%s`), not a live host**  \n",
			m.Host.FSRoot)
	} else if m.Host.FSRoot != "" {
		fmt.Fprintf(s, "filesystem root: `%s`  \n", m.Host.FSRoot)
	}
	fmt.Fprintf(s, "started: %s, ended: %s (%d ms)  \n",
		m.StartedAt.Format(time.RFC3339), m.EndedAt.Format(time.RFC3339), m.DurationMS)
	fmt.Fprintf(s, "ATT&CK: v%s (STIX sha256 `%s`)\n\n", m.ATTACKVersion, m.ATTACKSHA256)
	fmt.Fprintf(s, "> **%s**\n\n", TamperNotice)
	if len(m.UnavailableSources) > 0 {
		fmt.Fprintf(s, "> **Visibility note:** %d data source(s) were unavailable during "+
			"this scan. See `coverage_and_gaps.md`.\n\n", len(m.UnavailableSources))
	}
	fmt.Fprintf(s, "To exclude this tool's own activity from log review, filter on "+
		"scan_id `%s` / process `%s` (pid %d, user `%s`).\n\n",
		m.SelfTag.ScanID, m.SelfTag.ProcessName, m.SelfTag.PID, m.SelfTag.User)
}

func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
