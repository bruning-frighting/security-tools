package check

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"irscan/internal/collect"
	"irscan/internal/model"
)

// Helpers every check uses, so the data-contract rules are implemented once rather than
// re-derived (and mis-derived) per check.

// FileEvidence builds an EvidenceRef for a file: full-object hash plus a bounded excerpt.
//
// The hash covers the FULL file so an analyst can compare it against a reference copy or a
// threat-intel hash; the excerpt is bounded by the safety budget. HashScope records which,
// because a hash over a truncated excerpt is not comparable and silently conflating the two
// would mislead.
func FileEvidence(env Env, logicalPath, kind string) (model.EvidenceRef, error) {
	fi, err := env.FS.Stat(logicalPath)
	if err != nil {
		return model.EvidenceRef{}, err
	}
	data, truncated, err := env.FS.ReadFile(logicalPath)
	if err != nil {
		return model.EvidenceRef{}, err
	}
	ev := model.EvidenceRef{
		ID:        evidenceID(env.ScanID, logicalPath),
		Kind:      kind,
		Source:    logicalPath,
		SHA256:    collect.SHA256Hex(data),
		HashScope: "full_object",
		SizeBytes: fi.Size,
		ModTime:   fi.ModTime,
		Truncated: truncated,
	}
	if truncated {
		// The file was larger than MaxFileSizeBytes, so what we hashed is only the prefix.
		// Saying "full_object" here would be a lie an analyst could act on.
		ev.HashScope = "excerpt"
	}
	excerpt, cut := env.Budget.ClampExcerpt(string(data))
	ev.Excerpt = excerpt
	if cut {
		ev.Truncated = true
	}
	return ev, nil
}

// LineEvidence builds evidence for a single line within a file (a crontab entry, an
// authorized_keys line). The hash covers the line, so HashScope is "excerpt".
func LineEvidence(env Env, logicalPath string, lineNo int, line string) model.EvidenceRef {
	excerpt, cut := env.Budget.ClampExcerpt(line)
	return model.EvidenceRef{
		ID:        evidenceID(env.ScanID, fmt.Sprintf("%s:%d", logicalPath, lineNo)),
		Kind:      "file_line",
		Source:    fmt.Sprintf("%s:%d", logicalPath, lineNo),
		SHA256:    collect.SHA256Hex([]byte(line)),
		HashScope: "excerpt",
		SizeBytes: int64(len(line)),
		Excerpt:   excerpt,
		Truncated: cut,
	}
}

// RegistryEvidence builds evidence for a registry value.
func RegistryEvidence(env Env, keyPath string, v collect.RegValue) model.EvidenceRef {
	rendered := fmt.Sprintf("%s = (%s) %s", v.Name, v.Type, v.String)
	excerpt, cut := env.Budget.ClampExcerpt(rendered)
	return model.EvidenceRef{
		ID:        evidenceID(env.ScanID, keyPath+`\`+v.Name),
		Kind:      "registry_value",
		Source:    keyPath + `\` + v.Name,
		SHA256:    collect.SHA256Hex([]byte(rendered)),
		HashScope: "full_object",
		SizeBytes: int64(len(rendered)),
		Excerpt:   excerpt,
		Truncated: cut,
	}
}

// RedactedEvidence builds evidence for something that may contain secret material.
//
// Credential-related checks must use this: it records the path, the pattern type and
// metadata, and NEVER the secret value. The hash is over the redacted excerpt, so it cannot
// be used to recover or confirm-by-brute-force the secret.
func RedactedEvidence(env Env, source, kind, patternType string, size int64, note string) model.EvidenceRef {
	placeholder := fmt.Sprintf("[redacted: %s match, %d bytes]", patternType, size)
	return model.EvidenceRef{
		ID:            evidenceID(env.ScanID, source+"#"+patternType),
		Kind:          kind,
		Source:        source,
		SHA256:        collect.SHA256Hex([]byte(placeholder)),
		HashScope:     "excerpt",
		SizeBytes:     size,
		Excerpt:       placeholder,
		Redacted:      true,
		RedactionNote: note,
	}
}

func evidenceID(scanID, source string) string {
	return "ev-" + collect.SHA256Hex([]byte(scanID+"|"+source))[:16]
}

// ---------------------------------------------------------------------------------------
// Source status
// ---------------------------------------------------------------------------------------

// SourceStatus converts a collector's SourceResult plus its declared requirement into the
// DataSourceStatus the outcome logic consumes.
func SourceStatus(req SourceRequirement, r collect.SourceResult) model.DataSourceStatus {
	s := model.DataSourceStatus{
		Name:      req.Name,
		Available: r.Available,
		Reason:    r.Reason,
		ItemsSeen: r.ItemsSeen,
		Truncated: r.Truncated,
		Privilege: req.Privilege,
		Optional:  req.Optional,
	}
	if r.Available && len(r.Errors) > 0 {
		// Partial collection: the source answered, but not completely. Recorded as
		// Incomplete rather than Truncated so the report states the real cause (usually a
		// permission denial) instead of blaming a safety limit.
		s.Incomplete = true
		s.IncompleteReason = strings.Join(r.Errors, "; ")
		s.Reason = "partial collection: " + s.IncompleteReason
	}
	if !r.Available && s.Reason == "" {
		s.Reason = "source unavailable (no reason recorded by collector)"
	}
	return s
}

// ---------------------------------------------------------------------------------------
// Finding construction
// ---------------------------------------------------------------------------------------

// FindingSpec is the input to NewFinding. Using a struct keeps the required triage fields
// visible at every call site.
type FindingSpec struct {
	ArtifactType string
	ArtifactID   string
	Level        model.FindingLevel
	Title        string
	WhatAndWhere string
	Criteria     []model.Criterion
	Benign       []string
	NextPivot    []string
	Evidence     []model.EvidenceRef
	Aggregate    *model.Aggregate
	Context      map[string]string
	TechniqueIDs []string
}

// NewFinding assembles a finding, applies the allowlist, and sets the dedup key.
//
// The dedup key is host + artifact type + artifact identity. It deliberately does NOT
// include the check ID or the technique: that is what makes "one artifact is one finding"
// work when several checks match the same artifact.
func NewFinding(env Env, checkID string, spec FindingSpec) model.Finding {
	f := model.Finding{
		DedupKey:           DedupKey(env.Host.Hostname, spec.ArtifactType, spec.ArtifactID),
		Host:               env.Host.Hostname,
		ArtifactType:       spec.ArtifactType,
		ArtifactID:         spec.ArtifactID,
		Level:              spec.Level,
		TechniqueIDs:       model.Union(spec.TechniqueIDs, nil),
		CheckIDs:           []string{checkID},
		Title:              spec.Title,
		WhatAndWhere:       spec.WhatAndWhere,
		CriteriaMatched:    spec.Criteria,
		BenignExplanations: spec.Benign,
		NextPivot:          spec.NextPivot,
		Evidence:           spec.Evidence,
		Aggregate:          spec.Aggregate,
		Context:            spec.Context,
		AnalystDisposition: model.Unreviewed,
	}
	if env.Allowlist != nil {
		if id, reason := env.Allowlist.Match(spec.ArtifactType, spec.ArtifactID, spec.Context); id != "" {
			f.Suppressed = true
			f.SuppressedBy = id
			f.SuppressionReason = reason
		}
	}
	return f
}

// DedupKey is the canonical artifact identity.
func DedupKey(host, artifactType, artifactID string) string {
	return fmt.Sprintf("%s|%s|%s", strings.ToLower(host), artifactType,
		strings.ToLower(strings.ReplaceAll(artifactID, `\`, "/")))
}

// MergeFindings collapses findings sharing a dedup key, unioning technique and check
// attribution. The runner applies this across ALL checks, which is where cross-check
// deduplication actually happens.
func MergeFindings(in []model.Finding) []model.Finding {
	idx := map[string]int{}
	var out []model.Finding
	for _, f := range in {
		if i, ok := idx[f.DedupKey]; ok {
			out[i].Merge(f)
			continue
		}
		idx[f.DedupKey] = len(out)
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Level.Rank() != out[j].Level.Rank() {
			return out[i].Level.Rank() > out[j].Level.Rank()
		}
		return out[i].DedupKey < out[j].DedupKey
	})
	return out
}

// ---------------------------------------------------------------------------------------
// Result construction
// ---------------------------------------------------------------------------------------

// Result assembles a CheckResult with the correct outcome derived from source availability.
// Checks must go through this rather than setting Outcome directly.
func Result(checkID string, started time.Time, now func() time.Time,
	sources []model.DataSourceStatus, findings []model.Finding,
	inventory []model.InventoryItem) model.CheckResult {

	matched := false
	for _, f := range findings {
		if f.Level.Reportable() && !f.Suppressed {
			matched = true
			break
		}
	}
	outcome, reason := model.OutcomeFromSources(sources, matched)
	return model.CheckResult{
		CheckID:   checkID,
		Outcome:   outcome,
		Reason:    reason,
		Findings:  findings,
		Inventory: inventory,
		Sources:   sources,
		StartedAt: started,
		Duration:  now().Sub(started),
	}
}

// ErrorResult is for an unexpected failure. ERROR is never conflated with NOT_DETECTED.
func ErrorResult(checkID string, started time.Time, now func() time.Time, err error) model.CheckResult {
	return model.CheckResult{
		CheckID:   checkID,
		Outcome:   model.Error,
		Reason:    "check failed: " + err.Error(),
		Err:       err.Error(),
		StartedAt: started,
		Duration:  now().Sub(started),
	}
}

// NotTestedResult is for a check that was deliberately not run.
func NotTestedResult(checkID, reason string) model.CheckResult {
	return model.CheckResult{CheckID: checkID, Outcome: model.NotTested, Reason: reason}
}
