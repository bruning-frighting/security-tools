package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"irscan/internal/check"
	"irscan/internal/collect"
	"irscan/internal/model"
)

func init() { check.Register(&auditdImpairmentCheck{}) }

type auditdImpairmentCheck struct{}

const auditdCheckID = "LNX-DEFIMP-AUDITD-001"

// baselineWatchPaths are the files a competently configured audit policy watches. Their
// collective absence is evidence that audit coverage was never configured or was stripped.
var baselineWatchPaths = []string{
	"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers", "/etc/sudoers.d",
}

func (c *auditdImpairmentCheck) Meta() check.Meta {
	return check.Meta{
		ID:      auditdCheckID,
		Title:   "Linux audit subsystem disabled, unconfigured or neutered",
		OS:      []string{"linux"},
		Tactics: []string{"defense-impairment"},

		Techniques: []check.TechniqueMapping{
			{
				TechniqueID: "T1685.004",
				Justification: "This sub-technique is specifically 'Disable or Modify Linux " +
					"Audit System Log'. The check reads auditd's configuration, ruleset and " +
					"log state, which is exactly the artifact set that technique modifies.",
			},
			{
				TechniqueID: "T1685",
				Justification: "Parent technique (Disable or Modify Tools). Neutering auditd " +
					"is a direct instance of disabling a defensive tool.",
			},
			// Lineage note, deliberately NOT a mapping: pre-v20 ATT&CK called this
			// T1562.012 "Disable or Modify Linux Audit System", which v20.0 revoked in
			// favour of T1685.004. Mapping a revoked ID would send an analyst to a dead
			// ATT&CK page, and check.ValidateMapping rejects revoked IDs for that reason.
		},

		Sources: []check.SourceRequirement{
			{
				Name: "linux audit subsystem",
				Privilege: "root: /etc/audit and /var/log/audit are mode 0750 root-owned on " +
					"a default install",
				FailureModes: []string{
					"auditd not installed -> source unavailable -> INSUFFICIENT_DATA. This " +
						"is the single most important path in this check: a host with no " +
						"audit subsystem cannot produce audit evidence, so its absence " +
						"proves nothing about adversary activity.",
					"Running unprivileged -> /etc/audit unreadable -> PERMISSION_DENIED or " +
						"PARTIAL_DATA.",
					"Rule files readable but the log is not -> partial; the retention window " +
						"cannot be established and the report says so.",
				},
			},
			{
				Name:      "auditd log channel",
				Privilege: "root",
				Optional:  true,
				FailureModes: []string{
					"Channel absent or unreadable -> no aggregate is produced and the " +
						"finding says the event history could not be assessed.",
				},
			},
		},

		Criteria: []model.Criterion{
			{ID: "AUD-C1", Text: "auditd is installed and configured but its ruleset is " +
				"empty, so no events are being generated."},
			{ID: "AUD-C2", Text: "auditd is installed and configured but its log file is " +
				"absent or zero-length, so no history exists."},
			{ID: "AUD-C3", Text: "The effective ruleset deletes all rules (-D) with no rules " +
				"loaded afterwards, which disables auditing while leaving auditd installed."},
			{ID: "AUD-C4", Text: "auditd.conf neuters logging: write_logs=no, " +
				"log_format=NOLOG, max_log_file_action=ignore/rotate-with-num_logs=0, or " +
				"disk_full_action=ignore."},
			{ID: "AUD-C5", Text: "No watch rule covers any of the baseline sensitive files " +
				"(/etc/passwd, /etc/shadow, /etc/group, /etc/sudoers) and no execve syscall " +
				"rule exists, indicating audit coverage was never configured or was stripped."},
		},

		EscalationCriteria: "A fully configured, healthy audit subsystem produces no finding " +
			"at all. One matching criterion gives suspicious_indicator. Corroborated " +
			"requires a second independent criterion -- for example an empty ruleset " +
			"(AUD-C1) combined with a zero-length log (AUD-C2), which together indicate " +
			"auditing was actively neutered rather than merely never configured. Because " +
			"'never configured' and 'deliberately disabled' look identical in current " +
			"state, this check NEVER escalates above corroborated on its own.",

		FalsePositiveHandling: "Log clearing and defence impairment are explicitly " +
			"noise-prone, and the dominant false positive here is overwhelming: the large " +
			"majority of Linux hosts simply never had auditd configured. The check " +
			"therefore (a) emits nothing at all when auditd is absent, returning " +
			"INSUFFICIENT_DATA instead, so unconfigured hosts do not generate findings; " +
			"(b) fires only when auditd IS installed and configured yet is not producing " +
			"evidence, which is the genuinely anomalous combination; (c) states on every " +
			"finding that a never-configured subsystem is indistinguishable from a " +
			"deliberately disabled one in current state, and gives the package-install-time " +
			"pivot that can separate them; (d) treats containers and minimal images, where " +
			"auditd is intentionally absent, as the first benign explanation.",

		Overlay: check.Overlay{
			Behavior: "An adversary disables, empties or reconfigures the Linux audit " +
				"subsystem so that their subsequent actions are not recorded, or deletes " +
				"the audit log to remove records of what they already did.",
			Artifacts: []string{
				"/etc/audit/auditd.conf daemon settings",
				"/etc/audit/rules.d/*.rules and /etc/audit/audit.rules",
				"/var/log/audit/audit.log existence, size and time window",
				"Control rules such as -D (delete all) and -e 2 (lock the ruleset)",
			},
			Logic: "Read auditd's configuration and rule files and establish the audit log's " +
				"presence, size and actual retention window. If the subsystem is absent " +
				"entirely, return INSUFFICIENT_DATA and stop. Otherwise evaluate the five " +
				"documented criteria. Query the auditd telemetry channel and aggregate it " +
				"by entity (count, window, sample events) rather than emitting one finding " +
				"per event.",
			FalsePositives: []string{
				"Most Linux hosts, containers and minimal images never configure auditd at " +
					"all; this is the dominant benign case and is handled by returning " +
					"INSUFFICIENT_DATA rather than a finding.",
				"Some estates deliberately use a different audit pipeline (eBPF agents, EDR) " +
					"and leave auditd dormant on purpose.",
				"Log rotation can legitimately leave a small or newly created audit.log.",
				"Hardened images ship auditd installed but rules applied later by " +
					"configuration management, creating a genuine window with no rules.",
			},
			Limitations: []string{
				"Current state cannot distinguish 'never configured' from 'disabled by an " +
					"adversary'. The check says so explicitly on every finding instead of " +
					"implying intent.",
				"The in-kernel ruleset (what auditctl -l would show) can differ from the " +
					"files on disk; a runtime-only change leaves no file artifact and is " +
					"invisible here.",
				"Audit log content beyond the first and last timestamps is not parsed: the " +
					"files are routinely gigabytes and the safety limits forbid it.",
				"If an adversary deleted and recreated audit.log, the retention window will " +
					"look short but legitimate rotation looks identical.",
				"An unprivileged scan cannot read /etc/audit at all, which yields " +
					"PERMISSION_DENIED, not a clean result.",
			},
			References: []check.Reference{
				{Title: "MITRE ATT&CK T1685.004 Disable or Modify Linux Audit System Log",
					URL: "https://attack.mitre.org/techniques/T1685/004"},
				{Title: "MITRE ATT&CK T1685 Disable or Modify Tools",
					URL: "https://attack.mitre.org/techniques/T1685"},
				{Title: "auditd.conf(5) manual page",
					URL: "https://man7.org/linux/man-pages/man5/auditd.conf.5.html"},
				{Title: "auditctl(8) manual page",
					URL: "https://man7.org/linux/man-pages/man8/auditctl.8.html"},
			},
		},

		Validation: model.LabVerified,
		LabEvidence: "Executed 2026-10-14 against the LIVE root filesystem of WSL2 Kali " +
			"GNU/Linux Rolling 2026.1 (kernel 6.6.87.2-microsoft-standard-WSL2), " +
			"unprivileged as uid 1000, scan_id irscan-20261014T044834Z-7b0a0cd0. The " +
			"audit subsystem is genuinely absent on this host, and the check returned " +
			"INSUFFICIENT_DATA naming /etc/audit/auditd.conf, /etc/audit/rules.d and " +
			"/var/log/audit/audit.log as missing -- real-world confirmation of the " +
			"no-data path on an actual unconfigured host, not just a fixture.",
		FixtureProvenance: model.Synthetic,
		Telemetry:         true,
	}
}

func (c *auditdImpairmentCheck) Run(ctx context.Context, env check.Env) model.CheckResult {
	started := env.Now()
	m := c.Meta()

	state, src := collect.Auditd(env.FS)
	sources := []model.DataSourceStatus{check.SourceStatus(m.Sources[0], src)}

	// Telemetry channel status, recorded whether or not it is usable. This is the half of
	// the check that makes the telemetry matrix meaningful.
	chStatus := env.Telemetry.Status("linux:auditd")
	telSrc := collect.SourceResult{
		Name:      m.Sources[1].Name,
		Available: chStatus.Present && chStatus.Enabled,
		Reason:    chStatus.Reason,
	}
	// The channel is declared Optional, so its mere absence does not stop the configuration
	// evidence from yielding a determinate answer; model.OutcomeFromSources applies that
	// rule centrally rather than each check hand-rolling it.
	sources = append(sources, check.SourceStatus(m.Sources[1], telSrc))

	if !src.Available {
		// The whole point of this check: a host without auditd gets INSUFFICIENT_DATA with
		// an explanation, never NOT_DETECTED.
		return check.Result(m.ID, started, env.Now, sources, nil, nil)
	}

	if err := ctx.Err(); err != nil {
		return check.ErrorResult(m.ID, started, env.Now, err)
	}

	byID := map[string]model.Criterion{}
	for _, cr := range m.Criteria {
		byID[cr.ID] = cr
	}
	var matched []model.Criterion
	add := func(id string) {
		for _, x := range matched {
			if x.ID == id {
				return
			}
		}
		matched = append(matched, byID[id])
	}

	configured := state.DaemonConfigPresent || len(state.RuleFiles) > 0

	var realRules int
	lastControlDeleteAtEnd := false
	for i, r := range state.Rules {
		if r.Kind == "watch" || r.Kind == "syscall" {
			realRules++
		}
		if strings.HasPrefix(strings.TrimSpace(r.Line), "-D") {
			// -D deletes everything loaded so far; only meaningful if nothing real follows.
			rest := state.Rules[i+1:]
			any := false
			for _, rr := range rest {
				if rr.Kind == "watch" || rr.Kind == "syscall" {
					any = true
					break
				}
			}
			lastControlDeleteAtEnd = !any
		}
	}

	// A criterion may only be evaluated against data that was actually READ. Without these
	// guards an unprivileged scan of a mode-0750 /etc/audit concludes "configured but no
	// rules" and emits a corroborated finding -- a false positive manufactured entirely
	// out of missing data. The permission-denied fixture exists to catch exactly that, and
	// did.
	canAssessRules := state.ConfigReadable || state.RuleFilesRead > 0
	canAssessLog := state.LogStateKnown

	if configured && canAssessRules && realRules == 0 {
		add("AUD-C1")
	}
	if configured && canAssessLog && (!state.LogPresent || state.LogSize == 0) {
		add("AUD-C2")
	}
	if canAssessRules && lastControlDeleteAtEnd && realRules == 0 {
		add("AUD-C3")
	}
	if state.ConfigReadable {
		if neutered, _ := auditConfNeutered(state.Settings); neutered {
			add("AUD-C4")
		}
	}
	if configured && canAssessRules && realRules > 0 && !hasBaselineCoverage(state) {
		add("AUD-C5")
	}

	var inventory []model.InventoryItem
	inventory = append(inventory, model.InventoryItem{
		Group:        "audit subsystem",
		ArtifactType: "auditd_state",
		ArtifactID:   defaultStr(state.DaemonConfigPath, "/etc/audit"),
		Attributes: map[string]string{
			"config_present": fmt.Sprintf("%t", state.DaemonConfigPresent),
			"rule_files":     strings.Join(state.RuleFiles, ","),
			"rule_count":     strconv.Itoa(realRules),
			"log_path":       state.LogPath,
			"log_present":    fmt.Sprintf("%t", state.LogPresent),
			"log_size":       strconv.FormatInt(state.LogSize, 10),
			"immutable":      fmt.Sprintf("%t", state.ImmutableFlag),
		},
		TechniqueIDs: []string{"T1685", "T1685.004"},
		CheckIDs:     []string{m.ID},
	})

	if len(matched) == 0 {
		return check.Result(m.ID, started, env.Now, sources, nil, inventory)
	}

	level := model.SuspiciousIndicator
	if len(matched) >= 2 {
		level = model.Corroborated
	}

	agg := c.aggregate(env, state, chStatus)

	findings := []model.Finding{check.NewFinding(env, m.ID, check.FindingSpec{
		ArtifactType: "auditd_state",
		ArtifactID:   defaultStr(state.DaemonConfigPath, "/etc/audit"),
		Level:        level,
		TechniqueIDs: []string{"T1685", "T1685.004"},
		Title: fmt.Sprintf("Linux audit subsystem installed but not producing evidence (%d criteria)",
			len(matched)),
		WhatAndWhere: fmt.Sprintf(
			"auditd is configured on this host (config present=%t, %d rule file(s), %d "+
				"effective rules) but %s. Log %s at %s (%d bytes).",
			state.DaemonConfigPresent, len(state.RuleFiles), realRules,
			summariseCriteria(matched),
			map[bool]string{true: "present", false: "ABSENT"}[state.LogPresent],
			state.LogPath, state.LogSize),
		Criteria: matched,
		Benign: []string{
			"The host may simply never have had audit rules applied -- containers, minimal " +
				"images and many general-purpose servers never configure auditd.",
			"The estate may deliberately use a different audit pipeline (eBPF agent or EDR) " +
				"and leave auditd dormant.",
			"Configuration management may apply rules after boot, leaving a genuine window " +
				"with none loaded.",
			"Recent log rotation legitimately produces a small or newly created audit.log.",
		},
		NextPivot: []string{
			"Compare the audit package's install time against the mtime of " +
				defaultStr(state.DaemonConfigPath, "/etc/audit") +
				": a config far newer than the install suggests it was changed, not merely " +
				"never set up.",
			"Check whether rules.d files were recently modified or truncated, and by whom.",
			"Compare this host's audit configuration against a known-good peer built from " +
				"the same image -- that comparison, not this check, is what separates " +
				"'never configured' from 'disabled'.",
			"If an EDR or eBPF agent is present, pull its process-execution history for the " +
				"period auditd was blind.",
		},
		Aggregate: agg,
		Evidence:  c.evidence(env, state),
		Context: map[string]string{
			"auditd_configured":   fmt.Sprintf("%t", configured),
			"effective_rules":     strconv.Itoa(realRules),
			"log_window_known":    fmt.Sprintf("%t", state.WindowKnown),
			"telemetry_channel":   chStatus.Channel,
			"telemetry_available": fmt.Sprintf("%t", chStatus.Present && chStatus.Enabled),
			"interpretation_note": "Current state cannot distinguish a never-configured " +
				"audit subsystem from one an adversary disabled. This finding asserts the " +
				"former is possible, not that an adversary acted.",
		},
	})}

	return check.Result(m.ID, started, env.Now, sources, findings, inventory)
}

// aggregate builds the telemetry aggregate. Telemetry checks aggregate by entity -- never
// one finding per event.
func (c *auditdImpairmentCheck) aggregate(env check.Env, state collect.AuditdState,
	ch collect.ChannelStatus) *model.Aggregate {

	agg := &model.Aggregate{Entity: "auditd:" + state.LogPath}
	if !ch.Present {
		return agg
	}
	events, truncated, err := env.Telemetry.Query(collect.TelemetryQuery{
		Channel: "linux:auditd",
		Limit:   env.Limits.MaxEventsPerQuery,
	})
	if err != nil {
		return agg
	}
	agg.EventCount = len(events)
	agg.Truncated = truncated
	agg.WindowStart, agg.WindowEnd = state.Oldest, state.Newest

	// Top sources by audit record type, which is what an analyst scans first.
	counts := map[string]int{}
	for _, e := range events {
		counts[auditRecordType(e.Raw)]++
	}
	for k, v := range counts {
		agg.TopSources = append(agg.TopSources, model.CountedItem{Name: k, Count: v})
	}
	sort.Slice(agg.TopSources, func(i, j int) bool {
		if agg.TopSources[i].Count != agg.TopSources[j].Count {
			return agg.TopSources[i].Count > agg.TopSources[j].Count
		}
		return agg.TopSources[i].Name < agg.TopSources[j].Name
	})
	if len(agg.TopSources) > 10 {
		agg.TopSources = agg.TopSources[:10]
		agg.Truncated = true
	}

	for i, e := range events {
		if i >= env.Limits.MaxSampleEvents {
			agg.Truncated = true
			break
		}
		agg.SampleEvents = append(agg.SampleEvents,
			check.LineEvidence(env, state.LogPath, i+1, e.Raw))
	}
	return agg
}

func auditRecordType(raw string) string {
	if i := strings.Index(raw, "type="); i >= 0 {
		rest := raw[i+len("type="):]
		if j := strings.IndexAny(rest, " \t"); j > 0 {
			return rest[:j]
		}
	}
	return "(untyped)"
}

func (c *auditdImpairmentCheck) evidence(env check.Env, state collect.AuditdState) []model.EvidenceRef {
	var out []model.EvidenceRef
	if state.DaemonConfigPath != "" {
		if ev, err := check.FileEvidence(env, state.DaemonConfigPath, "config_file"); err == nil {
			out = append(out, ev)
		}
	}
	for _, rf := range state.RuleFiles {
		if ev, err := check.FileEvidence(env, rf, "config_file"); err == nil {
			out = append(out, ev)
		}
		if len(out) >= 4 {
			break
		}
	}
	if len(out) == 0 {
		// A finding above observed_artifact requires evidence; synthesise a state summary
		// rather than emitting an unsupported finding.
		summary := fmt.Sprintf("auditd state: config_present=%t rule_files=%d log_present=%t log_size=%d",
			state.DaemonConfigPresent, len(state.RuleFiles), state.LogPresent, state.LogSize)
		out = append(out, model.EvidenceRef{
			ID:        "ev-auditd-state",
			Kind:      "derived_state",
			Source:    "/etc/audit (derived summary)",
			SHA256:    collect.SHA256Hex([]byte(summary)),
			HashScope: "excerpt",
			Excerpt:   summary,
			SizeBytes: int64(len(summary)),
		})
	}
	return out
}

func auditConfNeutered(settings map[string]string) (bool, string) {
	get := func(k string) string { return strings.ToLower(strings.TrimSpace(settings[k])) }
	switch {
	case get("write_logs") == "no":
		return true, "write_logs=no"
	case get("log_format") == "nolog":
		return true, "log_format=NOLOG"
	case get("max_log_file_action") == "ignore":
		return true, "max_log_file_action=ignore"
	case get("disk_full_action") == "ignore":
		return true, "disk_full_action=ignore"
	case get("num_logs") == "0" && get("max_log_file_action") == "rotate":
		return true, "num_logs=0 with rotate"
	}
	return false, ""
}

func hasBaselineCoverage(state collect.AuditdState) bool {
	for _, r := range state.Rules {
		if r.Kind == "syscall" && strings.Contains(r.Line, "execve") {
			return true
		}
		for _, p := range baselineWatchPaths {
			if r.Kind == "watch" && strings.HasPrefix(r.Path, p) {
				return true
			}
		}
	}
	return false
}

func summariseCriteria(cs []model.Criterion) string {
	ids := make([]string, 0, len(cs))
	for _, c := range cs {
		ids = append(ids, c.ID)
	}
	return "matched " + strings.Join(ids, ", ")
}

func (c *auditdImpairmentCheck) Cases() []check.FixtureCase {
	dir := func(root, name string) string {
		return filepath.Join(root, "lnx-defimp-auditd-001", name)
	}
	withTelemetry := func(env check.Env, present bool, lines []string) check.Env {
		t := collect.NewFakeTelemetry()
		if present {
			t.Channels["linux:auditd"] = collect.ChannelStatus{
				Present: true, Enabled: true, EnabledKnown: true, RecordCount: int64(len(lines)),
			}
			for i, l := range lines {
				t.Events["linux:auditd"] = append(t.Events["linux:auditd"], collect.LogEvent{
					Channel: "linux:auditd", Raw: l, Message: l, EventID: i,
				})
			}
		} else {
			t.Channels["linux:auditd"] = collect.ChannelStatus{
				Present: false, Reason: "auditd log channel not present on this host",
			}
		}
		env.Telemetry = t
		return env
	}

	return []check.FixtureCase{
		{
			Name: "auditd installed, ruleset emptied and log truncated",
			Kind: check.CasePositive,
			Why: "The anomalous combination the check exists to find: the subsystem IS " +
				"configured yet produces nothing. Two criteria must fire and escalate to " +
				"corroborated.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(dir(root, "positive"), "linux")
				if err != nil {
					return env, err
				}
				return withTelemetry(env, false, nil), nil
			},
			WantOutcome:      model.Detected,
			MinFindings:      1,
			WantTechniqueIDs: []string{"T1685.004"},
		},
		{
			Name: "properly configured auditd with baseline rules and a populated log",
			Kind: check.CaseNegative,
			Why: "A healthy audit subsystem must produce no finding at all, proving the " +
				"check is not simply reporting that auditd exists.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(dir(root, "negative"), "linux")
				if err != nil {
					return env, err
				}
				return withTelemetry(env, true, []string{
					`type=SYSCALL msg=audit(1760000000.123:456): arch=c000003e syscall=59 comm="bash"`,
					`type=PATH msg=audit(1760000000.123:456): name="/usr/bin/id"`,
				}), nil
			},
			WantOutcome: model.NotDetected,
		},
		{
			Name: "auditd not installed at all (the common real case)",
			Kind: check.CaseNoData,
			Why: "This is THE critical path for this check and the reason it was chosen as " +
				"the pilot telemetry check. A host with no audit subsystem must yield " +
				"INSUFFICIENT_DATA. Returning NOT_DETECTED would tell an analyst that a " +
				"blind host is clean.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(dir(root, "nodata"), "linux")
				if err != nil {
					return env, err
				}
				return withTelemetry(env, false, nil), nil
			},
			WantOutcome: model.InsufficientData,
		},
		{
			Name: "/etc/audit unreadable (unprivileged scan)",
			Kind: check.CasePermissionDenied,
			Why: "Models the normal non-root case, where /etc/audit is mode 0750. Must not " +
				"read as an absent or healthy audit subsystem.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(dir(root, "positive"), "linux")
				if err != nil {
					return env, err
				}
				env.FS = &collect.ErrorFS{
					FileSystem: env.FS,
					DenyPrefix: []string{"/etc/audit", "/var/log/audit"},
				}
				return withTelemetry(env, false, nil), nil
			},
			WantOutcome: model.InsufficientData,
			AlsoAccept:  []model.Outcome{model.PermissionDenied, model.PartialData},
		},
	}
}
