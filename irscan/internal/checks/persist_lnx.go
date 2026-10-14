package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"irscan/internal/check"
	"irscan/internal/collect"
	"irscan/internal/model"
)

func init() {
	check.Register(&systemdUnitCheck{}, &cronCheck{})
}

// =======================================================================================
// LNX-PERSIST-SYSTEMD-001
// =======================================================================================

type systemdUnitCheck struct{}

const systemdCheckID = "LNX-PERSIST-SYSTEMD-001"

func (c *systemdUnitCheck) Meta() check.Meta {
	return check.Meta{
		ID:      systemdCheckID,
		Title:   "Suspicious systemd service or timer unit",
		OS:      []string{"linux"},
		Tactics: []string{"persistence", "privilege-escalation"},

		Techniques: []check.TechniqueMapping{
			{
				TechniqueID: "T1543.002",
				Justification: "A systemd service unit IS the artifact this sub-technique " +
					"describes: the check parses unit files under the systemd unit " +
					"directories and inspects their Exec* directives.",
			},
			{
				TechniqueID: "T1543",
				Justification: "Parent technique of T1543.002; a matched service unit is " +
					"direct evidence of creating or modifying a system process.",
			},
			{
				TechniqueID: "T1053.006",
				Justification: "Timer units are parsed by the same collector and are the " +
					"artifact for Systemd Timers. Mapped Partial because the check reasons " +
					"about the timer's Exec* command, not about timer-specific scheduling " +
					"evasion such as randomised OnCalendar drift.",
				Partial: true,
			},
		},

		Sources: []check.SourceRequirement{{
			Name:      "systemd unit files",
			Privilege: "read access to the unit directories; world-readable on a default install",
			FailureModes: []string{
				"No systemd unit directory exists (host does not use systemd) -> source " +
					"unavailable -> INSUFFICIENT_DATA, never NOT_DETECTED.",
				"A unit directory is unreadable -> recorded as a partial collection error, " +
					"which forces PARTIAL_DATA rather than NOT_DETECTED.",
				"A unit file exceeds the size limit -> truncated read, which also forces " +
					"PARTIAL_DATA.",
				"Units created at runtime via the D-Bus API without a file on disk are " +
					"invisible to a file-based collector; see Limitations.",
			},
		}},

		Criteria: []model.Criterion{
			{ID: "SYSD-C1", Text: "The unit's Exec* command runs a binary from a transient, " +
				"world-writable directory (/tmp, /var/tmp, /dev/shm, /run/shm)."},
			{ID: "SYSD-C2", Text: "A unit in /etc/systemd/system shadows a vendor unit of the " +
				"same name in /usr/lib/systemd/system or /lib/systemd/system, overriding it."},
			{ID: "SYSD-C3", Text: "An Exec* command pipes the output of a downloader " +
				"(curl/wget/fetch) directly into a shell interpreter."},
			{ID: "SYSD-C4", Text: "An Exec* command decodes and executes inline content " +
				"(base64 -d, openssl enc -d, eval, interpreter -c/-e)."},
			{ID: "SYSD-C5", Text: "An Exec* command constructs an interactive shell over a " +
				"socket (nc -e, ncat --exec, /dev/tcp, socat exec)."},
			{ID: "SYSD-C6", Text: "The unit file itself is world-writable, so any local user " +
				"can alter what the service executes."},
		},

		EscalationCriteria: "Every parsed unit is an observed_artifact and goes to Inventory " +
			"only. One matching criterion raises it to suspicious_indicator. Escalation to " +
			"corroborated requires a SECOND, independent criterion from the list above -- " +
			"for example a transient-directory ExecStart (SYSD-C1) that is ALSO a " +
			"vendor-shadowing unit (SYSD-C2). Two signals of the same kind do not corroborate.",

		FalsePositiveHandling: "systemd units are a known-noisy area, so existence alone " +
			"never produces a finding. Specifically: (a) /opt, /usr/local and /home paths " +
			"are NOT treated as transient, because legitimate third-party and user services " +
			"run from there; (b) SYSD-C2 fires only on same-filename shadowing, which is a " +
			"deliberate administrative override pattern as well as an attacker one, so it " +
			"is reported as context and cannot alone exceed suspicious_indicator; " +
			"(c) configuration-management tools (Ansible, Puppet, Chef) routinely write " +
			"units into /etc/systemd/system, and this is listed as the first benign " +
			"explanation on every such finding; (d) drop-in overrides under *.service.d/ " +
			"are not treated as shadowing.",

		Overlay: check.Overlay{
			Behavior: "An adversary installs or modifies a systemd service or timer unit so " +
				"that their payload is started by init at boot, on a schedule, or on a " +
				"system event. Because systemd restarts failed units, this also provides " +
				"resilience against the payload being killed.",
			Artifacts: []string{
				"Unit files (.service, .timer) under /etc/systemd/system, /run/systemd/system, " +
					"/usr/lib/systemd/system, /lib/systemd/system and the matching user paths.",
				"Enablement symlinks under <target>.wants/ and <target>.requires/.",
				"The ExecStart/ExecStartPre/ExecStartPost/ExecStop/ExecReload command lines.",
			},
			Logic: "Parse every .service and .timer file found in the standard unit " +
				"directories (no systemctl invocation, so the check works against a fixture " +
				"root and on a host where systemd is not running). Resolve enablement by " +
				"reading .wants/.requires directories. Evaluate the six documented criteria " +
				"against each unit's Exec* directives and file metadata. Emit every unit to " +
				"Inventory; emit a Finding only when at least one criterion matches.",
			FalsePositives: []string{
				"Configuration-management tooling writes units into /etc/systemd/system as " +
					"normal practice.",
				"Local administrators legitimately override vendor units by placing a " +
					"same-named unit in /etc/systemd/system.",
				"Container and virtualisation runtimes generate units referencing paths " +
					"under /run and /var that look transient.",
				"Developer and CI hosts genuinely run services from user-writable paths.",
			},
			Limitations: []string{
				"Transient units created over the D-Bus API without ever being written to " +
					"disk are invisible to a file-based collector.",
				"The check reads what is ON DISK NOW. A unit that ran and was then deleted " +
					"leaves nothing here; only journald would show it, and journald may not " +
					"be enabled or retained.",
				"An adversary with root can edit the unit file after execution, so content " +
					"seen here may have been tampered with.",
				"Drop-in overrides under /etc/systemd/system/<unit>.d/*.conf are collected " +
					"as files but their directive merge order is not modelled.",
				"Exec* command parsing does not expand systemd specifiers (%i, %H, %n), so a " +
					"templated unit's effective command may differ from the literal text.",
			},
			References: []check.Reference{
				{Title: "MITRE ATT&CK T1543.002 Systemd Service",
					URL: "https://attack.mitre.org/techniques/T1543/002"},
				{Title: "MITRE ATT&CK T1053.006 Systemd Timers",
					URL: "https://attack.mitre.org/techniques/T1053/006"},
				{Title: "systemd.service(5) manual page",
					URL: "https://www.freedesktop.org/software/systemd/man/systemd.service.html"},
				{Title: "systemd.unit(5) -- unit load path and precedence",
					URL: "https://www.freedesktop.org/software/systemd/man/systemd.unit.html"},
			},
		},

		Validation: model.LabVerified,
		LabEvidence: "Executed 2026-10-14 against the LIVE root filesystem of WSL2 Kali " +
			"GNU/Linux Rolling 2026.1 (kernel 6.6.87.2-microsoft-standard-WSL2), " +
			"unprivileged as uid 1000, scan_id irscan-20261014T044834Z-7b0a0cd0. Parsed " +
			"441 real unit files across the systemd unit directories (23 masked, 43 " +
			"symlinks) and returned NOT_DETECTED. An earlier revision of this check " +
			"produced 43 false positives on this same host (symlink mode bits and masked " +
			"units); both causes were fixed and locked in by fixture regression cases.",
		FixtureProvenance: model.Synthetic,
	}
}

func (c *systemdUnitCheck) Run(ctx context.Context, env check.Env) model.CheckResult {
	started := env.Now()
	m := c.Meta()

	units, src := collect.SystemdUnits(env.FS, env.Limits.MaxDirDepth)
	sources := []model.DataSourceStatus{check.SourceStatus(m.Sources[0], src)}
	if !src.Available {
		return check.Result(m.ID, started, env.Now, sources, nil, nil)
	}

	// Vendor-shadowing index: unit name -> set of directories it appears in.
	dirsByName := map[string]map[string]bool{}
	for _, u := range units {
		d := filepath.ToSlash(filepath.Dir(u.Source))
		if dirsByName[u.Name] == nil {
			dirsByName[u.Name] = map[string]bool{}
		}
		dirsByName[u.Name][d] = true
	}

	var findings []model.Finding
	var inventory []model.InventoryItem

	for _, u := range units {
		if err := ctx.Err(); err != nil {
			return check.ErrorResult(m.ID, started, env.Now, err)
		}

		inventory = append(inventory, model.InventoryItem{
			Group:        "systemd units",
			ArtifactType: "systemd_unit",
			ArtifactID:   u.Source,
			Attributes: map[string]string{
				"name":        u.Name,
				"exec_start":  Truncate(u.ImagePath, 200),
				"account":     u.Account,
				"enabled":     fmt.Sprintf("%t", u.Enabled),
				"symlink":     fmt.Sprintf("%t", u.IsSymlink),
				"link_target": u.LinkTarget,
				"masked":      fmt.Sprintf("%t", u.Masked),
				"description": Truncate(u.Description, 120),
			},
			TechniqueIDs: []string{"T1543", "T1543.002"},
			CheckIDs:     []string{m.ID},
		})

		// A masked unit is symlinked to /dev/null and cannot start. It is inventoried, but
		// evaluating persistence criteria against a unit that systemd refuses to run would
		// be reporting the opposite of what the artifact means.
		if u.Masked {
			continue
		}

		matched := c.evaluate(env, u, dirsByName)
		if len(matched) == 0 {
			continue
		}

		level := model.SuspiciousIndicator
		if len(matched) >= 2 {
			level = model.Corroborated
		}

		ev, err := check.FileEvidence(env, u.Source, "unit_file")
		if err != nil {
			// Evidence is mandatory above observed_artifact; without it the honest move is
			// to record the collection problem rather than emit an unsupported finding.
			src.Errors = append(src.Errors,
				fmt.Sprintf("matched %s but could not read it for evidence: %v", u.Source, err))
			sources[0] = check.SourceStatus(m.Sources[0], src)
			continue
		}

		techniques := []string{"T1543", "T1543.002"}
		if strings.HasSuffix(u.Name, ".timer") {
			techniques = append(techniques, "T1053.006")
		}

		findings = append(findings, check.NewFinding(env, m.ID, check.FindingSpec{
			ArtifactType: "systemd_unit",
			ArtifactID:   u.Source,
			Level:        level,
			TechniqueIDs: techniques,
			Title: fmt.Sprintf("systemd unit %s matches %d persistence criteria",
				u.Name, len(matched)),
			WhatAndWhere: fmt.Sprintf(
				"Unit %q at %s runs %q as %s (enabled=%t).",
				u.Name, u.Source, Truncate(u.ImagePath, 200), u.Account, u.Enabled),
			Criteria: matched,
			Benign: []string{
				"Configuration management (Ansible/Puppet/Chef/Salt) commonly installs units " +
					"into /etc/systemd/system -- check whether the file is managed.",
				"A local administrator may deliberately override a vendor unit by placing a " +
					"same-named file in /etc/systemd/system.",
				"Vendor software installed outside the package manager legitimately executes " +
					"from non-standard paths.",
				"On developer or CI hosts, services genuinely run from user-writable paths.",
			},
			NextPivot: []string{
				"Verify file ownership and mtime of " + u.Source + " against the package " +
					"manager's manifest (dpkg -S / rpm -qf) to see whether it is " +
					"vendor-supplied.",
				"Inspect the referenced executable " + FirstArg(u.ImagePath) +
					": owner, mtime, and whether any package owns it.",
				"Review journald for this unit's start history, bearing in mind journald may " +
					"not be enabled or retained.",
				"Check the .wants/.requires symlinks to confirm whether the unit actually " +
					"starts at boot.",
			},
			Evidence: []model.EvidenceRef{ev},
			Context: map[string]string{
				"unit_directory": filepath.ToSlash(filepath.Dir(u.Source)),
				"enabled":        fmt.Sprintf("%t", u.Enabled),
				"account":        u.Account,
				"note": "Package ownership or a vendor-looking path is context only, " +
					"never proof that the unit is benign.",
			},
		}))
	}

	return check.Result(m.ID, started, env.Now, sources, findings, inventory)
}

func (c *systemdUnitCheck) evaluate(env check.Env, u collect.Service,
	dirsByName map[string]map[string]bool) []model.Criterion {

	byID := map[string]model.Criterion{}
	for _, cr := range c.Meta().Criteria {
		byID[cr.ID] = cr
	}
	var out []model.Criterion
	add := func(id string) {
		for _, existing := range out {
			if existing.ID == id {
				return
			}
		}
		out = append(out, byID[id])
	}

	// Evaluate every Exec* directive, not just ExecStart: persistence is routinely hidden
	// in ExecStartPre/ExecStartPost, which a check that only reads ExecStart would miss.
	commands := []string{u.ImagePath}
	for k, v := range u.Extra {
		if strings.HasPrefix(strings.ToLower(k), "exec") {
			commands = append(commands, v)
		}
	}

	for _, cmd := range commands {
		if cmd == "" {
			continue
		}
		if _, hit := TransientExecutable(cmd); hit {
			add("SYSD-C1")
		}
		for _, sig := range LinuxCommandSignals(cmd) {
			switch sig {
			case "download-pipe-interpreter":
				add("SYSD-C3")
			case "encoded-or-eval-execution":
				add("SYSD-C4")
			case "interactive-shell-over-socket":
				add("SYSD-C5")
			}
		}
	}

	// SYSD-C2: same unit name present in both an admin directory and a vendor directory.
	//
	// Only a REGULAR FILE in /etc/systemd/system overrides a vendor unit. A symlink there
	// is systemd's normal enablement/aliasing mechanism, not an override. Verified against
	// a real host: stock Kali has 9 symlinks and 1 regular file in /etc/systemd/system,
	// and treating the symlinks as shadowing produced 6 false positives.
	dir := filepath.ToSlash(filepath.Dir(u.Source))
	if dir == "/etc/systemd/system" && !u.IsSymlink {
		for d := range dirsByName[u.Name] {
			if d == "/usr/lib/systemd/system" || d == "/lib/systemd/system" {
				add("SYSD-C2")
				break
			}
		}
	}

	// SYSD-C6: a world-writable unit file means any local user controls the service.
	//
	// Symlinks are excluded because a symlink's own mode is ALWAYS lrwxrwxrwx on Linux --
	// the permission bits are not used and carry no information. Testing them produced 43
	// false positives against a stock Kali host. The link TARGET's mode is what matters,
	// and that file is itself collected and evaluated when it lies in a unit directory.
	if !u.IsSymlink {
		if fi, err := env.FS.Stat(u.Source); err == nil && fi.WorldWritable {
			add("SYSD-C6")
		}
	}

	return out
}

func (c *systemdUnitCheck) Cases() []check.FixtureCase {
	dir := func(root, name string) string {
		return filepath.Join(root, "lnx-persist-systemd-001", name)
	}
	return []check.FixtureCase{
		{
			Name: "malicious unit executing from /tmp and shadowing a vendor unit",
			Kind: check.CasePositive,
			Why: "Proves the check detects both the transient-directory criterion and the " +
				"vendor-shadowing criterion, and that two independent criteria escalate to " +
				"corroborated.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "positive"), "linux")
			},
			WantOutcome:      model.Detected,
			MinFindings:      1,
			WantTechniqueIDs: []string{"T1543.002"},
		},
		{
			Name: "realistic distribution unit set (ssh, nginx, cron, systemd-timesyncd)",
			Kind: check.CaseNegative,
			Why: "Proves the check does not fire on ordinary legitimate software. This is " +
				"the case that distinguishes a real check from one that flags every unit.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "negative"), "linux")
			},
			WantOutcome: model.NotDetected,
		},
		{
			Name: "host without systemd",
			Kind: check.CaseNoData,
			Why: "Proves a host with no unit directories yields INSUFFICIENT_DATA. If this " +
				"ever returns NOT_DETECTED the tool is telling an analyst a non-systemd " +
				"host is clean of systemd persistence, which is meaningless.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "nodata"), "linux")
			},
			WantOutcome: model.InsufficientData,
		},
		{
			Name: "unit directories unreadable",
			Kind: check.CasePermissionDenied,
			Why: "Proves that an unreadable unit tree is reported as such. A locked-down " +
				"host must never read as a clean host.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(dir(root, "positive"), "linux")
				if err != nil {
					return env, err
				}
				env.FS = &collect.ErrorFS{
					FileSystem: env.FS,
					DenyPrefix: []string{"/etc/systemd", "/usr/lib/systemd", "/lib/systemd"},
				}
				return env, nil
			},
			WantOutcome: model.InsufficientData,
			AlsoAccept:  []model.Outcome{model.PermissionDenied, model.PartialData},
		},
	}
}

// =======================================================================================
// LNX-PERSIST-CRON-001
// =======================================================================================

type cronCheck struct{}

const cronCheckID = "LNX-PERSIST-CRON-001"

func (c *cronCheck) Meta() check.Meta {
	return check.Meta{
		ID:      cronCheckID,
		Title:   "Suspicious cron job",
		OS:      []string{"linux"},
		Tactics: []string{"persistence", "execution"},

		Techniques: []check.TechniqueMapping{
			{
				TechniqueID: "T1053.003",
				Justification: "Crontab entries ARE the artifact for this sub-technique: the " +
					"check parses /etc/crontab, /etc/cron.d, the cron.{hourly,daily,weekly," +
					"monthly} directories and the per-user spool.",
			},
			{
				TechniqueID: "T1053",
				Justification: "Parent technique of T1053.003; a matched cron entry is direct " +
					"evidence of scheduled task/job abuse.",
			},
		},

		Sources: []check.SourceRequirement{{
			Name: "cron tables",
			Privilege: "/etc/cron* is world-readable; /var/spool/cron is mode 0700 " +
				"root-owned and needs root",
			FailureModes: []string{
				"No cron path exists at all -> source unavailable -> INSUFFICIENT_DATA.",
				"The per-user spool is unreadable without root -> recorded as a partial " +
					"collection error -> PARTIAL_DATA, so an unprivileged scan can never " +
					"claim there are no user crontabs.",
				"A crontab larger than the size limit is truncated -> PARTIAL_DATA.",
			},
		}},

		Criteria: []model.Criterion{
			{ID: "CRON-C1", Text: "The scheduled command executes from a transient, " +
				"world-writable directory (/tmp, /var/tmp, /dev/shm, /run/shm)."},
			{ID: "CRON-C2", Text: "The command pipes a downloader (curl/wget/fetch) directly " +
				"into a shell interpreter."},
			{ID: "CRON-C3", Text: "The command decodes and executes inline content " +
				"(base64 -d, openssl enc -d, eval, interpreter -c/-e)."},
			{ID: "CRON-C4", Text: "The command constructs an interactive shell over a socket " +
				"(nc -e, ncat --exec, /dev/tcp, socat exec)."},
			{ID: "CRON-C5", Text: "A PATH assignment in the crontab prepends a writable " +
				"directory, so later entries may resolve to an attacker-controlled binary."},
		},

		EscalationCriteria: "Every parsed entry is an observed_artifact for Inventory. One " +
			"matching criterion gives suspicious_indicator. Corroborated requires a second, " +
			"independent criterion -- for instance a /tmp payload (CRON-C1) that is also " +
			"base64-decoded at runtime (CRON-C3).",

		FalsePositiveHandling: "Cron is a known-noisy area. Existence of a cron job is never " +
			"a finding. Monitoring agents, backup jobs and package-maintenance scripts " +
			"populate /etc/cron.d and the periodic directories heavily, so: (a) only the " +
			"documented command-shape criteria fire, never the mere presence of an entry; " +
			"(b) legitimate use of curl/wget WITHOUT a pipe into an interpreter does not " +
			"match CRON-C2, because downloading a file is ordinary; (c) environment " +
			"assignments are inventoried but only PATH prepending a writable directory " +
			"matches CRON-C5; (d) every finding lists package-maintenance and monitoring " +
			"agents as the first benign explanations to rule out.",

		Overlay: check.Overlay{
			Behavior: "An adversary adds a cron entry so their payload runs on a schedule or " +
				"at boot (@reboot), surviving reboots and process termination. Cron is " +
				"attractive because it is present on almost every Linux host and because " +
				"entries can be placed in several locations, not all of which an " +
				"investigator checks.",
			Artifacts: []string{
				"/etc/crontab",
				"Files in /etc/cron.d",
				"Scripts in /etc/cron.hourly, cron.daily, cron.weekly, cron.monthly",
				"Per-user crontabs in /var/spool/cron/crontabs or /var/spool/cron",
			},
			Logic: "Read every cron location, parse each non-comment line into schedule, " +
				"optional run-as user and command (system-format files carry the user " +
				"column, per-user spool files do not). Evaluate the documented criteria " +
				"against the command text. Inventory every entry; emit a Finding only on a " +
				"criterion match.",
			FalsePositives: []string{
				"Package maintenance scripts (logrotate, man-db, apt) populate the periodic " +
					"cron directories on every Debian-family host.",
				"Monitoring and backup agents schedule frequent jobs that fetch over the " +
					"network.",
				"Administrators legitimately use base64 in a cron entry to embed a quoted " +
					"payload safely.",
				"Containers and CI runners schedule jobs writing to /tmp as normal practice.",
			},
			Limitations: []string{
				"An unprivileged scan cannot read /var/spool/cron, so user crontabs are " +
					"invisible; the result is PARTIAL_DATA and the report says so.",
				"at(1) jobs, anacron and systemd timers are not covered here (timers are " +
					"covered by " + systemdCheckID + ").",
				"A job that ran and was then removed leaves nothing in these files; only " +
					"cron's syslog output would show it, if syslog was enabled and retained.",
				"The check reads current state, which a root-level adversary can edit after " +
					"the fact.",
			},
			References: []check.Reference{
				{Title: "MITRE ATT&CK T1053.003 Cron",
					URL: "https://attack.mitre.org/techniques/T1053/003"},
				{Title: "crontab(5) manual page",
					URL: "https://man7.org/linux/man-pages/man5/crontab.5.html"},
			},
		},

		Validation: model.LabVerified,
		LabEvidence: "Executed 2026-10-14 against the LIVE root filesystem of WSL2 Kali " +
			"GNU/Linux Rolling 2026.1 (kernel 6.6.87.2-microsoft-standard-WSL2), " +
			"unprivileged as uid 1000, scan_id irscan-20261014T044834Z-7b0a0cd0. Parsed " +
			"89 real cron entries and returned PARTIAL_DATA, correctly reporting the " +
			"genuine permission denial on /var/spool/cron/crontabs rather than claiming " +
			"there were no user crontabs. A false positive on stock Debian's " +
			"/etc/cron.daily/apt-compat was found on this host and fixed.",
		FixtureProvenance: model.Synthetic,
	}
}

func (c *cronCheck) Run(ctx context.Context, env check.Env) model.CheckResult {
	started := env.Now()
	m := c.Meta()

	entries, src := collect.CronEntries(env.FS)
	sources := []model.DataSourceStatus{check.SourceStatus(m.Sources[0], src)}
	if !src.Available {
		return check.Result(m.ID, started, env.Now, sources, nil, nil)
	}

	byID := map[string]model.Criterion{}
	for _, cr := range m.Criteria {
		byID[cr.ID] = cr
	}

	var findings []model.Finding
	var inventory []model.InventoryItem

	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return check.ErrorResult(m.ID, started, env.Now, err)
		}

		artifactID := fmt.Sprintf("%s:%d", e.Source, e.LineNo)
		inventory = append(inventory, model.InventoryItem{
			Group:        "cron entries",
			ArtifactType: "cron_entry",
			ArtifactID:   artifactID,
			Attributes: map[string]string{
				"schedule": e.Schedule,
				"run_as":   e.RunAs,
				"command":  Truncate(e.Command, 200),
			},
			TechniqueIDs: []string{"T1053", "T1053.003"},
			CheckIDs:     []string{m.ID},
		})

		var matched []model.Criterion
		add := func(id string) {
			for _, x := range matched {
				if x.ID == id {
					return
				}
			}
			matched = append(matched, byID[id])
		}

		if _, hit := TransientExecutable(e.Command); hit {
			add("CRON-C1")
		}
		for _, sig := range LinuxCommandSignals(e.Command) {
			switch sig {
			case "download-pipe-interpreter":
				add("CRON-C2")
			case "encoded-or-eval-execution":
				add("CRON-C3")
			case "interactive-shell-over-socket":
				add("CRON-C4")
			}
		}
		if strings.HasPrefix(e.Command, "PATH=") {
			val := strings.TrimPrefix(e.Command, "PATH=")
			for _, part := range strings.Split(val, ":") {
				if _, hit := InLinuxTransientDir(strings.TrimSpace(part) + "/"); hit {
					add("CRON-C5")
					break
				}
			}
		}

		if len(matched) == 0 {
			continue
		}
		level := model.SuspiciousIndicator
		if len(matched) >= 2 {
			level = model.Corroborated
		}

		findings = append(findings, check.NewFinding(env, m.ID, check.FindingSpec{
			ArtifactType: "cron_entry",
			ArtifactID:   artifactID,
			Level:        level,
			TechniqueIDs: []string{"T1053", "T1053.003"},
			Title: fmt.Sprintf("cron entry in %s matches %d persistence criteria",
				filepath.Base(e.Source), len(matched)),
			WhatAndWhere: fmt.Sprintf(
				"%s line %d schedules %q as %q with command: %s",
				e.Source, e.LineNo, e.Schedule, defaultStr(e.RunAs, "(file owner)"),
				Truncate(e.Command, 300)),
			Criteria: matched,
			Benign: []string{
				"Package maintenance scripts and monitoring agents populate cron heavily; " +
					"confirm whether a package owns this file.",
				"Backup jobs legitimately write to and read from temporary directories.",
				"Administrators sometimes base64-encode a command to avoid quoting problems.",
			},
			NextPivot: []string{
				"Establish file ownership and mtime of " + e.Source + " and whether a " +
					"package owns it (dpkg -S / rpm -qf).",
				"Inspect the target of the command: " + Truncate(FirstArg(e.Command), 120),
				"Correlate against cron's syslog entries for actual execution, noting that " +
					"syslog may not be enabled or retained.",
				"If the entry is in the per-user spool, identify the owning user and whether " +
					"that account should have scheduled jobs.",
			},
			Evidence: []model.EvidenceRef{check.LineEvidence(env, e.Source, e.LineNo, e.Line)},
			Context: map[string]string{
				"source_file": e.Source,
				"run_as":      e.RunAs,
			},
		}))
	}

	return check.Result(m.ID, started, env.Now, sources, findings, inventory)
}

func defaultStr(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func (c *cronCheck) Cases() []check.FixtureCase {
	dir := func(root, name string) string {
		return filepath.Join(root, "lnx-persist-cron-001", name)
	}
	return []check.FixtureCase{
		{
			Name: "@reboot curl|sh plus a base64-decoded /tmp payload",
			Kind: check.CasePositive,
			Why:  "Proves detection of the download-pipe and encoded-execution criteria.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "positive"), "linux")
			},
			WantOutcome:      model.Detected,
			MinFindings:      1,
			WantTechniqueIDs: []string{"T1053.003"},
		},
		{
			Name: "ordinary Debian cron layout (logrotate, man-db, apt, certbot)",
			Kind: check.CaseNegative,
			Why: "Proves the check tolerates the heavy, legitimate cron population every " +
				"Debian-family host carries, including a certbot job that uses curl.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "negative"), "linux")
			},
			WantOutcome: model.NotDetected,
		},
		{
			Name: "no cron installed",
			Kind: check.CaseNoData,
			Why:  "Proves absence of cron yields INSUFFICIENT_DATA rather than a clean bill.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "nodata"), "linux")
			},
			WantOutcome: model.InsufficientData,
		},
		{
			Name: "cron directories unreadable",
			Kind: check.CasePermissionDenied,
			Why:  "Proves an unreadable cron tree is reported, not silently treated as empty.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(dir(root, "positive"), "linux")
				if err != nil {
					return env, err
				}
				env.FS = &collect.ErrorFS{
					FileSystem: env.FS,
					DenyPrefix: []string{"/etc/crontab", "/etc/cron", "/var/spool/cron"},
				}
				return env, nil
			},
			WantOutcome: model.InsufficientData,
			AlsoAccept:  []model.Outcome{model.PermissionDenied, model.PartialData},
		},
	}
}
