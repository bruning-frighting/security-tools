package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"irscan/internal/check"
	"irscan/internal/collect"
	"irscan/internal/model"
)

func init() {
	check.Register(&histSuppressionCheck{}, &logSinkCheck{}, &hiddenArtifactCheck{})
}

// sinkTargets are the device paths that silently discard everything written to them.
// A log or history file symlinked to one of these is unambiguous: there is no legitimate
// reason for the system's own audit trail to be routed to /dev/null.
var sinkTargets = map[string]bool{
	"/dev/null": true, "/dev/zero": true, "/dev/full": true, "/dev/random": true,
	"/dev/urandom": true,
}

func isSinkTarget(p string) bool {
	return sinkTargets[strings.TrimSpace(strings.TrimRight(p, "/"))]
}

// linuxTempDirs are the world-writable staging directories.
var linuxTempDirs = []string{"/tmp", "/var/tmp", "/dev/shm", "/run/shm"}

// standardLogFiles are the log and accounting files a Linux host normally keeps.
var standardLogFiles = []string{
	"/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/messages",
	"/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog", "/var/log/faillog",
	"/var/log/audit/audit.log", "/var/log/kern.log", "/var/log/cron",
	"/var/log/daemon.log", "/var/log/dpkg.log", "/var/log/boot.log",
	"/var/log/sulog", "/var/log/maillog",
}

// shellHistoryFiles are the per-user history files, relative to a home directory.
var shellHistoryFiles = []string{
	".bash_history", ".zsh_history", ".sh_history", ".history", ".ksh_history",
	".python_history", ".mysql_history", ".psql_history", ".node_repl_history",
}

// =======================================================================================
// LNX-DEFIMP-HISTORY-001  (T1690, T1070.003)
// =======================================================================================

type histSuppressionCheck struct{}

// Patterns for shell-history suppression. Each is anchored to an assignment or a builtin so
// that a COMMENT mentioning HISTSIZE does not match -- the real Kali .bashrc contains the
// line "# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)", which a
// naive substring search would flag on every Debian-family host.
// RE2 (Go's regexp engine) has no backreferences, so quoting is matched by listing each
// quote style rather than by \N back-references to an earlier group.
var (
	histFileSinkPattern = regexp.MustCompile(
		`(?im)^\s*(export\s+)?HISTFILE\s*=\s*("(/dev/null|/dev/zero)?"|'(/dev/null|/dev/zero)?'|(/dev/null|/dev/zero)?)\s*(;|$)`)
	histSizeZeroPattern = regexp.MustCompile(
		`(?im)^\s*(export\s+)?HIST(FILE)?SIZE\s*=\s*("0+"|'0+'|0+)\s*(;|$)`)
	histDisablePattern = regexp.MustCompile(
		`(?im)^\s*(set\s+\+o\s+history|unset\s+HISTFILE\b|shopt\s+-u\s+hist\w+|` +
			`set\s+\+H)\s*(;|$)`)
)

func (c *histSuppressionCheck) Meta() check.Meta {
	return check.Meta{
		ID:      "LNX-DEFIMP-HISTORY-001",
		Title:   "Shell command history logging suppressed",
		OS:      []string{"linux"},
		Tactics: []string{"defense-impairment"},
		Techniques: []check.TechniqueMapping{
			{
				TechniqueID: "T1690",
				Justification: "This technique is Prevent Command History Logging. The " +
					"check reads shell initialisation files for the HISTFILE/HISTSIZE " +
					"assignments and history-disabling builtins that are precisely how it " +
					"is done, and detects history files redirected to a sink device.",
			},
			{
				TechniqueID: "T1070.003",
				Justification: "Clear Command History. A history file symlinked to " +
					"/dev/null is the persistent form of clearing it -- every future " +
					"command is discarded. Mapped Partial because this check does not " +
					"detect a history file that was simply deleted or truncated, which " +
					"needs a baseline (see Limitations).",
				Partial: true,
			},
			{
				TechniqueID: "T1070",
				Justification: "Parent technique (Indicator Removal) for the history-sink " +
					"artifact.",
			},
		},
		Sources: []check.SourceRequirement{
			{
				Name:      "shell initialisation files",
				Privilege: "/etc files are world-readable; other users' dotfiles need root",
				FailureModes: []string{
					"No shell initialisation file exists -> source unavailable -> " +
						"INSUFFICIENT_DATA.",
					"Other users' dotfiles unreadable unprivileged -> partial collection -> " +
						"PARTIAL_DATA, never NOT_DETECTED.",
				},
			},
			{
				Name:      "shell history files",
				Privilege: "a user's own history file; root for other users",
				Optional:  true,
				FailureModes: []string{
					"Absent history files are normal on a fresh account and are NOT a " +
						"finding.",
					"Unreadable history files -> partial collection -> PARTIAL_DATA.",
				},
			},
		},
		Criteria: []model.Criterion{
			{ID: "HIST-C1", Text: "A shell initialisation file assigns HISTFILE to " +
				"/dev/null, /dev/zero or the empty string, so no history is ever written."},
			{ID: "HIST-C2", Text: "A shell initialisation file sets HISTSIZE or " +
				"HISTFILESIZE to 0, which keeps no history."},
			{ID: "HIST-C3", Text: "A shell initialisation file disables history explicitly " +
				"(set +o history, set +H, unset HISTFILE, shopt -u hist*)."},
			{ID: "HIST-C4", Text: "A user's shell history file is a symbolic link to a sink " +
				"device (/dev/null and similar), so every command is discarded."},
		},
		EscalationCriteria: "Shell initialisation files are inventoried by " +
			"LNX-PERSIST-SHELLRC-001; this check reports only suppression. One criterion " +
			"gives suspicious_indicator. Corroborated requires a second independent " +
			"criterion -- for example HISTFILE=/dev/null in /etc/profile (HIST-C1) AND a " +
			"user's history file symlinked to /dev/null (HIST-C4), which together show both " +
			"a system-wide and a per-user suppression.",
		FalsePositiveHandling: "The dominant false positive here is textual, and it is " +
			"present on every Debian-family host: the stock ~/.bashrc contains the comment " +
			"'# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)' and " +
			"the lines HISTSIZE=1000 / HISTFILESIZE=2000. Therefore every pattern is " +
			"ANCHORED to a real assignment or builtin at the start of a line, so neither " +
			"the comment nor a non-zero size matches -- verified against the live host's " +
			"actual .bashrc. Additionally: (a) HISTCONTROL=ignoreboth and ignoredups are " +
			"privacy/convenience settings, not suppression, and are deliberately not " +
			"criteria; (b) an ABSENT history file is normal on a fresh or service account " +
			"and is not a finding; (c) a zero-BYTE history file is likewise not a finding, " +
			"because it is indistinguishable from an unused account without a baseline.",
		Overlay: check.Overlay{
			Behavior: "An adversary prevents their commands from being recorded, either by " +
				"editing a shell initialisation file so history is never kept, or by " +
				"replacing the history file with a link to /dev/null so writes are " +
				"discarded. Unlike deleting history after the fact, this leaves no gap for " +
				"an investigator to notice.",
			Artifacts: []string{
				"HISTFILE / HISTSIZE / HISTFILESIZE assignments in /etc/profile, " +
					"/etc/profile.d/*, /etc/bash.bashrc and per-user dotfiles",
				"set +o history, set +H, unset HISTFILE and shopt -u hist* in those files",
				"A per-user history file that is a symlink to /dev/null",
			},
			Logic: "Read the system-wide and per-user shell initialisation files and match " +
				"line-anchored patterns for history suppression. Separately, lstat each " +
				"user's history files and report any that are symlinks to a sink device. " +
				"Absent and empty history files are deliberately NOT reported.",
			FalsePositives: []string{
				"The stock Debian/Ubuntu .bashrc mentions HISTSIZE in a comment and sets " +
					"non-zero values; neither is suppression.",
				"Security-conscious users sometimes disable history for shells used to type " +
					"secrets.",
				"Some hardened images legitimately set a small HISTSIZE.",
				"Automation and service accounts often have no history at all.",
			},
			Limitations: []string{
				"A history file that was DELETED or TRUNCATED is not detected. Without a " +
					"baseline, an empty history is indistinguishable from an unused " +
					"account; reporting it would be noise. That gap is real and is why the " +
					"T1070.003 mapping is marked Partial.",
				"Suppression applied interactively (typing `unset HISTFILE` in a live " +
					"shell) leaves nothing on disk and is invisible.",
				"Only the common initialisation files are read; a suppression line in a " +
					"file sourced several levels deep is not followed.",
				"An unprivileged scan cannot read other users' dotfiles or history files.",
				"Root can edit these files after the fact, so what is seen may be tampered " +
					"with.",
			},
			References: []check.Reference{
				{Title: "MITRE ATT&CK T1690 Prevent Command History Logging",
					URL: "https://attack.mitre.org/techniques/T1690"},
				{Title: "MITRE ATT&CK T1070.003 Clear Command History",
					URL: "https://attack.mitre.org/techniques/T1070/003"},
				{Title: "bash(1) -- HISTFILE, HISTSIZE, HISTFILESIZE",
					URL: "https://www.gnu.org/software/bash/manual/bash.html#Bash-History-Facilities"},
			},
		},
		Validation: model.LabVerified,
		LabEvidence: "Executed 2026-10-14 against the LIVE root filesystem of WSL2 Kali " +
			"GNU/Linux Rolling 2026.1 (kernel 6.6.87.2-microsoft-standard-WSL2), " +
			"unprivileged as uid 1000. The host's real ~/.bashrc contains both the " +
			"HISTSIZE comment and HISTSIZE=1000 / HISTFILESIZE=2000; the anchored patterns " +
			"correctly produced no finding. See STATUS.md Phase 2b.",
		FixtureProvenance: model.Synthetic,
	}
}

func (c *histSuppressionCheck) Run(ctx context.Context, env check.Env) model.CheckResult {
	started := env.Now()
	m := c.Meta()

	initSrc := collect.SourceResult{
		Name: m.Sources[0].Name, Privilege: m.Sources[0].Privilege,
	}
	histSrc := collect.SourceResult{
		Name: m.Sources[1].Name, Privilege: m.Sources[1].Privilege,
	}

	users, uRes := collect.Users(env.FS)
	if !uRes.Available {
		initSrc.Errors = append(initSrc.Errors,
			"could not enumerate users for per-user dotfiles: "+uRes.Reason)
	}

	// Build the init-file candidate list: system-wide plus per-user.
	var candidates []string
	sysFiles := []string{
		"/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/etc/zsh/zshrc",
		"/etc/zsh/zshenv", "/etc/csh.cshrc",
	}
	for _, f := range sysFiles {
		if env.FS.Exists(f) {
			candidates = append(candidates, f)
		}
	}
	if env.FS.Exists("/etc/profile.d") {
		if entries, err := env.FS.ReadDir("/etc/profile.d"); err == nil {
			for _, e := range entries {
				if !e.IsDir {
					candidates = append(candidates, "/etc/profile.d/"+e.Name)
				}
			}
		} else {
			reportSrcErr(&initSrc, err, "listing /etc/profile.d")
		}
	}
	userDotfiles := []string{".bashrc", ".bash_profile", ".profile", ".zshrc", ".zshenv"}
	for _, u := range users {
		if u.HomeDir == "" {
			continue
		}
		for _, name := range userDotfiles {
			p := strings.TrimRight(u.HomeDir, "/") + "/" + name
			if _, err := env.FS.Stat(p); err != nil {
				if isPermErr(err) {
					initSrc.Errors = append(initSrc.Errors, fmt.Sprintf(
						"permission denied checking %s for user %q", p, u.Name))
				}
				continue
			}
			candidates = append(candidates, p)
		}
	}

	if len(candidates) == 0 {
		initSrc.Available = false
		initSrc.Reason = "no shell initialisation file exists on this host"
		histSrc.Available = false
		histSrc.Reason = "not examined: no shell initialisation file was found"
		return check.Result(m.ID, started, env.Now, []model.DataSourceStatus{
			check.SourceStatus(m.Sources[0], initSrc),
			check.SourceStatus(m.Sources[1], histSrc),
		}, nil, nil)
	}
	initSrc.Available = true

	byID := map[string]model.Criterion{}
	for _, cr := range m.Criteria {
		byID[cr.ID] = cr
	}

	var findings []model.Finding
	var inventory []model.InventoryItem

	// ---- init-file suppression --------------------------------------------------------
	for _, path := range candidates {
		if err := ctx.Err(); err != nil {
			return check.ErrorResult(m.ID, started, env.Now, err)
		}
		data, truncated, err := env.FS.ReadFile(path)
		if err != nil {
			reportSrcErr(&initSrc, err, "reading "+path)
			continue
		}
		if truncated {
			initSrc.Truncated = true
		}
		initSrc.ItemsSeen++
		content := string(data)

		var matched []model.Criterion
		var lines []string
		add := func(id string, re *regexp.Regexp) {
			if !re.MatchString(content) {
				return
			}
			for _, x := range matched {
				if x.ID == id {
					return
				}
			}
			matched = append(matched, byID[id])
			for _, mm := range re.FindAllString(content, 3) {
				lines = append(lines, strings.TrimSpace(mm))
			}
		}
		add("HIST-C1", histFileSinkPattern)
		add("HIST-C2", histSizeZeroPattern)
		add("HIST-C3", histDisablePattern)

		if len(matched) == 0 {
			continue
		}
		level := model.SuspiciousIndicator
		if len(matched) >= 2 {
			level = model.Corroborated
		}
		ev, err := check.FileEvidence(env, path, "script_file")
		if err != nil {
			reportSrcErr(&initSrc, err, "evidence for "+path)
			continue
		}
		findings = append(findings, check.NewFinding(env, m.ID, check.FindingSpec{
			ArtifactType: "shell_history_suppression",
			ArtifactID:   path,
			Level:        level,
			TechniqueIDs: []string{"T1690"},
			Title: fmt.Sprintf("shell history suppressed in %s (%d criteria)",
				baseNameOf(path), len(matched)),
			WhatAndWhere: fmt.Sprintf(
				"%s suppresses command history. Matching lines: %s",
				path, Truncate(strings.Join(lines, " | "), 300)),
			Criteria: matched,
			Benign: []string{
				"A security-conscious user may disable history for a shell used to type " +
					"secrets.",
				"Some hardened or appliance images legitimately restrict history.",
				"An administrator may have disabled history to avoid recording credentials " +
					"passed on a command line.",
			},
			NextPivot: []string{
				"Establish the mtime and owner of " + path + " and whether a package owns it.",
				"Compare the file against a known-good peer host built from the same image.",
				"If this is a per-user dotfile, correlate the account against " +
					"authentication logs for the period after the change.",
				"Treat the affected account's command history as unavailable for the whole " +
					"period the setting has been in place.",
			},
			Evidence: []model.EvidenceRef{ev},
			Context: map[string]string{
				"scope": map[bool]string{true: "system-wide", false: "per-user"}[
					strings.HasPrefix(path, "/etc/")],
			},
		}))
	}

	// ---- history files symlinked to a sink --------------------------------------------
	anyHistChecked := false
	for _, u := range users {
		if u.HomeDir == "" {
			continue
		}
		for _, name := range shellHistoryFiles {
			p := strings.TrimRight(u.HomeDir, "/") + "/" + name
			fi, err := env.FS.Stat(p)
			if err != nil {
				if isPermErr(err) {
					histSrc.Errors = append(histSrc.Errors, fmt.Sprintf(
						"permission denied checking %s", p))
				}
				continue
			}
			anyHistChecked = true
			histSrc.ItemsSeen++

			inventory = append(inventory, model.InventoryItem{
				Group:        "shell history files",
				ArtifactType: "shell_history_file",
				ArtifactID:   p,
				Attributes: map[string]string{
					"user":        u.Name,
					"size":        strconv.FormatInt(fi.Size, 10),
					"symlink":     fmt.Sprintf("%t", fi.IsSymlink),
					"link_target": fi.LinkTarget,
					"mode":        fi.ModeString,
					"note": "A zero-size or absent history file is NOT reported as a " +
						"finding: without a baseline it is indistinguishable from an " +
						"unused account.",
				},
				TechniqueIDs: []string{"T1690", "T1070", "T1070.003"},
				CheckIDs:     []string{m.ID},
			})

			if !fi.IsSymlink || !isSinkTarget(fi.LinkTarget) {
				continue
			}
			detail := fmt.Sprintf("%s is a symlink to %s", p, fi.LinkTarget)
			findings = append(findings, check.NewFinding(env, m.ID, check.FindingSpec{
				ArtifactType: "shell_history_file",
				ArtifactID:   p,
				Level:        model.SuspiciousIndicator,
				TechniqueIDs: []string{"T1690", "T1070", "T1070.003"},
				Title: fmt.Sprintf("history file for %q redirected to %s",
					u.Name, fi.LinkTarget),
				WhatAndWhere: detail + ". Every command written to this history file is " +
					"discarded, permanently and silently.",
				Criteria: []model.Criterion{byID["HIST-C4"]},
				Benign: []string{
					"A user may have deliberately linked their history to /dev/null for " +
						"privacy.",
					"Some container images ship this configuration to keep layers clean.",
				},
				NextPivot: []string{
					"Establish when the symlink was created (its own mtime) and by whom.",
					"Check whether other accounts on the host have the same configuration " +
						"-- one account differing from the rest is the interesting case.",
					"Treat this account's command history as unavailable for the whole " +
						"period the link has existed.",
				},
				Evidence: []model.EvidenceRef{{
					ID:        "ev-hist-" + collect.SHA256Hex([]byte(p))[:12],
					Kind:      "symlink",
					Source:    p,
					SHA256:    collect.SHA256Hex([]byte(detail)),
					HashScope: "full_object",
					Excerpt:   detail,
					SizeBytes: int64(len(detail)),
					ModTime:   fi.ModTime,
				}},
				Context: map[string]string{"user": u.Name, "link_target": fi.LinkTarget},
			}))
		}
	}
	histSrc.Available = true
	if !anyHistChecked {
		histSrc.Reason = "no shell history file was found for any enumerated account, " +
			"which is normal on a host with only service accounts"
	}

	return check.Result(m.ID, started, env.Now, []model.DataSourceStatus{
		check.SourceStatus(m.Sources[0], initSrc),
		check.SourceStatus(m.Sources[1], histSrc),
	}, findings, inventory)
}

func (c *histSuppressionCheck) Cases() []check.FixtureCase {
	dir := func(root, name string) string {
		return filepath.Join(root, "lnx-defimp-history-001", name)
	}
	return []check.FixtureCase{
		{
			Name: "HISTFILE=/dev/null in /etc/profile.d plus HISTSIZE=0",
			Kind: check.CasePositive,
			Why:  "Two independent suppression criteria must fire and escalate.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "positive"), "linux")
			},
			WantOutcome:      model.Detected,
			MinFindings:      1,
			WantTechniqueIDs: []string{"T1690"},
		},
		{
			Name: "the real stock Debian .bashrc (HISTSIZE comment and non-zero sizes)",
			Kind: check.CaseNegative,
			Why: "The decisive negative: the live host's own .bashrc contains both the " +
				"'see HISTSIZE and HISTFILESIZE' comment and HISTSIZE=1000. An unanchored " +
				"pattern flags every Debian-family machine; the anchored patterns must not.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "negative"), "linux")
			},
			WantOutcome: model.NotDetected,
		},
		{
			Name: "no shell initialisation files",
			Kind: check.CaseNoData,
			Why:  "Nothing to examine: INSUFFICIENT_DATA.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "nodata"), "linux")
			},
			WantOutcome: model.InsufficientData,
		},
		{
			Name: "initialisation files unreadable",
			Kind: check.CasePermissionDenied,
			Why:  "Unreadable init files must not read as 'history logging is intact'.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(dir(root, "positive"), "linux")
				if err != nil {
					return env, err
				}
				env.FS = &collect.ErrorFS{
					FileSystem: env.FS,
					DenyPrefix: []string{"/etc/profile", "/etc/bash", "/home", "/root"},
				}
				return env, nil
			},
			WantOutcome: model.PartialData,
			AlsoAccept: []model.Outcome{
				model.InsufficientData, model.PermissionDenied, model.Detected,
			},
		},
	}
}
