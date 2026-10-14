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

// =======================================================================================
// LNX-STEALTH-LOGSINK-001  (T1685.006, T1070)
// =======================================================================================

type logSinkCheck struct{}

func (c *logSinkCheck) Meta() check.Meta {
	return check.Meta{
		ID:      "LNX-STEALTH-LOGSINK-001",
		Title:   "System log redirected to a sink or replaced",
		OS:      []string{"linux"},
		Tactics: []string{"defense-impairment", "stealth"},
		Techniques: []check.TechniqueMapping{
			{
				TechniqueID: "T1685.006",
				Justification: "Clear Linux or Mac System Logs. A log file symlinked to " +
					"/dev/null, or replaced by a FIFO or directory, is the persistent form " +
					"of clearing it: every future record is discarded. The check lstats the " +
					"standard log paths, which are exactly those artifacts.",
			},
			{
				TechniqueID: "T1685",
				Justification: "Parent technique (Disable or Modify Tools): routing the " +
					"system's own audit trail to a sink disables the logging subsystem " +
					"without stopping it.",
			},
			{
				TechniqueID: "T1070",
				Justification: "Indicator Removal. Mapped Partial because this check " +
					"detects only the PERSISTENT redirection form. It deliberately does " +
					"NOT report deleted or truncated logs -- see Limitations, and the " +
					"false-positive handling, for why that needs a baseline.",
				Partial: true,
			},
		},
		Sources: []check.SourceRequirement{{
			Name:      "standard system log paths",
			Privilege: "/var/log is traversable by standard users; individual logs are often root-only",
			FailureModes: []string{
				"/var/log absent entirely -> source unavailable -> INSUFFICIENT_DATA.",
				"Individual logs unreadable unprivileged -> partial collection -> " +
					"PARTIAL_DATA. Note the check only needs to LSTAT these paths, not read " +
					"them, so it works better unprivileged than a content-based check would.",
				"A log on a network filesystem is skipped by default.",
			},
		}},
		Criteria: []model.Criterion{
			{ID: "LOG-C1", Text: "A standard system log file is a symbolic link to a sink " +
				"device (/dev/null, /dev/zero and similar), so every record written to it " +
				"is discarded."},
			{ID: "LOG-C2", Text: "/var/log itself, or a standard log subdirectory, is a " +
				"symbolic link, which can redirect the whole logging tree somewhere an " +
				"investigator will not look."},
			{ID: "LOG-C3", Text: "A standard log path exists but is a FIFO, socket or " +
				"directory where a regular file is expected, which silently breaks logging " +
				"while leaving the path present."},
		},
		EscalationCriteria: "One criterion gives suspicious_indicator. Corroborated " +
			"requires a second independent criterion -- for example both an auth log " +
			"symlinked to /dev/null (LOG-C1) and /var/log/audit replaced by a symlink " +
			"(LOG-C2). All three criteria are deliberately unambiguous artifacts, so a " +
			"single match is already a strong signal.",
		FalsePositiveHandling: "Log clearing is explicitly named as a known-noisy area, and " +
			"the noise comes almost entirely from EMPTY logs. Verified on a live host: " +
			"/var/log/btmp, /var/log/btmp.1, /var/log/lastlog, /var/log/bootstrap.log and " +
			"/var/log/alternatives.log are all ZERO BYTES on a clean WSL2 Kali install, and " +
			"/var/log/alternatives.log is zero while its rotated sibling " +
			"alternatives.log.1 is populated. A zero-size or 'zero-with-populated-rotation' " +
			"criterion would therefore have produced five to six findings on a clean " +
			"machine. Those shapes are consequently NOT criteria at all: they are recorded " +
			"in INVENTORY with an explicit note that size is not evidence without a " +
			"baseline. Only the three unambiguous criteria above produce findings. " +
			"Additionally, /var/log/README is a legitimate symlink on systemd hosts and " +
			"does not match, because LOG-C1 requires the target to be a sink DEVICE.",
		Overlay: check.Overlay{
			Behavior: "An adversary stops the host recording their activity by pointing a " +
				"log file at /dev/null, replacing it with a FIFO, or redirecting the whole " +
				"/var/log tree. This is more durable than deleting logs: it suppresses all " +
				"future records too, and the path still exists so a casual check passes.",
			Artifacts: []string{
				"The standard log and accounting files under /var/log (auth.log, secure, " +
					"syslog, messages, wtmp, btmp, lastlog, audit/audit.log and others)",
				"The /var/log directory itself and its standard subdirectories",
				"The file TYPE at each path (regular file vs symlink vs FIFO vs directory)",
			},
			Logic: "Lstat each standard log path -- lstat, not stat, so a symlink is seen as " +
				"a symlink rather than followed. Report a link to a sink device, a " +
				"redirected log directory, or a wrong file type. Record size and type for " +
				"every log in Inventory as context, explicitly labelled as not evidence.",
			FalsePositives: []string{
				"btmp, lastlog and bootstrap.log are legitimately zero bytes on a clean or " +
					"freshly imaged host -- which is why size is not a criterion.",
				"/var/log/README is a real symlink on systemd hosts, to documentation.",
				"Container images frequently ship with empty or absent logs by design.",
				"Minimal images legitimately omit many of the standard log files.",
			},
			Limitations: []string{
				"DELETED and TRUNCATED logs are NOT detected. On a single point-in-time scan " +
					"with no baseline, an empty log is indistinguishable from a quiet host, " +
					"and reporting it produced five false positives on a clean machine " +
					"during development. Detecting truncation needs either a baseline or " +
					"remote log comparison; that is PLANNED, not implemented.",
				"The check reads file metadata only, never log CONTENT, so it cannot detect " +
					"selective line removal -- which is the most common real-world form of " +
					"log tampering and the hardest to see.",
				"journald's binary journals under /var/log/journal are not parsed; a " +
					"vacuumed or rotated journal is not detected.",
				"Remote syslog forwarding means the authoritative copy may be off-host " +
					"entirely; an off-host comparison would be far stronger than anything " +
					"this check can do and should be preferred where available.",
				"An adversary with root can restore a log file's type and target after use.",
			},
			References: []check.Reference{
				{Title: "MITRE ATT&CK T1685.006 Clear Linux or Mac System Logs",
					URL: "https://attack.mitre.org/techniques/T1685/006"},
				{Title: "MITRE ATT&CK T1070 Indicator Removal",
					URL: "https://attack.mitre.org/techniques/T1070"},
			},
		},
		Validation: model.LabVerified,
		LabEvidence: "Executed 2026-10-14 against the LIVE root filesystem of WSL2 Kali " +
			"GNU/Linux Rolling 2026.1 (kernel 6.6.87.2-microsoft-standard-WSL2), " +
			"unprivileged as uid 1000. The host has five legitimately zero-byte logs and a " +
			"real /var/log/README symlink; the check correctly produced no finding and " +
			"recorded them as Inventory context. See STATUS.md Phase 2b.",
		FixtureProvenance: model.Synthetic,
	}
}

func (c *logSinkCheck) Run(ctx context.Context, env check.Env) model.CheckResult {
	started := env.Now()
	m := c.Meta()
	src := collect.SourceResult{Name: m.Sources[0].Name, Privilege: m.Sources[0].Privilege}

	if !env.FS.Exists("/var/log") {
		src.Available = false
		src.Reason = "/var/log does not exist on this host, so no system log state could " +
			"be assessed"
		return check.Result(m.ID, started, env.Now,
			[]model.DataSourceStatus{check.SourceStatus(m.Sources[0], src)}, nil, nil)
	}
	src.Available = true

	byID := map[string]model.Criterion{}
	for _, cr := range m.Criteria {
		byID[cr.ID] = cr
	}

	var findings []model.Finding
	var inventory []model.InventoryItem

	emit := func(path, critID, title, what string, fi collect.FileInfo) {
		detail := fmt.Sprintf("%s: mode=%s symlink=%t target=%q size=%d",
			path, fi.ModeString, fi.IsSymlink, fi.LinkTarget, fi.Size)
		findings = append(findings, check.NewFinding(env, m.ID, check.FindingSpec{
			ArtifactType: "system_log_path",
			ArtifactID:   path,
			Level:        model.SuspiciousIndicator,
			TechniqueIDs: []string{"T1685", "T1685.006"},
			Title:        title,
			WhatAndWhere: what,
			Criteria:     []model.Criterion{byID[critID]},
			Benign: []string{
				"Container and minimal images sometimes ship unusual log layouts by design.",
				"An administrator may have relocated logging to a dedicated volume, though " +
					"a symlink to a sink device is never a legitimate way to do that.",
				"Some appliances deliberately discard local logs because they forward " +
					"everything to a remote collector.",
			},
			NextPivot: []string{
				"Establish when the link or type change was made (the entry's own mtime).",
				"Compare the logging layout against a known-good peer host built from the " +
					"same image.",
				"Retrieve the authoritative copy from the remote log collector if one " +
					"exists -- off-host logs are not subject to this tampering.",
				"Treat the affected log as unavailable for the whole period the " +
					"redirection has been in place, and re-read every other check's " +
					"NOT_DETECTED result in that light.",
			},
			Evidence: []model.EvidenceRef{{
				ID:        "ev-log-" + collect.SHA256Hex([]byte(path))[:12],
				Kind:      "file_metadata",
				Source:    path,
				SHA256:    collect.SHA256Hex([]byte(detail)),
				HashScope: "full_object",
				Excerpt:   detail,
				SizeBytes: int64(len(detail)),
				ModTime:   fi.ModTime,
			}},
			Context: map[string]string{
				"link_target": fi.LinkTarget,
				"mode":        fi.ModeString,
			},
		}))
	}

	// LOG-C2: the log tree itself redirected.
	for _, dir := range []string{"/var/log", "/var/log/audit", "/var/log/journal"} {
		fi, err := env.FS.Stat(dir)
		if err != nil {
			if isPermErr(err) {
				src.Errors = append(src.Errors, "permission denied on "+dir)
			}
			continue
		}
		src.ItemsSeen++
		if fi.IsSymlink {
			emit(dir, "LOG-C2",
				fmt.Sprintf("log directory %s is a symlink to %s", dir, fi.LinkTarget),
				fmt.Sprintf("%s is a symbolic link to %q rather than a directory. The "+
					"whole logging tree beneath it may be redirected.", dir, fi.LinkTarget),
				fi)
		}
	}

	// LOG-C1 and LOG-C3: per-file state.
	for _, path := range standardLogFiles {
		if err := ctx.Err(); err != nil {
			return check.ErrorResult(m.ID, started, env.Now, err)
		}
		fi, err := env.FS.Stat(path)
		if err != nil {
			if isPermErr(err) {
				src.Errors = append(src.Errors, "permission denied on "+path)
			}
			// Absent standard logs are entirely normal on minimal images; not a gap.
			continue
		}
		src.ItemsSeen++

		// Inventory carries size and type as CONTEXT. Size is deliberately not a criterion:
		// five logs are legitimately zero bytes on a clean host.
		inventory = append(inventory, model.InventoryItem{
			Group:        "system log paths",
			ArtifactType: "system_log_path",
			ArtifactID:   path,
			Attributes: map[string]string{
				"size":        strconv.FormatInt(fi.Size, 10),
				"zero_bytes":  fmt.Sprintf("%t", fi.Size == 0),
				"mode":        fi.ModeString,
				"symlink":     fmt.Sprintf("%t", fi.IsSymlink),
				"link_target": fi.LinkTarget,
				"note": "Size is CONTEXT, not evidence. btmp, lastlog and bootstrap.log " +
					"are legitimately zero bytes on a clean host; detecting truncation " +
					"requires a baseline this tool does not have.",
			},
			TechniqueIDs: []string{"T1685", "T1685.006", "T1070"},
			CheckIDs:     []string{m.ID},
		})

		switch {
		case fi.IsSymlink && isSinkTarget(fi.LinkTarget):
			emit(path, "LOG-C1",
				fmt.Sprintf("system log %s is redirected to %s",
					baseNameOf(path), fi.LinkTarget),
				fmt.Sprintf("%s is a symbolic link to the sink device %q. Every record "+
					"written to this log is discarded, permanently and silently.",
					path, fi.LinkTarget),
				fi)
		case !fi.IsDir && fi.ModeString != "" &&
			(strings.HasPrefix(fi.ModeString, "p") || strings.HasPrefix(fi.ModeString, "S")):
			emit(path, "LOG-C3",
				fmt.Sprintf("system log %s has been replaced by a %s",
					baseNameOf(path), fifoOrSocket(fi.ModeString)),
				fmt.Sprintf("%s exists but is a %s, not a regular file. Logging to this "+
					"path is silently broken while the path still appears present.",
					path, fifoOrSocket(fi.ModeString)),
				fi)
		case fi.IsDir:
			emit(path, "LOG-C3",
				fmt.Sprintf("system log %s has been replaced by a directory",
					baseNameOf(path)),
				fmt.Sprintf("%s exists but is a directory, not a regular file. Logging to "+
					"this path is silently broken.", path),
				fi)
		}
	}

	return check.Result(m.ID, started, env.Now,
		[]model.DataSourceStatus{check.SourceStatus(m.Sources[0], src)}, findings, inventory)
}

func fifoOrSocket(mode string) string {
	if strings.HasPrefix(mode, "p") {
		return "named pipe (FIFO)"
	}
	return "socket"
}

func (c *logSinkCheck) Cases() []check.FixtureCase {
	dir := func(root, name string) string {
		return filepath.Join(root, "lnx-stealth-logsink-001", name)
	}
	return []check.FixtureCase{
		{
			Name: "auth.log symlinked to /dev/null and /var/log/audit redirected",
			Kind: check.CasePositive,
			Why:  "Two independent criteria (LOG-C1 and LOG-C2) must fire.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "positive"), "linux")
			},
			WantOutcome:      model.Detected,
			MinFindings:      2,
			WantTechniqueIDs: []string{"T1685.006"},
		},
		{
			Name: "clean host with five legitimately zero-byte logs and a real README symlink",
			Kind: check.CaseNegative,
			Why: "Reproduces the live host exactly: btmp, btmp.1, lastlog, bootstrap.log " +
				"and alternatives.log are zero bytes, alternatives.log.1 is populated, and " +
				"/var/log/README is a genuine symlink to documentation. A size-based or " +
				"naive symlink criterion produces five or six findings here; this check " +
				"must produce none.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "negative"), "linux")
			},
			WantOutcome: model.NotDetected,
		},
		{
			Name: "no /var/log",
			Kind: check.CaseNoData,
			Why:  "Nothing to assess: INSUFFICIENT_DATA.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "nodata"), "linux")
			},
			WantOutcome: model.InsufficientData,
		},
		{
			Name: "/var/log unreadable",
			Kind: check.CasePermissionDenied,
			Why:  "An unreadable log tree must not read as an intact one.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(dir(root, "positive"), "linux")
				if err != nil {
					return env, err
				}
				env.FS = &collect.ErrorFS{
					FileSystem:    env.FS,
					MissingPrefix: []string{"/var/log"},
				}
				return env, nil
			},
			WantOutcome: model.InsufficientData,
			AlsoAccept:  []model.Outcome{model.PermissionDenied, model.PartialData},
		},
	}
}

// =======================================================================================
// LNX-STEALTH-HIDDEN-001  (T1564.001, T1564)
// =======================================================================================

type hiddenArtifactCheck struct{}

// dotsOrSpacePattern matches a name made only of three-or-more dots, or only whitespace.
// Such names are near-invisible in a terminal listing and have no legitimate use.
var dotsOrSpacePattern = regexp.MustCompile(`^(\.{3,}|\s+|\.\s+|\s+\.)$`)

func (c *hiddenArtifactCheck) Meta() check.Meta {
	return check.Meta{
		ID:      "LNX-STEALTH-HIDDEN-001",
		Title:   "Hidden executable or deceptively named artifact",
		OS:      []string{"linux"},
		Tactics: []string{"stealth"},
		Techniques: []check.TechniqueMapping{
			{
				TechniqueID: "T1564.001",
				Justification: "Hidden Files and Directories. The check enumerates " +
					"dot-prefixed entries in the world-writable staging directories and at " +
					"the filesystem root, which is exactly where this sub-technique's " +
					"artifact appears on Linux.",
			},
			{
				TechniqueID: "T1564",
				Justification: "Parent technique (Hide Artifacts).",
			},
		},
		Sources: []check.SourceRequirement{{
			Name:      "world-writable staging directories and the filesystem root",
			Privilege: "/tmp, /var/tmp and /dev/shm are world-readable and traversable",
			FailureModes: []string{
				"None of the staging directories exist -> source unavailable -> " +
					"INSUFFICIENT_DATA.",
				"A directory is unreadable -> partial collection -> PARTIAL_DATA.",
				"The file-count safety limit stops the walk -> truncated -> PARTIAL_DATA, " +
					"because a truncated walk cannot justify NOT_DETECTED.",
				"Another user's private subdirectory under /tmp is unreadable " +
					"unprivileged; recorded as partial.",
			},
		}},
		Criteria: []model.Criterion{
			{ID: "HID-C1", Text: "A hidden (dot-prefixed) file in a world-writable staging " +
				"directory has an execute bit set. Hidden DATA files are common there; a " +
				"hidden EXECUTABLE is not."},
			{ID: "HID-C2", Text: "A hidden directory exists directly under the filesystem " +
				"root (/), where no standard distribution places one."},
			{ID: "HID-C3", Text: "An entry's name consists only of three or more dots, or " +
				"only whitespace, making it effectively invisible in a terminal listing."},
			{ID: "HID-C4", Text: "A hidden directory in a staging directory contains an " +
				"executable file."},
		},
		EscalationCriteria: "One criterion gives suspicious_indicator. Corroborated " +
			"requires a second independent criterion -- for example a hidden executable " +
			"(HID-C1) inside a hidden directory whose name is all dots (HID-C3). Hidden " +
			"non-executable files are NOT reported at all, not even as observed artifacts " +
			"in Findings; they go to Inventory only.",
		FalsePositiveHandling: "This is the check where a naive design fails hardest, and " +
			"it was measured: on a clean WSL2 Kali host /tmp contains 150 dot-prefixed " +
			"files (large non-executable ELF shared objects from a runtime cache, named " +
			"like .5bf7ffef699777db-00000000.so). A 'hidden file in /tmp' criterion would " +
			"therefore produce 150 findings on a pristine machine. The criterion is " +
			"consequently narrowed to hidden files that are EXECUTABLE, which measured ZERO " +
			"on that same host. Additionally: (a) the well-known X11/ICE/font socket " +
			"directories (.X11-unix and friends) are excluded by name, since every " +
			"graphical host has them; (b) hidden non-executable files go to Inventory only; " +
			"(c) hidden files in HOME directories are not examined at all -- dotfiles are " +
			"the normal case there and scanning them would be pure noise.",
		Overlay: check.Overlay{
			Behavior: "An adversary hides tooling and output by prefixing names with a dot " +
				"so they do not appear in a default listing, or by using a name made of " +
				"dots or spaces that is almost impossible to notice or to type. Staging " +
				"directories are preferred because they are world-writable.",
			Artifacts: []string{
				"Dot-prefixed files and directories in /tmp, /var/tmp, /dev/shm, /run/shm",
				"Dot-prefixed directories directly under /",
				"Entries named '...', '....' or consisting only of whitespace",
				"The execute bit on such files",
			},
			Logic: "Walk the staging directories to a bounded depth and list the filesystem " +
				"root. Report hidden entries only when they are executable, are a hidden " +
				"directory at /, have an all-dots or all-whitespace name, or are a hidden " +
				"directory containing an executable. Everything else hidden is inventoried " +
				"without being reported.",
			FalsePositives: []string{
				"Runtime and JIT caches write large numbers of hidden non-executable files " +
					"to /tmp -- measured at 150 on a clean host.",
				"X11, ICE and font socket directories (.X11-unix, .ICE-unix, .font-unix) " +
					"exist on every graphical host.",
				"Build tools and test harnesses create hidden scratch files in /tmp.",
				"Some package build processes leave hidden executables in /var/tmp " +
					"legitimately.",
			},
			Limitations: []string{
				"Home directories are deliberately not scanned: dotfiles are the norm there " +
					"and the signal-to-noise ratio would be hopeless. A payload hidden in a " +
					"home directory is therefore not found by this check.",
				"On Linux 'hidden' is only a naming convention, so an adversary who does " +
					"not prefix with a dot is entirely invisible to this check -- it finds " +
					"a specific concealment technique, not concealed files in general.",
				"The walk is depth- and count-bounded by the safety limits; a deeply nested " +
					"artifact may be missed, and truncation forces PARTIAL_DATA.",
				"Extended attributes, bind mounts and hidden filesystems (T1564.013, " +
					"T1564.014, T1564.005) are NOT covered and remain PLANNED.",
				"A file deleted before the scan leaves nothing.",
			},
			References: []check.Reference{
				{Title: "MITRE ATT&CK T1564.001 Hidden Files and Directories",
					URL: "https://attack.mitre.org/techniques/T1564/001"},
				{Title: "MITRE ATT&CK T1564 Hide Artifacts",
					URL: "https://attack.mitre.org/techniques/T1564"},
			},
		},
		Validation: model.LabVerified,
		LabEvidence: "Executed 2026-10-14 against the LIVE root filesystem of WSL2 Kali " +
			"GNU/Linux Rolling 2026.1 (kernel 6.6.87.2-microsoft-standard-WSL2), " +
			"unprivileged as uid 1000. That host carries 150 hidden non-executable files " +
			"in /tmp; the narrowed criteria produced no finding, which is the measurement " +
			"the design rests on. See STATUS.md Phase 2b.",
		FixtureProvenance: model.Synthetic,
	}
}

// wellKnownHiddenTempDirs exist on essentially every host with a display server.
var wellKnownHiddenTempDirs = map[string]bool{
	".X11-unix": true, ".ICE-unix": true, ".font-unix": true, ".Test-unix": true,
	".XIM-unix": true, ".X11-lock": true,
}

func (c *hiddenArtifactCheck) Run(ctx context.Context, env check.Env) model.CheckResult {
	started := env.Now()
	m := c.Meta()
	src := collect.SourceResult{Name: m.Sources[0].Name, Privilege: m.Sources[0].Privilege}

	anyDir := false
	byID := map[string]model.Criterion{}
	for _, cr := range m.Criteria {
		byID[cr.ID] = cr
	}

	type hit struct {
		info     collect.FileInfo
		criteria []model.Criterion
	}
	var hits []hit
	var inventory []model.InventoryItem
	hiddenInventoried := 0

	addHit := func(fi collect.FileInfo, ids ...string) {
		var crits []model.Criterion
		for _, id := range ids {
			crits = append(crits, byID[id])
		}
		hits = append(hits, hit{info: fi, criteria: crits})
	}

	// Hidden directories containing an executable (HID-C4) need a second pass, so record
	// the hidden directories found during the walk.
	hiddenDirs := map[string]collect.FileInfo{}
	execInDir := map[string]string{}

	for _, dir := range linuxTempDirs {
		if !env.FS.Exists(dir) {
			continue
		}
		anyDir = true
		err := env.FS.Walk(dir, 3, func(fi collect.FileInfo) error {
			name := fi.Name
			if !strings.HasPrefix(name, ".") && !dotsOrSpacePattern.MatchString(name) {
				// Not hidden by name; still note executables inside hidden directories.
				if !fi.IsDir && fi.Mode&0o111 != 0 {
					execInDir[filepath.ToSlash(filepath.Dir(fi.Path))] = fi.Path
				}
				return nil
			}
			if wellKnownHiddenTempDirs[name] {
				return nil
			}
			src.ItemsSeen++
			hiddenInventoried++

			if fi.IsDir {
				hiddenDirs[filepath.ToSlash(fi.Path)] = fi
			}

			var ids []string
			if dotsOrSpacePattern.MatchString(name) {
				ids = append(ids, "HID-C3")
			}
			// THE narrowing that makes this check usable: executable, not merely hidden.
			if !fi.IsDir && fi.Mode&0o111 != 0 {
				ids = append(ids, "HID-C1")
			}
			if len(ids) > 0 {
				addHit(fi, ids...)
			}
			return nil
		})
		if err != nil {
			reportSrcErr(&src, err, "walking "+dir)
		}
	}

	// HID-C4: a hidden directory containing an executable.
	for p, fi := range hiddenDirs {
		if ex, ok := execInDir[p]; ok {
			fi.Path = p
			addHit(fi, "HID-C4")
			_ = ex
		}
	}

	// HID-C2: hidden directory directly under /.
	if entries, err := env.FS.ReadDir("/"); err == nil {
		anyDir = true
		for _, e := range entries {
			if !strings.HasPrefix(e.Name, ".") && !dotsOrSpacePattern.MatchString(e.Name) {
				continue
			}
			fi, serr := env.FS.Stat("/" + e.Name)
			if serr != nil {
				continue
			}
			src.ItemsSeen++
			hiddenInventoried++
			var ids []string
			if fi.IsDir {
				ids = append(ids, "HID-C2")
			}
			if dotsOrSpacePattern.MatchString(e.Name) {
				ids = append(ids, "HID-C3")
			}
			if len(ids) > 0 {
				addHit(fi, ids...)
			}
		}
	} else {
		reportSrcErr(&src, err, "listing /")
	}

	if !anyDir {
		src.Available = false
		src.Reason = "none of the staging directories (" +
			strings.Join(linuxTempDirs, ", ") + ") exist and / could not be listed"
		return check.Result(m.ID, started, env.Now,
			[]model.DataSourceStatus{check.SourceStatus(m.Sources[0], src)}, nil, nil)
	}
	src.Available = true
	if env.Budget.Truncated() {
		src.Truncated = true
	}

	inventory = append(inventory, model.InventoryItem{
		Group:        "hidden artifacts",
		ArtifactType: "hidden_artifact_summary",
		ArtifactID:   "staging-directory-summary",
		Attributes: map[string]string{
			"hidden_entries_examined": strconv.Itoa(hiddenInventoried),
			"reportable_hits":         strconv.Itoa(len(hits)),
			"directories":             strings.Join(linuxTempDirs, ","),
			"note": "Hidden NON-executable files are counted here but deliberately not " +
				"reported: a clean host was measured with 150 of them in /tmp.",
		},
		TechniqueIDs: []string{"T1564", "T1564.001"},
		CheckIDs:     []string{m.ID},
	})

	var findings []model.Finding
	for _, h := range hits {
		if err := ctx.Err(); err != nil {
			return check.ErrorResult(m.ID, started, env.Now, err)
		}
		fi := h.info
		level := model.SuspiciousIndicator
		if len(h.criteria) >= 2 {
			level = model.Corroborated
		}
		detail := fmt.Sprintf("%s: mode=%s dir=%t size=%d owner=%s",
			fi.Path, fi.ModeString, fi.IsDir, fi.Size, defaultStr(fi.Owner, "unknown"))

		ev := model.EvidenceRef{
			ID:        "ev-hid-" + collect.SHA256Hex([]byte(fi.Path))[:12],
			Kind:      "file_metadata",
			Source:    fi.Path,
			SHA256:    collect.SHA256Hex([]byte(detail)),
			HashScope: "full_object",
			Excerpt:   detail,
			SizeBytes: int64(len(detail)),
			ModTime:   fi.ModTime,
		}
		// For a hidden executable the file's own hash is what an analyst pivots on.
		if !fi.IsDir && fi.Size > 0 {
			if fev, err := check.FileEvidence(env, fi.Path, "file_excerpt"); err == nil {
				ev = fev
			}
		}

		findings = append(findings, check.NewFinding(env, m.ID, check.FindingSpec{
			ArtifactType: "hidden_artifact",
			ArtifactID:   fi.Path,
			Level:        level,
			TechniqueIDs: []string{"T1564", "T1564.001"},
			Title: fmt.Sprintf("hidden %s %q matches %d criteria",
				map[bool]string{true: "directory", false: "file"}[fi.IsDir],
				fi.Name, len(h.criteria)),
			WhatAndWhere: fmt.Sprintf("%s (mode %s, owner %s, %d bytes) is concealed by "+
				"naming. %s", fi.Path, fi.ModeString, defaultStr(fi.Owner, "unknown"),
				fi.Size, detail),
			Criteria: h.criteria,
			Benign: []string{
				"Runtime and JIT caches write hidden files to /tmp in bulk; a clean host " +
					"was measured with 150 of them.",
				"Build tools and test harnesses create hidden scratch files and " +
					"directories.",
				"Some package build processes legitimately leave hidden executables in " +
					"/var/tmp.",
			},
			NextPivot: []string{
				"Hash the file and compare it against threat intelligence and against the " +
					"package manager's manifest.",
				"Establish its mtime and owner, and what else was created at the same time.",
				"If it is an ELF binary, review its imports and strings offline before " +
					"anything else.",
				"Check whether any persistence artifact references this path -- a hidden " +
					"binary plus a cron or unit entry pointing at it is the corroborating " +
					"pair worth escalating.",
			},
			Evidence: []model.EvidenceRef{ev},
			Context: map[string]string{
				"owner": defaultStr(fi.Owner, "unknown"),
				"mode":  fi.ModeString,
				"note": "Hidden naming alone is weak evidence on Linux, where it is only a " +
					"convention. What makes this reportable is the executable bit or the " +
					"deceptive name.",
			},
		}))
	}

	return check.Result(m.ID, started, env.Now,
		[]model.DataSourceStatus{check.SourceStatus(m.Sources[0], src)}, findings, inventory)
}

func (c *hiddenArtifactCheck) Cases() []check.FixtureCase {
	dir := func(root, name string) string {
		return filepath.Join(root, "lnx-stealth-hidden-001", name)
	}
	return []check.FixtureCase{
		{
			Name: "hidden executable in /tmp and an all-dots directory",
			Kind: check.CasePositive,
			Why: "Exercises HID-C1 (hidden + executable), HID-C3 (all-dots name) and " +
				"HID-C4 (hidden directory containing an executable).",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "positive"), "linux")
			},
			WantOutcome:      model.Detected,
			MinFindings:      2,
			WantTechniqueIDs: []string{"T1564.001"},
		},
		{
			Name: "clean host: many hidden NON-executable files in /tmp plus .X11-unix",
			Kind: check.CaseNegative,
			Why: "Reproduces the measured live-host condition that forced the narrowed " +
				"criteria: hidden non-executable files in bulk, and the X11 socket " +
				"directory. A 'hidden file in /tmp' criterion produces one finding per " +
				"file here; this check must produce none.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "negative"), "linux")
			},
			WantOutcome: model.NotDetected,
		},
		{
			Name: "no staging directories and no root listing",
			Kind: check.CaseNoData,
			Why:  "Nothing to examine: INSUFFICIENT_DATA.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(dir(root, "nodata"), "linux")
				if err != nil {
					return env, err
				}
				env.FS = &collect.ErrorFS{
					FileSystem:    env.FS,
					MissingPrefix: []string{"/"},
				}
				return env, nil
			},
			WantOutcome: model.InsufficientData,
		},
		{
			Name: "staging directories unreadable",
			Kind: check.CasePermissionDenied,
			Why:  "An unreadable /tmp must not read as a /tmp with nothing hidden in it.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(dir(root, "positive"), "linux")
				if err != nil {
					return env, err
				}
				env.FS = &collect.ErrorFS{
					FileSystem: env.FS,
					DenyPrefix: []string{"/tmp", "/var/tmp", "/dev/shm"},
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
