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

func init() { check.Register(&runKeyCheck{}) }

type runKeyCheck struct{}

const runKeyCheckID = "WIN-PERSIST-RUNKEY-001"

// runKeyPaths are the autostart registry locations this check reads. Both the native and
// the WOW64 views are covered, because a 32-bit payload registering under Wow6432Node is
// invisible to a check that only reads the native path.
var runKeyPaths = []struct {
	Hive string
	Path string
}{
	{"HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`},
	{"HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`},
	{"HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices`},
	{"HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce`},
	{"HKLM", `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`},
	{"HKLM", `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`},
}

// perUserRunSubPaths are appended to each loaded HKU hive.
var perUserRunSubPaths = []string{
	`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
	`SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
}

// startupFolders are the on-disk half of T1547.001.
var startupFolders = []string{
	`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`,
}

func (c *runKeyCheck) Meta() check.Meta {
	return check.Meta{
		ID:      runKeyCheckID,
		Title:   "Suspicious Run key or Startup folder autostart entry",
		OS:      []string{"windows"},
		Tactics: []string{"persistence", "privilege-escalation"},

		Techniques: []check.TechniqueMapping{
			{
				TechniqueID: "T1547.001",
				Justification: "Run/RunOnce registry values and Startup folder items ARE the " +
					"two artifacts this sub-technique is defined by; the check reads both.",
			},
			{
				TechniqueID: "T1547",
				Justification: "Parent technique; a matched autostart entry is direct " +
					"evidence of boot or logon autostart execution.",
			},
			{
				TechniqueID: "T1112",
				Justification: "Writing a Run value is a registry modification. Mapped " +
					"Partial because this check only looks at autostart keys, not at " +
					"registry modification generally.",
				Partial: true,
			},
		},

		Sources: []check.SourceRequirement{
			{
				Name:      "Windows registry autostart keys",
				Privilege: "HKLM Run keys are readable by standard users; reading other users' HKU hives requires Administrator",
				FailureModes: []string{
					"Not running on Windows, or scanning a relocated filesystem root -> the " +
						"registry source reports unavailable with a reason -> " +
						"INSUFFICIENT_DATA, never NOT_DETECTED.",
					"A key is access-denied -> PERMISSION_DENIED or PARTIAL_DATA.",
					"A user's hive is not loaded (user never logged on since boot) -> that " +
						"user's Run key cannot be read at all; recorded as partial.",
				},
			},
			{
				Name:      "Startup folder",
				Privilege: "the all-users Startup folder is readable by standard users",
				Optional:  true,
				FailureModes: []string{
					"Folder absent -> contributes nothing; the registry source still " +
						"determines the outcome.",
					"Folder unreadable -> partial collection -> PARTIAL_DATA.",
				},
			},
		},

		Criteria: []model.Criterion{
			{ID: "WRUN-C1", Text: "The autostart target executes from a user-writable " +
				"staging directory (%TEMP%, %APPDATA%, \\Users\\Public, \\ProgramData, " +
				"\\Windows\\Temp, $Recycle.Bin, \\PerfLogs)."},
			{ID: "WRUN-C2", Text: "The value invokes PowerShell with an encoded command " +
				"(-e/-ec/-enc/-EncodedCommand followed by a base64 blob)."},
			{ID: "WRUN-C3", Text: "The value suppresses the window or the profile " +
				"(-WindowStyle Hidden, -NoProfile combined with -NonInteractive)."},
			{ID: "WRUN-C4", Text: "The value runs through a signed-binary proxy " +
				"(mshta, regsvr32, rundll32, certutil, bitsadmin, msbuild, installutil, " +
				"cmstp, wmic, forfiles, scriptrunner)."},
			{ID: "WRUN-C5", Text: "The value references a remote payload or script URI " +
				"(http://, https://, ftp://, a UNC path, javascript:, vbscript:)."},
			{ID: "WRUN-C6", Text: "The autostart target has a non-executable file extension " +
				"(.jpg, .txt, .log, .dat and similar), indicating a renamed payload."},
		},

		EscalationCriteria: "Every autostart entry is an observed_artifact for Inventory. " +
			"One criterion gives suspicious_indicator. Corroborated requires a second " +
			"independent criterion -- for example a %TEMP% path (WRUN-C1) that is ALSO " +
			"launched via an encoded PowerShell command (WRUN-C2).",

		FalsePositiveHandling: "Run keys are among the noisiest artifacts on Windows, so " +
			"existence is never a finding -- a stock host has a dozen legitimate entries " +
			"(OneDrive, Teams, vendor updaters, printer utilities). Specifically: " +
			"(a) %APPDATA% and %LOCALAPPDATA% paths are extremely common for " +
			"legitimately per-user-installed software (OneDrive, Slack, Teams, Zoom), so " +
			"WRUN-C1 alone stays at suspicious_indicator and the finding names those " +
			"applications as the first benign explanation; (b) rundll32 is used " +
			"legitimately by many vendor components, so WRUN-C4 alone does not escalate; " +
			"(c) the check does not treat an unsigned binary as a criterion, because " +
			"plenty of legitimate software is unsigned and a valid signature is explicitly " +
			"not proof of benign; (d) every finding lists the vendor-updater explanation.",

		Overlay: check.Overlay{
			Behavior: "An adversary registers their payload in a Run/RunOnce registry value " +
				"or drops a shortcut in the Startup folder so it executes at user logon or " +
				"at boot. It is the most common Windows persistence mechanism because it " +
				"requires no special privilege for the per-user variants.",
			Artifacts: []string{
				`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run and RunOnce (plus the RunServices variants)`,
				`The Wow6432Node equivalents for 32-bit entries`,
				`The same paths under each loaded HKU per-user hive`,
				`Files and shortcuts in the all-users Startup folder`,
			},
			Logic: "Read each autostart registry key via the native API (no reg.exe child " +
				"process), enumerate loaded per-user hives under HKU so persistence planted " +
				"under other accounts is seen, and list the Startup folder. Evaluate the six " +
				"documented criteria against each value's data. Inventory every entry; emit " +
				"a Finding only on a criterion match.",
			FalsePositives: []string{
				"Vendor updaters and per-user applications (OneDrive, Teams, Slack, Zoom, " +
					"Dropbox) legitimately autostart from %LOCALAPPDATA% or %APPDATA%.",
				"Printer, audio and GPU utilities commonly autostart via rundll32.",
				"Enterprise software deployment tools stage installers in %ProgramData%.",
				"RunOnce entries left behind by an interrupted installer look anomalous but " +
					"are benign.",
			},
			Limitations: []string{
				"Only hives that are currently LOADED under HKU can be read, so a user who " +
					"has not logged on since boot has an unreadable Run key; this is " +
					"reported as partial rather than as absence.",
					"This check reads current state. An entry that ran at logon and was then " +
					"deleted leaves nothing here; only Sysmon registry events or the " +
					"Security log would show it, and neither may be enabled.",
				"Run key values are only one of many autostart locations; Winlogon, " +
					"Userinit, AppInit_DLLs, Image File Execution Options, Active Setup and " +
					"COM hijacking are NOT covered by this check.",
				"The check does not verify code signatures of the target binary. Signature " +
					"status would be context, not proof, and is deliberately out of scope here.",
				"Shortcut (.lnk) targets in the Startup folder are NOT resolved: the check " +
					"reasons about the item's own name and extension, not what the shortcut " +
					"points at. A .lnk aimed at a payload in %TEMP% is therefore inventoried " +
					"but will not match the transient-directory criterion.",
				"The transient-directory criterion is deliberately not applied to Startup " +
					"folder items, because the all-users Startup folder is itself under " +
					"C:\\ProgramData and the criterion would otherwise fire on every " +
					"legitimate entry.",
				"Only the all-users Startup folder is read; per-user Startup folders are " +
					"not enumerated in this phase.",
				"Registry last-write time is per-key, not per-value, so an individual " +
					"value's age cannot be established from the registry alone.",
			},
			References: []check.Reference{
				{Title: "MITRE ATT&CK T1547.001 Registry Run Keys / Startup Folder",
					URL: "https://attack.mitre.org/techniques/T1547/001"},
				{Title: "MITRE ATT&CK T1547 Boot or Logon Autostart Execution",
					URL: "https://attack.mitre.org/techniques/T1547"},
			},
		},

		// Capped at FIXTURE_TESTED: no Windows binary can be executed in this environment
		// (DECISIONS.md B-001), so the collector's real behaviour is unverified. The check
		// LOGIC is exercised through collect.FakeRegistry.
		Validation:        model.FixtureTested,
		FixtureProvenance: model.Synthetic,
	}
}

func (c *runKeyCheck) Run(ctx context.Context, env check.Env) model.CheckResult {
	started := env.Now()
	m := c.Meta()

	regAvailable, regReason := env.Registry.Available()
	regSrc := collect.SourceResult{
		Name:      m.Sources[0].Name,
		Available: regAvailable,
		Reason:    regReason,
	}

	type entry struct {
		artifactID string
		location   string
		name       string
		command    string
		// isStartup marks a Startup-folder item. The all-users Startup folder lives UNDER
		// C:\ProgramData, which is itself in the user-writable staging list, so applying
		// WRUN-C1 to such an item would fire on every legitimate Startup entry on every
		// Windows host. The criterion is therefore evaluated only for registry values.
		isStartup bool
		evidence  model.EvidenceRef
	}
	var entries []entry

	if regAvailable {
		targets := make([]struct{ Hive, Path string }, 0, len(runKeyPaths))
		targets = append(targets, runKeyPaths...)

		if hives, err := env.Registry.UserHives(); err == nil {
			for _, h := range hives {
				for _, sub := range perUserRunSubPaths {
					targets = append(targets, struct{ Hive, Path string }{
						"HKU", h.Root + `\` + sub})
				}
			}
		} else {
			regSrc.Errors = append(regSrc.Errors,
				fmt.Sprintf("could not enumerate per-user hives: %v; "+
					"persistence under other user accounts was not examined", err))
		}

		for _, t := range targets {
			if err := ctx.Err(); err != nil {
				return check.ErrorResult(m.ID, started, env.Now, err)
			}
			info, err := env.Registry.OpenKey(t.Hive, t.Path)
			if err != nil {
				// A missing autostart key is normal (not every host has RunServices).
				// An access-denied one is NOT normal and must be surfaced.
				if strings.Contains(err.Error(), "permission denied") {
					regSrc.Errors = append(regSrc.Errors,
						fmt.Sprintf("access denied reading %s\\%s", t.Hive, t.Path))
				}
				continue
			}
			regSrc.ItemsSeen += len(info.Values)
			for _, v := range info.Values {
				if strings.TrimSpace(v.String) == "" {
					continue
				}
				entries = append(entries, entry{
					artifactID: info.Path + `\` + v.Name,
					location:   info.Path,
					name:       v.Name,
					command:    v.String,
					evidence:   check.RegistryEvidence(env, info.Path, v),
				})
			}
		}
	}

	// Startup folder: the filesystem half of the same technique.
	startupSrc := collect.SourceResult{Name: m.Sources[1].Name}
	for _, folder := range startupFolders {
		if !env.FS.Exists(folder) {
			continue
		}
		startupSrc.Available = true
		items, err := env.FS.ReadDir(folder)
		if err != nil {
			startupSrc.Errors = append(startupSrc.Errors,
				fmt.Sprintf("listing %s: %v", folder, err))
			continue
		}
		for _, it := range items {
			if it.IsDir || strings.EqualFold(it.Name, "desktop.ini") {
				continue
			}
			p := folder + `\` + it.Name
			startupSrc.ItemsSeen++
			ev, err := check.FileEvidence(env, p, "startup_item")
			if err != nil {
				startupSrc.Errors = append(startupSrc.Errors,
					fmt.Sprintf("reading %s: %v", p, err))
				continue
			}
			entries = append(entries, entry{
				artifactID: p, location: folder, name: it.Name, command: p,
				isStartup: true, evidence: ev,
			})
		}
	}
	if !startupSrc.Available {
		startupSrc.Reason = "no all-users Startup folder found at " +
			strings.Join(startupFolders, ", ")
	}

	// The Startup folder is declared Optional, so model.OutcomeFromSources ignores its mere
	// absence while still counting a denial or truncation against confidence.
	sources := []model.DataSourceStatus{
		check.SourceStatus(m.Sources[0], regSrc),
		check.SourceStatus(m.Sources[1], startupSrc),
	}
	if !regAvailable {
		return check.Result(m.ID, started, env.Now, sources, nil, nil)
	}

	byID := map[string]model.Criterion{}
	for _, cr := range m.Criteria {
		byID[cr.ID] = cr
	}

	var findings []model.Finding
	var inventory []model.InventoryItem

	for _, e := range entries {
		inventory = append(inventory, model.InventoryItem{
			Group:        "windows autostart entries",
			ArtifactType: "windows_autostart",
			ArtifactID:   e.artifactID,
			Attributes: map[string]string{
				"location": e.location,
				"name":     e.name,
				"command":  Truncate(e.command, 200),
			},
			TechniqueIDs: []string{"T1547", "T1547.001"},
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

		if !e.isStartup {
			if _, hit := WindowsTransientExecutable(e.command); hit {
				add("WRUN-C1")
			}
		}
		for _, sig := range WindowsCommandSignals(e.command) {
			switch sig {
			case "powershell-encoded-command":
				add("WRUN-C2")
			case "hidden-window-or-no-profile":
				add("WRUN-C3")
			case "signed-binary-proxy-execution":
				add("WRUN-C4")
			case "remote-or-script-uri-payload":
				add("WRUN-C5")
			}
		}
		if _, hit := ExecutableExtMismatch(e.command); hit {
			add("WRUN-C6")
		}

		if len(matched) == 0 {
			continue
		}
		level := model.SuspiciousIndicator
		if len(matched) >= 2 {
			level = model.Corroborated
		}

		findings = append(findings, check.NewFinding(env, m.ID, check.FindingSpec{
			ArtifactType: "windows_autostart",
			ArtifactID:   e.artifactID,
			Level:        level,
			TechniqueIDs: []string{"T1547", "T1547.001", "T1112"},
			Title: fmt.Sprintf("autostart entry %q matches %d criteria",
				e.name, len(matched)),
			WhatAndWhere: fmt.Sprintf("%s sets %q to: %s",
				e.location, e.name, Truncate(e.command, 300)),
			Criteria: matched,
			Benign: []string{
				"Per-user applications (OneDrive, Teams, Slack, Zoom, Dropbox) legitimately " +
					"autostart from %LOCALAPPDATA% or %APPDATA%.",
				"Vendor hardware utilities commonly autostart via rundll32.",
				"Software deployment tooling stages installers under %ProgramData%.",
				"An interrupted installer can leave a benign but odd-looking RunOnce value.",
			},
			NextPivot: []string{
				"Examine the target binary " + Truncate(FirstArg(e.command), 160) +
					": creation time, digital signature, and whether any installed product " +
					"owns it (a valid signature is context, not proof).",
				"Check the registry key's last-write time to bound when the entry appeared.",
				"If an encoded PowerShell command is present, decode it offline and review " +
					"what it does before anything else.",
				"Look for Sysmon Event ID 13 (registry value set) or Security 4657 for this " +
					"value, bearing in mind neither may be enabled.",
			},
			Evidence: []model.EvidenceRef{e.evidence},
			Context: map[string]string{
				"autostart_location": e.location,
				"note": "Vendor-looking naming or an expected-looking path is context " +
					"only, never proof the entry is benign.",
			},
		}))
	}

	return check.Result(m.ID, started, env.Now, sources, findings, inventory)
}

func (c *runKeyCheck) Cases() []check.FixtureCase {
	// Windows fixtures combine a fixture filesystem root (Startup folder) with a
	// FakeRegistry, because a relocated filesystem root cannot contain a live registry.
	base := func(root, name string) string {
		return filepath.Join(root, "win-persist-runkey-001", name)
	}

	maliciousReg := func() *collect.FakeRegistry {
		r := collect.NewFakeRegistry()
		r.Set("HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, collect.RegKeyInfo{
			Values: []collect.RegValue{
				{Name: "SecurityHealthSystray", Type: collect.RegSZ,
					String: `C:\Windows\System32\SecurityHealthSystray.exe`},
				{Name: "Updater", Type: collect.RegSZ,
					String: `powershell.exe -nop -w hidden -enc ` +
						`SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA`},
			},
		})
		r.Hives = []collect.UserHive{{SID: "S-1-5-21-1-2-3-1001", Username: "jdoe",
			Root: "S-1-5-21-1-2-3-1001"}}
		r.Set("HKU", `S-1-5-21-1-2-3-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
			collect.RegKeyInfo{Values: []collect.RegValue{
				{Name: "OneDrive", Type: collect.RegSZ,
					String: `"C:\Users\jdoe\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background`},
			}})
		return r
	}

	benignReg := func() *collect.FakeRegistry {
		r := collect.NewFakeRegistry()
		r.Set("HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, collect.RegKeyInfo{
			Values: []collect.RegValue{
				{Name: "SecurityHealthSystray", Type: collect.RegSZ,
					String: `C:\Windows\System32\SecurityHealthSystray.exe`},
				{Name: "RTHDVCPL", Type: collect.RegSZ,
					String: `"C:\Program Files\Realtek\Audio\HDA\RAVCpl64.exe" -s`},
				{Name: "igfxTray", Type: collect.RegSZ,
					String: `C:\Windows\System32\igfxtray.exe`},
			},
		})
		return r
	}

	return []check.FixtureCase{
		{
			Name: "encoded hidden PowerShell Run value plus a renamed Startup payload",
			Kind: check.CasePositive,
			Why: "Exercises WRUN-C2/C3 on the registry side and WRUN-C1/C6 on the Startup " +
				"folder side, proving both halves of T1547.001 are covered.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(base(root, "positive"), "windows")
				if err != nil {
					return env, err
				}
				env.Registry = maliciousReg()
				return env, nil
			},
			WantOutcome:      model.Detected,
			MinFindings:      1,
			WantTechniqueIDs: []string{"T1547.001"},
		},
		{
			Name: "stock Windows autostart set (Security Health, Realtek audio, Intel graphics)",
			Kind: check.CaseNegative,
			Why: "Proves the check tolerates the legitimate autostart entries present on " +
				"essentially every Windows host, including vendor utilities.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(base(root, "negative"), "windows")
				if err != nil {
					return env, err
				}
				env.Registry = benignReg()
				return env, nil
			},
			WantOutcome: model.NotDetected,
		},
		{
			Name: "registry source unavailable (scanning a non-Windows host)",
			Kind: check.CaseNoData,
			Why: "Without a registry there is nothing to examine; the honest outcome is " +
				"INSUFFICIENT_DATA. NOT_DETECTED here would assert a Windows host is free " +
				"of Run-key persistence on the basis of never having looked.",
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
			Name: "Run keys access-denied",
			Kind: check.CasePermissionDenied,
			Why: "Models an under-privileged scan. Access-denied keys must surface as " +
				"reduced visibility, never as absence of persistence.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(base(root, "nodata"), "windows")
				if err != nil {
					return env, err
				}
				r := collect.NewFakeRegistry()
				r.Set("HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
					collect.RegKeyInfo{})
				r.Deny("HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`)
				env.Registry = r
				return env, nil
			},
			WantOutcome: model.PartialData,
			AlsoAccept:  []model.Outcome{model.PermissionDenied, model.InsufficientData},
		},
	}
}
