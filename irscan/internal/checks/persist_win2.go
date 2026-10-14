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

func init() { check.Register(&winServiceCheck{}, &winTaskCheck{}) }

// winSystemDirs are the locations from which a legitimate service binary or DLL normally
// runs. Used only to decide whether a path is WORTH REPORTING, never as proof of benign:
// a payload placed in System32 by an adversary with SYSTEM is in a "system directory" too.
var winSystemDirs = []string{
	`\windows\system32\`, `\windows\syswow64\`, `\program files\`,
	`\program files (x86)\`, `\windows\servicing\`, `\windows\microsoft.net\`,
	`\windows\winsxs\`, `\windows\systemapps\`,
}

func inWindowsSystemDir(p string) bool {
	q := strings.ToLower(strings.ReplaceAll(strings.Trim(p, `"`), "/", `\`))
	q = strings.ReplaceAll(q, `%systemroot%`, `\windows`)
	q = strings.ReplaceAll(q, `%windir%`, `\windows`)
	q = strings.ReplaceAll(q, `%programfiles%`, `\program files`)
	for _, d := range winSystemDirs {
		if strings.Contains(q, d) {
			return true
		}
	}
	return false
}

// =======================================================================================
// WIN-PERSIST-SERVICE-001  (T1543.003)
// =======================================================================================

type winServiceCheck struct{}

func (c *winServiceCheck) Meta() check.Meta {
	return check.Meta{
		ID:      "WIN-PERSIST-SERVICE-001",
		Title:   "Suspicious Windows service",
		OS:      []string{"windows"},
		Tactics: []string{"persistence", "privilege-escalation"},
		Techniques: []check.TechniqueMapping{
			{
				TechniqueID: "T1543.003",
				Justification: "A Windows service IS the artifact this sub-technique names. " +
					"The check enumerates HKLM\\SYSTEM\\CurrentControlSet\\Services and " +
					"inspects each service's ImagePath, Parameters\\ServiceDll, start type " +
					"and account.",
			},
			{
				TechniqueID: "T1543",
				Justification: "Parent technique: creating or modifying a service is the " +
					"canonical way to create or modify a system process on Windows.",
			},
		},
		Sources: []check.SourceRequirement{{
			Name:      "Windows service registry keys",
			Privilege: "HKLM\\SYSTEM\\CurrentControlSet\\Services is readable by standard users",
			FailureModes: []string{
				"Registry unavailable (non-Windows host, or a relocated filesystem root " +
					"with no fixture registry) -> INSUFFICIENT_DATA, never NOT_DETECTED.",
				"The Services key is access-denied -> PERMISSION_DENIED.",
				"An individual service key is access-denied -> recorded as a partial " +
					"collection error -> PARTIAL_DATA.",
			},
		}},
		Criteria: []model.Criterion{
			{ID: "SVC-C1", Text: "The service's executable runs from a user-writable " +
				"staging directory (%TEMP%, %APPDATA%, \\Users\\Public, \\ProgramData, " +
				"\\Windows\\Temp, $Recycle.Bin, \\PerfLogs)."},
			{ID: "SVC-C2", Text: "The ImagePath invokes a script interpreter, an encoded " +
				"PowerShell command, a signed-binary proxy (rundll32, mshta, regsvr32, " +
				"certutil and similar) or references a remote payload."},
			{ID: "SVC-C3", Text: "The service is svchost-hosted and its " +
				"Parameters\\ServiceDll points outside the Windows system directories -- " +
				"the classic service-DLL hijack, which an ImagePath-only review misses."},
			{ID: "SVC-C4", Text: "The service's executable has a non-executable file " +
				"extension (.jpg, .txt, .log, .dat), indicating a renamed payload."},
		},
		EscalationCriteria: "Every service is an observed_artifact for Inventory. One " +
			"criterion gives suspicious_indicator. Corroborated requires a second " +
			"independent criterion -- for example a %ProgramData% ImagePath (SVC-C1) that " +
			"is ALSO launched via rundll32 (SVC-C2). An auto-start type is recorded as " +
			"context and is deliberately NOT a criterion, because almost every legitimate " +
			"service is auto-start.",
		FalsePositiveHandling: "Services are a named noisy area, so existence, display " +
			"name and start type are never criteria. Specifically: (a) a service running " +
			"from \\Program Files or System32 does not match SVC-C1, which is where almost " +
			"all legitimate services live; (b) svchost-hosted services are extremely " +
			"common and only a ServiceDll OUTSIDE the system directories matches SVC-C3, " +
			"so the hundreds of stock svchost services do not fire; (c) rundll32 is used " +
			"by some legitimate vendor services, so SVC-C2 alone stays at " +
			"suspicious_indicator; (d) kernel drivers with \\??\\ and \\SystemRoot\\ " +
			"ImagePath prefixes are parsed correctly rather than being flagged as " +
			"malformed; (e) a valid Authenticode signature on the binary is explicitly NOT " +
			"treated as proof of benign and is not consulted.",
		Overlay: check.Overlay{
			Behavior: "An adversary installs a new service, or repoints an existing one, so " +
				"their payload is started by the Service Control Manager as SYSTEM at boot. " +
				"Services are attractive because they run with high privilege, restart " +
				"automatically, and are numerous enough on a normal host to hide in.",
			Artifacts: []string{
				`HKLM\SYSTEM\CurrentControlSet\Services\<name> -- ImagePath, Start, Type, ObjectName`,
				`HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\ServiceDll for svchost-hosted services`,
				"The service binary or DLL on disk",
			},
			Logic: "Enumerate every service subkey from the registry (no sc.exe child " +
				"process, and no reliance on SCM enumeration, which an adversary can hide " +
				"from). Resolve ImagePath through its quoting and \\??\\ / \\SystemRoot\\ " +
				"prefixes, and read Parameters\\ServiceDll. Evaluate the four documented " +
				"criteria. Inventory every service; emit a finding only on a match.",
			FalsePositives: []string{
				"Third-party software legitimately installs services running from " +
					"\\Program Files and occasionally from \\ProgramData.",
				"Some vendor components legitimately launch via rundll32.",
				"Driver services use \\??\\ and \\SystemRoot\\ path forms that look unusual " +
					"but are normal.",
				"Management agents create services with generic names.",
			},
			Limitations: []string{
				"The check reads CURRENT registry state. A service created, run and deleted " +
					"leaves nothing here; only Security 4697 / System 7045 would show it, " +
					"and neither may be enabled or retained.",
				"Only the CurrentControlSet is read. A service present in another control " +
					"set, or in an offline hive, is not examined.",
				"The service binary's digital signature and on-disk metadata are not " +
					"checked; signature status would be context, not proof.",
				"Service DACLs are not examined, so a weak-permissions service that a " +
					"local user could repoint is not detected.",
				"An adversary with SYSTEM can edit these keys after execution, so what is " +
					"seen here may have been tampered with.",
			},
			References: []check.Reference{
				{Title: "MITRE ATT&CK T1543.003 Windows Service",
					URL: "https://attack.mitre.org/techniques/T1543/003"},
				{Title: "MITRE ATT&CK T1543 Create or Modify System Process",
					URL: "https://attack.mitre.org/techniques/T1543"},
			},
		},
		Validation:        model.FixtureTested,
		FixtureProvenance: model.Synthetic,
	}
}

func (c *winServiceCheck) Run(ctx context.Context, env check.Env) model.CheckResult {
	started := env.Now()
	m := c.Meta()

	services, src := collect.WindowsServices(env.Registry)
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

	for _, s := range services {
		if err := ctx.Err(); err != nil {
			return check.ErrorResult(m.ID, started, env.Now, err)
		}
		serviceDll := s.Extra["ServiceDll"]

		inventory = append(inventory, model.InventoryItem{
			Group:        "windows services",
			ArtifactType: "windows_service",
			ArtifactID:   s.Name,
			Attributes: map[string]string{
				"display_name": Truncate(s.DisplayName, 100),
				"image_path":   Truncate(s.ImagePath, 200),
				"binary":       Truncate(s.ResolvedBinary, 160),
				"service_dll":  Truncate(serviceDll, 160),
				"start_type":   s.StartType,
				"type":         s.ServiceType,
				"account":      s.Account,
			},
			TechniqueIDs: []string{"T1543", "T1543.003"},
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

		if _, hit := WindowsTransientExecutable(s.ImagePath); hit {
			add("SVC-C1")
		}
		for _, sig := range WindowsCommandSignals(s.ImagePath) {
			_ = sig
			add("SVC-C2")
		}
		if serviceDll != "" && !inWindowsSystemDir(serviceDll) {
			add("SVC-C3")
		}
		if _, hit := ExecutableExtMismatch(s.ResolvedBinary); hit {
			add("SVC-C4")
		}

		if len(matched) == 0 {
			continue
		}
		level := model.SuspiciousIndicator
		if len(matched) >= 2 {
			level = model.Corroborated
		}

		detail := fmt.Sprintf("ImagePath=%q ServiceDll=%q Start=%s Type=%s Account=%s",
			s.ImagePath, serviceDll, s.StartType, s.ServiceType, s.Account)

		findings = append(findings, check.NewFinding(env, m.ID, check.FindingSpec{
			ArtifactType: "windows_service",
			ArtifactID:   s.Name,
			Level:        level,
			TechniqueIDs: []string{"T1543", "T1543.003"},
			Title: fmt.Sprintf("service %q matches %d criteria", s.Name, len(matched)),
			WhatAndWhere: fmt.Sprintf("Service %q (%s) at %s: %s",
				s.Name, defaultStr(s.DisplayName, "no display name"), s.Source, detail),
			Criteria: matched,
			Benign: []string{
				"Third-party software legitimately installs services under \\Program Files " +
					"and sometimes \\ProgramData.",
				"Some vendor components legitimately launch through rundll32.",
				"Management and backup agents create services with generic names.",
			},
			NextPivot: []string{
				"Inspect " + defaultStr(s.ResolvedBinary, "the service binary") +
					": creation time, version resources, and whether an installed product " +
					"owns it (a valid signature is context, not proof).",
				"If a ServiceDll is set, inspect that DLL specifically -- it, not the " +
					"ImagePath, is what runs.",
				"Check the service key's last-write time to bound when it was created or " +
					"changed.",
				"Look for System 7045 (service installed) or Security 4697 around that " +
					"time, bearing in mind neither may be enabled.",
			},
			Evidence: []model.EvidenceRef{{
				ID:        "ev-svc-" + collect.SHA256Hex([]byte(s.Source))[:12],
				Kind:      "service_config",
				Source:    s.Source,
				SHA256:    collect.SHA256Hex([]byte(detail)),
				HashScope: "full_object",
				Excerpt:   Truncate(detail, env.Limits.MaxExcerptBytes),
				SizeBytes: int64(len(detail)),
			}},
			Context: map[string]string{
				"start_type": s.StartType,
				"account":    s.Account,
				"note": "An auto start type and a system-looking path are context only, " +
					"never proof the service is benign.",
			},
		}))
	}

	return check.Result(m.ID, started, env.Now, sources, findings, inventory)
}

func (c *winServiceCheck) Cases() []check.FixtureCase {
	base := func(root, name string) string {
		return filepath.Join(root, "win-persist-service-001", name)
	}

	malicious := func() *collect.FakeRegistry {
		r := collect.NewFakeRegistry()
		r.Set("HKLM", `SYSTEM\CurrentControlSet\Services`, collect.RegKeyInfo{
			SubKeys: []string{"WinDefendUpdate", "Spooler", "WerSvc"},
		})
		// SVC-C1 + SVC-C2: ProgramData path launched via rundll32.
		r.Set("HKLM", `SYSTEM\CurrentControlSet\Services\WinDefendUpdate`, collect.RegKeyInfo{
			Values: []collect.RegValue{
				{Name: "ImagePath", Type: collect.RegExpandSZ,
					String: `rundll32.exe C:\ProgramData\Microsoft\update\svcupd.dll,ServiceMain`},
				{Name: "DisplayName", Type: collect.RegSZ, String: "Windows Defender Update"},
				{Name: "Start", Type: collect.RegDWord, Number: 2},
				{Name: "Type", Type: collect.RegDWord, Number: 16},
				{Name: "ObjectName", Type: collect.RegSZ, String: "LocalSystem"},
			},
		})
		// SVC-C3: svchost-hosted service whose ServiceDll is outside the system dirs.
		r.Set("HKLM", `SYSTEM\CurrentControlSet\Services\WerSvc`, collect.RegKeyInfo{
			Values: []collect.RegValue{
				{Name: "ImagePath", Type: collect.RegExpandSZ,
					String: `%SystemRoot%\System32\svchost.exe -k WerSvcGroup`},
				{Name: "Start", Type: collect.RegDWord, Number: 3},
				{Name: "Type", Type: collect.RegDWord, Number: 32},
			},
		})
		r.Set("HKLM", `SYSTEM\CurrentControlSet\Services\WerSvc\Parameters`,
			collect.RegKeyInfo{Values: []collect.RegValue{
				{Name: "ServiceDll", Type: collect.RegExpandSZ,
					String: `C:\Users\Public\Libraries\wer.dll`},
			}})
		r.Set("HKLM", `SYSTEM\CurrentControlSet\Services\Spooler`, collect.RegKeyInfo{
			Values: []collect.RegValue{
				{Name: "ImagePath", Type: collect.RegExpandSZ,
					String: `C:\Windows\System32\spoolsv.exe`},
				{Name: "Start", Type: collect.RegDWord, Number: 2},
				{Name: "Type", Type: collect.RegDWord, Number: 272},
			},
		})
		return r
	}

	benign := func() *collect.FakeRegistry {
		r := collect.NewFakeRegistry()
		r.Set("HKLM", `SYSTEM\CurrentControlSet\Services`, collect.RegKeyInfo{
			SubKeys: []string{"Spooler", "Dnscache", "wuauserv", "ACPI", "EdgeUpdate"},
		})
		r.Set("HKLM", `SYSTEM\CurrentControlSet\Services\Spooler`, collect.RegKeyInfo{
			Values: []collect.RegValue{
				{Name: "ImagePath", Type: collect.RegExpandSZ,
					String: `C:\Windows\System32\spoolsv.exe`},
				{Name: "Start", Type: collect.RegDWord, Number: 2},
			},
		})
		// Stock svchost-hosted service: ServiceDll IS under System32, so SVC-C3 must not
		// fire. Hundreds of these exist on a real host.
		r.Set("HKLM", `SYSTEM\CurrentControlSet\Services\Dnscache`, collect.RegKeyInfo{
			Values: []collect.RegValue{
				{Name: "ImagePath", Type: collect.RegExpandSZ,
					String: `%SystemRoot%\System32\svchost.exe -k NetworkService -p`},
				{Name: "Start", Type: collect.RegDWord, Number: 2},
			},
		})
		r.Set("HKLM", `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters`,
			collect.RegKeyInfo{Values: []collect.RegValue{
				{Name: "ServiceDll", Type: collect.RegExpandSZ,
					String: `%SystemRoot%\System32\dnsrslvr.dll`},
			}})
		r.Set("HKLM", `SYSTEM\CurrentControlSet\Services\wuauserv`, collect.RegKeyInfo{
			Values: []collect.RegValue{
				{Name: "ImagePath", Type: collect.RegExpandSZ,
					String: `%systemroot%\system32\svchost.exe -k netsvcs -p`},
				{Name: "Start", Type: collect.RegDWord, Number: 3},
			},
		})
		r.Set("HKLM", `SYSTEM\CurrentControlSet\Services\wuauserv\Parameters`,
			collect.RegKeyInfo{Values: []collect.RegValue{
				{Name: "ServiceDll", Type: collect.RegExpandSZ,
					String: `C:\Windows\system32\wuaueng.dll`},
			}})
		// Kernel driver with the \??\ prefix form -- must parse, must not fire.
		r.Set("HKLM", `SYSTEM\CurrentControlSet\Services\ACPI`, collect.RegKeyInfo{
			Values: []collect.RegValue{
				{Name: "ImagePath", Type: collect.RegExpandSZ,
					String: `\SystemRoot\System32\drivers\ACPI.sys`},
				{Name: "Start", Type: collect.RegDWord, Number: 0},
				{Name: "Type", Type: collect.RegDWord, Number: 1},
			},
		})
		// Third-party updater under Program Files -- legitimate, must not fire.
		r.Set("HKLM", `SYSTEM\CurrentControlSet\Services\EdgeUpdate`, collect.RegKeyInfo{
			Values: []collect.RegValue{
				{Name: "ImagePath", Type: collect.RegSZ,
					String: `"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /svc`},
				{Name: "Start", Type: collect.RegDWord, Number: 3},
			},
		})
		return r
	}

	return []check.FixtureCase{
		{
			Name: "rundll32 service from ProgramData plus a hijacked svchost ServiceDll",
			Kind: check.CasePositive,
			Why: "Exercises SVC-C1/C2 on the ImagePath and SVC-C3 on the ServiceDll, the " +
				"latter being the case an ImagePath-only review misses entirely.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(base(root, "positive"), "windows")
				if err != nil {
					return env, err
				}
				env.Registry = malicious()
				return env, nil
			},
			WantOutcome:      model.Detected,
			MinFindings:      2,
			WantTechniqueIDs: []string{"T1543.003"},
		},
		{
			Name: "stock service set: spoolsv, two svchost services, a driver, an updater",
			Kind: check.CaseNegative,
			Why: "Proves the check tolerates the real shapes a Windows host carries, " +
				"including svchost-hosted services with System32 ServiceDlls and \\SystemRoot\\ " +
				"driver paths.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(base(root, "negative"), "windows")
				if err != nil {
					return env, err
				}
				env.Registry = benign()
				return env, nil
			},
			WantOutcome: model.NotDetected,
		},
		{
			Name: "registry unavailable",
			Kind: check.CaseNoData,
			Why:  "No registry means nothing was examined: INSUFFICIENT_DATA.",
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
			Name: "Services key access-denied",
			Kind: check.CasePermissionDenied,
			Why:  "A denied Services key must not read as a host with no services.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(base(root, "nodata"), "windows")
				if err != nil {
					return env, err
				}
				r := collect.NewFakeRegistry()
				r.Set("HKLM", `SYSTEM\CurrentControlSet\Services`, collect.RegKeyInfo{})
				r.Deny("HKLM", `SYSTEM\CurrentControlSet\Services`)
				env.Registry = r
				return env, nil
			},
			WantOutcome: model.PermissionDenied,
			AlsoAccept:  []model.Outcome{model.InsufficientData, model.PartialData},
		},
	}
}

// =======================================================================================
// WIN-PERSIST-SCHTASK-001  (T1053.005)
// =======================================================================================

type winTaskCheck struct{}

func (c *winTaskCheck) Meta() check.Meta {
	return check.Meta{
		ID:      "WIN-PERSIST-SCHTASK-001",
		Title:   "Suspicious Windows scheduled task",
		OS:      []string{"windows"},
		Tactics: []string{"persistence", "privilege-escalation", "execution"},
		Techniques: []check.TechniqueMapping{
			{
				TechniqueID: "T1053.005",
				Justification: "A Task Scheduler definition IS the artifact this " +
					"sub-technique names. The check parses the XML definitions under " +
					"%SystemRoot%\\System32\\Tasks and inspects their actions, principal " +
					"and hidden flag.",
			},
			{
				TechniqueID: "T1053",
				Justification: "Parent technique: a scheduled task is the Windows form of " +
					"scheduled task/job abuse.",
			},
		},
		Sources: []check.SourceRequirement{{
			Name: "Windows scheduled task definitions",
			Privilege: "C:\\Windows\\System32\\Tasks is readable by Administrators; a " +
				"standard user can read only parts of the tree",
			FailureModes: []string{
				"No Tasks folder exists (non-Windows host, or a relocated root without " +
					"one) -> INSUFFICIENT_DATA, never NOT_DETECTED.",
				"Subtrees unreadable without Administrator -> partial collection -> " +
					"PARTIAL_DATA. This is the normal unprivileged case.",
				"A task file that will not parse is reported as a collection error rather " +
					"than skipped, because a malformed definition may itself be evasion.",
				"Task files are UTF-16 with a BOM on a real host; the collector decodes " +
					"UTF-16LE/BE and UTF-8 so a parse failure means genuine malformation.",
			},
		}},
		Criteria: []model.Criterion{
			{ID: "TASK-C1", Text: "A task action runs an executable from a user-writable " +
				"staging directory (%TEMP%, %APPDATA%, \\Users\\Public, \\ProgramData, " +
				"\\Windows\\Temp, $Recycle.Bin, \\PerfLogs)."},
			{ID: "TASK-C2", Text: "A task action invokes an encoded PowerShell command, a " +
				"hidden window, a signed-binary proxy (mshta, regsvr32, rundll32, certutil " +
				"and similar), or references a remote payload."},
			{ID: "TASK-C3", Text: "The task is marked Hidden AND runs as SYSTEM " +
				"(S-1-5-18 / LocalSystem) AND is registered OUTSIDE the \\Microsoft\\ task " +
				"folder namespace. Hidden+SYSTEM on its own is normal -- Microsoft's stock " +
				"maintenance tasks are exactly that -- so the location is what makes the " +
				"combination anomalous."},
			{ID: "TASK-C4", Text: "A task action's executable has a non-executable file " +
				"extension (.jpg, .txt, .log, .dat), indicating a renamed payload."},
		},
		EscalationCriteria: "Every task is an observed_artifact for Inventory. One criterion " +
			"gives suspicious_indicator. Corroborated requires a second independent " +
			"criterion -- for example a %TEMP% action (TASK-C1) in a task that is also " +
			"hidden and runs as SYSTEM (TASK-C3). The Hidden flag ALONE is not a criterion: " +
			"Microsoft marks many stock maintenance tasks hidden, so it only contributes " +
			"when combined with a SYSTEM principal.",
		FalsePositiveHandling: "Scheduled tasks are a named noisy area -- a stock Windows " +
			"install ships several hundred, many hidden and many running as SYSTEM. " +
			"Therefore: (a) existence, trigger type and enabled state are never criteria; " +
			"(b) the Hidden flag alone does not fire, because Microsoft's own " +
			"\\Microsoft\\Windows\\* maintenance tasks are routinely hidden; (c) hidden AND " +
			"SYSTEM together still does not fire inside the \\Microsoft\\ namespace -- " +
			"verified against a fixture modelling 'Schedule Scan' and 'ScheduledDefrag', " +
			"which are both hidden and SYSTEM on a stock install; TASK-C3 requires that " +
			"combination OUTSIDE that namespace; (d) tasks whose action is under " +
			"\\Program Files or System32 do not " +
			"match TASK-C1; (e) COM-handler actions are recorded distinctly rather than " +
			"being treated as an empty action, so stock COM tasks are not misread.",
		Overlay: check.Overlay{
			Behavior: "An adversary registers a scheduled task so their payload runs at " +
				"logon, at boot, on a timer or on an event, usually as SYSTEM. It is one of " +
				"the most common Windows persistence mechanisms because the task store is " +
				"large and the definitions look much like Microsoft's own.",
			Artifacts: []string{
				`XML definitions under C:\Windows\System32\Tasks (and SysWOW64\Tasks)`,
				`The task's <Actions> -- Exec Command/Arguments, or a ComHandler ClassId`,
				`<Principals> UserId / RunLevel, and <Settings> Hidden / Enabled`,
				`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache (not read by this check)`,
			},
			Logic: "Walk the Tasks folders, decode each definition (UTF-16 or UTF-8) and " +
				"parse the XML. Evaluate the four documented criteria against each action " +
				"plus the principal and hidden flag. Inventory every task; emit a finding " +
				"only on a criterion match.",
			FalsePositives: []string{
				"Stock Windows maintenance tasks are numerous, frequently hidden and " +
					"frequently run as SYSTEM.",
				"Software updaters (Edge, Chrome, Office, vendor agents) register tasks that " +
					"run from \\Program Files and occasionally \\ProgramData.",
				"Management suites create tasks with generic names and obscure arguments.",
			},
			Limitations: []string{
				"Without Administrator, parts of the Tasks tree are unreadable, so the " +
					"result is PARTIAL_DATA and an absence of findings means little.",
				"The registry TaskCache is NOT read. A task registered only in TaskCache " +
					"with its XML deleted -- a known evasion -- is therefore invisible to " +
					"this check. This is a real gap, not a theoretical one.",
				"Task action binaries are not signature-checked or hashed on disk.",
				"A task created, run and deleted leaves nothing here; only Security 4698 or " +
					"the TaskScheduler operational log would show it.",
				"An adversary with SYSTEM can edit or delete the XML after execution.",
				"TASK-C3's \\Microsoft\\ folder condition is noise reduction, not a " +
					"boundary: a task registered under \\Microsoft\\Windows\\ with a " +
					"plausible name evades that criterion entirely. It was added because " +
					"Microsoft's stock hidden+SYSTEM tasks otherwise made the criterion " +
					"fire on every Windows host; TASK-C1, C2 and C4 still apply there.",
			},
			References: []check.Reference{
				{Title: "MITRE ATT&CK T1053.005 Scheduled Task",
					URL: "https://attack.mitre.org/techniques/T1053/005"},
				{Title: "Task Scheduler schema reference",
					URL: "https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema"},
			},
		},
		Validation:        model.FixtureTested,
		FixtureProvenance: model.Synthetic,
	}
}

// inMicrosoftTaskFolder reports whether a task lives in the \Microsoft\ namespace that
// Windows' own maintenance tasks occupy.
//
// This is a NOISE-REDUCTION measure, not a security boundary: an adversary who can register
// a task can register it under \Microsoft\Windows\ and evade this condition. That bypass is
// stated in the check's Limitations rather than being left implicit.
func inMicrosoftTaskFolder(t collect.ScheduledTask) bool {
	rel := strings.ToLower(strings.ReplaceAll(t.Extra["task_path"], "/", `\`))
	rel = strings.TrimPrefix(rel, `\`)
	return strings.HasPrefix(rel, `microsoft\`)
}

// systemPrincipals identify a task running with full local privilege.
func isSystemPrincipal(p string) bool {
	q := strings.ToLower(strings.TrimSpace(p))
	return q == "s-1-5-18" || q == "localsystem" || q == "system" ||
		strings.HasSuffix(q, `\system`)
}

func (c *winTaskCheck) Run(ctx context.Context, env check.Env) model.CheckResult {
	started := env.Now()
	m := c.Meta()

	tasks, src := collect.WindowsScheduledTasks(env.FS, env.Limits.MaxDirDepth)
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

	for _, t := range tasks {
		if err := ctx.Err(); err != nil {
			return check.ErrorResult(m.ID, started, env.Now, err)
		}
		var cmds []string
		for _, a := range t.Actions {
			cmds = append(cmds, strings.TrimSpace(a.Command+" "+a.Arguments))
		}

		inventory = append(inventory, model.InventoryItem{
			Group:        "windows scheduled tasks",
			ArtifactType: "windows_scheduled_task",
			ArtifactID:   t.Path,
			Attributes: map[string]string{
				"name":      t.Name,
				"principal": t.Principal,
				"run_level": t.Extra["run_level"],
				"hidden":    fmt.Sprintf("%t", t.Hidden),
				"enabled":   fmt.Sprintf("%t", t.Enabled),
				"author":    Truncate(t.Author, 80),
				"triggers":  strings.Join(t.Triggers, ","),
				"actions":   Truncate(strings.Join(cmds, " ; "), 200),
			},
			TechniqueIDs: []string{"T1053", "T1053.005"},
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

		for _, a := range t.Actions {
			full := strings.TrimSpace(a.Command + " " + a.Arguments)
			// Pass the FULL action, not just Command: the usual shape is
			// Command=powershell.exe with the staged payload path in Arguments, so
			// inspecting Command alone would miss it. WindowsTransientExecutable only
			// looks into the arguments when the command is a known interpreter or script
			// host, so a legitimate task that merely logs into %TEMP% still does not match.
			if _, hit := WindowsTransientExecutable(full); hit {
				add("TASK-C1")
			}
			if len(WindowsCommandSignals(full)) > 0 {
				add("TASK-C2")
			}
			if _, hit := ExecutableExtMismatch(a.Command); hit {
				add("TASK-C4")
			}
		}
		// Hidden alone is common on stock Windows, and so is hidden+SYSTEM: Microsoft's
		// own \Microsoft\Windows\* maintenance tasks are both. Verified by the negative
		// fixture, where "Schedule Scan" and "ScheduledDefrag" fired until the folder
		// condition was added. The anomaly is hidden+SYSTEM OUTSIDE that namespace.
		if t.Hidden && isSystemPrincipal(t.Principal) && !inMicrosoftTaskFolder(t) {
			add("TASK-C3")
		}

		if len(matched) == 0 {
			continue
		}
		level := model.SuspiciousIndicator
		if len(matched) >= 2 {
			level = model.Corroborated
		}

		ev, err := check.FileEvidence(env, t.Path, "scheduled_task_xml")
		if err != nil {
			reportSrcErr(&src, err, "evidence for "+t.Path)
			sources[0] = check.SourceStatus(m.Sources[0], src)
			continue
		}

		findings = append(findings, check.NewFinding(env, m.ID, check.FindingSpec{
			ArtifactType: "windows_scheduled_task",
			ArtifactID:   t.Path,
			Level:        level,
			TechniqueIDs: []string{"T1053", "T1053.005"},
			Title: fmt.Sprintf("scheduled task %q matches %d criteria", t.Name, len(matched)),
			WhatAndWhere: fmt.Sprintf(
				"Task %q at %s runs as %s (run level %s, hidden=%t, enabled=%t, triggers "+
					"%s). Actions: %s",
				t.Name, t.Path, defaultStr(t.Principal, "unknown"),
				defaultStr(t.Extra["run_level"], "unspecified"), t.Hidden, t.Enabled,
				defaultStr(strings.Join(t.Triggers, ","), "none parsed"),
				Truncate(strings.Join(cmds, " ; "), 300)),
			Criteria: matched,
			Benign: []string{
				"Stock Windows maintenance tasks are numerous, often hidden and often run " +
					"as SYSTEM.",
				"Software updaters (Edge, Chrome, Office, vendor agents) register tasks " +
					"with obscure arguments.",
				"Management suites create generically named tasks running from " +
					"\\ProgramData.",
			},
			NextPivot: []string{
				"Inspect the action target and establish whether an installed product owns " +
					"it (a valid signature is context, not proof).",
				"Compare the task against the same path on a known-good peer host.",
				"Check the XML file's mtime and the task's RegistrationInfo/Date -- a " +
					"mismatch between them is itself worth explaining.",
				"Look for Security 4698 (task created) or the TaskScheduler operational log " +
					"around that time, bearing in mind neither may be enabled.",
			},
			Evidence: []model.EvidenceRef{ev},
			Context: map[string]string{
				"principal":    t.Principal,
				"hidden":       fmt.Sprintf("%t", t.Hidden),
				"author":       t.Author,
				"taskcache_not_read": "true: a task registered only in the registry " +
					"TaskCache with its XML removed would not be seen by this check",
			},
		}))
	}

	return check.Result(m.ID, started, env.Now, sources, findings, inventory)
}

func (c *winTaskCheck) Cases() []check.FixtureCase {
	dir := func(root, name string) string {
		return filepath.Join(root, "win-persist-schtask-001", name)
	}
	return []check.FixtureCase{
		{
			Name: "hidden SYSTEM task running an encoded PowerShell command from %TEMP%",
			Kind: check.CasePositive,
			Why: "Exercises TASK-C1, TASK-C2 and TASK-C3 together, and proves UTF-16 task " +
				"XML is decoded correctly.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "positive"), "windows")
			},
			WantOutcome:      model.Detected,
			MinFindings:      1,
			WantTechniqueIDs: []string{"T1053.005"},
		},
		{
			Name: "stock Microsoft maintenance tasks (hidden, SYSTEM) and an Edge updater",
			Kind: check.CaseNegative,
			Why: "The decisive negative case: Microsoft's own tasks are hidden AND run as " +
				"SYSTEM, so a naive check flags a stock install. These must not fire.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "negative"), "windows")
			},
			WantOutcome: model.NotDetected,
		},
		{
			Name: "no Tasks folder",
			Kind: check.CaseNoData,
			Why:  "Nothing to examine: INSUFFICIENT_DATA.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "nodata"), "windows")
			},
			WantOutcome: model.InsufficientData,
		},
		{
			Name: "Tasks folder unreadable (unprivileged scan)",
			Kind: check.CasePermissionDenied,
			Why: "The normal non-Administrator case; must not read as a host with no " +
				"scheduled tasks.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(dir(root, "positive"), "windows")
				if err != nil {
					return env, err
				}
				env.FS = &collect.ErrorFS{
					FileSystem: env.FS,
					DenyPrefix: []string{`C:\Windows\System32\Tasks`, "C:/Windows/System32/Tasks"},
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
