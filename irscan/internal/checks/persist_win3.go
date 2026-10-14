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

func init() { check.Register(&regLoadPointCheck{}) }

// regLoadPointCheck inspects the registry values that cause a DLL to be loaded into a
// privileged process, or a process launch to be hijacked.
//
// One check covers several ATT&CK sub-techniques, and that is deliberate rather than
// convenient: every one of these is the same evidence shape (a named registry value whose
// content must match a documented Windows default), the collector work is identical, and
// the false-positive handling is identical. Crucially, attribution is PER ARTIFACT -- a
// finding about AppInit_DLLs cites T1546.010 and nothing else; a finding about Notification
// Packages cites T1556.002 and nothing else. No finding is ever tagged with a technique its
// artifact does not evidence.
type regLoadPointCheck struct{}

// loadPoint is one registry value this check understands.
type loadPoint struct {
	Hive string
	Path string
	// Value is the value name. When empty, the check enumerates Path's subkeys and reads
	// SubValue inside each (the Image File Execution Options shape).
	Value    string
	SubValue string
	// Technique is the specific ATT&CK ID this artifact evidences.
	Technique string
	// Expected lists the acceptable contents, lowercased. An entry of "" means the value
	// is expected to be absent or empty.
	Expected []string
	// NoLegitimateDefault marks a value whose mere presence is notable (IFEO Debugger).
	NoLegitimateDefault bool
	// Kind is "dll_list", "command" or "debugger"; it selects how content is split.
	Kind string
	// What describes the artifact for the finding text.
	What string
	// SubKeyLabel names what a SubValue entry's enumerated subkey represents ("image" for
	// IFEO, "package" for Winlogon Notify). Defaults to "image" if empty. Needed because
	// the two SubValue-shaped load points enumerate semantically different things, and
	// labelling a Notify package name as an "image" would misdescribe the artifact.
	SubKeyLabel string
}

// loadPoints is the table. Each entry's Expected set is the documented Windows default.
var loadPoints = []loadPoint{
	{
		Hive: "HKLM", Path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
		Value: "Shell", Technique: "T1547.004", Kind: "command",
		Expected: []string{"explorer.exe"},
		What:     "the Winlogon shell, launched for every interactive logon",
	},
	{
		Hive: "HKLM", Path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
		Value: "Userinit", Technique: "T1547.004", Kind: "command",
		Expected: []string{`c:\windows\system32\userinit.exe,`, `userinit.exe,`,
			`c:\windows\system32\userinit.exe`, `userinit.exe`},
		What: "the Winlogon userinit program, launched for every interactive logon",
	},
	{
		// MITRE's own detection strategy for T1547.004 (DET0404) names three Winlogon
		// locations to watch: "Shell, Notify, or Userinit". Shell and Userinit were
		// covered above from the start; Notify was missing until this entry was added
		// after cross-checking this check's coverage against MITRE's Analytic data
		// directly (see STATUS.md). Notify packages are a pre-Vista GINA-era mechanism;
		// on any modern Windows build this key is normally empty, so any populated
		// DLLName value is itself the artifact -- the same shape as IFEO's Debugger value.
		Hive: "HKLM", Path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify`,
		SubValue: "DLLName", Technique: "T1547.004", Kind: "debugger",
		NoLegitimateDefault: true, SubKeyLabel: "package",
		What: "a Winlogon Notify package DLL (a legacy notification-package load point " +
			"still named in MITRE's current detection guidance for this technique)",
	},
	{
		Hive: "HKLM", Path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
		Value: "AppInit_DLLs", Technique: "T1546.010", Kind: "dll_list",
		Expected: []string{""},
		What: "AppInit_DLLs, loaded into every process that links user32.dll",
	},
	{
		Hive: "HKLM", Path: `SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows`,
		Value: "AppInit_DLLs", Technique: "T1546.010", Kind: "dll_list",
		Expected: []string{""},
		What: "AppInit_DLLs (32-bit view), loaded into every process that links user32.dll",
	},
	{
		Hive: "HKLM", Path: `SYSTEM\CurrentControlSet\Control\Lsa`,
		Value: "Authentication Packages", Technique: "T1547.002", Kind: "dll_list",
		Expected: []string{"msv1_0", "relyingpartysuffix"},
		What:     "LSA authentication packages, loaded into LSASS at boot",
	},
	{
		Hive: "HKLM", Path: `SYSTEM\CurrentControlSet\Control\Lsa`,
		Value: "Security Packages", Technique: "T1547.005", Kind: "dll_list",
		Expected: []string{"", "kerberos", "msv1_0", "schannel", "wdigest", "tspkg",
			"pku2u", "cloudap", "negoexts", "ctxsmartcardpsp"},
		What: "LSA security support providers, loaded into LSASS at boot",
	},
	{
		Hive: "HKLM", Path: `SYSTEM\CurrentControlSet\Control\Lsa\OSConfig`,
		Value: "Security Packages", Technique: "T1547.005", Kind: "dll_list",
		Expected: []string{"", "kerberos", "msv1_0", "schannel", "wdigest", "tspkg",
			"pku2u", "cloudap", "negoexts"},
		What: "LSA security support providers (OSConfig view)",
	},
	{
		Hive: "HKLM", Path: `SYSTEM\CurrentControlSet\Control\Lsa`,
		Value: "Notification Packages", Technique: "T1556.002", Kind: "dll_list",
		Expected: []string{"scecli", "rassfm"},
		What: "LSA notification packages (password filters), which receive every password change",
	},
	{
		Hive: "HKLM", Path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`,
		SubValue: "Debugger", Technique: "T1546.012", Kind: "debugger",
		NoLegitimateDefault: true,
		What: "an Image File Execution Options Debugger value, which replaces the program that runs",
	},
}

func (c *regLoadPointCheck) Meta() check.Meta {
	return check.Meta{
		ID:      "WIN-PERSIST-REGLOADPOINT-001",
		Title:   "DLL load point or launch hijack in the registry",
		OS:      []string{"windows"},
		Tactics: []string{"persistence", "privilege-escalation", "credential-access"},
		Techniques: []check.TechniqueMapping{
			{
				TechniqueID: "T1547.004",
				Justification: "The check reads the Winlogon Shell and Userinit values and " +
					"compares them against their documented Windows defaults. Those values " +
					"are precisely the artifact of Winlogon Helper DLL abuse. Findings " +
					"about those two values cite this technique and no other.",
			},
			{
				TechniqueID: "T1546.010",
				Justification: "The check reads AppInit_DLLs in both the native and " +
					"Wow6432Node views, which is exactly the artifact of AppInit DLL abuse.",
			},
			{
				TechniqueID: "T1547.002",
				Justification: "The check reads LSA 'Authentication Packages', the registry " +
					"value this sub-technique is defined by.",
			},
			{
				TechniqueID: "T1547.005",
				Justification: "The check reads LSA 'Security Packages', the registry value " +
					"Security Support Provider abuse adds to.",
			},
			{
				TechniqueID: "T1556.002",
				Justification: "The check reads LSA 'Notification Packages', which is how a " +
					"malicious password filter DLL is registered.",
			},
			{
				TechniqueID: "T1546.012",
				Justification: "The check enumerates Image File Execution Options subkeys " +
					"and reports any Debugger value, which is the artifact of IFEO injection.",
			},
			{
				TechniqueID: "T1547",
				Justification: "Parent technique for the Winlogon, authentication-package " +
					"and SSP load points.",
			},
			{
				TechniqueID: "T1546",
				Justification: "Parent technique for AppInit_DLLs and IFEO, both of which " +
					"execute on the event of a process starting.",
			},
		},
		Sources: []check.SourceRequirement{{
			Name:      "Windows registry DLL load points",
			Privilege: "the HKLM Winlogon, Windows, Lsa and IFEO keys are readable by standard users",
			FailureModes: []string{
				"Registry unavailable (non-Windows host, or a relocated root with no " +
					"fixture registry) -> INSUFFICIENT_DATA, never NOT_DETECTED.",
				"A key is access-denied -> recorded per key -> PERMISSION_DENIED or " +
					"PARTIAL_DATA.",
				"A key that is simply absent is normal (OSConfig and Wow6432Node do not " +
					"exist on every host) and is NOT treated as a visibility gap.",
				"Reading a value does not prove the referenced DLL exists on disk; the " +
					"check reports the configured path, not its presence.",
			},
		}},
		Criteria: []model.Criterion{
			{ID: "RLP-C1", Text: "The value's content deviates from its documented Windows " +
				"default (for example Winlogon Shell is not explorer.exe, or an unknown " +
				"package name appears in the LSA package list)."},
			{ID: "RLP-C2", Text: "A referenced DLL or executable lies outside the Windows " +
				"system directories, so it is not a shipped operating-system component."},
			{ID: "RLP-C3", Text: "A referenced path lies in a user-writable staging " +
				"directory (%TEMP%, %APPDATA%, \\Users\\Public, \\ProgramData, " +
				"\\Windows\\Temp, $Recycle.Bin, \\PerfLogs)."},
			{ID: "RLP-C4", Text: "An Image File Execution Options Debugger value, or a " +
				"Winlogon Notify package DLLName value, is present. Neither has a " +
				"legitimate default, so mere presence is the artifact."},
			{ID: "RLP-C5", Text: "The value invokes a script interpreter, an encoded " +
				"PowerShell command, a signed-binary proxy, or references a remote payload."},
		},
		EscalationCriteria: "Every load point that exists is an observed_artifact for " +
			"Inventory, including the ones holding their default value -- an analyst " +
			"benefits from seeing that Userinit IS correct. One criterion gives " +
			"suspicious_indicator. Corroborated requires a second independent criterion -- " +
			"for example a Userinit value that both deviates from the default (RLP-C1) and " +
			"points into %ProgramData% (RLP-C3). Because these values have narrow, " +
			"documented defaults, a single deviation is already a strong signal and is " +
			"reported as such rather than being diluted.",
		FalsePositiveHandling: "These keys are far less noisy than Run keys, but they are " +
			"not silent. Specifically: (a) a value holding its documented default never " +
			"produces a finding, only an Inventory row; (b) the LSA package lists are " +
			"compared against the full known-good set including the newer cloudap, " +
			"negoexts and pku2u entries, so a modern Windows build does not fire; " +
			"(c) legitimate smart-card and third-party SSP vendors DO add packages, so " +
			"RLP-C1 on an LSA list names that explicitly as the first benign explanation; " +
			"(d) Userinit legitimately appears with and without a full path and with a " +
			"trailing comma, and all those forms are accepted; (e) absence of a key is not " +
			"a finding and not a visibility gap; (f) a valid signature on a referenced DLL " +
			"is not consulted and would be context, not proof.",
		Overlay: check.Overlay{
			Behavior: "An adversary writes a registry value that makes Windows load their " +
				"DLL into a privileged process, or replaces the program a launch resolves " +
				"to. LSASS load points (authentication packages, security packages, " +
				"notification packages) are especially valuable because LSASS handles " +
				"credentials, so a DLL loaded there can capture them at the source.",
			Artifacts: []string{
				`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -- Shell, Userinit`,
				`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\<package> -- DLLName (the third Winlogon location MITRE's T1547.004 detection strategy DET0404 names, alongside Shell and Userinit)`,
				`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows -- AppInit_DLLs (and the Wow6432Node view)`,
				`HKLM\SYSTEM\CurrentControlSet\Control\Lsa -- Authentication Packages, Security Packages, Notification Packages`,
				`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe> -- Debugger`,
			},
			Logic: "Read each load point from the registry via the native API. Compare its " +
				"content against the documented Windows default for that specific value. " +
				"For Image File Execution Options, enumerate subkeys and report any " +
				"Debugger value, since no default exists. Attribute each finding to the " +
				"ATT&CK sub-technique that the specific value evidences. Inventory every " +
				"load point found, including correct ones.",
			FalsePositives: []string{
				"Smart-card middleware and third-party SSP/AP vendors legitimately add LSA " +
					"packages.",
				"Some enterprise password-complexity products legitimately register a " +
					"notification package (password filter).",
				"Accessibility and input-method software has historically used AppInit_DLLs, " +
					"though it is deprecated.",
				"Developers and installers occasionally set an IFEO Debugger value " +
					"deliberately for debugging.",
			},
			Limitations: []string{
				"Reading the configured path does not establish that the DLL exists, nor " +
					"what it does. The check reports configuration, not behaviour.",
				"Referenced DLLs are not hashed or signature-checked by this check.",
				"The registry's last-write time is per key, not per value, so the age of an " +
					"individual value cannot be established.",
				"This check reads current state. A load point added, used and removed " +
					"leaves nothing here; only Sysmon registry events or Security 4657 " +
					"would show it, and neither may be enabled.",
				"Several related load points are deliberately NOT covered here and remain " +
					"PLANNED: Netsh helper DLLs (T1546.007), COM hijacking (T1546.015), " +
					"print processors and port monitors (T1547.012/.010), time providers " +
					"(T1547.003) and network provider DLLs (T1556.008).",
				"AppInit_DLLs is ignored by Windows when Secure Boot is enabled, so a value " +
					"there may be inert; the check reports it regardless and says so.",
			},
			References: []check.Reference{
				{Title: "MITRE ATT&CK T1547.004 Winlogon Helper DLL",
					URL: "https://attack.mitre.org/techniques/T1547/004"},
				{Title: "MITRE ATT&CK T1546.010 AppInit DLLs",
					URL: "https://attack.mitre.org/techniques/T1546/010"},
				{Title: "MITRE ATT&CK T1547.002 Authentication Package",
					URL: "https://attack.mitre.org/techniques/T1547/002"},
				{Title: "MITRE ATT&CK T1547.005 Security Support Provider",
					URL: "https://attack.mitre.org/techniques/T1547/005"},
				{Title: "MITRE ATT&CK T1556.002 Password Filter DLL",
					URL: "https://attack.mitre.org/techniques/T1556/002"},
				{Title: "MITRE ATT&CK T1546.012 Image File Execution Options Injection",
					URL: "https://attack.mitre.org/techniques/T1546/012"},
				{Title: "MITRE ATT&CK Detection Strategy DET0404 (names Shell, Notify and " +
					"Userinit as the Winlogon locations for T1547.004 -- cross-checked " +
					"directly against the pinned STIX bundle to find the Notify gap this " +
					"check closes)",
					URL: "https://attack.mitre.org/detectionstrategies/DET0404"},
			},
		},
		Validation:        model.FixtureTested,
		FixtureProvenance: model.Synthetic,
	}
}

// parentOf returns the top-level technique for a sub-technique ID.
func parentOf(id string) string {
	if i := strings.Index(id, "."); i > 0 {
		return id[:i]
	}
	return id
}

func (c *regLoadPointCheck) Run(ctx context.Context, env check.Env) model.CheckResult {
	started := env.Now()
	m := c.Meta()

	src := collect.SourceResult{
		Name:      m.Sources[0].Name,
		Privilege: m.Sources[0].Privilege,
	}
	if ok, reason := env.Registry.Available(); !ok {
		src.Available = false
		src.Reason = reason
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

	for _, lp := range loadPoints {
		if err := ctx.Err(); err != nil {
			return check.ErrorResult(m.ID, started, env.Now, err)
		}
		info, err := env.Registry.OpenKey(lp.Hive, lp.Path)
		if err != nil {
			if strings.Contains(err.Error(), "permission denied") {
				src.Errors = append(src.Errors,
					fmt.Sprintf("access denied reading %s\\%s", lp.Hive, lp.Path))
			}
			// A missing key is normal (OSConfig and Wow6432Node are not on every host)
			// and is deliberately not treated as a visibility gap.
			continue
		}

		if lp.SubValue != "" {
			// IFEO shape: enumerate subkeys and read the named value in each.
			for _, sub := range info.SubKeys {
				subInfo, serr := env.Registry.OpenKey(lp.Hive, lp.Path+`\`+sub)
				if serr != nil {
					if strings.Contains(serr.Error(), "permission denied") {
						src.Errors = append(src.Errors, fmt.Sprintf(
							"access denied reading %s\\%s\\%s", lp.Hive, lp.Path, sub))
					}
					continue
				}
				src.ItemsSeen++
				for _, v := range subInfo.Values {
					if !strings.EqualFold(v.Name, lp.SubValue) || strings.TrimSpace(v.String) == "" {
						continue
					}
					label := lp.SubKeyLabel
					if label == "" {
						label = "image"
					}
					f, inv := c.assess(env, m, byID, lp, subInfo.Path, v,
						fmt.Sprintf("%s for %s %q", lp.What, label, sub))
					inventory = append(inventory, inv)
					if f != nil {
						findings = append(findings, *f)
					}
				}
			}
			continue
		}

		for _, v := range info.Values {
			if !strings.EqualFold(v.Name, lp.Value) {
				continue
			}
			src.ItemsSeen++
			f, inv := c.assess(env, m, byID, lp, info.Path, v, lp.What)
			inventory = append(inventory, inv)
			if f != nil {
				findings = append(findings, *f)
			}
		}
	}

	return check.Result(m.ID, started, env.Now,
		[]model.DataSourceStatus{check.SourceStatus(m.Sources[0], src)}, findings, inventory)
}

// assess evaluates one load-point value, returning a finding (or nil) and an inventory row.
func (c *regLoadPointCheck) assess(env check.Env, m check.Meta,
	byID map[string]model.Criterion, lp loadPoint, keyPath string,
	v collect.RegValue, what string) (*model.Finding, model.InventoryItem) {

	artifactID := keyPath + `\` + v.Name
	// Per-artifact attribution: ONLY the technique this specific value evidences, plus its
	// parent. No finding is tagged with a technique its artifact does not support.
	techniques := []string{lp.Technique, parentOf(lp.Technique)}

	content := strings.TrimSpace(v.String)
	parts := splitLoadPointContent(lp.Kind, content)

	inv := model.InventoryItem{
		Group:        "windows registry load points",
		ArtifactType: "windows_registry_load_point",
		ArtifactID:   artifactID,
		Attributes: map[string]string{
			"value":      Truncate(content, 200),
			"type":       string(v.Type),
			"technique":  lp.Technique,
			"what":       what,
			"at_default": fmt.Sprintf("%t", matchesExpected(lp, parts)),
		},
		TechniqueIDs: techniques,
		CheckIDs:     []string{m.ID},
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

	if lp.NoLegitimateDefault {
		add("RLP-C4")
	} else if !matchesExpected(lp, parts) {
		add("RLP-C1")
	}

	for _, p := range parts {
		if p == "" {
			continue
		}
		ref := FirstArg(p)
		// A bare package NAME (no path, no extension) is how the LSA lists normally
		// reference a DLL in System32, so it is not "outside the system directories".
		if strings.ContainsAny(ref, `\/`) || strings.HasSuffix(strings.ToLower(ref), ".dll") ||
			strings.HasSuffix(strings.ToLower(ref), ".exe") {
			if strings.ContainsAny(ref, `\/`) && !inWindowsSystemDir(ref) {
				add("RLP-C2")
			}
		}
		if _, hit := InWindowsTransientDir(ref); hit {
			add("RLP-C3")
		}
		if len(WindowsCommandSignals(p)) > 0 {
			add("RLP-C5")
		}
	}

	if len(matched) == 0 {
		return nil, inv
	}

	level := model.SuspiciousIndicator
	if len(matched) >= 2 {
		level = model.Corroborated
	}

	f := check.NewFinding(env, m.ID, check.FindingSpec{
		ArtifactType: "windows_registry_load_point",
		ArtifactID:   artifactID,
		Level:        level,
		TechniqueIDs: techniques,
		Title: fmt.Sprintf("registry load point %s\\%s matches %d criteria",
			baseWindowsKey(keyPath), v.Name, len(matched)),
		WhatAndWhere: fmt.Sprintf(
			"%s is %s. Value: %s. Documented default: %s.",
			artifactID, what, Truncate(content, 300), describeExpected(lp)),
		Criteria: matched,
		Benign: []string{
			"Smart-card middleware and third-party SSP/AP vendors legitimately add LSA " +
				"packages.",
			"Enterprise password-complexity products legitimately register a notification " +
				"package (password filter).",
			"A developer or installer may deliberately set an IFEO Debugger value.",
			"Accessibility and input-method software has historically used AppInit_DLLs.",
		},
		NextPivot: []string{
			"Identify the referenced DLL or executable on disk and establish which product " +
				"owns it (a valid signature is context, not proof).",
			"Compare this value against the same value on a known-good peer host built " +
				"from the same image -- for these narrow-default values that comparison is " +
				"decisive.",
			"Check the key's last-write time to bound when the change happened.",
			"For an LSASS load point, treat credential exposure as likely and plan " +
				"credential rotation accordingly.",
		},
		Evidence: []model.EvidenceRef{check.RegistryEvidence(env, keyPath, v)},
		Context: map[string]string{
			"technique":        lp.Technique,
			"documented_default": describeExpected(lp),
			"note": "This check reports CONFIGURATION. It does not establish that the " +
				"referenced DLL exists, is loaded, or is malicious.",
		},
	})
	return &f, inv
}

func splitLoadPointContent(kind, content string) []string {
	switch kind {
	case "dll_list":
		// REG_MULTI_SZ renders joined with " | "; AppInit_DLLs uses spaces or commas.
		repl := strings.NewReplacer(" | ", "\n", ",", "\n", ";", "\n")
		var out []string
		for _, p := range strings.Split(repl.Replace(content), "\n") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		if len(out) == 0 {
			return []string{""}
		}
		return out
	default:
		return []string{content}
	}
}

func matchesExpected(lp loadPoint, parts []string) bool {
	if lp.NoLegitimateDefault {
		return false
	}
	for _, p := range parts {
		q := strings.ToLower(strings.TrimSpace(strings.Trim(p, `"`)))
		// A bare package name may appear with or without a .dll suffix.
		q = strings.TrimSuffix(q, ".dll")
		ok := false
		for _, e := range lp.Expected {
			if q == strings.TrimSuffix(strings.ToLower(e), ".dll") {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func describeExpected(lp loadPoint) string {
	if lp.NoLegitimateDefault {
		return "no legitimate default exists for this value"
	}
	var shown []string
	for _, e := range lp.Expected {
		if e == "" {
			shown = append(shown, "(empty)")
		} else {
			shown = append(shown, e)
		}
	}
	return strings.Join(shown, ", ")
}

func baseWindowsKey(p string) string {
	p = strings.TrimRight(strings.ReplaceAll(p, "/", `\`), `\`)
	if i := strings.LastIndex(p, `\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func (c *regLoadPointCheck) Cases() []check.FixtureCase {
	base := func(root, name string) string {
		return filepath.Join(root, "win-persist-regloadpoint-001", name)
	}

	// A realistic modern Windows LSA/Winlogon configuration, all at defaults.
	benign := func() *collect.FakeRegistry {
		r := collect.NewFakeRegistry()
		r.Set("HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
			collect.RegKeyInfo{Values: []collect.RegValue{
				{Name: "Shell", Type: collect.RegSZ, String: "explorer.exe"},
				{Name: "Userinit", Type: collect.RegSZ,
					String: `C:\Windows\system32\userinit.exe,`},
			}})
		r.Set("HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
			collect.RegKeyInfo{Values: []collect.RegValue{
				{Name: "AppInit_DLLs", Type: collect.RegSZ, String: ""},
			}})
		r.Set("HKLM", `SYSTEM\CurrentControlSet\Control\Lsa`,
			collect.RegKeyInfo{Values: []collect.RegValue{
				{Name: "Authentication Packages", Type: collect.RegMultiSZ,
					Multi:  []string{"msv1_0"},
					String: "msv1_0"},
				{Name: "Security Packages", Type: collect.RegMultiSZ,
					Multi: []string{"kerberos", "msv1_0", "schannel", "wdigest", "tspkg",
						"pku2u", "cloudap", "negoexts"},
					String: "kerberos | msv1_0 | schannel | wdigest | tspkg | pku2u | cloudap | negoexts"},
				{Name: "Notification Packages", Type: collect.RegMultiSZ,
					Multi:  []string{"scecli"},
					String: "scecli"},
			}})
		// IFEO exists on every Windows host with legitimate subkeys that carry no
		// Debugger value -- so the key's presence alone must not fire.
		r.Set("HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`,
			collect.RegKeyInfo{SubKeys: []string{"dfsvc.exe", "javaw.exe"}})
		r.Set("HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dfsvc.exe`,
			collect.RegKeyInfo{Values: []collect.RegValue{
				{Name: "MitigationOptions", Type: collect.RegQWord, Number: 0x1000, String: "4096"},
			}})
		r.Set("HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\javaw.exe`,
			collect.RegKeyInfo{Values: []collect.RegValue{
				{Name: "DisableExceptionChainValidation", Type: collect.RegDWord, Number: 0, String: "0"},
			}})
		return r
	}

	malicious := func() *collect.FakeRegistry {
		r := benign()
		// Userinit appended with a second program from ProgramData: RLP-C1 + RLP-C2/C3.
		r.Set("HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
			collect.RegKeyInfo{Values: []collect.RegValue{
				{Name: "Shell", Type: collect.RegSZ, String: "explorer.exe"},
				{Name: "Userinit", Type: collect.RegSZ,
					String: `C:\Windows\system32\userinit.exe,C:\ProgramData\Intel\drvupd.exe`},
			}})
		// A rogue password filter registered alongside scecli: RLP-C1 on T1556.002.
		r.Set("HKLM", `SYSTEM\CurrentControlSet\Control\Lsa`,
			collect.RegKeyInfo{Values: []collect.RegValue{
				{Name: "Authentication Packages", Type: collect.RegMultiSZ,
					Multi: []string{"msv1_0"}, String: "msv1_0"},
				{Name: "Security Packages", Type: collect.RegMultiSZ,
					Multi: []string{"kerberos", "msv1_0", "schannel", "wdigest", "tspkg",
						"pku2u", "cloudap", "negoexts"},
					String: "kerberos | msv1_0 | schannel | wdigest | tspkg | pku2u | cloudap | negoexts"},
				{Name: "Notification Packages", Type: collect.RegMultiSZ,
					Multi:  []string{"scecli", "pwmon"},
					String: "scecli | pwmon"},
			}})
		// IFEO Debugger hijacking a common binary: RLP-C4.
		r.Set("HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`,
			collect.RegKeyInfo{SubKeys: []string{"dfsvc.exe", "sethc.exe"}})
		r.Set("HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe`,
			collect.RegKeyInfo{Values: []collect.RegValue{
				{Name: "Debugger", Type: collect.RegSZ, String: `C:\Windows\System32\cmd.exe`},
			}})
		// Winlogon Notify package DLL: RLP-C4, the gap found by cross-checking this check
		// against MITRE's own T1547.004 detection strategy (DET0404), which names Shell,
		// Notify and Userinit as the three Winlogon locations to watch.
		r.Set("HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify`,
			collect.RegKeyInfo{SubKeys: []string{"legacyhook"}})
		r.Set("HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\legacyhook`,
			collect.RegKeyInfo{Values: []collect.RegValue{
				{Name: "DLLName", Type: collect.RegSZ, String: `C:\ProgramData\legacyhook.dll`},
			}})
		return r
	}

	return []check.FixtureCase{
		{
			Name: "appended Userinit, rogue password filter and an IFEO Debugger",
			Kind: check.CasePositive,
			Why: "Exercises three different load points and proves per-artifact ATT&CK " +
				"attribution: the Userinit finding must cite T1547.004, the notification " +
				"package finding T1556.002, and the IFEO finding T1546.012.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(base(root, "positive"), "windows")
				if err != nil {
					return env, err
				}
				env.Registry = malicious()
				return env, nil
			},
			WantOutcome: model.Detected,
			MinFindings: 4,
			WantTechniqueIDs: []string{
				"T1547.004", "T1556.002", "T1546.012",
			},
		},
		{
			Name: "modern Windows defaults including cloudap/negoexts and benign IFEO subkeys",
			Kind: check.CaseNegative,
			Why: "The decisive negative: a current Windows build has a long Security " +
				"Packages list and populated IFEO subkeys. A check with a stale known-good " +
				"set, or one that fires on IFEO's existence, flags every host.",
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
			Why:  "Nothing examined: INSUFFICIENT_DATA.",
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
			Name: "load point keys access-denied",
			Kind: check.CasePermissionDenied,
			Why: "Denied keys must surface as reduced visibility, not as a host with " +
				"default load points.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(base(root, "nodata"), "windows")
				if err != nil {
					return env, err
				}
				r := collect.NewFakeRegistry()
				for _, lp := range loadPoints {
					r.Set(lp.Hive, lp.Path, collect.RegKeyInfo{})
					r.Deny(lp.Hive, lp.Path)
				}
				env.Registry = r
				return env, nil
			},
			WantOutcome: model.PartialData,
			AlsoAccept:  []model.Outcome{model.PermissionDenied, model.InsufficientData},
		},
	}
}
