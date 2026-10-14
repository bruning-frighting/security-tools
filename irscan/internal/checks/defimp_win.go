package checks

import (
	"irscan/internal/check"
	"irscan/internal/collect"
	"irscan/internal/model"
)

func init() {
	check.Register(defenderCheck(), firewallCheck(), eventLogPolicyCheck())
}

// Registry paths, named once so the fixtures and the checks cannot drift apart.
const (
	defPolicy   = `SOFTWARE\Policies\Microsoft\Windows Defender`
	defProduct  = `SOFTWARE\Microsoft\Windows Defender`
	fwService   = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`
	fwPolicy    = `SOFTWARE\Policies\Microsoft\WindowsFirewall`
	winevt      = `SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels`
	psPolicy    = `SOFTWARE\Policies\Microsoft\Windows\PowerShell`
)

// =======================================================================================
// WIN-DEFIMP-DEFENDER-001
// =======================================================================================

func defenderCheck() *regPolicyCheck {
	return &regPolicyCheck{
		id:      "WIN-DEFIMP-DEFENDER-001",
		title:   "Microsoft Defender disabled, tampered with, or given exclusions",
		tactics: []string{"defense-impairment"},
		techniques: []check.TechniqueMapping{
			{
				TechniqueID: "T1685.007",
				Justification: "This sub-technique is Impair Autonomous Defenses. The check " +
					"reads the Defender policy and product values that switch off " +
					"antimalware, real-time, behaviour and on-access protection, which are " +
					"exactly those artifacts. Findings about those values cite this " +
					"technique and no other.",
			},
			{
				TechniqueID: "T1685",
				Justification: "Parent technique (Disable or Modify Tools): disabling " +
					"Defender is the canonical instance on Windows.",
			},
			{
				TechniqueID: "T1564.012",
				Justification: "This sub-technique is File/Path Exclusions. The check " +
					"enumerates Defender's Exclusions\\Paths, \\Extensions and \\Processes " +
					"keys, which ARE the artifact of adding an exclusion so a payload is " +
					"not scanned. Exclusion findings cite this technique, not T1685.007.",
			},
			{
				TechniqueID: "T1564",
				Justification: "Parent technique (Hide Artifacts) for the exclusion artifacts.",
			},
		},
		sourceName: "Microsoft Defender policy and exclusion registry keys",
		sourcePrivilege: "the Defender policy keys are readable by standard users; some " +
			"product keys under SOFTWARE\\Microsoft\\Windows Defender are ACL'd to SYSTEM " +
			"and need Administrator",
		sourceFailures: []string{
			"Registry unavailable -> INSUFFICIENT_DATA, never 'Defender is fine'.",
			"A key ACL'd to SYSTEM is access-denied to an unprivileged scan -> the value's " +
				"state is recorded as UNKNOWN, not as enabled, and the result is " +
				"PARTIAL_DATA. Inferring 'enabled' from 'could not read' would be the worst " +
				"possible error for this check.",
			"A key that is simply absent means the setting is unmanaged, which for these " +
				"values is the secure default and is NOT a visibility gap.",
			"Defender may be legitimately absent (a third-party AV product replaced it); " +
				"the check reports configuration, not product presence.",
		},
		criteria: []model.Criterion{
			{ID: "DEF-C1", Text: "A Defender protection is EXPLICITLY disabled by a policy " +
				"or product value (DisableAntiSpyware, DisableRealtimeMonitoring, " +
				"DisableBehaviorMonitoring, DisableOnAccessProtection set to 1)."},
			{ID: "DEF-C2", Text: "Tamper Protection is off, which is what must be defeated " +
				"first before the other Defender settings can be changed at all."},
			{ID: "DEF-C3", Text: "Antivirus exclusions are configured. Reported as one " +
				"aggregated finding per exclusion list, with entries covering " +
				"user-writable or whole-volume paths called out separately."},
		},
		values: []policyValue{
			{Hive: "HKLM", Path: defPolicy, Value: "DisableAntiSpyware",
				What: "Defender antimalware protection (policy DisableAntiSpyware)",
				DisabledWhen: []uint64{1}, AbsentMeans: "enabled",
				Criterion: "DEF-C1", Technique: "T1685.007"},
			{Hive: "HKLM", Path: defPolicy + `\Real-Time Protection`,
				Value: "DisableRealtimeMonitoring",
				What:  "Defender real-time monitoring (policy DisableRealtimeMonitoring)",
				DisabledWhen: []uint64{1}, AbsentMeans: "enabled",
				Criterion: "DEF-C1", Technique: "T1685.007"},
			{Hive: "HKLM", Path: defPolicy + `\Real-Time Protection`,
				Value: "DisableBehaviorMonitoring",
				What:  "Defender behaviour monitoring (policy DisableBehaviorMonitoring)",
				DisabledWhen: []uint64{1}, AbsentMeans: "enabled",
				Criterion: "DEF-C1", Technique: "T1685.007"},
			{Hive: "HKLM", Path: defPolicy + `\Real-Time Protection`,
				Value: "DisableOnAccessProtection",
				What:  "Defender on-access protection (policy DisableOnAccessProtection)",
				DisabledWhen: []uint64{1}, AbsentMeans: "enabled",
				Criterion: "DEF-C1", Technique: "T1685.007"},
			{Hive: "HKLM", Path: defProduct + `\Features`, Value: "TamperProtection",
				What: "Defender Tamper Protection (product Features\\TamperProtection; " +
					"5 means enabled)",
				// 0 and 4 are the observed "off" states; absence is common on older builds
				// and on hosts where Defender is not the active product, so absence is
				// deliberately NEUTRAL rather than reported as disabled.
				DisabledWhen: []uint64{0, 4}, AbsentMeans: "neutral",
				Criterion: "DEF-C2", Technique: "T1685.007"},
		},
		exclusions: []exclusionKey{
			{Hive: "HKLM", Path: defProduct + `\Exclusions\Paths`,
				What: "Defender path exclusions", Kind: "path",
				Criterion: "DEF-C3", Technique: "T1564.012"},
			{Hive: "HKLM", Path: defProduct + `\Exclusions\Extensions`,
				What: "Defender extension exclusions", Kind: "extension",
				Criterion: "DEF-C3", Technique: "T1564.012"},
			{Hive: "HKLM", Path: defProduct + `\Exclusions\Processes`,
				What: "Defender process exclusions", Kind: "process",
				Criterion: "DEF-C3", Technique: "T1564.012"},
			{Hive: "HKLM", Path: defPolicy + `\Exclusions\Paths`,
				What: "Defender path exclusions set by policy", Kind: "path",
				Criterion: "DEF-C3", Technique: "T1564.012"},
		},
		artifactType:   "windows_defender_setting",
		inventoryGroup: "defender configuration",
		escalation: "Each disabled protection and each exclusion list is reported at " +
			"suspicious_indicator. This check deliberately does NOT escalate to " +
			"corroborated on its own: configuration state shows that a protection is off, " +
			"not that an adversary turned it off, and administrators disable these settings " +
			"legitimately. Corroboration must come from a second, independent source -- the " +
			"key's last-write time correlating with other activity, or a persistence " +
			"finding inside an excluded path -- and that is an analyst judgement, not " +
			"something this check may assert.",
		fpHandling: "Defender exclusions are explicitly named in the specification as a " +
			"known-noisy area, and they are: vendor guidance for SQL Server, Exchange, " +
			"Hyper-V, domain controllers and build agents all mandate exclusions, so large " +
			"estates legitimately carry long lists. Therefore: (a) exclusions produce ONE " +
			"aggregated finding per list, never one per entry, so a 200-entry legitimate " +
			"list cannot bury an analyst; (b) entries covering user-writable or " +
			"whole-volume paths are counted and listed SEPARATELY, because those are the " +
			"ones worth triaging first; (c) vendor-required exclusions are named as the " +
			"first benign explanation; (d) the check never escalates above " +
			"suspicious_indicator on configuration alone; (e) an ABSENT setting is treated " +
			"as the secure default and produces nothing, so a stock host is silent; " +
			"(f) a key that could not be READ is recorded as UNKNOWN rather than enabled.",
		overlay: check.Overlay{
			Behavior: "An adversary disables Microsoft Defender, or adds an exclusion for " +
				"the directory their payload lives in, so their tooling is neither blocked " +
				"nor recorded. Adding an exclusion is often preferred over disabling the " +
				"product outright because the endpoint continues to look healthy.",
			Artifacts: []string{
				`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender -- DisableAntiSpyware`,
				`...\Windows Defender\Real-Time Protection -- DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableOnAccessProtection`,
				`HKLM\SOFTWARE\Microsoft\Windows Defender\Features -- TamperProtection`,
				`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\{Paths,Extensions,Processes}`,
				`The policy-set exclusion key under SOFTWARE\Policies\...\Exclusions\Paths`,
			},
			Logic: "Read each Defender policy and product value and compare it against the " +
				"documented secure default, distinguishing EXPLICITLY DISABLED from absent " +
				"(unmanaged, secure) and from unreadable (unknown). Enumerate each " +
				"exclusion key and aggregate its entries into a single finding, " +
				"separately counting entries that cover user-writable or whole-volume " +
				"paths. Inventory every setting, including the correctly configured ones.",
			FalsePositives: []string{
				"A host running a third-party AV product legitimately has Defender's " +
					"real-time protection disabled.",
				"Vendor documentation for SQL Server, Exchange, Hyper-V and build agents " +
					"mandates specific exclusions.",
				"Developer workstations and CI runners are commonly excluded for performance.",
				"Older Windows builds do not expose TamperProtection at all.",
			},
			Limitations: []string{
				"This reads CONFIGURATION, not product health. It cannot tell whether the " +
					"Defender service is actually running, nor whether its signatures are " +
					"current.",
				"Some product keys are ACL'd to SYSTEM, so an unprivileged scan cannot read " +
					"them and their state is reported UNKNOWN rather than guessed.",
				"The check cannot tell WHO disabled a protection or WHEN beyond the key's " +
					"last-write time, which is per key rather than per value.",
				"Defender's own operational event log (Microsoft-Windows-Windows " +
					"Defender/Operational) is NOT read by this build, so a protection that " +
					"was disabled and re-enabled leaves nothing here.",
				"Third-party endpoint products are out of scope entirely: their equivalent " +
					"settings are not examined, so a host protected only by a disabled " +
					"third-party agent looks clean to this check.",
				"An exclusion removed before the scan is invisible.",
			},
			References: []check.Reference{
				{Title: "MITRE ATT&CK T1685.007 Impair Autonomous Defenses",
					URL: "https://attack.mitre.org/techniques/T1685/007"},
				{Title: "MITRE ATT&CK T1564.012 File/Path Exclusions",
					URL: "https://attack.mitre.org/techniques/T1564/012"},
				{Title: "MITRE ATT&CK T1685 Disable or Modify Tools",
					URL: "https://attack.mitre.org/techniques/T1685"},
			},
		},
		fixtureDir:     "win-defimp-defender-001",
		wantTechniques: []string{"T1685.007", "T1564.012"},
		minFindings:    2,
		positiveWhy: "Real-time protection explicitly disabled, Tamper Protection off, and " +
			"a path exclusion covering %ProgramData%. Proves per-artifact attribution: the " +
			"disabled-protection findings cite T1685.007 and the exclusion finding cites " +
			"T1564.012.",
		negativeWhy: "A stock host where the policy keys are ABSENT (unmanaged, which is " +
			"the secure default) and Tamper Protection is 5. Proves absence is not read as " +
			"disabled -- otherwise every default Windows install would fire.",
		positiveReg: func() *collect.FakeRegistry {
			r := collect.NewFakeRegistry()
			r.Set("HKLM", defPolicy, collect.RegKeyInfo{Values: []collect.RegValue{
				{Name: "DisableAntiSpyware", Type: collect.RegDWord, Number: 1, String: "1"},
			}})
			r.Set("HKLM", defPolicy+`\Real-Time Protection`,
				collect.RegKeyInfo{Values: []collect.RegValue{
					{Name: "DisableRealtimeMonitoring", Type: collect.RegDWord,
						Number: 1, String: "1"},
				}})
			r.Set("HKLM", defProduct+`\Features`,
				collect.RegKeyInfo{Values: []collect.RegValue{
					{Name: "TamperProtection", Type: collect.RegDWord, Number: 0, String: "0"},
				}})
			r.Set("HKLM", defProduct+`\Exclusions\Paths`,
				collect.RegKeyInfo{Values: []collect.RegValue{
					{Name: `C:\ProgramData\Intel\drv`, Type: collect.RegSZ, String: "0"},
					{Name: `C:\Windows\Temp`, Type: collect.RegSZ, String: "0"},
				}})
			return r
		},
		negativeReg: func() *collect.FakeRegistry {
			r := collect.NewFakeRegistry()
			// The policy keys are absent entirely, which is the stock state.
			r.Set("HKLM", defProduct+`\Features`,
				collect.RegKeyInfo{Values: []collect.RegValue{
					{Name: "TamperProtection", Type: collect.RegDWord, Number: 5, String: "5"},
				}})
			// An empty exclusions key must produce nothing.
			r.Set("HKLM", defProduct+`\Exclusions\Paths`, collect.RegKeyInfo{})
			return r
		},
	}
}

// =======================================================================================
// WIN-DEFIMP-FIREWALL-001
// =======================================================================================

func firewallCheck() *regPolicyCheck {
	profile := func(base, name, tech string) policyValue {
		return policyValue{
			Hive: "HKLM", Path: base + `\` + name + "Profile", Value: "EnableFirewall",
			What:         "Windows host firewall, " + name + " profile",
			DisabledWhen: []uint64{0}, AbsentMeans: "enabled",
			Criterion: "FW-C1", Technique: tech,
		}
	}
	return &regPolicyCheck{
		id:      "WIN-DEFIMP-FIREWALL-001",
		title:   "Windows host firewall profile disabled",
		tactics: []string{"defense-impairment"},
		techniques: []check.TechniqueMapping{
			{
				TechniqueID: "T1686.003",
				Justification: "This sub-technique is Windows Host Firewall. The check reads " +
					"the EnableFirewall value for each profile in both the service " +
					"configuration and the group-policy location, which are precisely the " +
					"artifacts of disabling it.",
			},
			{
				TechniqueID: "T1686",
				Justification: "Parent technique (Disable or Modify System Firewall).",
			},
		},
		sourceName:      "Windows firewall profile registry values",
		sourcePrivilege: "readable by standard users",
		sourceFailures: []string{
			"Registry unavailable -> INSUFFICIENT_DATA, never 'the firewall is on'.",
			"A profile key access-denied -> that profile's state is UNKNOWN and the result " +
				"is PARTIAL_DATA.",
			"Absence of EnableFirewall means the default (enabled) applies, which is NOT a " +
				"visibility gap.",
			"The group-policy location may be absent on an unmanaged host; that is normal.",
		},
		criteria: []model.Criterion{
			{ID: "FW-C1", Text: "A Windows firewall profile has EnableFirewall explicitly " +
				"set to 0, so inbound filtering is off for that profile."},
		},
		values: []policyValue{
			profile(fwService, "Domain", "T1686.003"),
			profile(fwService, "Standard", "T1686.003"),
			profile(fwService, "Public", "T1686.003"),
			profile(fwPolicy, "Domain", "T1686.003"),
			profile(fwPolicy, "Standard", "T1686.003"),
			profile(fwPolicy, "Public", "T1686.003"),
		},
		artifactType:   "windows_firewall_profile",
		inventoryGroup: "firewall configuration",
		escalation: "Each disabled profile is reported at suspicious_indicator. The check " +
			"does not escalate on its own: disabling a profile is a routine, if unwise, " +
			"administrative act, and a second independent signal (a listening service that " +
			"appeared at the same time, or a correlated persistence finding) is required to " +
			"corroborate, which is an analyst judgement.",
		fpHandling: "Firewall state is genuinely often disabled for benign reasons, so: " +
			"(a) only an EXPLICIT 0 fires -- absence means the enabled default and produces " +
			"nothing; (b) hosts behind a third-party endpoint firewall legitimately have " +
			"the built-in profiles off, which is the first benign explanation on every " +
			"finding; (c) both the service and the group-policy locations are read and " +
			"reported separately, so an analyst can see whether the change was local or " +
			"pushed by GPO -- a locally disabled profile on a GPO-managed estate is the " +
			"interesting case; (d) the check never claims the firewall was disabled by an " +
			"adversary.",
		overlay: check.Overlay{
			Behavior: "An adversary disables the host firewall so their listener, lateral " +
				"movement or exfiltration channel is not blocked. It is often done per " +
				"profile rather than wholesale, which is quieter.",
			Artifacts: []string{
				`HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{Domain,Standard,Public}Profile -- EnableFirewall`,
				`HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\{Domain,Standard,Public}Profile -- EnableFirewall (group policy)`,
			},
			Logic: "Read EnableFirewall for all three profiles in both the service and " +
				"group-policy locations. Report only an explicit 0. Inventory all six " +
				"values including the enabled ones, so an analyst can see the whole posture.",
			FalsePositives: []string{
				"A host protected by a third-party endpoint firewall legitimately has the " +
					"built-in profiles disabled.",
				"Lab, build and imaging hosts are commonly configured with the firewall off.",
				"Some appliance-style images ship with a profile disabled.",
			},
			Limitations: []string{
				"Only the on/off state is read. The actual RULE SET is not examined, so an " +
					"'enabled' firewall carrying a permissive allow-any inbound rule looks " +
					"healthy to this check. That is a significant gap and the rule set is " +
					"listed as PLANNED.",
				"The effective policy is a merge of local and group-policy settings; the " +
					"check reports both locations rather than computing the merge.",
				"A profile disabled and re-enabled before the scan leaves nothing here.",
				"Third-party firewall products are not examined at all.",
			},
			References: []check.Reference{
				{Title: "MITRE ATT&CK T1686.003 Windows Host Firewall",
					URL: "https://attack.mitre.org/techniques/T1686/003"},
				{Title: "MITRE ATT&CK T1686 Disable or Modify System Firewall",
					URL: "https://attack.mitre.org/techniques/T1686"},
			},
		},
		fixtureDir:     "win-defimp-firewall-001",
		wantTechniques: []string{"T1686.003"},
		minFindings:    1,
		positiveWhy: "Two profiles explicitly set to 0 while the third stays enabled, " +
			"proving per-profile reporting rather than an all-or-nothing verdict.",
		negativeWhy: "All profiles enabled, and the group-policy key absent entirely. " +
			"Proves that an unmanaged host (no GPO firewall key) is not reported as " +
			"disabled -- the most likely false positive for this check.",
		positiveReg: func() *collect.FakeRegistry {
			r := collect.NewFakeRegistry()
			r.Set("HKLM", fwService+`\DomainProfile`,
				collect.RegKeyInfo{Values: []collect.RegValue{
					{Name: "EnableFirewall", Type: collect.RegDWord, Number: 1, String: "1"},
				}})
			r.Set("HKLM", fwService+`\StandardProfile`,
				collect.RegKeyInfo{Values: []collect.RegValue{
					{Name: "EnableFirewall", Type: collect.RegDWord, Number: 0, String: "0"},
				}})
			r.Set("HKLM", fwService+`\PublicProfile`,
				collect.RegKeyInfo{Values: []collect.RegValue{
					{Name: "EnableFirewall", Type: collect.RegDWord, Number: 0, String: "0"},
				}})
			return r
		},
		negativeReg: func() *collect.FakeRegistry {
			r := collect.NewFakeRegistry()
			for _, p := range []string{"DomainProfile", "StandardProfile", "PublicProfile"} {
				r.Set("HKLM", fwService+`\`+p,
					collect.RegKeyInfo{Values: []collect.RegValue{
						{Name: "EnableFirewall", Type: collect.RegDWord,
							Number: 1, String: "1"},
					}})
			}
			return r
		},
	}
}

// =======================================================================================
// WIN-DEFIMP-EVENTLOG-001
// =======================================================================================

func eventLogPolicyCheck() *regPolicyCheck {
	return &regPolicyCheck{
		id:      "WIN-DEFIMP-EVENTLOG-001",
		title:   "Windows event logging or script logging disabled",
		tactics: []string{"defense-impairment"},
		techniques: []check.TechniqueMapping{
			{
				TechniqueID: "T1685.001",
				Justification: "This sub-technique is Disable or Modify Windows Event Log. " +
					"The check reads the WINEVT channel Enabled values and the PowerShell " +
					"script-block-logging and transcription policy values, which are the " +
					"registry artifacts of turning that logging off.",
			},
			{
				TechniqueID: "T1685",
				Justification: "Parent technique: disabling the Sysmon driver service, also " +
					"read here, is disabling a defensive tool rather than a Windows log " +
					"channel specifically.",
			},
		},
		sourceName:      "Windows event log and script logging policy values",
		sourcePrivilege: "the WINEVT and PowerShell policy keys are readable by standard users",
		sourceFailures: []string{
			"Registry unavailable -> INSUFFICIENT_DATA, never 'logging is on'.",
			"A key access-denied -> that setting's state is UNKNOWN -> PARTIAL_DATA.",
			"Script block logging absent means NOT CONFIGURED, which is the Windows " +
				"default. That is a real visibility gap but it is not evidence of " +
				"tampering, so absence is treated as neutral and does not fire; only an " +
				"explicit 0 does.",
			"The Sysmon service key is absent on hosts without Sysmon, which is normal.",
		},
		criteria: []model.Criterion{
			{ID: "EVT-C1", Text: "A Windows event log channel has Enabled explicitly set " +
				"to 0, so that channel records nothing."},
			{ID: "EVT-C2", Text: "PowerShell script block logging or transcription is " +
				"explicitly set to 0. Someone turning it OFF is different from it never " +
				"having been turned on, and only the former matches."},
			{ID: "EVT-C3", Text: "The Sysmon driver service start type is set to disabled " +
				"(4) while the service is still installed."},
		},
		values: []policyValue{
			{Hive: "HKLM", Path: winevt + `\Security`, Value: "Enabled",
				What: "the Security event log channel", DisabledWhen: []uint64{0},
				AbsentMeans: "enabled", Criterion: "EVT-C1", Technique: "T1685.001"},
			{Hive: "HKLM", Path: winevt + `\Microsoft-Windows-PowerShell%4Operational`,
				Value: "Enabled", What: "the PowerShell operational event log channel",
				DisabledWhen: []uint64{0}, AbsentMeans: "neutral",
				Criterion: "EVT-C1", Technique: "T1685.001"},
			{Hive: "HKLM", Path: winevt + `\Microsoft-Windows-Sysmon%4Operational`,
				Value: "Enabled", What: "the Sysmon operational event log channel",
				DisabledWhen: []uint64{0}, AbsentMeans: "neutral",
				Criterion: "EVT-C1", Technique: "T1685.001"},
			{Hive: "HKLM", Path: winevt + `\Microsoft-Windows-TaskScheduler%4Operational`,
				Value: "Enabled", What: "the Task Scheduler operational event log channel",
				DisabledWhen: []uint64{0}, AbsentMeans: "neutral",
				Criterion: "EVT-C1", Technique: "T1685.001"},
			{Hive: "HKLM", Path: psPolicy + `\ScriptBlockLogging`,
				Value: "EnableScriptBlockLogging",
				What:  "PowerShell script block logging",
				// Absence means "never configured", which is the Windows default. Treating
				// that as disabled would fire on the majority of hosts and tell an analyst
				// nothing about tampering.
				DisabledWhen: []uint64{0}, AbsentMeans: "neutral",
				Criterion: "EVT-C2", Technique: "T1685.001"},
			{Hive: "HKLM", Path: psPolicy + `\Transcription`, Value: "EnableTranscripting",
				What: "PowerShell transcription", DisabledWhen: []uint64{0},
				AbsentMeans: "neutral", Criterion: "EVT-C2", Technique: "T1685.001"},
			{Hive: "HKLM", Path: `SYSTEM\CurrentControlSet\Services\SysmonDrv`,
				Value: "Start", What: "the Sysmon driver service start type",
				DisabledWhen: []uint64{4}, AbsentMeans: "neutral",
				Criterion: "EVT-C3", Technique: "T1685"},
		},
		artifactType:   "windows_logging_setting",
		inventoryGroup: "logging configuration",
		escalation: "Each explicitly disabled logging setting is reported at " +
			"suspicious_indicator. The check does not escalate alone, because disabling a " +
			"channel is also a (poor) performance practice. What this check contributes to " +
			"an investigation is a VISIBILITY MAP: every other check's NOT_DETECTED result " +
			"must be read in light of which logs were off.",
		fpHandling: "Log clearing and logging configuration are explicitly named as a noisy " +
			"area. Therefore: (a) absence of a setting is NOT treated as disabled -- " +
			"PowerShell script block logging is unconfigured on most Windows hosts by " +
			"default, and firing on that would make the check useless; only an explicit 0 " +
			"matches; (b) the Sysmon keys are absent on hosts without Sysmon and produce " +
			"nothing; (c) performance-motivated channel disabling is named as the first " +
			"benign explanation; (d) a denied key is UNKNOWN, never assumed enabled.",
		overlay: check.Overlay{
			Behavior: "An adversary disables an event log channel, PowerShell logging, or " +
				"the Sysmon service so their subsequent actions are not recorded. This is " +
				"preferable to clearing logs afterwards because it leaves no clearing event.",
			Artifacts: []string{
				`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\<channel> -- Enabled`,
				`HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -- EnableScriptBlockLogging`,
				`HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription -- EnableTranscripting`,
				`HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv -- Start`,
			},
			Logic: "Read each channel's Enabled value and each logging policy value, " +
				"distinguishing explicitly disabled from unconfigured from unreadable. " +
				"Report only explicit disabling. Inventory every setting so the report " +
				"doubles as a visibility map for the rest of the scan.",
			FalsePositives: []string{
				"Administrators disable verbose channels for performance or disk reasons.",
				"PowerShell script block logging is unconfigured by default on most hosts.",
				"Sysmon is absent on most hosts, so its keys do not exist.",
				"Imaging and lab hosts frequently have reduced logging.",
			},
			Limitations: []string{
				"Channel SIZE and RETENTION are not evaluated. A channel left enabled but " +
					"capped at 1 MB rolls over in minutes and is effectively blind; that " +
					"shape is not detected and is listed as PLANNED.",
				"The check does not read the logs themselves, so it cannot detect that a log " +
					"was CLEARED (Security 1102) -- only that logging is configured off. " +
					"Clearing detection needs event log access, which this build does not " +
					"implement.",
				"Audit POLICY (auditpol subcategories) is not read, so a host with the " +
					"Security channel enabled but process-creation auditing off looks " +
					"healthy here.",
				"Group policy may override local values; both locations are reported rather " +
					"than merged.",
				"A setting disabled and restored before the scan is invisible.",
			},
			References: []check.Reference{
				{Title: "MITRE ATT&CK T1685.001 Disable or Modify Windows Event Log",
					URL: "https://attack.mitre.org/techniques/T1685/001"},
				{Title: "MITRE ATT&CK T1685 Disable or Modify Tools",
					URL: "https://attack.mitre.org/techniques/T1685"},
			},
		},
		fixtureDir:     "win-defimp-eventlog-001",
		wantTechniques: []string{"T1685.001"},
		minFindings:    2,
		positiveWhy: "The Security channel explicitly disabled, script block logging " +
			"explicitly set to 0, and the Sysmon driver set to disabled while still " +
			"installed -- three distinct logging-impairment artifacts.",
		negativeWhy: "A realistic stock host: the Security channel enabled, and the " +
			"PowerShell logging and Sysmon keys ABSENT. This is the decisive negative, " +
			"because treating 'script block logging not configured' as disabled would fire " +
			"on the majority of real Windows hosts.",
		positiveReg: func() *collect.FakeRegistry {
			r := collect.NewFakeRegistry()
			r.Set("HKLM", winevt+`\Security`,
				collect.RegKeyInfo{Values: []collect.RegValue{
					{Name: "Enabled", Type: collect.RegDWord, Number: 0, String: "0"},
				}})
			r.Set("HKLM", psPolicy+`\ScriptBlockLogging`,
				collect.RegKeyInfo{Values: []collect.RegValue{
					{Name: "EnableScriptBlockLogging", Type: collect.RegDWord,
						Number: 0, String: "0"},
				}})
			r.Set("HKLM", `SYSTEM\CurrentControlSet\Services\SysmonDrv`,
				collect.RegKeyInfo{Values: []collect.RegValue{
					{Name: "Start", Type: collect.RegDWord, Number: 4, String: "4"},
				}})
			return r
		},
		negativeReg: func() *collect.FakeRegistry {
			r := collect.NewFakeRegistry()
			r.Set("HKLM", winevt+`\Security`,
				collect.RegKeyInfo{Values: []collect.RegValue{
					{Name: "Enabled", Type: collect.RegDWord, Number: 1, String: "1"},
				}})
			// PowerShell logging and Sysmon keys deliberately absent: the stock state.
			return r
		},
	}
}
