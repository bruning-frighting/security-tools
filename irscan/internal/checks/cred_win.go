package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"irscan/internal/check"
	"irscan/internal/collect"
	"irscan/internal/model"
)

func init() { check.Register(&winCredentialCheck{}) }

type winCredentialCheck struct{}

// unattendPaths are the standard locations Windows Setup and Sysprep leave an answer file,
// which historically carries a local account password in plaintext or in a trivially
// reversible base64 encoding (neither is encryption).
var unattendPaths = []string{
	`C:\Windows\Panther\Unattend.xml`,
	`C:\Windows\Panther\Unattend\Unattend.xml`,
	`C:\Windows\System32\Sysprep\Sysprep.xml`,
	`C:\Windows\System32\Sysprep\Panther\Unattend.xml`,
	`C:\unattend.xml`,
}

var unattendPasswordPattern = regexp.MustCompile(`(?is)<Password>.*?</Password>`)
var unattendPlainTextPattern = regexp.MustCompile(`(?i)PlainText\s*=\s*"true"`)
var unattendValuePattern = regexp.MustCompile(`(?is)<Value>(.*?)</Value>`)

func (c *winCredentialCheck) Meta() check.Meta {
	return check.Meta{
		ID:      "WIN-CRED-UNSECURED-001",
		Title:   "Unsecured credentials in the registry or an unattended-setup file",
		OS:      []string{"windows"},
		Tactics: []string{"credential-access"},
		Techniques: []check.TechniqueMapping{
			{
				TechniqueID: "T1552.002",
				Justification: "Credentials in Registry. The check reads Winlogon's " +
					"AutoAdminLogon / DefaultPassword / AltDefaultPassword values and " +
					"PuTTY's saved-session ProxyPassword value, which are exactly the " +
					"documented examples of this sub-technique.",
			},
			{
				TechniqueID: "T1552.001",
				Justification: "Credentials In Files. The check reads the standard " +
					"Windows Setup / Sysprep answer-file locations and detects a " +
					"<Password> element, which is the Windows file-based artifact for " +
					"this sub-technique.",
			},
			{
				TechniqueID: "T1552",
				Justification: "Parent technique (Unsecured Credentials) for both artifact " +
					"classes.",
			},
		},
		Sources: []check.SourceRequirement{
			{
				Name:      "Winlogon and PuTTY credential registry values",
				Privilege: "readable by standard users",
				FailureModes: []string{
					"Registry unavailable -> INSUFFICIENT_DATA, never 'no credentials " +
						"found'.",
					"A key access-denied -> recorded per key -> PARTIAL_DATA.",
					"PuTTY sessions are per-user (HKCU); only hives currently loaded " +
						"under HKU are visible, so another user's saved sessions may be " +
						"missed -- recorded as a limitation, not silently.",
				},
			},
			{
				Name:      "unattended-setup answer files",
				Privilege: "readable by standard users; some copies may be ACL'd to SYSTEM",
				Optional:  true,
				FailureModes: []string{
					"Absent is the common, clean case (the files are normally deleted " +
						"after setup) and is NOT a visibility gap.",
					"Present but unreadable -> partial collection -> PARTIAL_DATA.",
				},
			},
		},
		Criteria: []model.Criterion{
			{ID: "WCR-C1", Text: "Winlogon DefaultPassword (or AltDefaultPassword) holds a " +
				"non-empty value, which is a plaintext password stored for automatic " +
				"logon."},
			{ID: "WCR-C2", Text: "Winlogon AutoAdminLogon is enabled (1) while a " +
				"DefaultPassword is also set -- the combination that actually performs an " +
				"unattended logon with the stored password."},
			{ID: "WCR-C3", Text: "A PuTTY saved session has a non-empty ProxyPassword " +
				"value, which PuTTY stores in plaintext in the registry."},
			{ID: "WCR-C4", Text: "A standard Windows Setup or Sysprep answer-file location " +
				"contains a <Password> element."},
		},
		EscalationCriteria: "Each matching value is an observed_artifact for Inventory. " +
			"One criterion gives suspicious_indicator. Corroborated requires a second " +
			"independent criterion -- for example DefaultPassword set (WCR-C1) together " +
			"with AutoAdminLogon enabled (WCR-C2), which together confirm the credential " +
			"is actively used for logon rather than a leftover value from a disabled " +
			"configuration.",
		FalsePositiveHandling: "Each of these artifacts is already narrow and specific, so " +
			"the main discipline is in what is NOT read as a criterion. Specifically: " +
			"(a) AutoAdminLogon=1 with NO DefaultPassword set (some domain configurations " +
			"use this with a different mechanism) does not match WCR-C1 or WCR-C2, only an " +
			"actually non-empty password does; (b) an EMPTY PuTTY ProxyPassword value -- " +
			"the default when no proxy is configured -- does not match WCR-C3; (c) an " +
			"unattend.xml file that exists but has no <Password> element (common once " +
			"Microsoft's own cleanup has partially run) does not match WCR-C4; (d) presence " +
			"of the unattend file PATH alone, without a password element, is Inventory " +
			"only; (e) no secret value from any of these sources is ever retained in a " +
			"finding, only its presence and location.",
		Overlay: check.Overlay{
			Behavior: "An adversary who has landed on a host, or who is reviewing an image " +
				"before deployment, looks for credentials Windows itself stored in " +
				"plaintext or near-plaintext: an unattended-logon password left in the " +
				"registry, a leftover Setup answer file, or a saved PuTTY session's proxy " +
				"password.",
			Artifacts: []string{
				`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -- AutoAdminLogon, DefaultPassword, AltDefaultPassword`,
				`HKCU (and each loaded HKU hive)\Software\SimonTatham\PuTTY\Sessions\<name> -- ProxyPassword`,
				`C:\Windows\Panther\Unattend.xml and the other standard Setup/Sysprep answer-file locations -- the <Password> element`,
			},
			Logic: "Read the Winlogon values via the native registry API. Enumerate loaded " +
				"HKU hives and read each one's PuTTY Sessions subkeys for ProxyPassword. " +
				"Read each standard unattend/sysprep path and check for a <Password> " +
				"element without decoding or retaining its content -- the element's mere " +
				"presence, and whether it declares PlainText=\"true\", is the artifact.",
			FalsePositives: []string{
				"Unattended-logon is sometimes deliberately configured on kiosk or lab " +
					"machines, which is a known risk accepted by the owner, not necessarily " +
					"an adversary's doing.",
				"Setup answer files are occasionally retained deliberately for re-imaging " +
					"and are access-restricted at the filesystem level.",
				"A PuTTY ProxyPassword may be an intentionally low-value proxy credential.",
			},
			Limitations: []string{
				"PuTTY sessions are per-user; only hives currently LOADED under HKU can be " +
					"read, so a user who has not logged on since boot is invisible to this " +
					"check -- the same limitation as the Run-key check.",
				"The unattend.xml <Password> element may itself be base64-encoded rather " +
					"than literal plaintext; the check does not decode it, and either form " +
					"is treated the same way since base64 is not encryption.",
				"Credential Manager (vaulted credentials), DPAPI blobs, and browser-saved " +
					"passwords are NOT covered by this check; those need separate, " +
					"PLANNED checks.",
				"Group Policy Preferences cpassword (SYSVOL Groups.xml) is NOT covered: it " +
					"requires a domain SYSVOL share, and this tool skips network " +
					"filesystems by default.",
				"An adversary with sufficient privilege can clear these values after use.",
			},
			References: []check.Reference{
				{Title: "MITRE ATT&CK T1552.002 Credentials in Registry",
					URL: "https://attack.mitre.org/techniques/T1552/002"},
				{Title: "MITRE ATT&CK T1552.001 Credentials In Files",
					URL: "https://attack.mitre.org/techniques/T1552/001"},
				{Title: "MITRE ATT&CK T1552 Unsecured Credentials",
					URL: "https://attack.mitre.org/techniques/T1552"},
			},
		},
		Validation:        model.FixtureTested,
		FixtureProvenance: model.Synthetic,
	}
}

func (c *winCredentialCheck) Run(ctx context.Context, env check.Env) model.CheckResult {
	started := env.Now()
	m := c.Meta()

	regSrc := collect.SourceResult{Name: m.Sources[0].Name, Privilege: m.Sources[0].Privilege}
	fileSrc := collect.SourceResult{Name: m.Sources[1].Name, Privilege: m.Sources[1].Privilege}

	regAvailable, regReason := env.Registry.Available()
	if !regAvailable {
		regSrc.Available, fileSrc.Available = false, false
		regSrc.Reason = regReason
		fileSrc.Reason = "not examined: " + regReason
		return check.Result(m.ID, started, env.Now, []model.DataSourceStatus{
			check.SourceStatus(m.Sources[0], regSrc),
			check.SourceStatus(m.Sources[1], fileSrc),
		}, nil, nil)
	}
	regSrc.Available = true

	byID := map[string]model.Criterion{}
	for _, cr := range m.Criteria {
		byID[cr.ID] = cr
	}

	var findings []model.Finding
	var inventory []model.InventoryItem

	// ---- Winlogon AutoAdminLogon / DefaultPassword ----------------------------------
	winlogonPath := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
	if info, err := env.Registry.OpenKey("HKLM", winlogonPath); err == nil {
		regSrc.ItemsSeen++
		var autoAdmin bool
		var defaultPw, altPw, userName string
		for _, v := range info.Values {
			switch strings.ToLower(v.Name) {
			case "autoadminlogon":
				autoAdmin = v.String == "1" || v.Number == 1
			case "defaultpassword":
				defaultPw = v.String
			case "altdefaultpassword":
				altPw = v.String
			case "defaultusername":
				userName = v.String
			}
		}
		pw := defaultPw
		if pw == "" {
			pw = altPw
		}
		inventory = append(inventory, model.InventoryItem{
			Group:        "credential registry values",
			ArtifactType: "winlogon_autologon",
			ArtifactID:   `HKLM\` + winlogonPath,
			Attributes: map[string]string{
				"auto_admin_logon":    fmt.Sprintf("%t", autoAdmin),
				"default_user_name":   userName,
				"default_password_set": fmt.Sprintf("%t", pw != ""),
			},
			TechniqueIDs: []string{"T1552.002", "T1552"},
			CheckIDs:     []string{m.ID},
		})
		if pw != "" {
			var matched []model.Criterion
			matched = append(matched, byID["WCR-C1"])
			if autoAdmin {
				matched = append(matched, byID["WCR-C2"])
			}
			level := model.SuspiciousIndicator
			if len(matched) >= 2 {
				level = model.Corroborated
			}
			findings = append(findings, check.NewFinding(env, m.ID, check.FindingSpec{
				ArtifactType: "winlogon_autologon",
				ArtifactID:   `HKLM\` + winlogonPath + `\DefaultPassword`,
				Level:        level,
				TechniqueIDs: []string{"T1552.002", "T1552"},
				Title:        "Winlogon stores a plaintext autologon password",
				WhatAndWhere: fmt.Sprintf(
					"HKLM\\%s has a non-empty DefaultPassword for account %q "+
						"(AutoAdminLogon=%t). The value itself is not recorded.",
					winlogonPath, defaultStr(userName, "(unspecified)"), autoAdmin),
				Criteria: matched,
				Benign: []string{
					"Kiosk, lab and demo machines are sometimes deliberately configured " +
						"for unattended logon, a known and accepted risk on those hosts.",
				},
				NextPivot: []string{
					"Confirm with the owner whether unattended logon is an intended " +
						"configuration for this host.",
					"If not intended, remove the stored password and disable " +
						"AutoAdminLogon, then rotate the account's password.",
					"Check the key's last-write time to bound when this was configured.",
				},
				Evidence: []model.EvidenceRef{check.RedactedEvidence(env,
					`HKLM\`+winlogonPath+`\DefaultPassword`, "registry_value",
					"Winlogon DefaultPassword", int64(len(pw)),
					"The stored password is never retained")},
				Context: map[string]string{
					"auto_admin_logon": fmt.Sprintf("%t", autoAdmin),
					"account":          userName,
				},
			}))
		}
	} else if strings.Contains(err.Error(), "permission denied") {
		regSrc.Errors = append(regSrc.Errors, "access denied reading HKLM\\"+winlogonPath)
	}

	// ---- PuTTY ProxyPassword across loaded hives -------------------------------------
	hives := []collect.UserHive{{SID: "(current user)", Root: ""}}
	if extra, err := env.Registry.UserHives(); err == nil {
		for _, h := range extra {
			hives = append(hives, h)
		}
	} else {
		regSrc.Errors = append(regSrc.Errors,
			"could not enumerate per-user hives: "+err.Error())
	}
	for _, h := range hives {
		hive, base := "HKCU", `Software\SimonTatham\PuTTY\Sessions`
		if h.Root != "" {
			hive, base = "HKU", h.Root+`\Software\SimonTatham\PuTTY\Sessions`
		}
		sessions, err := env.Registry.OpenKey(hive, base)
		if err != nil {
			if strings.Contains(err.Error(), "permission denied") {
				regSrc.Errors = append(regSrc.Errors,
					fmt.Sprintf("access denied reading %s\\%s", hive, base))
			}
			continue
		}
		for _, sess := range sessions.SubKeys {
			if err := ctx.Err(); err != nil {
				return check.ErrorResult(m.ID, started, env.Now, err)
			}
			info, err := env.Registry.OpenKey(hive, base+`\`+sess)
			if err != nil {
				continue
			}
			regSrc.ItemsSeen++
			var proxyPw string
			for _, v := range info.Values {
				if strings.EqualFold(v.Name, "ProxyPassword") {
					proxyPw = v.String
				}
			}
			if proxyPw == "" {
				continue
			}
			artifactID := hive + `\` + base + `\` + sess + `\ProxyPassword`
			findings = append(findings, check.NewFinding(env, m.ID, check.FindingSpec{
				ArtifactType: "putty_session_credential",
				ArtifactID:   artifactID,
				Level:        model.SuspiciousIndicator,
				TechniqueIDs: []string{"T1552.002", "T1552"},
				Title:        fmt.Sprintf("PuTTY session %q stores a proxy password", sess),
				WhatAndWhere: fmt.Sprintf(
					"%s has a non-empty ProxyPassword. PuTTY stores this value in "+
						"plaintext in the registry. The value itself is not recorded.",
					artifactID),
				Criteria: []model.Criterion{byID["WCR-C3"]},
				Benign:   []string{"The stored credential may be a low-value proxy account."},
				NextPivot: []string{
					"Identify what the proxy credential grants access to.",
					"Confirm with the user whether this session is still in active use.",
				},
				Evidence: []model.EvidenceRef{check.RedactedEvidence(env, artifactID,
					"registry_value", "PuTTY ProxyPassword", int64(len(proxyPw)),
					"The stored password is never retained")},
				Context: map[string]string{"session": sess, "hive": hive},
			}))
		}
	}

	// ---- unattend / sysprep answer files ---------------------------------------------
	anyUnattend := false
	for _, p := range unattendPaths {
		fi, err := env.FS.Stat(p)
		if err != nil {
			if isPermErr(err) {
				fileSrc.Errors = append(fileSrc.Errors,
					fmt.Sprintf("permission denied checking %s", p))
			}
			continue
		}
		anyUnattend = true
		fileSrc.ItemsSeen++
		data, truncated, err := env.FS.ReadFile(p)
		if err != nil {
			reportSrcErr(&fileSrc, err, "reading "+p)
			continue
		}
		if truncated {
			fileSrc.Truncated = true
		}
		content := string(data)
		hasPassword := unattendPasswordPattern.MatchString(content)
		plainText := unattendPlainTextPattern.MatchString(content)

		inventory = append(inventory, model.InventoryItem{
			Group:        "unattend answer files",
			ArtifactType: "unattend_file",
			ArtifactID:   p,
			Attributes: map[string]string{
				"has_password_element": fmt.Sprintf("%t", hasPassword),
				"plain_text_flag":      fmt.Sprintf("%t", plainText),
				"size":                 fmt.Sprintf("%d", fi.Size),
			},
			TechniqueIDs: []string{"T1552.001", "T1552"},
			CheckIDs:     []string{m.ID},
		})
		if !hasPassword {
			continue
		}

		findings = append(findings, check.NewFinding(env, m.ID, check.FindingSpec{
			ArtifactType: "unattend_file",
			ArtifactID:   p,
			Level:        model.SuspiciousIndicator,
			TechniqueIDs: []string{"T1552.001", "T1552"},
			Title:        fmt.Sprintf("%s contains a <Password> element", baseWindowsKey(p)),
			WhatAndWhere: fmt.Sprintf(
				"%s (%d bytes) contains a <Password> element (PlainText=%t). Windows "+
					"Setup answer files store this value in plaintext or in a trivially "+
					"reversible encoding; the value itself is not recorded.",
				p, fi.Size, plainText),
			Criteria: []model.Criterion{byID["WCR-C4"]},
			Benign: []string{
				"The file may be retained deliberately for re-imaging on a host with " +
					"restricted filesystem access to compensate.",
			},
			NextPivot: []string{
				"If this file is not required for imaging on this host, delete it and " +
					"rotate the account whose password it contains.",
				"Check the file's mtime to establish when it was created or last modified.",
			},
			Evidence: []model.EvidenceRef{check.RedactedEvidence(env, p, "unattend_file",
				"Windows Setup/Sysprep <Password> element", fi.Size,
				"The password value is never retained, regardless of its encoding")},
			Context: map[string]string{"plain_text_flag": fmt.Sprintf("%t", plainText)},
		}))
	}

	fileSrc.Available = true
	if m.Sources[1].Optional && !anyUnattend && len(fileSrc.Errors) == 0 {
		fileSrc.Reason = "optional source absent: no unattend/sysprep answer file exists, " +
			"which is the common case once Setup has completed"
	}

	return check.Result(m.ID, started, env.Now, []model.DataSourceStatus{
		check.SourceStatus(m.Sources[0], regSrc),
		check.SourceStatus(m.Sources[1], fileSrc),
	}, findings, inventory)
}

func (c *winCredentialCheck) Cases() []check.FixtureCase {
	base := func(root, name string) string {
		return filepath.Join(root, "win-cred-unsecured-001", name)
	}

	malicious := func() *collect.FakeRegistry {
		r := collect.NewFakeRegistry()
		r.Set("HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
			collect.RegKeyInfo{Values: []collect.RegValue{
				{Name: "AutoAdminLogon", Type: collect.RegSZ, String: "1"},
				{Name: "DefaultUserName", Type: collect.RegSZ, String: "kiosk"},
				{Name: "DefaultPassword", Type: collect.RegSZ, String: "fixtureNotARealSecret"},
			}})
		r.Set("HKCU", `Software\SimonTatham\PuTTY\Sessions`,
			collect.RegKeyInfo{SubKeys: []string{"jumpbox"}})
		r.Set("HKCU", `Software\SimonTatham\PuTTY\Sessions\jumpbox`,
			collect.RegKeyInfo{Values: []collect.RegValue{
				{Name: "ProxyPassword", Type: collect.RegSZ, String: "fixtureNotARealSecret"},
			}})
		return r
	}
	benign := func() *collect.FakeRegistry {
		r := collect.NewFakeRegistry()
		r.Set("HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
			collect.RegKeyInfo{Values: []collect.RegValue{
				// AutoAdminLogon present but no password: must NOT fire.
				{Name: "AutoAdminLogon", Type: collect.RegSZ, String: "0"},
				{Name: "DefaultUserName", Type: collect.RegSZ, String: ""},
			}})
		r.Set("HKCU", `Software\SimonTatham\PuTTY\Sessions`,
			collect.RegKeyInfo{SubKeys: []string{"internal-wiki"}})
		r.Set("HKCU", `Software\SimonTatham\PuTTY\Sessions\internal-wiki`,
			collect.RegKeyInfo{Values: []collect.RegValue{
				// Empty ProxyPassword is the default; must NOT fire.
				{Name: "ProxyPassword", Type: collect.RegSZ, String: ""},
			}})
		return r
	}

	return []check.FixtureCase{
		{
			Name: "autologon password plus a PuTTY proxy password plus a leftover unattend.xml",
			Kind: check.CasePositive,
			Why: "Exercises WCR-C1+C2 together (corroborated), WCR-C3, and WCR-C4 " +
				"independently, proving per-artifact attribution.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(base(root, "positive"), "windows")
				if err != nil {
					return env, err
				}
				env.Registry = malicious()
				return env, nil
			},
			WantOutcome: model.Detected,
			MinFindings: 2,
			WantTechniqueIDs: []string{
				"T1552.002", "T1552.001",
			},
		},
		{
			Name: "AutoAdminLogon disabled, empty ProxyPassword default, no unattend file",
			Kind: check.CaseNegative,
			Why: "AutoAdminLogon present without a password, and an empty ProxyPassword " +
				"(PuTTY's default), must not fire.",
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
			Name: "Winlogon key access-denied",
			Kind: check.CasePermissionDenied,
			Why:  "A denied key must not read as 'no autologon password configured'.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(base(root, "nodata"), "windows")
				if err != nil {
					return env, err
				}
				r := collect.NewFakeRegistry()
				r.Set("HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
					collect.RegKeyInfo{})
				r.Deny("HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`)
				env.Registry = r
				return env, nil
			},
			WantOutcome: model.PartialData,
			AlsoAccept:  []model.Outcome{model.PermissionDenied, model.NotDetected},
		},
	}
}
