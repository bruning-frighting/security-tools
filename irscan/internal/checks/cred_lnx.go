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

func init() { check.Register(&linuxCredentialCheck{}) }

type linuxCredentialCheck struct{}

// credFileSpec names one well-known credential-bearing file, relative to a home directory
// (or absolute for system-wide paths), and the field names within it that carry a secret.
//
// This check is deliberately NOT a filesystem-wide grep for the word "password" or
// "secret". Measured on a real development/security-research host before writing this
// check: such a grep returns hundreds of matches from node_modules, nuclei-templates,
// documentation, and the source code of other security tools -- none of them an actual
// credential. Scope is instead a short, named list of files a credential realistically
// lives in, which is both far more precise and far cheaper to collect.
type credFileSpec struct {
	// RelPath is relative to a home directory; AbsPath is used instead for system files.
	RelPath, AbsPath string
	What             string
	// FieldPattern recognises a secret-bearing LINE by its key name, not by the presence
	// of an English word. Group 1 is the field, used only to name the pattern type.
	FieldPattern *regexp.Regexp
	Technique    string
}

var credFileSpecs = []credFileSpec{
	{RelPath: ".netrc", What: "a .netrc file (plaintext FTP/HTTP credentials)",
		FieldPattern: regexp.MustCompile(`(?im)^\s*password\s+\S+`), Technique: "T1552.001"},
	{RelPath: ".pgpass", What: "a .pgpass file (PostgreSQL connection credentials)",
		FieldPattern: regexp.MustCompile(`^[^#\n]*:[^#\n]*:[^#\n]*:[^#\n]*:\S+`),
		Technique:    "T1552.001"},
	{RelPath: ".my.cnf", What: "a MySQL client option file",
		FieldPattern: regexp.MustCompile(`(?im)^\s*password\s*=\s*\S+`), Technique: "T1552.001"},
	{RelPath: ".pg_service.conf", What: "a PostgreSQL service file",
		FieldPattern: regexp.MustCompile(`(?im)^\s*password\s*=\s*\S+`), Technique: "T1552.001"},
	{RelPath: ".aws/credentials", What: "an AWS CLI credentials file",
		FieldPattern: regexp.MustCompile(`(?im)^\s*(aws_secret_access_key|aws_session_token)\s*=\s*\S+`),
		Technique:    "T1552.001"},
	{RelPath: ".docker/config.json", What: "a Docker client config with a registry auth token",
		FieldPattern: regexp.MustCompile(`"auth"\s*:\s*"[^"]{4,}"`), Technique: "T1552.001"},
	{RelPath: ".npmrc", What: "an npm config with a registry auth token",
		FieldPattern: regexp.MustCompile(`(?im)^\s*(//\S+/:)?_authToken\s*=\s*\S+`),
		Technique:    "T1552.001"},
	{RelPath: ".git-credentials", What: "a git-credential-store file (plaintext, by design)",
		FieldPattern: regexp.MustCompile(`https?://[^:\s]+:[^@\s]+@`), Technique: "T1552.001"},
	{AbsPath: "/etc/environment", What: "the system-wide environment file",
		FieldPattern: regexp.MustCompile(`(?im)^\s*\w*(PASSWORD|SECRET|TOKEN|API_KEY)\w*\s*=\s*\S+`),
		Technique:    "T1552.001"},
}

// sshPrivateKeyNames are checked under ~/.ssh and /etc/ssh. A PEM/OpenSSH header match
// anywhere else in the filesystem is deliberately NOT searched for: on the real
// reconnaissance host that scoped this check, such a search matched exclusively test
// fixtures, documentation and the source of other security tools, never a real key.
var sshPrivateKeyNames = []string{
	"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "identity",
}

var pemHeaderPattern = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)
var encryptedKeyPattern = regexp.MustCompile(`Proc-Type:\s*4,ENCRYPTED|BEGIN ENCRYPTED PRIVATE KEY`)

// credCLIPatterns recognise a secret passed on a command line, for shell history review.
// Each requires the secret to be CONTIGUOUS with the flag (no space, or an = sign), which
// excludes the extremely common interactive-prompt idiom "mysql -u root -p" (no attached
// value, so no secret was ever typed into history).
var credCLIPatterns = []struct {
	Name    string
	Pattern *regexp.Regexp
}{
	{"mysql -p<password> (inline, no prompt)", regexp.MustCompile(`\bmysql\b[^\n|;&]*\s-p\S`)},
	{"PGPASSWORD environment assignment", regexp.MustCompile(`\bPGPASSWORD=\S`)},
	{"AWS_SECRET_ACCESS_KEY environment assignment", regexp.MustCompile(`\bAWS_SECRET_ACCESS_KEY=\S`)},
	{"AWS_SESSION_TOKEN environment assignment", regexp.MustCompile(`\bAWS_SESSION_TOKEN=\S`)},
	{"sshpass inline password", regexp.MustCompile(`\bsshpass\s+-p\S`)},
	{"curl/wget basic-auth user:pass in URL", regexp.MustCompile(`(?i)\b(curl|wget)\b[^\n|;&]*://[^/\s:@]+:[^/\s@]+@`)},
	{"curl -u / --user inline credential", regexp.MustCompile(`\b(curl|wget)\b[^\n|;&]*(-u|--user)\s+\S+:\S`)},
	{"--password= inline credential", regexp.MustCompile(`--password[=\s]\S`)},
	{"HTTP Authorization header with an attached token", regexp.MustCompile(`(?i)Authorization:\s*(Bearer|Basic)\s+\S`)},
}

func (c *linuxCredentialCheck) Meta() check.Meta {
	return check.Meta{
		ID:      "LNX-CRED-FILES-001",
		Title:   "Unsecured credentials in files, private keys, or shell history",
		OS:      []string{"linux"},
		Tactics: []string{"credential-access"},
		Techniques: []check.TechniqueMapping{
			{
				TechniqueID: "T1552.001",
				Justification: "Credentials In Files. The check reads a short, named list " +
					"of well-known credential-bearing files (.netrc, .pgpass, .my.cnf, AWS " +
					"CLI credentials, Docker/npm/git credential stores, /etc/environment) " +
					"and recognises secret-bearing FIELDS by name, which is precisely the " +
					"artifact this sub-technique describes.",
			},
			{
				TechniqueID: "T1552.004",
				Justification: "Private Keys. The check looks for PEM/OpenSSH private key " +
					"material specifically in ~/.ssh and /etc/ssh -- the locations an SSH " +
					"client and server actually use -- rather than scanning arbitrary " +
					"files for a PEM header.",
			},
			{
				TechniqueID: "T1552.003",
				Justification: "Shell History. The check matches a short list of " +
					"command-line idioms that attach a secret directly to the command " +
					"(mysql -pVALUE, PGPASSWORD=, curl -u user:pass and similar). Mapped " +
					"Partial: it recognises known idioms, not all possible ways a secret " +
					"can appear on a command line, so absence of a match is weak evidence.",
				Partial: true,
			},
			{
				TechniqueID: "T1552",
				Justification: "Parent technique (Unsecured Credentials) for all three " +
					"artifact classes above.",
			},
		},
		Sources: []check.SourceRequirement{
			{
				Name:      "well-known credential files",
				Privilege: "a user's own files; root for other users' home directories",
				FailureModes: []string{
					"No candidate file exists for any enumerated user -> that is the " +
						"common, clean case and produces Inventory only, not a gap.",
					"Other users' home directories unreadable unprivileged -> partial " +
						"collection -> PARTIAL_DATA, never NOT_DETECTED.",
				},
			},
			{
				Name:      "SSH private key files",
				Privilege: "~/.ssh is normally 0700 to its owner; /etc/ssh host keys need root",
				FailureModes: []string{
					"Unreadable unprivileged -> partial collection -> PARTIAL_DATA.",
				},
			},
			{
				Name:      "shell history files",
				Privilege: "a user's own history; root for other users",
				Optional:  true,
				FailureModes: []string{
					"Absent history is normal and is not a finding.",
					"Unreadable unprivileged -> partial collection -> PARTIAL_DATA.",
				},
			},
		},
		Criteria: []model.Criterion{
			{ID: "CRF-C1", Text: "A well-known credential file contains a recognised " +
				"secret-bearing field (by field name, not by the presence of an English " +
				"word like 'password')."},
			{ID: "CRF-C2", Text: "A private key file is present under ~/.ssh or /etc/ssh " +
				"and is NOT passphrase-protected (no Proc-Type: 4,ENCRYPTED / 'BEGIN " +
				"ENCRYPTED PRIVATE KEY' marker)."},
			{ID: "CRF-C3", Text: "A private key file is world- or group-readable, so any " +
				"local user (or, if group-readable, members of its group) can read it."},
			{ID: "CRF-C4", Text: "A shell history file contains a command matching a known " +
				"secret-on-the-command-line idiom (inline -p, PGPASSWORD=, curl -u " +
				"user:pass, an attached Authorization header, and similar)."},
		},
		EscalationCriteria: "Every candidate file is an observed_artifact for Inventory. " +
			"One criterion gives suspicious_indicator. Corroborated requires a second " +
			"independent criterion -- for example an unencrypted private key (CRF-C2) that " +
			"is ALSO world-readable (CRF-C3). CRF-C1 and CRF-C4 are reported per FILE, " +
			"aggregating every matching field or history line into one finding, so a " +
			"history file with many matching lines produces one finding, not dozens.",
		FalsePositiveHandling: "The dominant false positive for any credential-hunting check " +
			"is matching the WORD rather than the ARTIFACT, and it was measured directly: a " +
			"recursive case-insensitive grep for 'password' across /home, /root and /etc on " +
			"a real development host returned files from node_modules, vulnerability-scanner " +
			"templates, documentation and other security tools' own source code -- none of " +
			"them a credential. This check never does that. Instead: (a) only the named " +
			"files in credFileSpecs are read, never an arbitrary file; (b) within those " +
			"files, only a recognised FIELD NAME (password=, _authToken=, " +
			"aws_secret_access_key=) matches, never a bare keyword; (c) private keys are " +
			"looked for only in ~/.ssh and /etc/ssh, never scanned for across the whole " +
			"filesystem -- the same real-host recon found PEM headers almost exclusively in " +
			"test fixtures, CVE proof-of-concept payloads and documentation elsewhere on the " +
			"disk; (d) public keys (*.pub) and known_hosts are never treated as secrets; " +
			"(e) shell-history idioms require the secret to be CONTIGUOUS with the flag, so " +
			"the extremely common 'mysql -u root -p' (interactive prompt, no secret typed) " +
			"does not match.",
		Overlay: check.Overlay{
			Behavior: "An adversary who has landed on a host searches for credentials " +
				"stored in configuration files, SSH private keys, or typed directly on a " +
				"command line and preserved in shell history, to pivot to other systems or " +
				"services without needing to crack or dump anything.",
			Artifacts: []string{
				".netrc, .pgpass, .my.cnf, .pg_service.conf, .aws/credentials, " +
					".docker/config.json, .npmrc, .git-credentials, /etc/environment",
				"PEM/OpenSSH private key files under ~/.ssh and /etc/ssh",
				"Shell history lines matching a known secret-on-the-command-line idiom",
			},
			Logic: "For every enumerated user, check the named credential files and apply " +
				"each file's field-name pattern; check ~/.ssh and /etc/ssh for private key " +
				"files and classify encrypted vs not and world/group-readable vs not; scan " +
				"shell history files against the CLI-idiom pattern list. In every case, " +
				"NEVER retain the matched value: findings record the file path, the pattern " +
				"type, and a redacted placeholder plus the matched length, following " +
				"check.RedactedEvidence.",
			FalsePositives: []string{
				"CI/CD and automation accounts legitimately store credentials in these " +
					"exact files as part of normal operation.",
				"A development workstation may have scoped, intentionally short-lived " +
					"tokens in .npmrc or .docker/config.json.",
				"Backup or migration scripts sometimes leave an unencrypted key temporarily.",
			},
			Limitations: []string{
				"Only the named files are examined. A credential in an arbitrary " +
					"application config file, a database dump, or a custom script is " +
					"invisible to this check by design -- the alternative (grepping " +
					"everything) was measured to be both far too slow and almost entirely " +
					"noise.",
				"Shell-history idioms cover known patterns only; an adversary using an " +
					"unlisted tool or syntax is not detected, hence the Partial mapping to " +
					"T1552.003.",
				"Password MANAGERS (KeePass, Bitwarden vaults, browser credential stores) " +
					"are not covered here; see the Credentials from Password Stores " +
					"technique, which is a separate, PLANNED check.",
				"The check cannot tell whether a found credential is still valid.",
				"An unprivileged scan cannot read other users' files, which is the common " +
					"real case and yields PARTIAL_DATA.",
			},
			References: []check.Reference{
				{Title: "MITRE ATT&CK T1552.001 Credentials In Files",
					URL: "https://attack.mitre.org/techniques/T1552/001"},
				{Title: "MITRE ATT&CK T1552.004 Private Keys",
					URL: "https://attack.mitre.org/techniques/T1552/004"},
				{Title: "MITRE ATT&CK T1552.003 Shell History",
					URL: "https://attack.mitre.org/techniques/T1552/003"},
				{Title: "MITRE ATT&CK T1552 Unsecured Credentials",
					URL: "https://attack.mitre.org/techniques/T1552"},
			},
		},
		Validation: model.LabVerified,
		LabEvidence: "Executed 2026-10-14 against the LIVE root filesystem of WSL2 Kali " +
			"GNU/Linux Rolling 2026.1 (kernel 6.6.87.2-microsoft-standard-WSL2), " +
			"unprivileged as uid 1000. See STATUS.md Phase 2c for the observed result and " +
			"for the reconnaissance that scoped this check away from a filesystem-wide " +
			"keyword search.",
		FixtureProvenance: model.Synthetic,
	}
}

func (c *linuxCredentialCheck) Run(ctx context.Context, env check.Env) model.CheckResult {
	started := env.Now()
	m := c.Meta()

	users, uRes := collect.Users(env.FS)
	fileSrc := collect.SourceResult{Name: m.Sources[0].Name, Privilege: m.Sources[0].Privilege}
	keySrc := collect.SourceResult{Name: m.Sources[1].Name, Privilege: m.Sources[1].Privilege}
	histSrc := collect.SourceResult{Name: m.Sources[2].Name, Privilege: m.Sources[2].Privilege}

	if !uRes.Available {
		fileSrc.Available, keySrc.Available, histSrc.Available = false, false, false
		fileSrc.Reason = "cannot enumerate users to locate home directories: " + uRes.Reason
		keySrc.Reason, histSrc.Reason = fileSrc.Reason, fileSrc.Reason
		return check.Result(m.ID, started, env.Now, []model.DataSourceStatus{
			check.SourceStatus(m.Sources[0], fileSrc),
			check.SourceStatus(m.Sources[1], keySrc),
			check.SourceStatus(m.Sources[2], histSrc),
		}, nil, nil)
	}

	byID := map[string]model.Criterion{}
	for _, cr := range m.Criteria {
		byID[cr.ID] = cr
	}

	var findings []model.Finding
	var inventory []model.InventoryItem

	homesChecked := 0
	for _, u := range users {
		if u.HomeDir == "" {
			continue
		}
		homesChecked++
		if err := ctx.Err(); err != nil {
			return check.ErrorResult(m.ID, started, env.Now, err)
		}

		// ---- named credential files ----------------------------------------------
		for _, spec := range credFileSpecs {
			path := spec.AbsPath
			if path == "" {
				path = strings.TrimRight(u.HomeDir, "/") + "/" + spec.RelPath
			}
			fi, err := env.FS.Stat(path)
			if err != nil {
				if isPermErr(err) {
					fileSrc.Errors = append(fileSrc.Errors,
						fmt.Sprintf("permission denied checking %s", path))
				}
				continue
			}
			if spec.AbsPath != "" && u.Name != users[0].Name {
				continue // system-wide file: examine once, not once per user
			}
			fileSrc.ItemsSeen++
			data, truncated, err := env.FS.ReadFile(path)
			if err != nil {
				reportSrcErr(&fileSrc, err, "reading "+path)
				continue
			}
			if truncated {
				fileSrc.Truncated = true
			}
			matchCount := len(spec.FieldPattern.FindAllString(string(data), -1))

			inventory = append(inventory, model.InventoryItem{
				Group:        "credential-bearing files",
				ArtifactType: "credential_file",
				ArtifactID:   path,
				Attributes: map[string]string{
					"what":              spec.What,
					"matching_fields":   strconv.Itoa(matchCount),
					"mode":              fi.ModeString,
					"owner":             u.Name,
				},
				TechniqueIDs: []string{spec.Technique, "T1552"},
				CheckIDs:     []string{m.ID},
			})
			if matchCount == 0 {
				continue
			}

			findings = append(findings, check.NewFinding(env, m.ID, check.FindingSpec{
				ArtifactType: "credential_file",
				ArtifactID:   path,
				Level:        model.SuspiciousIndicator,
				TechniqueIDs: []string{spec.Technique, "T1552"},
				Title: fmt.Sprintf("%s contains %d credential field(s)",
					baseNameOf(path), matchCount),
				WhatAndWhere: fmt.Sprintf("%s is %s and contains %d field(s) matching a "+
					"known secret-bearing pattern. The value itself is not recorded; only "+
					"its location and pattern type are.", path, spec.What, matchCount),
				Criteria: []model.Criterion{byID["CRF-C1"]},
				Benign: []string{
					"Automation and CI accounts legitimately store credentials in exactly " +
						"this file as part of normal operation.",
					"The token or password may be short-lived and already rotated.",
				},
				NextPivot: []string{
					"Confirm with the system owner whether this credential is still " +
						"active, and rotate it if it should not be here.",
					"Check the file's mtime and owner to establish when it was created.",
					"Determine what service or host the credential grants access to and " +
						"review that service's own access logs for the period since.",
				},
				Evidence: []model.EvidenceRef{check.RedactedEvidence(
					env, path, "credential_file", spec.What, fi.Size,
					fmt.Sprintf("%d matching field(s); values are never retained", matchCount)),
				},
				Context: map[string]string{
					"file_mode":       fi.ModeString,
					"matching_fields": strconv.Itoa(matchCount),
				},
			}))
		}

		// ---- private keys in ~/.ssh --------------------------------------------
		sshDir := strings.TrimRight(u.HomeDir, "/") + "/.ssh"
		if entries, err := env.FS.ReadDir(sshDir); err == nil {
			for _, e := range entries {
				if e.IsDir || strings.HasSuffix(e.Name, ".pub") || e.Name == "known_hosts" ||
					e.Name == "authorized_keys" || e.Name == "authorized_keys2" ||
					e.Name == "config" {
					continue
				}
				isNamed := false
				for _, n := range sshPrivateKeyNames {
					if e.Name == n {
						isNamed = true
					}
				}
				p := sshDir + "/" + e.Name
				data, truncated, rerr := env.FS.ReadFile(p)
				if rerr != nil {
					if isPermErr(rerr) {
						keySrc.Errors = append(keySrc.Errors,
							fmt.Sprintf("permission denied reading %s", p))
					}
					continue
				}
				if truncated {
					keySrc.Truncated = true
				}
				if !isNamed && !pemHeaderPattern.Match(data) {
					continue
				}
				c.assessKey(env, m, byID, p, u.Name, data, &keySrc, &findings, &inventory)
			}
		} else if isPermErr(err) {
			keySrc.Errors = append(keySrc.Errors,
				fmt.Sprintf("permission denied listing %s", sshDir))
		}

		// ---- shell history -------------------------------------------------------
		for _, name := range shellHistoryFiles {
			p := strings.TrimRight(u.HomeDir, "/") + "/" + name
			data, truncated, err := env.FS.ReadFile(p)
			if err != nil {
				if isPermErr(err) {
					histSrc.Errors = append(histSrc.Errors,
						fmt.Sprintf("permission denied reading %s", p))
				}
				continue
			}
			histSrc.ItemsSeen++
			if truncated {
				histSrc.Truncated = true
			}
			c.assessHistory(env, m, byID, p, string(data), &findings)
		}
	}

	// /etc/ssh host private keys.
	if entries, err := env.FS.ReadDir("/etc/ssh"); err == nil {
		for _, e := range entries {
			if e.IsDir || !strings.HasSuffix(e.Name, "_key") || strings.HasSuffix(e.Name, ".pub") {
				continue
			}
			p := "/etc/ssh/" + e.Name
			data, truncated, rerr := env.FS.ReadFile(p)
			if rerr != nil {
				if isPermErr(rerr) {
					keySrc.Errors = append(keySrc.Errors,
						fmt.Sprintf("permission denied reading %s", p))
				}
				continue
			}
			if truncated {
				keySrc.Truncated = true
			}
			c.assessKey(env, m, byID, p, "(host key)", data, &keySrc, &findings, &inventory)
		}
	} else if isPermErr(err) {
		keySrc.Errors = append(keySrc.Errors, "permission denied listing /etc/ssh")
	}

	fileSrc.Available, keySrc.Available, histSrc.Available = true, true, true
	if homesChecked == 0 {
		fileSrc.Available, keySrc.Available = false, false
		fileSrc.Reason = "no account with a home directory was enumerated"
		keySrc.Reason = fileSrc.Reason
	}

	return check.Result(m.ID, started, env.Now, []model.DataSourceStatus{
		check.SourceStatus(m.Sources[0], fileSrc),
		check.SourceStatus(m.Sources[1], keySrc),
		check.SourceStatus(m.Sources[2], histSrc),
	}, findings, inventory)
}

func (c *linuxCredentialCheck) assessKey(env check.Env, m check.Meta,
	byID map[string]model.Criterion, path, owner string, data []byte,
	src *collect.SourceResult, findings *[]model.Finding, inventory *[]model.InventoryItem) {

	src.ItemsSeen++
	encrypted := encryptedKeyPattern.Match(data)

	var fi collect.FileInfo
	if got, err := env.FS.Stat(path); err == nil {
		fi = got
	}
	worldReadable := len(fi.ModeString) >= 10 &&
		(fi.ModeString[7] == 'r' || fi.ModeString[len(fi.ModeString)-1] == 'r')

	*inventory = append(*inventory, model.InventoryItem{
		Group:        "ssh private keys",
		ArtifactType: "ssh_private_key",
		ArtifactID:   path,
		Attributes: map[string]string{
			"owner":           owner,
			"encrypted":       fmt.Sprintf("%t", encrypted),
			"mode":            fi.ModeString,
			"world_readable":  fmt.Sprintf("%t", worldReadable),
		},
		TechniqueIDs: []string{"T1552.004", "T1552"},
		CheckIDs:     []string{m.ID},
	})

	var matched []model.Criterion
	if !encrypted {
		matched = append(matched, byID["CRF-C2"])
	}
	if worldReadable {
		matched = append(matched, byID["CRF-C3"])
	}
	if len(matched) == 0 {
		return
	}
	level := model.SuspiciousIndicator
	if len(matched) >= 2 {
		level = model.Corroborated
	}
	*findings = append(*findings, check.NewFinding(env, m.ID, check.FindingSpec{
		ArtifactType: "ssh_private_key",
		ArtifactID:   path,
		Level:        level,
		TechniqueIDs: []string{"T1552.004", "T1552"},
		Title: fmt.Sprintf("private key %s matches %d criteria", baseNameOf(path),
			len(matched)),
		WhatAndWhere: fmt.Sprintf(
			"%s (owner %s, mode %s) is a private key. encrypted=%t world_readable=%t. "+
				"Key material is never recorded in evidence.",
			path, owner, fi.ModeString, encrypted, worldReadable),
		Criteria: matched,
		Benign: []string{
			"Automated deployment and CI systems routinely use unencrypted keys because " +
				"no human is present to enter a passphrase.",
			"The key may already be revoked or rotated.",
		},
		NextPivot: []string{
			"Identify every host and service this key authenticates to.",
			"Confirm with the owner whether the key is still in active use.",
			"If world-readable, establish how long it has been that way via the file's mtime.",
			"Consider rotation regardless of current validity.",
		},
		Evidence: []model.EvidenceRef{check.RedactedEvidence(
			env, path, "ssh_private_key", "PEM/OpenSSH private key", fi.Size,
			"Key material is never retained; only presence, encryption state and "+
				"permissions are recorded"),
		},
		Context: map[string]string{
			"owner": owner, "encrypted": fmt.Sprintf("%t", encrypted),
			"world_readable": fmt.Sprintf("%t", worldReadable),
		},
	}))
}

func (c *linuxCredentialCheck) assessHistory(env check.Env, m check.Meta,
	byID map[string]model.Criterion, path, content string, findings *[]model.Finding) {

	type hit struct {
		name  string
		count int
	}
	var hits []hit
	total := 0
	for _, p := range credCLIPatterns {
		n := len(p.Pattern.FindAllString(content, -1))
		if n > 0 {
			hits = append(hits, hit{p.Name, n})
			total += n
		}
	}
	if total == 0 {
		return
	}
	var names []string
	for _, h := range hits {
		names = append(names, fmt.Sprintf("%s (x%d)", h.name, h.count))
	}

	*findings = append(*findings, check.NewFinding(env, m.ID, check.FindingSpec{
		ArtifactType: "shell_history_credential",
		ArtifactID:   path,
		Level:        model.SuspiciousIndicator,
		TechniqueIDs: []string{"T1552.003", "T1552"},
		Title: fmt.Sprintf("%s contains %d command(s) with an attached credential",
			baseNameOf(path), total),
		WhatAndWhere: fmt.Sprintf(
			"%s contains %d command(s) matching known secret-on-the-command-line "+
				"idioms: %s. Neither the commands nor the secrets are recorded; only the "+
				"pattern types and counts are.", path, total, strings.Join(names, "; ")),
		Criteria: []model.Criterion{byID["CRF-C4"]},
		Benign: []string{
			"Interactive administration legitimately involves typing credentials " +
				"occasionally; this is a hygiene finding, not proof of compromise.",
			"The credentials may already be rotated.",
		},
		NextPivot: []string{
			"If operationally acceptable, review the account's own history interactively " +
				"(outside this tool) to identify which specific credentials were exposed, " +
				"then rotate them.",
			"Consider enabling HISTCONTROL=ignorespace and educating the user to prefix " +
				"sensitive commands with a space.",
			"Clear history is not a fix: the credential may already be compromised.",
		},
		Evidence: []model.EvidenceRef{check.RedactedEvidence(
			env, path, "shell_history", strings.Join(names, "; "), int64(len(content)),
			fmt.Sprintf("%d command(s) matched; neither commands nor secrets are retained",
				total)),
		},
		Context: map[string]string{"pattern_types": strings.Join(names, "; ")},
	}))
}

func (c *linuxCredentialCheck) Cases() []check.FixtureCase {
	dir := func(root, name string) string {
		return filepath.Join(root, "lnx-cred-files-001", name)
	}
	return []check.FixtureCase{
		{
			Name: "AWS credentials file, unencrypted world-readable key, and a history hit",
			Kind: check.CasePositive,
			Why: "Exercises all three artifact classes: CRF-C1 on .aws/credentials, " +
				"CRF-C2+C3 together on a world-readable unencrypted key (corroborated), " +
				"and CRF-C4 on a PGPASSWORD history line.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "positive"), "linux")
			},
			WantOutcome: model.Detected,
			MinFindings: 3,
			WantTechniqueIDs: []string{
				"T1552.001", "T1552.004", "T1552.003",
			},
		},
		{
			Name: "clean host: no credential files, a passphrase-protected key, benign history",
			Kind: check.CaseNegative,
			Why: "An encrypted key (mode 0600) and an ordinary history file with 'mysql " +
				"-u root -p' (no attached password) must not fire.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "negative"), "linux")
			},
			WantOutcome: model.NotDetected,
		},
		{
			Name: "no /etc/passwd",
			Kind: check.CaseNoData,
			Why:  "Without a user list there is nothing to examine: INSUFFICIENT_DATA.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "nodata"), "linux")
			},
			WantOutcome: model.InsufficientData,
		},
		{
			Name: "home directories unreadable (unprivileged scan)",
			Kind: check.CasePermissionDenied,
			Why:  "Must report reduced visibility, never a clean result.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(dir(root, "positive"), "linux")
				if err != nil {
					return env, err
				}
				env.FS = &collect.ErrorFS{
					FileSystem: env.FS,
					DenyPrefix: []string{"/home", "/root"},
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
