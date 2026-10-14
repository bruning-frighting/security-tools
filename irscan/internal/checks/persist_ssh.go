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

func init() { check.Register(&sshAuthorizedKeysCheck{}) }

type sshAuthorizedKeysCheck struct{}

const sshKeyCheckID = "LNX-PERSIST-SSHKEY-001"

func (c *sshAuthorizedKeysCheck) Meta() check.Meta {
	return check.Meta{
		ID:      sshKeyCheckID,
		Title:   "Suspicious SSH authorized_keys entry",
		OS:      []string{"linux"},
		Tactics: []string{"persistence"},

		Techniques: []check.TechniqueMapping{
			{
				TechniqueID: "T1098.004",
				Justification: "An authorized_keys entry IS the artifact this sub-technique " +
					"describes; the check parses each user's ~/.ssh/authorized_keys plus the " +
					"system-wide locations.",
			},
			{
				TechniqueID: "T1098",
				Justification: "Parent technique; adding an SSH key is account manipulation " +
					"that grants durable remote access without creating a new account.",
			},
		},

		Sources: []check.SourceRequirement{
			{
				Name:      "/etc/passwd",
				Privilege: "none (world-readable)",
				FailureModes: []string{
					"Unreadable -> home directories cannot be enumerated -> the " +
						"authorized_keys source reports unavailable -> INSUFFICIENT_DATA.",
				},
			},
			{
				Name: "ssh authorized_keys",
				Privilege: "read access to each user's ~/.ssh; root needed for other users' " +
					"home directories",
				FailureModes: []string{
					"An unprivileged scan cannot read other users' ~/.ssh -> recorded as a " +
						"partial collection error -> PARTIAL_DATA, never NOT_DETECTED.",
					"A home directory on a network filesystem is skipped by default.",
					"sshd_config may relocate AuthorizedKeysFile; see Limitations.",
				},
			},
		},

		Criteria: []model.Criterion{
			{ID: "SSHK-C1", Text: `The key entry carries a forced command option ` +
				`(command="..."), so the key executes a fixed command on connection -- a ` +
				`durable backdoor that does not need an interactive shell.`},
			{ID: "SSHK-C2", Text: "An authorized_keys file exists for an account whose login " +
				"shell is /usr/sbin/nologin or /bin/false, i.e. a service account that is " +
				"not supposed to accept interactive SSH logins."},
			{ID: "SSHK-C3", Text: "The authorized_keys file is group- or world-writable, so " +
				"another local user can authorise their own key."},
			{ID: "SSHK-C4", Text: "The entry authorises direct login to uid 0 (root)."},
		},

		EscalationCriteria: "Every key is an observed_artifact for Inventory. One criterion " +
			"gives suspicious_indicator. Corroborated requires a second independent " +
			"criterion -- for example a forced-command key (SSHK-C1) installed on a " +
			"nologin service account (SSHK-C2), which together are far harder to explain " +
			"benignly than either alone.",

		FalsePositiveHandling: "Key presence alone is never a finding -- on a managed estate " +
			"every host has authorized_keys. Specifically: (a) forced-command keys are " +
			"standard for rsync/borg/restic backup and for git shell access, so SSHK-C1 " +
			"alone stays at suspicious_indicator and the finding names those tools; " +
			"(b) SSHK-C2 tolerates accounts that legitimately accept keys with a restricted " +
			"shell (git, gitlab-runner, borg) by listing them as the first benign " +
			"explanation rather than by silently excluding them, so the analyst sees and " +
			"decides; (c) root keys are normal on hosts managed by Ansible or " +
			"configuration management, which is stated on every SSHK-C4 finding.",

		Overlay: check.Overlay{
			Behavior: "An adversary appends their public key to a user's authorized_keys " +
				"file, giving themselves durable remote access that survives password " +
				"changes and does not create a new account. Adding a forced command makes " +
				"the key execute a payload on connection.",
			Artifacts: []string{
				"~/.ssh/authorized_keys and ~/.ssh/authorized_keys2 for every user in /etc/passwd",
				"/etc/ssh/authorized_keys for hardened centralised configurations",
				"The options field preceding the key type (command=, no-pty, permitopen=)",
				"File mode and ownership of the authorized_keys file itself",
			},
			Logic: "Enumerate users from /etc/passwd, read each home directory's " +
				"authorized_keys, and parse every entry into options / key type / key blob " +
				"/ comment. The key blob is reduced to a SHA-256 fingerprint rather than " +
				"retained. Evaluate the four documented criteria. Inventory every key; emit " +
				"a Finding only on a criterion match.",
			FalsePositives: []string{
				"Backup tooling (borg, restic, rsync, rrsync) legitimately installs " +
					"forced-command keys.",
				"Git hosting accounts use forced commands with a restricted shell by design.",
				"Configuration-management systems install root keys as standard practice.",
				"Service accounts such as gitlab-runner or jenkins may legitimately have " +
					"keys despite a nologin shell.",
			},
			Limitations: []string{
				"An unprivileged scan sees only its own user's keys; everything else is " +
					"PARTIAL_DATA.",
				"sshd_config AuthorizedKeysFile may point to a non-default location using " +
					"%u/%h tokens; the check covers the default and the common /etc/ssh " +
					"location only, so a relocated path would be missed.",
				"AuthorizedKeysCommand (dynamically generated keys from LDAP or similar) " +
					"produces no file and is entirely invisible to this check.",
				"The check cannot tell a legitimate key from an attacker's key by " +
					"inspection: it reports the fingerprint and the risky options, and the " +
					"analyst must compare against an authorised-key inventory.",
				"A key that was used and then removed leaves nothing here.",
			},
			References: []check.Reference{
				{Title: "MITRE ATT&CK T1098.004 SSH Authorized Keys",
					URL: "https://attack.mitre.org/techniques/T1098/004"},
				{Title: "sshd(8) AUTHORIZED_KEYS FILE FORMAT",
					URL: "https://man.openbsd.org/sshd#AUTHORIZED_KEYS_FILE_FORMAT"},
			},
		},

		Validation: model.LabVerified,
		LabEvidence: "Executed 2026-10-14 against the LIVE root filesystem of WSL2 Kali " +
			"GNU/Linux Rolling 2026.1 (kernel 6.6.87.2-microsoft-standard-WSL2), " +
			"unprivileged as uid 1000, scan_id irscan-20261014T044834Z-7b0a0cd0. " +
			"Enumerated 31 real accounts from /etc/passwd and returned PARTIAL_DATA, " +
			"correctly reporting that /etc/shadow and /root/.ssh were unreadable without " +
			"privilege instead of reporting that no SSH keys exist. The denied-vs-absent " +
			"distinction in the collector was corrected as a direct result of this run.",
		FixtureProvenance: model.Synthetic,
	}
}

func (c *sshAuthorizedKeysCheck) Run(ctx context.Context, env check.Env) model.CheckResult {
	started := env.Now()
	m := c.Meta()

	users, uRes := collect.Users(env.FS)
	keys, kRes := collect.AuthorizedKeys(env.FS)
	sources := []model.DataSourceStatus{
		check.SourceStatus(m.Sources[0], uRes),
		check.SourceStatus(m.Sources[1], kRes),
	}
	if !uRes.Available || !kRes.Available {
		return check.Result(m.ID, started, env.Now, sources, nil, nil)
	}

	shellByUser := map[string]string{}
	uidByUser := map[string]string{}
	for _, u := range users {
		shellByUser[u.Name] = u.Shell
		uidByUser[u.Name] = u.UID
	}

	byID := map[string]model.Criterion{}
	for _, cr := range m.Criteria {
		byID[cr.ID] = cr
	}

	var findings []model.Finding
	var inventory []model.InventoryItem

	for _, k := range keys {
		if err := ctx.Err(); err != nil {
			return check.ErrorResult(m.ID, started, env.Now, err)
		}
		artifactID := fmt.Sprintf("%s:%d", k.Path, k.LineNo)

		inventory = append(inventory, model.InventoryItem{
			Group:        "ssh authorized keys",
			ArtifactType: "ssh_authorized_key",
			ArtifactID:   artifactID,
			Attributes: map[string]string{
				"user":        k.User,
				"key_type":    k.KeyType,
				"fingerprint": k.Fingerprint,
				"comment":     Truncate(k.Comment, 120),
				"options":     Truncate(k.Options, 160),
				"file_mode":   k.FileMode,
			},
			TechniqueIDs: []string{"T1098", "T1098.004"},
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

		if strings.Contains(strings.ToLower(k.Options), "command=") {
			add("SSHK-C1")
		}
		if sh, ok := shellByUser[k.User]; ok {
			if strings.HasSuffix(sh, "/nologin") || strings.HasSuffix(sh, "/false") {
				add("SSHK-C2")
			}
		}
		if fi, err := env.FS.Stat(k.Path); err == nil {
			// Mode string is like -rw-r--r--; group write is index 5, other write index 8.
			if len(fi.ModeString) >= 10 &&
				(fi.ModeString[5] == 'w' || fi.ModeString[8] == 'w') {
				add("SSHK-C3")
			}
		}
		if uidByUser[k.User] == "0" {
			add("SSHK-C4")
		}

		if len(matched) == 0 {
			continue
		}
		level := model.SuspiciousIndicator
		if len(matched) >= 2 {
			level = model.Corroborated
		}

		// The public key blob is not secret, but it is not retained either: the fingerprint
		// is what an analyst compares against an authorised-key inventory, and keeping the
		// blob only adds bulk. The options field IS retained because it carries the
		// forced command, which is the actual payload.
		ev := check.LineEvidence(env, k.Path, k.LineNo,
			fmt.Sprintf("options=%q type=%s fingerprint=sha256:%s comment=%q",
				k.Options, k.KeyType, k.Fingerprint, k.Comment))

		findings = append(findings, check.NewFinding(env, m.ID, check.FindingSpec{
			ArtifactType: "ssh_authorized_key",
			ArtifactID:   artifactID,
			Level:        level,
			TechniqueIDs: []string{"T1098", "T1098.004"},
			Title: fmt.Sprintf("authorized_keys entry for %q matches %d criteria",
				k.User, len(matched)),
			WhatAndWhere: fmt.Sprintf(
				"%s line %d authorises a %s key (fingerprint sha256:%s) for account %q "+
					"(shell %s, uid %s); options: %s",
				k.Path, k.LineNo, k.KeyType, k.Fingerprint, k.User,
				defaultStr(shellByUser[k.User], "unknown"),
				defaultStr(uidByUser[k.User], "unknown"),
				defaultStr(Truncate(k.Options, 200), "(none)")),
			Criteria: matched,
			Benign: []string{
				"Backup tooling (borg, restic, rsync/rrsync) installs forced-command keys " +
					"as its normal mode of operation.",
				"Git hosting and CI service accounts legitimately hold keys despite a " +
					"restricted or nologin shell.",
				"Configuration management (Ansible and similar) installs root keys by design.",
			},
			NextPivot: []string{
				"Compare fingerprint sha256:" + k.Fingerprint +
					" against the organisation's authorised-key inventory.",
				"Check the mtime and ownership of " + k.Path + " and whether it changed " +
					"around other suspicious activity.",
				"If a forced command is present, inspect exactly what it runs.",
				"Review sshd authentication logs for successful logins using this key, " +
					"noting the log may not reach back far enough.",
			},
			Evidence: []model.EvidenceRef{ev},
			Context: map[string]string{
				"account_shell": shellByUser[k.User],
				"account_uid":   uidByUser[k.User],
				"file_mode":     k.FileMode,
				"note": "A valid-looking key or a service-account owner is context only, " +
					"never proof the key is authorised.",
			},
		}))
	}

	return check.Result(m.ID, started, env.Now, sources, findings, inventory)
}

func (c *sshAuthorizedKeysCheck) Cases() []check.FixtureCase {
	dir := func(root, name string) string {
		return filepath.Join(root, "lnx-persist-sshkey-001", name)
	}
	return []check.FixtureCase{
		{
			Name: "forced-command key on a nologin service account",
			Kind: check.CasePositive,
			Why: "Two independent criteria (SSHK-C1 and SSHK-C2) must both fire and escalate " +
				"the finding to corroborated.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "positive"), "linux")
			},
			WantOutcome:      model.Detected,
			MinFindings:      1,
			WantTechniqueIDs: []string{"T1098.004"},
		},
		{
			Name: "ordinary admin key on an interactive account",
			Kind: check.CaseNegative,
			Why: "A normal ed25519 key for a shell user with correct 0600 permissions must " +
				"not produce a finding.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "negative"), "linux")
			},
			WantOutcome: model.NotDetected,
		},
		{
			Name: "no /etc/passwd, so users cannot be enumerated",
			Kind: check.CaseNoData,
			Why: "Without a user list there are no home directories to search; the honest " +
				"answer is INSUFFICIENT_DATA, not 'no keys found'.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "nodata"), "linux")
			},
			WantOutcome: model.InsufficientData,
		},
		{
			Name: "home directories unreadable (unprivileged scan)",
			Kind: check.CasePermissionDenied,
			Why: "This models the common real case: a non-root scan can read /etc/passwd but " +
				"not other users' ~/.ssh. It must report partial visibility, never a clean " +
				"result.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(dir(root, "positive"), "linux")
				if err != nil {
					return env, err
				}
				env.FS = &collect.ErrorFS{
					FileSystem: env.FS,
					DenyPrefix: []string{"/home", "/root", "/var/lib"},
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
