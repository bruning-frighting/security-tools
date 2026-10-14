package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"irscan/internal/check"
	"irscan/internal/collect"
	"irscan/internal/model"
)

func joinFixture(root, dir, name string) string { return filepath.Join(root, dir, name) }

func init() {
	check.Register(shellRCCheck(), rcScriptCheck(), &localAccountCheck{})
}

// =======================================================================================
// LNX-PERSIST-SHELLRC-001  (T1546.004)
// =======================================================================================

func shellRCCheck() *scriptFileCheck {
	return &scriptFileCheck{
		id:      "LNX-PERSIST-SHELLRC-001",
		title:   "Suspicious content in a shell initialisation file",
		tactics: []string{"persistence", "privilege-escalation"},
		techniques: []check.TechniqueMapping{
			{
				TechniqueID: "T1546.004",
				Justification: "Shell initialisation files (/etc/profile, /etc/profile.d, " +
					"~/.bashrc and the zsh/csh equivalents) ARE the artifact this " +
					"sub-technique is defined by; the check reads exactly those files.",
			},
			{
				TechniqueID: "T1546",
				Justification: "Parent technique: a payload planted in a shell rc file is " +
					"executed by the event of a shell starting.",
			},
		},
		files: []string{
			"/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/etc/zsh/zshrc",
			"/etc/zsh/zshenv", "/etc/zsh/zprofile", "/etc/csh.cshrc", "/etc/csh.login",
		},
		dirs:         []string{"/etc/profile.d"},
		perUserFiles: []string{".bashrc", ".bash_profile", ".bash_login", ".profile",
			".zshrc", ".zprofile", ".zlogin", ".zshenv", ".kshrc", ".cshrc", ".bash_logout"},
		sourceName: "shell initialisation files",
		sourcePrivilege: "/etc files are world-readable; other users' dotfiles need root",
		sourceFailures: []string{
			"No shell initialisation file exists -> source unavailable -> INSUFFICIENT_DATA.",
			"Other users' home directories are unreadable unprivileged -> recorded as a " +
				"partial collection error -> PARTIAL_DATA, never NOT_DETECTED.",
			"A file larger than the size limit is truncated -> PARTIAL_DATA.",
		},
		criteriaPrefix: "SHRC",
		artifactType:   "shell_init_file",
		inventoryGroup: "shell initialisation files",
		fixtureDir:     "lnx-persist-shellrc-001",
		wantTechnique:  "T1546.004",
		escalation: "Every shell init file is an observed_artifact for Inventory. One " +
			"content criterion gives suspicious_indicator. Corroborated requires a second " +
			"independent criterion. A permissive file mode (SHRC-C5) alone never produces " +
			"a finding: it is a hygiene issue, not evidence of persistence, and would " +
			"otherwise fire on every developer workstation.",
		fpHandling: "Shell rc files are heavily and legitimately modified, so presence and " +
			"size are never criteria. Specifically: (a) developer tool installers (nvm, " +
			"rbenv, pyenv, conda, cargo, sdkman) append initialisation blocks as normal " +
			"behaviour and are named as the first benign explanation; (b) sourcing a file " +
			"from a home directory is NOT a criterion, because that is exactly what these " +
			"tools do; (c) only the documented command shapes match, so an rc file that " +
			"merely sets PATH or aliases cannot fire; (d) a world-writable mode alone is " +
			"suppressed as described above.",
		overlay: check.Overlay{
			Behavior: "An adversary appends commands to a shell initialisation file so their " +
				"payload runs whenever a user (or root) starts a shell. It survives reboots, " +
				"needs no scheduler or service, and on a shared host can be planted by any " +
				"user who can write the file.",
			Artifacts: []string{
				"/etc/profile and /etc/profile.d/*.sh",
				"/etc/bash.bashrc, /etc/bashrc, /etc/zsh/*, /etc/csh.*",
				"Per-user ~/.bashrc, ~/.bash_profile, ~/.profile, ~/.zshrc and friends",
				"The file's mode and owner",
			},
			Logic: "Enumerate the system-wide initialisation files and directories plus the " +
				"per-user dotfiles for every account in /etc/passwd. Read each file and " +
				"evaluate every non-comment line against the shared command criteria. " +
				"Inventory every file; emit a finding only on a content criterion match.",
			FalsePositives: []string{
				"Version managers (nvm, rbenv, pyenv, conda) append sourcing blocks on install.",
				"Site-specific administrative customisation is routine in /etc/profile.d.",
				"Some vendor agents legitimately add an initialisation line.",
			},
			Limitations: []string{
				"An unprivileged scan sees only its own user's dotfiles; the rest is " +
					"PARTIAL_DATA.",
				"Non-login, non-interactive shells read different files; a payload in a file " +
					"this check does not list (for example a sourced helper several levels " +
					"deep) is not followed -- the check does not resolve `source`/`.` chains.",
				"A line added and later removed leaves nothing here.",
				"Content seen here may have been tampered with by a root-level adversary.",
				"zsh's and csh's full file-precedence rules are not modelled; the common " +
					"files are read, not the complete per-shell search order.",
			},
			References: []check.Reference{
				{Title: "MITRE ATT&CK T1546.004 Unix Shell Configuration Modification",
					URL: "https://attack.mitre.org/techniques/T1546/004"},
				{Title: "bash(1) INVOCATION -- startup file order",
					URL: "https://www.gnu.org/software/bash/manual/bash.html#Bash-Startup-Files"},
			},
		},
		validation: model.LabVerified,
		labEvidence: "Executed 2026-10-14 against the LIVE root filesystem of WSL2 Kali " +
			"GNU/Linux Rolling 2026.1 (kernel 6.6.87.2-microsoft-standard-WSL2), " +
			"unprivileged as uid 1000; see STATUS.md Phase 2a for the recorded counts.",
	}
}

// =======================================================================================
// LNX-PERSIST-RCSCRIPT-001  (T1037.004)
// =======================================================================================

func rcScriptCheck() *scriptFileCheck {
	return &scriptFileCheck{
		id:      "LNX-PERSIST-RCSCRIPT-001",
		title:   "Suspicious content in an RC or init script",
		tactics: []string{"persistence", "privilege-escalation"},
		techniques: []check.TechniqueMapping{
			{
				TechniqueID: "T1037.004",
				Justification: "RC scripts (/etc/rc.local, /etc/rc.d/*, /etc/init.d/*) ARE " +
					"the artifact this sub-technique names; the check reads those paths.",
			},
			{
				TechniqueID: "T1037",
				Justification: "Parent technique: an RC script runs at boot, which is boot " +
					"or logon initialisation script execution.",
			},
		},
		files: []string{
			"/etc/rc.local", "/etc/rc.common", "/etc/rc.d/rc.local", "/etc/conf.d/local.start",
		},
		dirs:            []string{"/etc/init.d", "/etc/rc.d", "/etc/rc.local.d"},
		sourceName:      "rc and init scripts",
		sourcePrivilege: "normally world-readable",
		sourceFailures: []string{
			"No rc or init path exists (common on a pure-systemd host) -> source " +
				"unavailable -> INSUFFICIENT_DATA.",
			"A directory is unreadable -> partial collection -> PARTIAL_DATA.",
			"A script larger than the size limit is truncated -> PARTIAL_DATA.",
		},
		criteriaPrefix: "RCSC",
		artifactType:   "rc_script",
		inventoryGroup: "rc and init scripts",
		fixtureDir:     "lnx-persist-rcscript-001",
		wantTechnique:  "T1037.004",
		escalation: "Every rc/init script is an observed_artifact for Inventory. One " +
			"content criterion gives suspicious_indicator; corroborated requires a second " +
			"independent criterion. A permissive mode alone never produces a finding -- " +
			"init scripts are legitimately 0755 and executable.",
		fpHandling: "/etc/init.d is densely populated with legitimate SysV scripts on any " +
			"host with a compatibility layer, so presence is never a criterion. " +
			"Specifically: (a) init scripts legitimately reference /var/run and /run paths, " +
			"which are NOT in the transient-directory list; (b) they legitimately use " +
			"start-stop-daemon and source /lib/lsb/init-functions, neither of which " +
			"matches; (c) only the documented command shapes fire; (d) the executable bit " +
			"and 0755 mode, normal for these files, are not criteria.",
		overlay: check.Overlay{
			Behavior: "An adversary adds commands to an rc or init script so they execute at " +
				"boot with root privilege, before most monitoring is running.",
			Artifacts: []string{
				"/etc/rc.local and its variants",
				"SysV init scripts under /etc/init.d",
				"Runlevel directories under /etc/rc.d",
			},
			Logic: "Read each rc/init path and evaluate every non-comment line against the " +
				"shared command criteria. Inventory every script; emit a finding only on a " +
				"content criterion match.",
			FalsePositives: []string{
				"Legacy SysV init scripts shipped by packages populate /etc/init.d heavily.",
				"Site-specific boot customisation in /etc/rc.local is a long-standing " +
					"administrative practice.",
				"Container entrypoint tooling sometimes writes rc.local.",
			},
			Limitations: []string{
				"On a pure-systemd host these paths may not exist at all, which yields " +
					"INSUFFICIENT_DATA -- correct, but it means this check contributes " +
					"nothing there and the systemd check carries the coverage.",
				"The check does not resolve scripts that source other files.",
				"Runlevel symlink ordering is not modelled, so whether a given script " +
					"actually runs at boot is not established.",
				"A line added and later removed leaves nothing here.",
			},
			References: []check.Reference{
				{Title: "MITRE ATT&CK T1037.004 RC Scripts",
					URL: "https://attack.mitre.org/techniques/T1037/004"},
				{Title: "MITRE ATT&CK T1037 Boot or Logon Initialization Scripts",
					URL: "https://attack.mitre.org/techniques/T1037"},
			},
		},
		validation: model.LabVerified,
		labEvidence: "Executed 2026-10-14 against the LIVE root filesystem of WSL2 Kali " +
			"GNU/Linux Rolling 2026.1 (kernel 6.6.87.2-microsoft-standard-WSL2), " +
			"unprivileged as uid 1000; see STATUS.md Phase 2a for the recorded counts.",
	}
}

// =======================================================================================
// LNX-PERSIST-ACCOUNT-001
// =======================================================================================

type localAccountCheck struct{}

const accountCheckID = "LNX-PERSIST-ACCOUNT-001"

// privilegedGroups confer administrative or host-escape capability.
var privilegedGroups = map[string]string{
	"sudo":   "can execute commands as root via sudo",
	"wheel":  "can execute commands as root via sudo/su",
	"admin":  "legacy administrative group",
	"root":   "root's own group",
	"docker": "can mount the host filesystem into a container and so become root",
	"lxd":    "can mount the host filesystem into a container and so become root",
	"disk":   "raw block device access, which is equivalent to root",
	"shadow": "can read password hashes",
	"adm":    "can read system logs",
}

func (c *localAccountCheck) Meta() check.Meta {
	return check.Meta{
		ID:      accountCheckID,
		Title:   "Suspicious local account or privileged group membership",
		OS:      []string{"linux"},
		Tactics: []string{"persistence", "privilege-escalation"},
		Techniques: []check.TechniqueMapping{
			{
				TechniqueID: "T1136.001",
				Justification: "A created local account persists as an /etc/passwd entry; " +
					"the check enumerates exactly those entries and flags the shapes a " +
					"legitimately provisioned account does not have.",
			},
			{
				TechniqueID: "T1136",
				Justification: "Parent technique of T1136.001.",
			},
			{
				TechniqueID: "T1098.007",
				Justification: "Adding an account to sudo/wheel/docker is 'Additional Local " +
					"or Domain Groups'; the check reads /etc/group membership directly.",
			},
			{
				TechniqueID: "T1098",
				Justification: "Parent technique: modifying an existing account's group " +
					"membership to retain privileged access.",
			},
			{
				TechniqueID: "T1078.003",
				Justification: "Local account abuse. Mapped Partial: the check can show a " +
					"local account exists and is privileged, but cannot show it was USED, " +
					"which is the core of the technique and needs authentication telemetry.",
				Partial: true,
			},
		},
		Sources: []check.SourceRequirement{
			{
				Name:      "/etc/passwd",
				Privilege: "none (world-readable)",
				FailureModes: []string{
					"Unreadable -> source unavailable -> INSUFFICIENT_DATA.",
					"/etc/shadow unreadable unprivileged -> password state is unknown, " +
						"recorded as a partial collection error -> PARTIAL_DATA.",
				},
			},
			{
				Name:      "/etc/group",
				Privilege: "none (world-readable)",
				FailureModes: []string{
					"Unreadable -> group-membership criteria cannot be evaluated -> " +
						"PARTIAL_DATA.",
					"Primary-group membership is NOT listed in /etc/group, so membership " +
						"derived here is incomplete by construction.",
				},
			},
		},
		Criteria: []model.Criterion{
			{ID: "ACCT-C1", Text: "A non-root account has uid 0, giving it full root " +
				"privilege while appearing in listings as an ordinary user."},
			{ID: "ACCT-C2", Text: "An account has an EMPTY password field in /etc/shadow, " +
				"so it can be authenticated with no password."},
			{ID: "ACCT-C3", Text: "A system account (uid below 1000) has an interactive " +
				"login shell, which service accounts normally do not."},
			{ID: "ACCT-C4", Text: "A system account or an account with a nologin shell is a " +
				"member of a privileged group (sudo, wheel, admin, docker, lxd, disk, shadow)."},
			{ID: "ACCT-C5", Text: "An account's home directory is in a transient, " +
				"world-writable location (/tmp, /var/tmp, /dev/shm)."},
		},
		EscalationCriteria: "Every account is an observed_artifact for Inventory. One " +
			"criterion gives suspicious_indicator. Corroborated requires a second " +
			"independent criterion -- for example a uid-0 non-root account (ACCT-C1) that " +
			"also has an empty password (ACCT-C2). ACCT-C1 and ACCT-C2 are strong on their " +
			"own; ACCT-C3 and ACCT-C4 are common enough on real systems that they are " +
			"reported but do not escalate alone.",
		FalsePositiveHandling: "Account inventories are noisy on real hosts, so: (a) the " +
			"check never reports the mere existence of an account; (b) ACCT-C3 excludes " +
			"the well-known system accounts that legitimately carry a shell (root, sync, " +
			"halt, shutdown, operator, and postgres -- Debian's postgresql package ships " +
			"it with /bin/bash, which produced a finding on a real host), and that " +
			"exclusion applies ONLY when the account is not uid 0 and not in a privileged " +
			"group, so it cannot launder a backdoor named after a service; the account is " +
			"still listed in Inventory either way; (c) ACCT-C4 " +
			"names the common legitimate cases -- CI runners, build agents and " +
			"container-management service accounts are routinely in docker or sudo -- as " +
			"the first benign explanation rather than excluding them silently; (d) when " +
			"/etc/shadow is unreadable, ACCT-C2 is NOT evaluated at all rather than assumed " +
			"false, and the result is PARTIAL_DATA.",
		Overlay: check.Overlay{
			Behavior: "An adversary creates a local account, or adds an existing one to a " +
				"privileged group, to retain access that survives password resets and does " +
				"not depend on a dropped file. A uid-0 account is a classic backdoor because " +
				"it is root but does not look like root in a casual listing.",
			Artifacts: []string{
				"/etc/passwd entries: name, uid, gid, home directory, login shell",
				"/etc/shadow password state (hashed / locked / empty)",
				"/etc/group supplementary membership of privileged groups",
			},
			Logic: "Parse /etc/passwd and /etc/group, and /etc/shadow when readable. " +
				"Password HASHES ARE NEVER RETAINED -- only the state. Evaluate the five " +
				"documented criteria per account. Inventory every account; emit a finding " +
				"only on a criterion match.",
			FalsePositives: []string{
				"CI runners, build agents and container tooling are routinely members of " +
					"docker or sudo.",
				"Some appliances and vendor images legitimately ship a second uid-0 account.",
				"Service accounts occasionally need a real shell for maintenance scripts.",
				"Locked accounts with no password hash are normal and are NOT the same as " +
					"an empty password field.",
			},
			Limitations: []string{
				"Only LOCAL accounts are visible. Domain, LDAP, SSSD and cloud-directory " +
					"accounts are not in /etc/passwd and are entirely out of view.",
				"Primary-group membership does not appear in /etc/group, so privileged " +
					"membership derived here is incomplete.",
				"Without root, /etc/shadow cannot be read and password state is unknown; " +
					"ACCT-C2 is then not evaluated.",
				"The check cannot tell when an account was created: /etc/passwd carries no " +
					"timestamps. The file's mtime bounds the most recent change only.",
				"sudoers rules (including NOPASSWD entries in /etc/sudoers.d) are NOT read " +
					"by this check, so privilege granted that way is not seen.",
			},
			References: []check.Reference{
				{Title: "MITRE ATT&CK T1136.001 Create Account: Local Account",
					URL: "https://attack.mitre.org/techniques/T1136/001"},
				{Title: "MITRE ATT&CK T1098.007 Additional Local or Domain Groups",
					URL: "https://attack.mitre.org/techniques/T1098/007"},
				{Title: "passwd(5) manual page",
					URL: "https://man7.org/linux/man-pages/man5/passwd.5.html"},
			},
		},
		Validation: model.LabVerified,
		LabEvidence: "Executed 2026-10-14 against the LIVE root filesystem of WSL2 Kali " +
			"GNU/Linux Rolling 2026.1 (kernel 6.6.87.2-microsoft-standard-WSL2), " +
			"unprivileged as uid 1000, enumerating the host's real /etc/passwd and " +
			"/etc/group; see STATUS.md Phase 2a.",
		FixtureProvenance: model.Synthetic,
	}
}

// shellBearingSystemAccounts legitimately carry an interactive shell on a stock system, so
// ACCT-C3 does not fire for them.
//
// Found by the real-host run: Debian's postgresql package creates `postgres` with
// /bin/bash, so every PostgreSQL host produced a finding. That is noise, and the spec
// requires documented false-positive handling for noisy areas before a check may count as
// IMPLEMENTED.
//
// IMPORTANT: this list suppresses ACCT-C3 ONLY, and only for an account that is not uid 0
// and not in a privileged group (see the call site). An adversary who names a backdoor
// "postgres" still trips ACCT-C1 (uid 0), ACCT-C2 (empty password), ACCT-C4 (privileged
// group) or ACCT-C5 (transient home). The account also remains in the Inventory report
// either way, so the suppression is visible rather than silent.
var shellBearingSystemAccounts = map[string]string{
	"root":     "the superuser account",
	"sync":     "ships with /bin/sync as its shell by design",
	"halt":     "legacy shutdown account",
	"shutdown": "legacy shutdown account",
	"operator": "legacy operator account",
	"postgres": "Debian/RHEL postgresql packages create this account with /bin/bash",
}

func (c *localAccountCheck) Run(ctx context.Context, env check.Env) model.CheckResult {
	started := env.Now()
	m := c.Meta()

	users, uRes := collect.Users(env.FS)
	groups, gRes := collect.Groups(env.FS)
	sources := []model.DataSourceStatus{
		check.SourceStatus(m.Sources[0], uRes),
		check.SourceStatus(m.Sources[1], gRes),
	}
	if !uRes.Available {
		return check.Result(m.ID, started, env.Now, sources, nil, nil)
	}

	// Supplementary membership only; primary-group membership is not in /etc/group.
	privOf := map[string][]string{}
	for _, g := range groups {
		if _, ok := privilegedGroups[strings.ToLower(g.Name)]; !ok {
			continue
		}
		for _, mem := range g.Members {
			privOf[mem] = append(privOf[mem], g.Name)
		}
	}

	// Password state is only knowable when /etc/shadow was readable. uRes records a
	// partial-collection error when it was not; in that case ACCT-C2 is not evaluated at
	// all rather than assumed false.
	shadowReadable := true
	for _, e := range uRes.Errors {
		if strings.Contains(e, "/etc/shadow") {
			shadowReadable = false
		}
	}

	byID := map[string]model.Criterion{}
	for _, cr := range m.Criteria {
		byID[cr.ID] = cr
	}

	var findings []model.Finding
	var inventory []model.InventoryItem

	for _, u := range users {
		if err := ctx.Err(); err != nil {
			return check.ErrorResult(m.ID, started, env.Now, err)
		}
		uid, uidErr := strconv.Atoi(u.UID)
		priv := privOf[u.Name]
		sort.Strings(priv)

		inventory = append(inventory, model.InventoryItem{
			Group:        "local accounts",
			ArtifactType: "local_account",
			ArtifactID:   u.Name,
			Attributes: map[string]string{
				"uid":                u.UID,
				"gid":                u.GID,
				"home":               u.HomeDir,
				"shell":              u.Shell,
				"password_state":     u.PasswordState,
				"privileged_groups":  strings.Join(priv, ","),
			},
			TechniqueIDs: []string{"T1136", "T1136.001", "T1098", "T1098.007"},
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

		if uidErr == nil && uid == 0 && u.Name != "root" {
			add("ACCT-C1")
		}
		if shadowReadable && u.PasswordState == "empty" {
			add("ACCT-C2")
		}
		interactive := u.Shell != "" &&
			!strings.HasSuffix(u.Shell, "/nologin") && !strings.HasSuffix(u.Shell, "/false") &&
			!strings.HasSuffix(u.Shell, "/sync")
		// The known-shell-bearing exclusion applies ONLY when nothing else is wrong with
		// the account, so it cannot be used to launder a backdoor named after a service.
		_, knownShellAccount := shellBearingSystemAccounts[u.Name]
		excusedByName := knownShellAccount && len(priv) == 0 &&
			!(uidErr == nil && uid == 0 && u.Name != "root")
		if uidErr == nil && uid < 1000 && interactive && !excusedByName {
			add("ACCT-C3")
		}
		if len(priv) > 0 && ((uidErr == nil && uid < 1000) || !interactive) &&
			u.Name != "root" {
			add("ACCT-C4")
		}
		if _, hit := InLinuxTransientDir(strings.TrimRight(u.HomeDir, "/") + "/"); hit {
			add("ACCT-C5")
		}

		if len(matched) == 0 {
			continue
		}
		// ACCT-C3 and ACCT-C4 are common on real systems; alone they stay at
		// suspicious_indicator. Only two independent criteria corroborate.
		level := model.SuspiciousIndicator
		if len(matched) >= 2 {
			level = model.Corroborated
		}

		detail := fmt.Sprintf("name=%s uid=%s gid=%s home=%s shell=%s password_state=%s "+
			"privileged_groups=%s", u.Name, u.UID, u.GID, u.HomeDir, u.Shell,
			u.PasswordState, defaultStr(strings.Join(priv, ","), "(none)"))

		findings = append(findings, check.NewFinding(env, m.ID, check.FindingSpec{
			ArtifactType: "local_account",
			ArtifactID:   u.Name,
			Level:        level,
			TechniqueIDs: []string{"T1136", "T1136.001", "T1098", "T1098.007"},
			Title: fmt.Sprintf("local account %q matches %d criteria", u.Name, len(matched)),
			WhatAndWhere: fmt.Sprintf("Account %q in /etc/passwd: %s", u.Name, detail),
			Criteria:     matched,
			Benign: []string{
				"CI runners, build agents and container tooling are routinely members of " +
					"docker, lxd or sudo.",
				"Some vendor appliances legitimately ship a second uid-0 account.",
				"A service account may legitimately need a shell for maintenance scripts.",
				"A locked account (password field '!' or '*') is normal and is NOT an " +
					"empty password.",
			},
			NextPivot: []string{
				"Compare this account against the host build standard and against a " +
					"known-good peer built from the same image.",
				"Check the mtime of /etc/passwd, /etc/shadow and /etc/group to bound when " +
					"the account or membership last changed.",
				"Review authentication logs for successful logins by " + u.Name +
					", bearing in mind the logs may not reach back far enough.",
				"Read /etc/sudoers and /etc/sudoers.d for rules granting this account " +
					"privilege -- this check does not parse them.",
			},
			// The password HASH is never retained; only the state, recorded as metadata.
			Evidence: []model.EvidenceRef{check.RedactedEvidence(
				env, "/etc/passwd#"+u.Name, "account_record", "local account record",
				int64(len(detail)),
				"Account metadata is retained; the /etc/shadow password hash is never read "+
					"into evidence. Only the derived state ("+u.PasswordState+") is recorded.",
			)},
			Context: map[string]string{
				"uid":                 u.UID,
				"shell":               u.Shell,
				"privileged_groups":   strings.Join(priv, ","),
				"shadow_readable":     fmt.Sprintf("%t", shadowReadable),
				"group_data_complete": "false: /etc/group lists supplementary members only, " +
					"so primary-group privilege is not visible here",
			},
		}))
	}

	return check.Result(m.ID, started, env.Now, sources, findings, inventory)
}

func (c *localAccountCheck) Cases() []check.FixtureCase {
	dir := func(root, name string) string {
		return filepath.Join(root, "lnx-persist-account-001", name)
	}
	return []check.FixtureCase{
		{
			Name: "uid-0 backdoor account with an empty password",
			Kind: check.CasePositive,
			Why: "Two independent strong criteria (ACCT-C1, ACCT-C2) must fire and escalate " +
				"to corroborated.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "positive"), "linux")
			},
			WantOutcome:      model.Detected,
			MinFindings:      1,
			WantTechniqueIDs: []string{"T1136.001"},
		},
		{
			Name: "stock /etc/passwd with ordinary service accounts and a CI runner in docker",
			Kind: check.CaseNegative,
			Why: "A realistic account set -- including a sudo-capable human admin and " +
				"nologin service accounts -- must not fire.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "negative"), "linux")
			},
			WantOutcome: model.NotDetected,
		},
		{
			Name: "no /etc/passwd",
			Kind: check.CaseNoData,
			Why:  "Without an account database the honest answer is INSUFFICIENT_DATA.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "nodata"), "linux")
			},
			WantOutcome: model.InsufficientData,
		},
		{
			Name: "/etc/shadow unreadable (unprivileged scan)",
			Kind: check.CasePermissionDenied,
			Why: "The normal non-root case. Password state becomes unknown, so ACCT-C2 must " +
				"NOT be evaluated and the result must not read as clean.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(dir(root, "negative"), "linux")
				if err != nil {
					return env, err
				}
				env.FS = &collect.ErrorFS{
					FileSystem: env.FS,
					DenyPrefix: []string{"/etc/shadow"},
				}
				return env, nil
			},
			WantOutcome: model.PartialData,
			AlsoAccept:  []model.Outcome{model.InsufficientData, model.PermissionDenied},
		},
	}
}
