package checks

import (
	"context"
	"fmt"
	"strings"

	"irscan/internal/check"
	"irscan/internal/collect"
	"irscan/internal/model"
)

// scriptFileCheck is a reusable implementation for the family of Linux persistence
// techniques whose artifact is "a shell script the system sources or executes at a
// predictable moment".
//
// Sharing the implementation is legitimate here because the EVIDENCE SHAPE is genuinely
// identical -- a script file whose content is evaluated against the same documented command
// criteria. What is NOT shared is the documentation: each instance carries its own ATT&CK
// mapping with its own justification, its own overlay, its own false-positive handling and
// its own fixtures. A generic check is never stapled onto unrelated techniques.
type scriptFileCheck struct {
	id      string
	title   string
	tactics []string

	techniques []check.TechniqueMapping

	// files are individual paths; dirs are enumerated one level deep.
	files []string
	dirs  []string
	// perUserFiles are appended to each user's home directory.
	perUserFiles []string

	sourceName      string
	sourcePrivilege string
	sourceFailures  []string

	// criteriaPrefix namespaces the criteria IDs, e.g. "SHRC".
	criteriaPrefix string
	artifactType   string
	inventoryGroup string

	escalation    string
	fpHandling    string
	overlay       check.Overlay
	validation    model.ValidationStatus
	labEvidence   string
	fixtureDir    string
	wantTechnique string
}

func (c *scriptFileCheck) Meta() check.Meta {
	p := c.criteriaPrefix
	return check.Meta{
		ID:         c.id,
		Title:      c.title,
		OS:         []string{"linux"},
		Tactics:    c.tactics,
		Techniques: c.techniques,
		Sources: []check.SourceRequirement{{
			Name:         c.sourceName,
			Privilege:    c.sourcePrivilege,
			FailureModes: c.sourceFailures,
		}},
		Criteria: []model.Criterion{
			{ID: p + "-C1", Text: "The script executes a binary from a transient, " +
				"world-writable directory (/tmp, /var/tmp, /dev/shm, /run/shm)."},
			{ID: p + "-C2", Text: "The script pipes a downloader (curl/wget/fetch) directly " +
				"into a shell interpreter."},
			{ID: p + "-C3", Text: "The script decodes and executes inline content " +
				"(base64 -d, openssl enc -d, xxd -r, eval of a downloaded command)."},
			{ID: p + "-C4", Text: "The script constructs an interactive shell over a socket " +
				"(nc -e, ncat --exec, /dev/tcp, socat exec)."},
			{ID: p + "-C5", Text: "The script file is group- or world-writable, so any local " +
				"user can change what runs."},
		},
		EscalationCriteria: c.escalation,
		FalsePositiveHandling: c.fpHandling,
		Overlay:               c.overlay,
		Validation:            c.validation,
		LabEvidence:           c.labEvidence,
		FixtureProvenance:     model.Synthetic,
	}
}

func (c *scriptFileCheck) Run(ctx context.Context, env check.Env) model.CheckResult {
	started := env.Now()
	m := c.Meta()

	// Resolve the candidate file set.
	var candidates []string
	anyPathExists := false
	src := collect.SourceResult{Name: c.sourceName, Privilege: c.sourcePrivilege}

	for _, f := range c.files {
		if env.FS.Exists(f) {
			anyPathExists = true
			candidates = append(candidates, f)
		}
	}
	for _, d := range c.dirs {
		if !env.FS.Exists(d) {
			continue
		}
		anyPathExists = true
		entries, err := env.FS.ReadDir(d)
		if err != nil {
			reportSrcErr(&src, err, "listing "+d)
			continue
		}
		for _, e := range entries {
			if !e.IsDir {
				candidates = append(candidates, strings.TrimRight(d, "/")+"/"+e.Name)
			}
		}
	}
	if len(c.perUserFiles) > 0 {
		users, uRes := collect.Users(env.FS)
		if !uRes.Available {
			src.Errors = append(src.Errors,
				"could not enumerate users to locate per-user files: "+uRes.Reason)
		}
		for _, u := range users {
			if u.HomeDir == "" {
				continue
			}
			for _, name := range c.perUserFiles {
				p := strings.TrimRight(u.HomeDir, "/") + "/" + name
				if _, err := env.FS.Stat(p); err != nil {
					if isPermErr(err) {
						src.Errors = append(src.Errors, fmt.Sprintf(
							"permission denied checking %s for user %q", p, u.Name))
					}
					continue
				}
				anyPathExists = true
				candidates = append(candidates, p)
			}
		}
	}

	if !anyPathExists {
		src.Available = false
		src.Reason = fmt.Sprintf("none of the %s paths exist on this host (searched %s)",
			c.sourceName, strings.Join(append(append([]string{}, c.files...), c.dirs...), ", "))
		return check.Result(m.ID, started, env.Now,
			[]model.DataSourceStatus{check.SourceStatus(m.Sources[0], src)}, nil, nil)
	}

	byID := map[string]model.Criterion{}
	for _, cr := range m.Criteria {
		byID[cr.ID] = cr
	}
	p := c.criteriaPrefix

	var findings []model.Finding
	var inventory []model.InventoryItem

	for _, path := range candidates {
		if err := ctx.Err(); err != nil {
			return check.ErrorResult(m.ID, started, env.Now, err)
		}
		fi, err := env.FS.Stat(path)
		if err != nil {
			reportSrcErr(&src, err, "stat "+path)
			continue
		}
		data, truncated, err := env.FS.ReadFile(path)
		if err != nil {
			reportSrcErr(&src, err, "reading "+path)
			continue
		}
		if truncated {
			src.Truncated = true
		}
		src.ItemsSeen++

		inventory = append(inventory, model.InventoryItem{
			Group:        c.inventoryGroup,
			ArtifactType: c.artifactType,
			ArtifactID:   path,
			Attributes: map[string]string{
				"mode":  fi.ModeString,
				"owner": fi.Owner,
				"size":  fmt.Sprintf("%d", fi.Size),
				"lines": fmt.Sprintf("%d", strings.Count(string(data), "\n")+1),
			},
			TechniqueIDs: m.FullyCoveredTechniqueIDs(),
			CheckIDs:     []string{m.ID},
		})

		var matched []model.Criterion
		var matchedLines []string
		add := func(id string) {
			for _, x := range matched {
				if x.ID == id {
					return
				}
			}
			matched = append(matched, byID[id])
		}

		for n, line := range strings.Split(string(data), "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			hit := false
			if _, ok := TransientExecutable(t); ok {
				add(p + "-C1")
				hit = true
			}
			for _, sig := range LinuxCommandSignals(t) {
				switch sig {
				case "download-pipe-interpreter":
					add(p + "-C2")
				case "encoded-or-eval-execution":
					add(p + "-C3")
				case "interactive-shell-over-socket":
					add(p + "-C4")
				}
				hit = true
			}
			if hit && len(matchedLines) < 5 {
				matchedLines = append(matchedLines,
					fmt.Sprintf("%d: %s", n+1, Truncate(t, 200)))
			}
		}

		if len(fi.ModeString) >= 10 &&
			(fi.ModeString[5] == 'w' || fi.ModeString[8] == 'w') {
			add(p + "-C5")
		}

		if len(matched) == 0 {
			continue
		}
		// C5 alone (a permissive mode) is a hygiene issue, not evidence of persistence.
		// Requiring at least one content criterion stops this check firing on every
		// loosely-permissioned profile script on a developer box.
		onlyPermissions := len(matched) == 1 && matched[0].ID == p+"-C5"
		if onlyPermissions {
			continue
		}

		level := model.SuspiciousIndicator
		if len(matched) >= 2 {
			level = model.Corroborated
		}

		ev, err := check.FileEvidence(env, path, "script_file")
		if err != nil {
			reportSrcErr(&src, err, "evidence for "+path)
			continue
		}

		findings = append(findings, check.NewFinding(env, m.ID, check.FindingSpec{
			ArtifactType: c.artifactType,
			ArtifactID:   path,
			Level:        level,
			TechniqueIDs: m.FullyCoveredTechniqueIDs(),
			Title: fmt.Sprintf("%s %s matches %d criteria",
				c.artifactType, baseNameOf(path), len(matched)),
			WhatAndWhere: fmt.Sprintf(
				"%s (mode %s, owner %s) contains content matching %d documented criteria. "+
					"Matching lines: %s",
				path, fi.ModeString, defaultStr(fi.Owner, "unknown"), len(matched),
				defaultStr(strings.Join(matchedLines, " | "), "(permissions only)")),
			Criteria: matched,
			Benign: append([]string{
				"Administrators and configuration management legitimately add lines to " +
					"shell initialisation and rc scripts.",
				"Developer tooling (nvm, rbenv, pyenv, conda, cargo) appends initialisation " +
					"lines to shell startup files as part of normal installation.",
			}, c.overlay.FalsePositives...),
			NextPivot: []string{
				"Establish the mtime and owner of " + path + " and whether a package owns " +
					"it (dpkg -S / rpm -qf).",
				"Compare the file against a known-good peer host built from the same image.",
				"Inspect any referenced binary or URL before anything else.",
				"Check shell history and auth logs around the file's mtime, bearing in mind " +
					"both may be absent or truncated.",
			},
			Evidence: []model.EvidenceRef{ev},
			Context: map[string]string{
				"mode":  fi.ModeString,
				"owner": defaultStr(fi.Owner, "unknown"),
				"note": "Ownership by root or by a package is context only, never proof " +
					"the content is benign.",
			},
		}))
	}

	src.Available = true
	return check.Result(m.ID, started, env.Now,
		[]model.DataSourceStatus{check.SourceStatus(m.Sources[0], src)}, findings, inventory)
}

func (c *scriptFileCheck) Cases() []check.FixtureCase {
	dir := func(root, name string) string { return joinFixture(root, c.fixtureDir, name) }
	return []check.FixtureCase{
		{
			Name: "malicious line appended to a startup script",
			Kind: check.CasePositive,
			Why:  "Proves content-based detection fires on the documented command shapes.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "positive"), "linux")
			},
			WantOutcome:      model.Detected,
			MinFindings:      1,
			WantTechniqueIDs: []string{c.wantTechnique},
		},
		{
			Name: "ordinary distribution and developer-tooling content",
			Kind: check.CaseNegative,
			Why: "Proves the check tolerates the real content these files carry on a normal " +
				"host, including developer tool initialisation.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "negative"), "linux")
			},
			WantOutcome: model.NotDetected,
		},
		{
			Name: "none of the paths exist",
			Kind: check.CaseNoData,
			Why:  "Proves absence of the artifact class yields INSUFFICIENT_DATA.",
			Build: func(root string) (check.Env, error) {
				return check.FixtureEnv(dir(root, "nodata"), "linux")
			},
			WantOutcome: model.InsufficientData,
		},
		{
			Name: "paths unreadable",
			Kind: check.CasePermissionDenied,
			Why:  "Proves an unreadable path is reported, never treated as clean.",
			Build: func(root string) (check.Env, error) {
				env, err := check.FixtureEnv(dir(root, "positive"), "linux")
				if err != nil {
					return env, err
				}
				env.FS = &collect.ErrorFS{
					FileSystem: env.FS,
					DenyPrefix: append(append([]string{}, c.files...), c.dirs...),
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

// ---------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------

func reportSrcErr(res *collect.SourceResult, err error, what string) {
	msg := what + ": " + err.Error()
	if isPermErr(err) {
		msg = "permission denied " + what
	}
	for _, e := range res.Errors {
		if e == msg {
			return
		}
	}
	res.Errors = append(res.Errors, msg)
}

func isPermErr(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "permission denied")
}

func baseNameOf(p string) string {
	p = strings.TrimRight(strings.ReplaceAll(p, `\`, "/"), "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}
