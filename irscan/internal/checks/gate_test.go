package checks

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"irscan/internal/check"
	"irscan/internal/model"
	"irscan/internal/registry"
)

// This file is the machine-verified half of the per-check quality gate.
//
// Rather than trusting a check's declared validation status, it runs every case the check
// supplies and asserts the outcomes. A check cannot reach IMPLEMENTED by asserting that it
// is good; it has to demonstrate a passing positive, negative, no-data and
// permission-denied case, plus complete documentation and a valid ATT&CK mapping.

// prepareFixtures copies the fixture tree into a temp directory and applies the POSIX modes
// recorded in each tree's modes.json.
//
// This indirection exists for two concrete reasons:
//   - git stores only the executable bit, so world-writable fixtures could not survive a
//     checkout, yet several criteria depend on exactly that;
//   - the repository lives on /mnt/c (drvfs) in this environment, which reports every file
//     as mode 0777. Running the negative fixtures directly from there would make every unit
//     file look world-writable and the negative cases would fail for a reason that has
//     nothing to do with the checks.
func prepareFixtures(t *testing.T) string {
	t.Helper()
	src, err := filepath.Abs(filepath.Join("..", "..", "testdata", "fixtures"))
	if err != nil {
		t.Fatalf("resolving fixture dir: %v", err)
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("fixtures missing (run: python testdata/make_fixtures.py): %v", err)
	}
	dst := t.TempDir()

	err = filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
	if err != nil {
		t.Fatalf("copying fixtures: %v", err)
	}

	// Apply recorded modes.
	entries, err := os.ReadDir(dst)
	if err != nil {
		t.Fatalf("reading fixture root: %v", err)
	}
	for _, checkDir := range entries {
		if !checkDir.IsDir() {
			continue
		}
		caseDirs, err := os.ReadDir(filepath.Join(dst, checkDir.Name()))
		if err != nil {
			continue
		}
		for _, cd := range caseDirs {
			if !cd.IsDir() {
				continue
			}
			base := filepath.Join(dst, checkDir.Name(), cd.Name())
			applyRenames(t, base)
			applyModes(t, base)
			applyLinks(t, base)
		}
	}
	return dst
}

// applyRenames moves fixture entries from a Windows-safe placeholder path to their real
// path. Some real-world artifact names (an all-dots directory, trailing dots or spaces)
// are rejected or silently normalised by the Win32 API that the fixture generator runs
// under, so such paths are written under a safe name and renamed here -- this harness
// always runs on Linux and has no such restriction.
func applyRenames(t *testing.T, base string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(base, "renames.json"))
	if err != nil {
		return
	}
	var renames map[string]string
	if err := json.Unmarshal(data, &renames); err != nil {
		t.Fatalf("parsing renames.json in %s: %v", base, err)
	}
	for safe, real := range renames {
		src := filepath.Join(base, filepath.FromSlash(safe))
		dst := filepath.Join(base, filepath.FromSlash(real))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatalf("creating parent dir for rename target %s: %v", real, err)
		}
		if err := os.Rename(src, dst); err != nil {
			t.Fatalf("renaming %s -> %s: %v", safe, real, err)
		}
	}
}

func applyModes(t *testing.T, base string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(base, "modes.json"))
	if err != nil {
		return // no explicit modes for this tree
	}
	var modes map[string]string
	if err := json.Unmarshal(data, &modes); err != nil {
		t.Fatalf("parsing modes.json in %s: %v", base, err)
	}
	for rel, octal := range modes {
		m, err := strconv.ParseUint(strings.TrimPrefix(octal, "0o"), 8, 32)
		if err != nil {
			t.Fatalf("bad mode %q for %s: %v", octal, rel, err)
		}
		if err := os.Chmod(filepath.Join(base, filepath.FromSlash(rel)),
			os.FileMode(m)); err != nil {
			t.Fatalf("chmod %s: %v", rel, err)
		}
	}
}

// applyLinks materialises the symlinks declared in links.json.
//
// Symlinks live in a manifest rather than in the repository because they cannot be created
// portably from a Windows checkout and git does not preserve them reliably across
// platforms. They matter: a symlink's own mode is always lrwxrwxrwx, and masked systemd
// units are symlinks to /dev/null -- two real false-positive sources this fixture locks in.
func applyLinks(t *testing.T, base string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(base, "links.json"))
	if err != nil {
		return
	}
	var links map[string]string
	if err := json.Unmarshal(data, &links); err != nil {
		t.Fatalf("parsing links.json in %s: %v", base, err)
	}
	for rel, target := range links {
		p := filepath.Join(base, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("creating dir for link %s: %v", rel, err)
		}
		// A declared link replaces any placeholder file of the same name.
		_ = os.Remove(p)
		if err := os.Symlink(target, p); err != nil {
			t.Fatalf("symlink %s -> %s: %v", rel, target, err)
		}
	}
}

// TestCheckGate is the gate. Every registered check must pass every item.
func TestCheckGate(t *testing.T) {
	reg, err := registry.Load()
	if err != nil {
		t.Fatalf("loading embedded registry: %v", err)
	}
	checks := check.All()
	if len(checks) == 0 {
		t.Fatal("no checks registered")
	}
	fixtures := prepareFixtures(t)

	for _, c := range checks {
		c := c
		m := c.Meta()
		t.Run(m.ID, func(t *testing.T) {
			// --- static gate items ---
			if g := check.EvaluateGate(c); !g.Passes() {
				for _, f := range g.Failures {
					t.Errorf("gate item failed: %s", f)
				}
			}

			// --- ATT&CK mapping validity ---
			for _, p := range check.ValidateMapping(c, reg) {
				t.Errorf("mapping problem: %s", p)
			}

			// --- declared criteria are the only ones findings may cite ---
			declared := map[string]bool{}
			for _, cr := range m.Criteria {
				if cr.ID == "" || strings.TrimSpace(cr.Text) == "" {
					t.Errorf("criterion with empty ID or text: %+v", cr)
				}
				declared[cr.ID] = true
			}

			// --- executable cases ---
			for _, cs := range c.Cases() {
				cs := cs
				t.Run(string(cs.Kind), func(t *testing.T) {
					env, err := cs.Build(fixtures)
					if err != nil {
						t.Fatalf("building case env: %v", err)
					}
					res := c.Run(context.Background(), env)

					if err := res.Validate(); err != nil {
						t.Errorf("result violates the data contract: %v", err)
					}
					if !cs.Accepts(res.Outcome) {
						t.Errorf("outcome = %s, want %s (also accepted: %v)\n  case: %s\n  why: %s\n  reason: %s",
							res.Outcome, cs.WantOutcome, cs.AlsoAccept, cs.Name, cs.Why, res.Reason)
					}

					// THE core invariant: missing data or denied access must never read as
					// a clean result.
					if cs.Kind == check.CaseNoData || cs.Kind == check.CasePermissionDenied {
						if res.Outcome == model.NotDetected {
							t.Errorf("CRITICAL: %s case returned NOT_DETECTED; missing data "+
								"or denied access must never be reported as 'nothing found'",
								cs.Kind)
						}
					}

					reportable := res.ReportableFindings()
					if len(reportable) < cs.MinFindings {
						t.Errorf("got %d reportable findings, want >= %d",
							len(reportable), cs.MinFindings)
					}
					if cs.Kind == check.CaseNegative && len(reportable) > 0 {
						for _, f := range reportable {
							t.Errorf("negative fixture produced a finding (%s): %s",
								f.Level, f.Title)
						}
					}

					// Findings may only cite declared criteria.
					for _, f := range res.Findings {
						for _, cr := range f.CriteriaMatched {
							if !declared[cr.ID] {
								t.Errorf("finding cites undeclared criterion %q", cr.ID)
							}
						}
						for _, id := range f.TechniqueIDs {
							tq := reg.Get(id)
							if tq == nil {
								t.Errorf("finding cites non-existent ATT&CK ID %q", id)
								continue
							}
							if !tq.Active {
								t.Errorf("finding cites revoked/deprecated ATT&CK ID %q", id)
							}
						}
					}

					for _, want := range cs.WantTechniqueIDs {
						found := false
						for _, f := range res.Findings {
							for _, id := range f.TechniqueIDs {
								if id == want {
									found = true
								}
							}
						}
						if !found {
							t.Errorf("expected a finding citing %s, none did", want)
						}
					}

					// Telemetry checks must aggregate, not emit per-event findings.
					if m.Telemetry && res.Outcome == model.Detected {
						for _, f := range reportable {
							if f.Aggregate == nil {
								t.Errorf("telemetry check finding %q has no aggregate; "+
									"telemetry results must aggregate by entity",
									f.DedupKey)
							}
						}
					}
				})
			}
		})
	}
}

// TestNoFalseLabVerifiedClaims enforces that a LAB_VERIFIED claim names a concrete
// environment consistent with the check's target OS.
func TestNoFalseLabVerifiedClaims(t *testing.T) {
	for _, p := range check.VerifyLabClaims(check.All()) {
		t.Errorf("%s", p)
	}
}

// TestWindowsChecksAreNotLabVerified encodes blocker B-001 as a test.
//
// Smart App Control on the build host blocks all unsigned binaries, so no Windows build of
// irscan can be executed in this environment. Any Windows check claiming LAB_VERIFIED in
// this repository is therefore necessarily a false claim. If the blocker is ever cleared,
// this test must be deliberately removed along with B-001 -- it should not be quietly
// deleted to make a claim pass.
func TestWindowsChecksAreNotLabVerified(t *testing.T) {
	for _, c := range check.All() {
		m := c.Meta()
		if m.Validation != model.LabVerified {
			continue
		}
		onlyWindows := true
		for _, o := range m.OS {
			if o != "windows" {
				onlyWindows = false
			}
		}
		if onlyWindows {
			t.Errorf("%s claims LAB_VERIFIED but is Windows-only; no Windows binary can be "+
				"executed in this environment (DECISIONS.md B-001). Cap it at "+
				"FIXTURE_TESTED.", m.ID)
		}
	}
}

// TestDedupMergesAcrossChecks proves the "one artifact is one finding" rule: two findings
// for the same artifact from different checks collapse into one carrying both attributions.
func TestDedupMergesAcrossChecks(t *testing.T) {
	mk := func(checkID, technique string) model.Finding {
		return model.Finding{
			DedupKey:           check.DedupKey("host1", "systemd_unit", "/etc/systemd/system/x.service"),
			Host:               "host1",
			ArtifactType:       "systemd_unit",
			ArtifactID:         "/etc/systemd/system/x.service",
			Level:              model.SuspiciousIndicator,
			TechniqueIDs:       []string{technique},
			CheckIDs:           []string{checkID},
			CriteriaMatched:    []model.Criterion{{ID: checkID + "-C1", Text: "t"}},
			BenignExplanations: []string{"b"},
			NextPivot:          []string{"p"},
			Evidence: []model.EvidenceRef{
				{ID: "e", SHA256: "abc", HashScope: "full_object"},
			},
		}
	}
	merged := check.MergeFindings([]model.Finding{
		mk("CHECK-A", "T1543.002"),
		mk("CHECK-B", "T1053.006"),
	})
	if len(merged) != 1 {
		t.Fatalf("got %d findings, want 1 (same artifact must merge)", len(merged))
	}
	if len(merged[0].CheckIDs) != 2 {
		t.Errorf("merged finding carries %v, want both check IDs", merged[0].CheckIDs)
	}
	if len(merged[0].TechniqueIDs) != 2 {
		t.Errorf("merged finding carries %v, want both technique IDs", merged[0].TechniqueIDs)
	}
}

// TestOutcomeNeverCleanOnMissingData exercises the outcome derivation directly, including
// the combinations the fixture cases do not reach.
func TestOutcomeNeverCleanOnMissingData(t *testing.T) {
	cases := []struct {
		name    string
		sources []model.DataSourceStatus
		matched bool
		want    model.Outcome
	}{
		{"all available, nothing found", []model.DataSourceStatus{
			{Name: "a", Available: true}, {Name: "b", Available: true}}, false, model.NotDetected},
		{"all available, match", []model.DataSourceStatus{
			{Name: "a", Available: true}}, true, model.Detected},
		{"one missing", []model.DataSourceStatus{
			{Name: "a", Available: true}, {Name: "b", Reason: "absent"}}, false, model.PartialData},
		{"all missing", []model.DataSourceStatus{
			{Name: "a", Reason: "absent"}}, false, model.InsufficientData},
		{"all denied", []model.DataSourceStatus{
			{Name: "a", Reason: "permission denied"}}, false, model.PermissionDenied},
		{"available but truncated", []model.DataSourceStatus{
			{Name: "a", Available: true, Truncated: true}}, false, model.PartialData},
		{"no sources declared", nil, false, model.InsufficientData},
		{"match wins over partial", []model.DataSourceStatus{
			{Name: "a", Available: true}, {Name: "b", Reason: "absent"}}, true, model.Detected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := model.OutcomeFromSources(tc.sources, tc.matched)
			if got != tc.want {
				t.Errorf("got %s want %s (reason %q)", got, tc.want, reason)
			}
			if !got.Determinate() && reason == "" {
				t.Errorf("non-determinate outcome %s must carry a reason", got)
			}
		})
	}
}

// TestCheckResultRejectsCleanOnMissingData proves the contract is enforced, not just
// produced correctly by the helper.
func TestCheckResultRejectsCleanOnMissingData(t *testing.T) {
	r := model.CheckResult{
		CheckID: "X",
		Outcome: model.NotDetected,
		Sources: []model.DataSourceStatus{{Name: "s", Available: false, Reason: "absent"}},
	}
	if err := r.Validate(); err == nil {
		t.Fatal("expected Validate to reject NOT_DETECTED with an unavailable source")
	}
}
