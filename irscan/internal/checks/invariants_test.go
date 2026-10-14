package checks

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"irscan/internal/check"
)

// expectedChecks is the authoritative list of checks that MUST be registered in every build.
//
// This exists because of a real defect found during Phase 1: the Windows check lived in
// internal/checks/persist_windows.go, and Go treats a `_windows.go` filename suffix as an
// implicit GOOS build constraint. The file was therefore silently excluded from the Linux
// build, the check was never registered, and the gate test passed while testing only four
// of five checks. Nothing failed -- the check simply vanished.
//
// Asserting the expected set by name turns that class of silent disappearance into a test
// failure. Adding a check means adding it here deliberately.
var expectedChecks = []string{
	// Phase 1 pilot
	"LNX-DEFIMP-AUDITD-001",
	"LNX-PERSIST-CRON-001",
	"LNX-PERSIST-SSHKEY-001",
	"LNX-PERSIST-SYSTEMD-001",
	"WIN-PERSIST-RUNKEY-001",
	// Phase 2a persistence
	"LNX-PERSIST-ACCOUNT-001",
	"LNX-PERSIST-RCSCRIPT-001",
	"LNX-PERSIST-SHELLRC-001",
	"WIN-PERSIST-REGLOADPOINT-001",
	"WIN-PERSIST-SCHTASK-001",
	"WIN-PERSIST-SERVICE-001",
	// Phase 2b defence evasion
	"WIN-DEFIMP-DEFENDER-001",
	"WIN-DEFIMP-EVENTLOG-001",
	"WIN-DEFIMP-FIREWALL-001",
	"LNX-DEFIMP-HISTORY-001",
	"LNX-STEALTH-LOGSINK-001",
	"LNX-STEALTH-HIDDEN-001",
	// Phase 2c credential access
	"LNX-CRED-FILES-001",
	"WIN-CRED-UNSECURED-001",
}

func TestExpectedChecksAreRegistered(t *testing.T) {
	got := map[string]bool{}
	for _, c := range check.All() {
		got[c.Meta().ID] = true
	}
	for _, want := range expectedChecks {
		if !got[want] {
			t.Errorf("check %s is NOT registered in this build. If it lives in a file whose "+
				"name ends in _windows.go, _linux.go, _darwin.go or similar, Go has applied "+
				"an implicit GOOS build constraint and excluded it.", want)
		}
	}
	for id := range got {
		found := false
		for _, want := range expectedChecks {
			if id == want {
				found = true
			}
		}
		if !found {
			t.Errorf("check %s is registered but not listed in expectedChecks; add it "+
				"deliberately so the inventory stays auditable", id)
		}
	}
}

// goosSuffixes are filename suffixes Go interprets as implicit build constraints.
var goosSuffixes = []string{
	"_windows", "_linux", "_darwin", "_freebsd", "_openbsd", "_netbsd", "_android",
	"_ios", "_js", "_plan9", "_solaris", "_aix", "_dragonfly", "_illumos", "_wasip1",
}

// TestNoAccidentalPlatformConstrainedCheckFiles guards the whole checks package against the
// filename trap above. Platform-specific code belongs in internal/collect behind an
// explicit //go:build tag, never in a check: checks must be pure functions over data
// objects so that Windows check logic is testable on Linux (DECISIONS.md B-001).
func TestNoAccidentalPlatformConstrainedCheckFiles(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		base := strings.TrimSuffix(e.Name(), ".go")
		base = strings.TrimSuffix(base, "_test")
		for _, sfx := range goosSuffixes {
			if strings.HasSuffix(base, sfx) {
				t.Errorf("%s has an implicit GOOS build constraint from its %q suffix, so it "+
					"is excluded from builds for other platforms. Checks must build on every "+
					"platform; rename it (e.g. _win.go / _lnx.go).", e.Name(), sfx)
			}
		}
	}
}

// writePrimitives are the ways Go code can modify the filesystem.
var writePrimitives = regexp.MustCompile(
	`\bos\.(Create|CreateTemp|Remove|RemoveAll|Rename|Truncate|Chmod|Chown|Chtimes|` +
		`Mkdir|MkdirAll|WriteFile|Symlink|Link)\b|` +
		`\bos\.OpenFile\b|\bioutil\.WriteFile\b|\bexec\.Command\b|\bsyscall\.Unlink\b`)

// TestCollectorsAndChecksAreReadOnly proves the read-only claim instead of asserting it.
//
// It scans the source of the packages that touch the host for any write or
// process-spawning primitive. The report and evidence packages are deliberately excluded:
// writing into the operator's --output directory is the tool's one permitted write, and it
// goes through safety.OutputGuard.
func TestCollectorsAndChecksAreReadOnly(t *testing.T) {
	// Paths that touch the scanned host and must never write to it or spawn a process.
	hostFacing := []string{
		filepath.Join("..", "collect"),
		filepath.Join("..", "check"),
		".",
	}
	for _, dir := range hostFacing {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
				continue
			}
			// Test files legitimately create fixtures in temp directories.
			if strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			p := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("reading %s: %v", p, err)
			}
			for i, line := range strings.Split(string(data), "\n") {
				// Skip comments: the prohibition is discussed in prose in several places.
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
					continue
				}
				if m := writePrimitives.FindString(line); m != "" {
					t.Errorf("%s:%d uses write/exec primitive %q in host-facing code; "+
						"irscan must be strictly read-only and must not spawn child "+
						"processes.\n    %s", p, i+1, m, trimmed)
				}
			}
		}
	}
}

// TestNoSensitiveProcessMemoryAccess guards the explicit prohibition on reading sensitive
// process memory.
//
// The banned set is deliberately the set of APIs and pseudo-file paths that actually open
// process memory, NOT the word "lsass". An earlier version banned the substring "lsass" and
// failed on documentation prose explaining that LSA registry load points are valuable
// because LSASS handles credentials -- which is exactly the kind of explanation an analyst
// needs. Naming a process in a comment is not reading its memory; calling OpenProcess is.
func TestNoSensitiveProcessMemoryAccess(t *testing.T) {
	banned := []string{
		"MiniDumpWriteDump", "OpenProcess", "ReadProcessMemory", "NtReadVirtualMemory",
		"process_vm_readv", "/proc/self/mem", "ptrace",
	}
	dirs := []string{filepath.Join("..", "collect"), filepath.Join("..", "check"), "."}
	for _, dir := range dirs {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
				strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			p := filepath.Join(dir, e.Name())
			data, _ := os.ReadFile(p)
			for i, line := range strings.Split(string(data), "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "//") {
					continue
				}
				low := strings.ToLower(line)
				for _, b := range banned {
					if strings.Contains(low, strings.ToLower(b)) {
						t.Errorf("%s:%d references %q; irscan must never open sensitive "+
							"process memory.\n    %s", p, i+1, b, trimmed)
					}
				}
			}
		}
	}
}

// TestEveryCheckDeclaresDistinctCriteriaIDs catches copy-paste errors that would make two
// criteria indistinguishable in a report.
func TestEveryCheckDeclaresDistinctCriteriaIDs(t *testing.T) {
	for _, c := range check.All() {
		m := c.Meta()
		seen := map[string]bool{}
		for _, cr := range m.Criteria {
			if seen[cr.ID] {
				t.Errorf("%s declares criterion %s more than once", m.ID, cr.ID)
			}
			seen[cr.ID] = true
		}
	}
}
