// Package checks holds the check implementations.
//
// Every check in here is a pure function of the data objects in its Env. None of them touch
// the OS directly, which is what makes them testable against fixtures -- and, given
// DECISIONS.md B-001, is the only reason the Windows checks are tested at all.
package checks

import (
	"regexp"
	"strings"
)

// Shared detection vocabulary.
//
// It lives in one place so that "what counts as a suspicious path" is defined once and can
// be reviewed once, rather than drifting between checks. Each entry is a documented
// criterion component, not a heuristic hunch: the criteria that cite these are written out
// in each check's Meta.Criteria and overlay.

// ---------------------------------------------------------------------------------------
// Linux
// ---------------------------------------------------------------------------------------

// linuxTransientDirs are world-writable or user-writable locations that legitimate system
// persistence essentially never executes from. A service or cron job running a binary from
// here is the classic drop-and-persist pattern.
//
// /home is deliberately NOT in this list: user-level services legitimately run from a home
// directory, and including it would make the check fire on every developer workstation.
var linuxTransientDirs = []string{
	"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/var/spool/samba/",
}

// InLinuxTransientDir reports whether a single PATH lies in a transient location.
func InLinuxTransientDir(path string) (string, bool) {
	p := strings.ToLower(strings.TrimSpace(strings.Trim(path, `"'`)))
	for _, d := range linuxTransientDirs {
		if strings.HasPrefix(p, d) {
			return strings.TrimSuffix(d, "/"), true
		}
	}
	return "", false
}

// interpreters whose first non-flag argument is the thing actually executed.
var shellInterpreters = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "ash": true,
	"python": true, "python2": true, "python3": true, "perl": true, "ruby": true,
	"php": true, "lua": true, "node": true,
}

// TransientExecutable reports whether the command EXECUTES something from a transient
// directory.
//
// It deliberately inspects the executable (and an interpreter's script argument) rather
// than searching the whole command string. Searching the whole string was the first
// implementation and it false-positived on the extremely common monitoring pattern
//
//	curl -s -o /tmp/metrics.json http://localhost:9100/metrics
//
// which merely WRITES to /tmp. Writing to a temp directory is ordinary; executing from one
// is not, and only the latter is what criterion C1 claims.
func TransientExecutable(cmd string) (string, bool) {
	tokens := splitCommand(cmd)
	if len(tokens) == 0 {
		return "", false
	}
	if d, ok := InLinuxTransientDir(tokens[0]); ok {
		return d, true
	}
	if !shellInterpreters[baseName(tokens[0])] {
		return "", false
	}
	// Skip the interpreter's own flags and find the script it runs.
	for _, t := range tokens[1:] {
		if strings.HasPrefix(t, "-") {
			continue
		}
		if d, ok := InLinuxTransientDir(t); ok {
			return d, true
		}
		// Only the first non-flag argument is the script; anything after it belongs to
		// the script, not to the interpreter.
		break
	}
	return "", false
}

func baseName(p string) string {
	p = strings.Trim(p, `"'`)
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return strings.ToLower(p[i+1:])
	}
	return strings.ToLower(p)
}

func splitCommand(cmd string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	for _, r := range cmd {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote = r
		case r == ' ' || r == '\t':
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// downloadPipePattern matches the fetch-and-execute idiom. Scoped to a pipe into an
// interpreter so that an ordinary `curl -o /tmp/file` backup job does not match.
var downloadPipePattern = regexp.MustCompile(
	`(?i)\b(curl|wget|fetch)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|k|da)?sh\b`)

// encodedExecPattern matches inline-decoded execution.
//
// The interpreter clause requires a decode/exec/eval keyword in the inline code, not merely
// the presence of `-c`/`-e`. An earlier, looser version matched any `interpreter -e ...`
// and therefore fired on the stock Debian certbot cron line
//
//	perl -e 'sleep int(rand(43200))' && certbot -q renew
//
// which exists on a very large number of hosts. Catching that in the negative fixture is
// precisely why the negative fixture is required by the gate.
// A bare `eval $(...)` is NOT included. Verified against a real host: stock Debian's
// /etc/cron.daily/apt-compat contains
//
//	eval $(apt-config shell RandomSleep APT::Periodic::RandomSleep)
//
// which exists on essentially every Debian-family machine. Only eval of a DOWNLOADED
// command substitution is matched; eval of decoded content is already covered by the
// decoder clauses, since the decoder itself appears in the command.
var encodedExecPattern = regexp.MustCompile(
	`(?i)(base64\s+(-d|--decode)\b|openssl\s+enc\b[^|;&]*\s-d\b|\bxxd\s+-r\b|` +
		`\beval\s*["']?\$\(\s*(curl|wget|fetch)\b|` +
		`\b(python3?|perl|ruby|php)\b[^|;&]*\s-[ce]\s[^|;&]*` +
		`\b(b64decode|base64|decodestring|exec|eval|system)\b)`)

// reverseShellPattern matches the common interactive-shell-over-socket constructions.
var reverseShellPattern = regexp.MustCompile(
	`(?i)(\bnc\b[^|;&]*\s-[a-z]*e\b|\bncat\b[^|;&]*--exec|/dev/tcp/|/dev/udp/|` +
		`\bsocat\b[^|;&]*exec)`)

// LinuxCommandSignals classifies a command string, returning the criterion IDs it triggers.
// Returning IDs (not booleans) keeps findings citing declared criteria.
func LinuxCommandSignals(cmd string) []string {
	var out []string
	if downloadPipePattern.MatchString(cmd) {
		out = append(out, "download-pipe-interpreter")
	}
	if encodedExecPattern.MatchString(cmd) {
		out = append(out, "encoded-or-eval-execution")
	}
	if reverseShellPattern.MatchString(cmd) {
		out = append(out, "interactive-shell-over-socket")
	}
	return out
}

// ---------------------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------------------

// winTransientDirs are user-writable locations. Note %ProgramData% and %Public% are included
// because they are writable by standard users yet look system-ish, which is exactly why
// they are favoured for persistence staging.
var winTransientDirs = []string{
	`\appdata\local\temp\`, `\appdata\roaming\`, `\windows\temp\`,
	`\users\public\`, `\programdata\`, `$recycle.bin`, `\windows\tasks\`,
	`\perflogs\`,
}

// InWindowsTransientDir reports whether a path lives in a user-writable staging location.
func InWindowsTransientDir(path string) (string, bool) {
	p := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	// Expand the handful of environment variables that commonly appear in Run values, so
	// %TEMP%\x.exe is recognised without executing anything.
	for from, to := range map[string]string{
		"%temp%": `\appdata\local\temp\`, "%tmp%": `\appdata\local\temp\`,
		"%appdata%": `\appdata\roaming\`, "%localappdata%": `\appdata\local\`,
		"%programdata%": `\programdata\`, "%public%": `\users\public\`,
	} {
		p = strings.ReplaceAll(p, from, to)
	}
	for _, d := range winTransientDirs {
		if strings.Contains(p, d) {
			return strings.Trim(d, `\`), true
		}
	}
	return "", false
}

// WindowsTransientExecutable reports whether the command EXECUTES from a user-writable
// staging directory. Like its Linux counterpart it inspects the executable rather than the
// whole command line, so a legitimate entry that merely logs into %TEMP% does not match.
func WindowsTransientExecutable(cmd string) (string, bool) {
	exe := firstArg(cmd)
	if d, ok := InWindowsTransientDir(exe); ok {
		return d, true
	}
	// Script hosts and shells execute their argument, so inspect it too.
	switch baseName(exe) {
	case "powershell.exe", "powershell", "pwsh.exe", "pwsh", "cmd.exe", "cmd",
		"wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe":
		if d, ok := InWindowsTransientDir(cmd); ok {
			return d, true
		}
	}
	return "", false
}

// winEncodedPSPattern matches PowerShell encoded-command and hidden-window invocations.
// -enc/-e/-ec are all valid abbreviations of -EncodedCommand, which is why the pattern
// accepts the prefixes rather than the full switch name.
var winEncodedPSPattern = regexp.MustCompile(
	`(?i)powershell(\.exe)?[^"]*\s-(e|ec|enc|encod\w*)\s+[A-Za-z0-9+/=]{16,}`)

var winHiddenWindowPattern = regexp.MustCompile(
	`(?i)\s-(w|windowstyle)\s+hidden\b|\s-nop\b|\s-noprofile\b.*\s-nonin\w*`)

// winLolbinPattern matches the signed-binary proxy-execution tools most often used to run
// attacker code from an autostart entry.
var winLolbinPattern = regexp.MustCompile(
	`(?i)\b(mshta|regsvr32|rundll32|certutil|bitsadmin|installutil|msbuild|` +
		`cmstp|msiexec|wmic|forfiles|scriptrunner)\b`)

// winRemotePayloadPattern matches an autostart entry that fetches from the network.
var winRemotePayloadPattern = regexp.MustCompile(
	`(?i)(https?://|ftp://|\\\\[a-z0-9._-]+\\|javascript:|vbscript:)`)

// WindowsCommandSignals classifies a Run-key value or Startup shortcut target.
func WindowsCommandSignals(cmd string) []string {
	var out []string
	if winEncodedPSPattern.MatchString(cmd) {
		out = append(out, "powershell-encoded-command")
	}
	if winHiddenWindowPattern.MatchString(cmd) {
		out = append(out, "hidden-window-or-no-profile")
	}
	if winLolbinPattern.MatchString(cmd) {
		out = append(out, "signed-binary-proxy-execution")
	}
	if winRemotePayloadPattern.MatchString(cmd) {
		out = append(out, "remote-or-script-uri-payload")
	}
	return out
}

// executableExtMismatch reports a command whose target carries a non-executable extension.
// Attackers rename payloads to .jpg/.txt/.log to survive a casual directory listing; the
// autostart entry still has to point at them.
var nonExecExts = map[string]bool{
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".txt": true,
	".log": true, ".dat": true, ".tmp": true, ".doc": true, ".pdf": true,
}

// ExecutableExtMismatch returns the offending extension when an autostart target points at
// something that should not be executable.
func ExecutableExtMismatch(target string) (string, bool) {
	t := strings.ToLower(strings.Trim(firstArg(target), `"`))
	i := strings.LastIndex(t, ".")
	if i < 0 {
		return "", false
	}
	ext := t[i:]
	if nonExecExts[ext] {
		return ext, true
	}
	return "", false
}

// firstArg extracts the executable from a command line, honouring quoting.
func firstArg(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	if cmd[0] == '"' {
		if j := strings.Index(cmd[1:], `"`); j >= 0 {
			return cmd[1 : 1+j]
		}
	}
	if i := strings.IndexAny(cmd, " \t"); i > 0 {
		return cmd[:i]
	}
	return cmd
}

// FirstArg is the exported form.
func FirstArg(cmd string) string { return firstArg(cmd) }

// Truncate bounds a string for use in a human-readable title.
func Truncate(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
