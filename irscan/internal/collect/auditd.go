package collect

import (
	"bufio"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Linux audit subsystem collector.
//
// This is the telemetry-side counterpart to the file-based collectors, and it is the one
// that proves the INSUFFICIENT_DATA path works for real: on a host where auditd was never
// installed, the honest answer is "I could not see", not "nothing happened".

// AuditdState describes the audit subsystem's configuration and log availability.
type AuditdState struct {
	// DaemonConfigPresent: /etc/audit/auditd.conf exists.
	DaemonConfigPresent bool
	DaemonConfigPath    string
	// RuleFiles are the configured rule files that exist.
	RuleFiles []string
	// Rules are the non-comment rule lines found.
	Rules []AuditRule
	// LogPath is the configured or default log file.
	LogPath string
	// LogPresent / LogReadable distinguish "no auditing" from "auditing I cannot read".
	LogPresent  bool
	LogReadable bool
	LogSize     int64
	// Oldest/Newest bound the retention window actually present in the log.
	Oldest, Newest time.Time
	WindowKnown    bool
	// LogFormat, MaxLogFile and NumLogs come from auditd.conf and bound how far back
	// evidence could possibly go.
	Settings map[string]string
	// ImmutableFlag is true when a `-e 2` rule makes the ruleset immutable until reboot.
	ImmutableFlag bool

	// The following flags separate "read it, found nothing" from "could not read it".
	// Without them a check concludes "auditd is configured but has no rules" when the
	// truth is "the rules are mode 0640 and this scan is unprivileged" -- manufacturing a
	// finding out of missing data, which is the exact failure the outcome contract exists
	// to prevent.

	// ConfigReadable: auditd.conf was successfully read.
	ConfigReadable bool
	// RuleFilesRead counts rule files successfully read.
	RuleFilesRead int
	// LogStateKnown: the log's presence and size were established (either it was stat'd,
	// or it was confirmed genuinely absent). False means access was denied.
	LogStateKnown bool
	// PermissionError: at least one audit path existed but could not be read.
	PermissionError bool
}

type AuditRule struct {
	File   string
	LineNo int
	Line   string
	// Kind is "watch" (-w), "syscall" (-a), "control" (-D/-e/-f/-b) or "other".
	Kind string
	// Path is the watched path for -w rules.
	Path string
	// Key is the -k tag, which is what analysts pivot on.
	Key string
}

// AuditdRuleDirs and files, in the order auditd itself reads them.
var (
	AuditdConfPath = "/etc/audit/auditd.conf"
	AuditdRuleDir  = "/etc/audit/rules.d"
	AuditdRuleFile = "/etc/audit/audit.rules"
	AuditdLogDir   = "/var/log/audit"
)

// Auditd inspects the audit subsystem configuration and log availability.
//
// It does not parse the whole audit log: that can be gigabytes, and the safety limits forbid
// it. It establishes whether the evidence could exist at all, which is what a check needs in
// order to choose between NOT_DETECTED and INSUFFICIENT_DATA.
func Auditd(fs FileSystem) (AuditdState, SourceResult) {
	st := AuditdState{Settings: map[string]string{}}
	res := SourceResult{
		Name:      "linux audit subsystem",
		Privilege: "root (/etc/audit and /var/log/audit are normally mode 0750 root-owned)",
	}

	if fs.Exists(AuditdConfPath) {
		st.DaemonConfigPresent = true
		st.DaemonConfigPath = AuditdConfPath
		if data, _, err := fs.ReadFile(AuditdConfPath); err == nil {
			st.ConfigReadable = true
			sc := bufio.NewScanner(strings.NewReader(string(data)))
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if k, v, ok := strings.Cut(line, "="); ok {
					st.Settings[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
				}
			}
		} else {
			if errors.Is(err, ErrPermission) {
				st.PermissionError = true
			}
			reportErr(&res, err, "reading "+AuditdConfPath)
		}
	}

	// Rule files: rules.d/*.rules first, then the compiled audit.rules.
	var ruleFiles []string
	if fs.Exists(AuditdRuleDir) {
		if entries, err := fs.ReadDir(AuditdRuleDir); err == nil {
			for _, e := range entries {
				if !e.IsDir && strings.HasSuffix(e.Name, ".rules") {
					ruleFiles = append(ruleFiles, AuditdRuleDir+"/"+e.Name)
				}
			}
		} else {
			if errors.Is(err, ErrPermission) {
				st.PermissionError = true
			}
			reportErr(&res, err, "listing "+AuditdRuleDir)
		}
	}
	if fs.Exists(AuditdRuleFile) {
		ruleFiles = append(ruleFiles, AuditdRuleFile)
	}
	sort.Strings(ruleFiles)
	st.RuleFiles = ruleFiles

	for _, rf := range ruleFiles {
		data, truncated, err := fs.ReadFile(rf)
		if err != nil {
			if errors.Is(err, ErrPermission) {
				st.PermissionError = true
			}
			reportErr(&res, err, "reading "+rf)
			continue
		}
		st.RuleFilesRead++
		if truncated {
			res.Truncated = true
		}
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		n := 0
		for sc.Scan() {
			n++
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			r := parseAuditRule(line)
			r.File, r.LineNo = rf, n
			if r.Kind == "control" && strings.HasPrefix(line, "-e 2") {
				st.ImmutableFlag = true
			}
			st.Rules = append(st.Rules, r)
		}
	}

	// Log availability.
	st.LogPath = st.Settings["log_file"]
	if st.LogPath == "" {
		st.LogPath = AuditdLogDir + "/audit.log"
	}
	if fi, err := fs.Stat(st.LogPath); err == nil {
		st.LogStateKnown = true
		st.LogPresent = true
		st.LogSize = fi.Size
		if _, _, rerr := fs.ReadFile(st.LogPath); rerr == nil {
			st.LogReadable = true
			st.Oldest, st.Newest, st.WindowKnown = auditLogWindow(fs, st.LogPath)
		} else if errors.Is(rerr, ErrPermission) {
			st.PermissionError = true
			res.addErr("permission denied reading %s; audit history cannot be assessed",
				st.LogPath)
		}
	} else if errors.Is(err, ErrPermission) {
		// Denied is NOT absent. Leaving LogStateKnown false stops the caller inferring
		// "there is no audit log" from "I was not allowed to look".
		st.PermissionError = true
		res.addErr("permission denied on %s", st.LogPath)
	} else {
		// A genuine not-found: the log's state IS known, and it is absent.
		st.LogStateKnown = true
	}

	anythingReadable := st.ConfigReadable || st.RuleFilesRead > 0 || st.LogStateKnown

	switch {
	case !st.DaemonConfigPresent && len(ruleFiles) == 0 && !st.LogPresent &&
		st.LogStateKnown && !st.PermissionError:
		res.Available = false
		res.Reason = fmt.Sprintf(
			"the Linux audit subsystem is not installed or configured on this host: "+
				"%s absent, no rule files under %s or %s, and no audit log at %s. "+
				"Audit-dependent evidence cannot exist, so its absence proves nothing.",
			AuditdConfPath, AuditdRuleDir, AuditdRuleFile, st.LogPath)
		return st, res

	case !anythingReadable:
		res.Available = false
		res.Reason = fmt.Sprintf(
			"permission denied reading the audit configuration and log (%s, %s, %s). "+
				"The audit subsystem's state could not be assessed at all; this is a "+
				"visibility gap, not evidence that auditing is absent or intact.",
			AuditdConfPath, AuditdRuleDir, st.LogPath)
		return st, res

	default:
		res.Available = true
		res.ItemsSeen = len(st.Rules)
	}
	return st, res
}

func parseAuditRule(line string) AuditRule {
	r := AuditRule{Line: line, Kind: "other"}
	fields := strings.Fields(line)
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "-w":
			r.Kind = "watch"
			if i+1 < len(fields) {
				r.Path = fields[i+1]
			}
		case "-a", "-A":
			r.Kind = "syscall"
		case "-D", "-e", "-f", "-b", "-r", "--loginuid-immutable":
			if r.Kind == "other" {
				r.Kind = "control"
			}
		case "-k", "--key":
			if i+1 < len(fields) {
				r.Key = fields[i+1]
			}
		}
	}
	return r
}

// auditLogWindow reads the first and last timestamped records to bound the retention window.
//
// Audit records carry msg=audit(<epoch>.<ms>:<serial>). Knowing the window matters: a check
// must not claim "no log clearing in the last 30 days" when the log only reaches back 2 days.
func auditLogWindow(fs FileSystem, path string) (time.Time, time.Time, bool) {
	data, _, err := fs.ReadFile(path)
	if err != nil {
		return time.Time{}, time.Time{}, false
	}
	var first, last time.Time
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if ts, ok := parseAuditTimestamp(sc.Text()); ok {
			if first.IsZero() {
				first = ts
			}
			last = ts
		}
	}
	if first.IsZero() {
		return time.Time{}, time.Time{}, false
	}
	return first, last, true
}

func parseAuditTimestamp(line string) (time.Time, bool) {
	i := strings.Index(line, "audit(")
	if i < 0 {
		return time.Time{}, false
	}
	rest := line[i+len("audit("):]
	j := strings.IndexAny(rest, ":)")
	if j < 0 {
		return time.Time{}, false
	}
	secs, _, _ := strings.Cut(rest[:j], ".")
	v, err := strconv.ParseInt(secs, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(v, 0).UTC(), true
}

// ---------------------------------------------------------------------------------------
// FileTelemetry
// ---------------------------------------------------------------------------------------

// FileTelemetry implements TelemetrySource over plain log files, which is how Linux
// telemetry is read: no child processes, works against a fixture root, works on a host where
// journald is not running.
type FileTelemetry struct {
	FS FileSystem
	// Channels maps a logical channel name to a candidate file list; the first that exists
	// is used.
	Channels map[string][]string
	// Privileges maps a channel to the privilege its file normally requires.
	Privileges map[string]string
}

// DefaultLinuxTelemetry wires the conventional Linux log locations.
func DefaultLinuxTelemetry(fs FileSystem) *FileTelemetry {
	return &FileTelemetry{
		FS: fs,
		Channels: map[string][]string{
			"linux:auditd":   {"/var/log/audit/audit.log"},
			"linux:auth":     {"/var/log/auth.log", "/var/log/secure"},
			"linux:syslog":   {"/var/log/syslog", "/var/log/messages"},
			"linux:wtmp":     {"/var/log/wtmp"},
			"linux:lastlog":  {"/var/log/lastlog"},
			"linux:dpkg":     {"/var/log/dpkg.log"},
			"linux:journal":  {"/var/log/journal", "/run/log/journal"},
		},
		Privileges: map[string]string{
			"linux:auditd":  "root",
			"linux:auth":    "root or adm group",
			"linux:syslog":  "root or adm group",
			"linux:journal": "root or systemd-journal group",
		},
	}
}

func (t *FileTelemetry) Name() string { return "telemetry:files" }

func (t *FileTelemetry) resolve(channel string) (string, bool) {
	for _, c := range t.Channels[channel] {
		if t.FS.Exists(c) {
			return c, true
		}
	}
	return "", false
}

func (t *FileTelemetry) Status(channel string) ChannelStatus {
	st := ChannelStatus{
		Channel:           channel,
		RecordCount:       -1,
		RequiredPrivilege: t.Privileges[channel],
	}
	candidates, known := t.Channels[channel]
	if !known {
		st.Reason = "unknown channel " + channel + " for this telemetry source"
		return st
	}
	path, ok := t.resolve(channel)
	if !ok {
		st.Reason = "none of the expected files exist: " + strings.Join(candidates, ", ")
		return st
	}
	st.Present = true
	fi, err := t.FS.Stat(path)
	if err != nil {
		st.Reason = fmt.Sprintf("cannot stat %s: %v", path, err)
		return st
	}
	// A log file that exists but is empty is "present, collecting nothing" -- materially
	// different from absent, and from healthy.
	if fi.Size == 0 {
		st.Enabled, st.EnabledKnown = false, true
		st.Reason = path + " exists but is empty"
		return st
	}
	if _, _, rerr := t.FS.ReadFile(path); rerr != nil {
		st.Reason = fmt.Sprintf("cannot read %s: %v", path, rerr)
		if errors.Is(rerr, ErrPermission) {
			st.Reason = "permission denied reading " + path
		}
		return st
	}
	st.Enabled, st.EnabledKnown = true, true
	return st
}

func (t *FileTelemetry) Query(q TelemetryQuery) ([]LogEvent, bool, error) {
	path, ok := t.resolve(q.Channel)
	if !ok {
		return nil, false, fmt.Errorf("channel %s: no backing file present", q.Channel)
	}
	data, truncated, err := t.FS.ReadFile(path)
	if err != nil {
		return nil, truncated, err
	}
	var out []LogEvent
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		e := LogEvent{Channel: q.Channel, Raw: line, Message: line}
		if ts, ok := parseAuditTimestamp(line); ok {
			e.Time = ts
		}
		if !matchesQuery(e, q) {
			continue
		}
		out = append(out, e)
		if q.Limit > 0 && len(out) >= q.Limit {
			truncated = true
			break
		}
	}
	return out, truncated, nil
}
