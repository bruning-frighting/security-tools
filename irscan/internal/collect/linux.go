package collect

import (
	"bufio"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Linux collectors. Each returns data objects plus a DataSourceStatus-shaped result so the
// caller can distinguish "nothing there" from "could not look" without inspecting errors.

// SourceResult pairs collected objects with the honest status of the collection.
type SourceResult struct {
	Name      string
	Available bool
	Reason    string
	ItemsSeen int
	Truncated bool
	Privilege string
	// Errors records per-path problems that did not stop collection. Non-empty Errors with
	// Available=true means the result is partial.
	Errors []string
}

func (s *SourceResult) addErr(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	for _, e := range s.Errors {
		if e == msg {
			return
		}
	}
	s.Errors = append(s.Errors, msg)
}

// Partial reports whether collection succeeded but incompletely.
func (s SourceResult) Partial() bool { return s.Available && (s.Truncated || len(s.Errors) > 0) }

// ---------------------------------------------------------------------------------------
// systemd
// ---------------------------------------------------------------------------------------

// SystemdUnitDirs are searched in precedence order. Units in /etc override /run which
// overrides /usr/lib -- an adversary-planted unit in /etc shadowing a vendor unit is itself
// a signal, so the originating directory is retained on every unit.
var SystemdUnitDirs = []string{
	"/etc/systemd/system",
	"/run/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
	"/etc/systemd/user",
	"/usr/lib/systemd/user",
}

// SystemdUnits parses .service and .timer unit files.
//
// Deliberately parses files rather than shelling out to systemctl: no child processes
// (PLAN.md 5.4), it works against a fixture root, and it works on a host where systemd is
// not running -- which includes the WSL2 environment used for validation.
func SystemdUnits(fs FileSystem, maxDepth int) ([]Service, SourceResult) {
	res := SourceResult{Name: "systemd unit files", Privilege: "read access to unit directories"}
	var units []Service
	seen := map[string]bool{}
	anyDir := false

	for _, dir := range SystemdUnitDirs {
		if !fs.Exists(dir) {
			continue
		}
		anyDir = true
		err := fs.Walk(dir, maxDepth, func(fi FileInfo) error {
			if fi.IsDir {
				return nil
			}
			ext := strings.ToLower(fi.Name[strings.LastIndex(fi.Name, ".")+1:])
			if ext != "service" && ext != "timer" {
				return nil
			}
			// A unit symlinked into a .wants directory is the same unit; record enablement
			// on the real unit instead of emitting a duplicate.
			if fi.IsSymlink && strings.Contains(fi.Path, ".wants/") {
				return nil
			}
			key := dir + "|" + fi.Name
			if seen[key] {
				return nil
			}
			seen[key] = true

			// A unit symlinked to /dev/null is MASKED: systemd refuses to start it. Record
			// it without reading content (there is none) so callers can see it and skip it.
			if fi.IsSymlink && strings.TrimSpace(fi.LinkTarget) == "/dev/null" {
				units = append(units, Service{
					Name: fi.Name, Source: fi.Path, IsSymlink: true,
					LinkTarget: fi.LinkTarget, Masked: true,
					Description: "masked unit (symlinked to /dev/null; cannot start)",
					Extra:       map[string]string{},
				})
				return nil
			}

			data, truncated, err := fs.ReadFile(fi.Path)
			if err != nil {
				if errors.Is(err, ErrPermission) {
					res.addErr("permission denied reading %s", fi.Path)
				} else {
					res.addErr("reading %s: %v", fi.Path, err)
				}
				return nil
			}
			if truncated {
				res.Truncated = true
			}
			u := parseSystemdUnit(fi, string(data))
			u.IsSymlink = fi.IsSymlink
			u.LinkTarget = fi.LinkTarget
			units = append(units, u)
			return nil
		})
		if err != nil {
			if errors.Is(err, ErrPermission) {
				res.addErr("permission denied walking %s", dir)
			} else {
				res.addErr("walking %s: %v", dir, err)
			}
		}
	}

	if !anyDir {
		res.Available = false
		res.Reason = "no systemd unit directory exists on this host (searched " +
			strings.Join(SystemdUnitDirs, ", ") + "); the host may not use systemd"
		return nil, res
	}

	markSystemdEnabled(fs, units, &res)

	res.Available = true
	res.ItemsSeen = len(units)
	sort.Slice(units, func(i, j int) bool { return units[i].Source < units[j].Source })
	return units, res
}

func parseSystemdUnit(fi FileInfo, content string) Service {
	u := Service{
		Name:   fi.Name,
		Source: fi.Path,
		Extra:  map[string]string{},
	}
	section := ""
	sc := bufio.NewScanner(strings.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch section + "." + strings.ToLower(k) {
		case "unit.description":
			u.Description = v
		case "service.execstart":
			if u.ImagePath == "" {
				u.ImagePath = v
			} else {
				u.ImagePath += " ; " + v
			}
		case "service.execstartpre", "service.execstartpost", "service.execstop",
			"service.execreload":
			// Retained because persistence is frequently hidden in the auxiliary Exec*
			// directives rather than ExecStart.
			u.Extra[k] = v
		case "service.user":
			u.Account = v
		case "service.type":
			u.ServiceType = v
		case "install.wantedby", "install.requiredby":
			u.Extra[k] = v
		case "timer.onbootsec", "timer.oncalendar", "timer.onunitactivesec":
			u.Extra[k] = v
		case "unit.conditionpathexists", "service.workingdirectory", "service.environmentfile":
			u.Extra[k] = v
		}
	}
	u.ResolvedBinary = firstToken(u.ImagePath)
	if u.Account == "" {
		u.Account = "root"
		u.Extra["_account_assumed"] = "User= not set; systemd defaults system units to root"
	}
	return u
}

// markSystemdEnabled resolves .wants/.requires symlinks to set Enabled on the real unit.
func markSystemdEnabled(fs FileSystem, units []Service, res *SourceResult) {
	enabled := map[string]bool{}
	for _, dir := range []string{"/etc/systemd/system", "/usr/lib/systemd/system"} {
		if !fs.Exists(dir) {
			continue
		}
		entries, err := fs.ReadDir(dir)
		if err != nil {
			res.addErr("listing %s: %v", dir, err)
			continue
		}
		for _, e := range entries {
			if !e.IsDir || (!strings.HasSuffix(e.Name, ".wants") &&
				!strings.HasSuffix(e.Name, ".requires")) {
				continue
			}
			sub := dir + "/" + e.Name
			links, err := fs.ReadDir(sub)
			if err != nil {
				res.addErr("listing %s: %v", sub, err)
				continue
			}
			for _, l := range links {
				enabled[l.Name] = true
			}
		}
	}
	for i := range units {
		units[i].Enabled = enabled[units[i].Name]
		units[i].EnabledKnown = true
	}
}

// ---------------------------------------------------------------------------------------
// cron
// ---------------------------------------------------------------------------------------

type CronEntry struct {
	// Source is the file the entry came from.
	Source string
	// Line is the raw crontab line, bounded by the caller before persistence.
	Line string
	// Schedule is the time specification or the @reboot-style shortcut.
	Schedule string
	// RunAs is the user column, present in system crontabs but not in per-user ones.
	RunAs string
	// Command is everything after the schedule (and user, where present).
	Command string
	// LineNo aids triage.
	LineNo int
}

// CronSystemFiles and CronDirs cover the standard layout.
var (
	CronSystemFiles = []string{"/etc/crontab"}
	CronDirs        = []string{
		"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
		"/etc/cron.weekly", "/etc/cron.monthly",
	}
	CronSpoolDirs = []string{"/var/spool/cron/crontabs", "/var/spool/cron"}
)

// CronEntries parses system and per-user crontabs.
//
// Per-user spool directories are usually mode 0700 root-owned, so an unprivileged scan gets
// a permission error there. That is reported as such; it must never silently read as "no
// user crontabs exist".
func CronEntries(fs FileSystem) ([]CronEntry, SourceResult) {
	res := SourceResult{
		Name:      "cron tables",
		Privilege: "read /etc/cron*; root required for /var/spool/cron",
	}
	var out []CronEntry
	found := false

	for _, f := range CronSystemFiles {
		if !fs.Exists(f) {
			continue
		}
		found = true
		out = append(out, readCronFile(fs, f, true, &res)...)
	}
	for _, d := range CronDirs {
		if !fs.Exists(d) {
			continue
		}
		found = true
		entries, err := fs.ReadDir(d)
		if err != nil {
			reportErr(&res, err, "listing "+d)
			continue
		}
		for _, e := range entries {
			if e.IsDir {
				continue
			}
			// cron ignores files with a dot in the name in cron.d; retained anyway because
			// a dropped file that cron ignores is still worth inventorying.
			out = append(out, readCronFile(fs, d+"/"+e.Name, true, &res)...)
		}
	}
	for _, d := range CronSpoolDirs {
		if !fs.Exists(d) {
			continue
		}
		found = true
		entries, err := fs.ReadDir(d)
		if err != nil {
			reportErr(&res, err, "listing "+d)
			continue
		}
		for _, e := range entries {
			if e.IsDir {
				continue
			}
			out = append(out, readCronFile(fs, d+"/"+e.Name, false, &res)...)
		}
	}

	if !found {
		res.Available = false
		res.Reason = "no cron configuration path exists on this host"
		return nil, res
	}
	res.Available = true
	res.ItemsSeen = len(out)
	return out, res
}

func readCronFile(fs FileSystem, path string, systemFormat bool, res *SourceResult) []CronEntry {
	data, truncated, err := fs.ReadFile(path)
	if err != nil {
		reportErr(res, err, "reading "+path)
		return nil
	}
	if truncated {
		res.Truncated = true
	}
	var out []CronEntry
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Environment assignments (SHELL=, PATH=, MAILTO=) are not jobs, but PATH= is a
		// persistence vector in its own right, so keep it as an entry with no schedule.
		if k, v, ok := strings.Cut(line, "="); ok && !strings.ContainsAny(k, " \t") {
			out = append(out, CronEntry{
				Source: path, Line: line, LineNo: n,
				Schedule: "", Command: strings.TrimSpace(k) + "=" + strings.TrimSpace(v),
			})
			continue
		}
		e := parseCronLine(line, systemFormat)
		e.Source, e.LineNo = path, n
		out = append(out, e)
	}
	return out
}

func parseCronLine(line string, systemFormat bool) CronEntry {
	e := CronEntry{Line: line}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return e
	}
	idx := 5
	if strings.HasPrefix(fields[0], "@") {
		// @reboot / @daily / @hourly ... one schedule token.
		idx = 1
	}
	if len(fields) <= idx {
		e.Command = line
		return e
	}
	e.Schedule = strings.Join(fields[:idx], " ")
	rest := fields[idx:]
	if systemFormat && len(rest) > 1 {
		e.RunAs = rest[0]
		rest = rest[1:]
	}
	e.Command = strings.Join(rest, " ")
	return e
}

// ---------------------------------------------------------------------------------------
// SSH authorized_keys
// ---------------------------------------------------------------------------------------

type AuthorizedKey struct {
	// Path of the authorized_keys file.
	Path string
	// User who owns the file (derived from the home directory it lives in).
	User string
	// Options are the leading restrictions, e.g. command="...",no-pty. An entry with
	// command= is a frequent persistence mechanism.
	Options string
	KeyType string
	// Fingerprint is a SHA-256 over the base64 key blob. The key material itself is NOT
	// retained in evidence: a public key is not secret, but retaining the full blob adds
	// bulk without triage value, and the fingerprint is what an analyst compares.
	Fingerprint string
	Comment     string
	LineNo      int
	// FileMode and FileOwner support the "weak permissions" criterion.
	FileMode  string
	FileOwner string
}

// AuthorizedKeys enumerates SSH authorized_keys for every user in /etc/passwd plus the
// system-wide sshd locations.
func AuthorizedKeys(fs FileSystem) ([]AuthorizedKey, SourceResult) {
	res := SourceResult{
		Name:      "ssh authorized_keys",
		Privilege: "read access to each user's ~/.ssh (root required for other users)",
	}
	users, uRes := Users(fs)
	if !uRes.Available {
		res.Available = false
		res.Reason = "cannot enumerate users to locate home directories: " + uRes.Reason
		return nil, res
	}

	var out []AuthorizedKey
	checked := 0
	for _, u := range users {
		if u.HomeDir == "" {
			continue
		}
		for _, name := range []string{"authorized_keys", "authorized_keys2"} {
			p := strings.TrimRight(u.HomeDir, "/") + "/.ssh/" + name
			// Stat rather than Exists: Exists() collapses "absent" and "denied" into the
			// same false, which would let an unprivileged scan of a 0700 home directory
			// report "no SSH keys" when the truth is "I could not look". Observed on a
			// real host: /root is mode 0700, so a non-root scan cannot see root's keys.
			if _, err := fs.Stat(p); err != nil {
				if errors.Is(err, ErrPermission) {
					res.addErr("permission denied checking %s for user %q; that user's "+
						"authorized_keys could not be examined", p, u.Name)
				}
				continue
			}
			checked++
			out = append(out, readAuthKeys(fs, p, u.Name, &res)...)
		}
	}
	// sshd_config AuthorizedKeysFile may point elsewhere; the common hardened location is
	// covered explicitly. A fully general resolution would require parsing sshd_config
	// tokens (%u/%h) and is listed as a limitation in the overlay.
	for _, p := range []string{"/etc/ssh/authorized_keys", "/etc/ssh/authorized_keys2"} {
		if fs.Exists(p) {
			checked++
			out = append(out, readAuthKeys(fs, p, "(system-wide)", &res)...)
		}
	}

	res.Available = true
	res.ItemsSeen = len(out)
	if checked == 0 {
		res.addErr("no authorized_keys file found for any of the %d enumerated users", len(users))
	}
	return out, res
}

func readAuthKeys(fs FileSystem, path, user string, res *SourceResult) []AuthorizedKey {
	fi, err := fs.Stat(path)
	if err != nil {
		reportErr(res, err, "stat "+path)
		return nil
	}
	data, truncated, err := fs.ReadFile(path)
	if err != nil {
		reportErr(res, err, "reading "+path)
		return nil
	}
	if truncated {
		res.Truncated = true
	}
	var out []AuthorizedKey
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k := parseAuthKeyLine(line)
		k.Path, k.User, k.LineNo = path, user, n
		k.FileMode, k.FileOwner = fi.ModeString, fi.Owner
		out = append(out, k)
	}
	return out
}

// knownKeyTypes is used to find where the options field ends, since options are optional and
// may contain spaces inside quotes.
var knownKeyTypes = map[string]bool{
	"ssh-rsa": true, "ssh-dss": true, "ssh-ed25519": true, "ssh-ed25519-sk": true,
	"ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true, "ecdsa-sha2-nistp521": true,
	"sk-ssh-ed25519@openssh.com": true, "sk-ecdsa-sha2-nistp256@openssh.com": true,
	"ssh-rsa-cert-v01@openssh.com": true, "ssh-ed25519-cert-v01@openssh.com": true,
}

func parseAuthKeyLine(line string) AuthorizedKey {
	k := AuthorizedKey{}
	fields := splitRespectingQuotes(line)
	idx := -1
	for i, f := range fields {
		if knownKeyTypes[f] {
			idx = i
			break
		}
	}
	if idx < 0 {
		// Unrecognised shape; keep the whole line as the comment so it is still visible.
		k.Comment = line
		return k
	}
	if idx > 0 {
		k.Options = strings.Join(fields[:idx], " ")
	}
	k.KeyType = fields[idx]
	if idx+1 < len(fields) {
		k.Fingerprint = sha256Hex([]byte(fields[idx+1]))
	}
	if idx+2 < len(fields) {
		k.Comment = strings.Join(fields[idx+2:], " ")
	}
	return k
}

func splitRespectingQuotes(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case (r == ' ' || r == '\t') && !inQuote:
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

// ---------------------------------------------------------------------------------------
// users
// ---------------------------------------------------------------------------------------

// Users parses /etc/passwd, and /etc/shadow when readable, to derive password state.
//
// Password hashes are NEVER retained. Only the state (hashed / locked / empty / unknown) is
// kept, per the credential-redaction rule.
func Users(fs FileSystem) ([]UserAccount, SourceResult) {
	res := SourceResult{Name: "/etc/passwd", Privilege: "world-readable; /etc/shadow needs root"}
	data, truncated, err := fs.ReadFile("/etc/passwd")
	if err != nil {
		res.Available = false
		if errors.Is(err, ErrPermission) {
			res.Reason = "permission denied reading /etc/passwd"
		} else {
			res.Reason = fmt.Sprintf("cannot read /etc/passwd: %v", err)
		}
		return nil, res
	}
	if truncated {
		res.Truncated = true
	}

	shadow := map[string]string{}
	if sdata, _, serr := fs.ReadFile("/etc/shadow"); serr == nil {
		for _, line := range strings.Split(string(sdata), "\n") {
			parts := strings.Split(line, ":")
			if len(parts) < 2 {
				continue
			}
			shadow[parts[0]] = passwordState(parts[1])
		}
	} else if errors.Is(serr, ErrPermission) {
		// Expected unprivileged. Recorded so a check can say password state is unknown
		// rather than implying every account is fine.
		res.addErr("permission denied reading /etc/shadow; password state unknown")
	}

	var out []UserAccount
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.Split(line, ":")
		if len(p) < 7 {
			continue
		}
		u := UserAccount{
			Name: p[0], UID: p[2], GID: p[3], HomeDir: p[5], Shell: p[6],
			Source: "/etc/passwd", PasswordState: "unknown",
		}
		if s, ok := shadow[u.Name]; ok {
			u.PasswordState = s
		}
		u.Disabled = strings.HasSuffix(u.Shell, "/nologin") || strings.HasSuffix(u.Shell, "/false")
		out = append(out, u)
	}
	res.Available = true
	res.ItemsSeen = len(out)
	return out, res
}

// Group is one /etc/group entry.
type Group struct {
	Name    string
	GID     string
	Members []string
}

// Groups parses /etc/group.
//
// Note the deliberate limitation: /etc/group lists SUPPLEMENTARY members only. A user whose
// PRIMARY group is a privileged group does not appear in its member list, so membership
// derived from here is incomplete and checks must say so rather than implying completeness.
func Groups(fs FileSystem) ([]Group, SourceResult) {
	res := SourceResult{Name: "/etc/group", Privilege: "none (world-readable)"}
	data, truncated, err := fs.ReadFile("/etc/group")
	if err != nil {
		res.Available = false
		if errors.Is(err, ErrPermission) {
			res.Reason = "permission denied reading /etc/group"
		} else {
			res.Reason = fmt.Sprintf("cannot read /etc/group: %v", err)
		}
		return nil, res
	}
	if truncated {
		res.Truncated = true
	}
	var out []Group
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.Split(line, ":")
		if len(p) < 4 {
			continue
		}
		g := Group{Name: p[0], GID: p[2]}
		for _, mem := range strings.Split(p[3], ",") {
			if mem = strings.TrimSpace(mem); mem != "" {
				g.Members = append(g.Members, mem)
			}
		}
		out = append(out, g)
	}
	res.Available = true
	res.ItemsSeen = len(out)
	return out, res
}

func passwordState(field string) string {
	switch {
	case field == "":
		return "empty"
	case field == "*" || field == "!" || strings.HasPrefix(field, "!"):
		return "locked"
	case strings.HasPrefix(field, "$"):
		return "hashed"
	default:
		return "unknown"
	}
}

// ---------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------

func reportErr(res *SourceResult, err error, what string) {
	if errors.Is(err, ErrPermission) {
		res.addErr("permission denied %s", what)
		return
	}
	res.addErr("%s: %v", what, err)
}

func firstToken(s string) string {
	s = strings.TrimSpace(s)
	// systemd Exec lines may be prefixed with -, @, +, !, : modifiers.
	s = strings.TrimLeft(s, "-@+!:")
	fields := splitRespectingQuotes(s)
	if len(fields) == 0 {
		return ""
	}
	return strings.Trim(fields[0], `"`)
}
