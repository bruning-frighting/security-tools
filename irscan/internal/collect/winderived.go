package collect

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// Windows collectors derived from the filesystem and registry interfaces.
//
// Neither of these needs a native API beyond the registry reader: a Windows service is a
// registry key, and a scheduled task is an XML file. Deriving them this way means they are
// fully exercised by fixtures, which -- given that no Windows binary can be executed in
// this environment (DECISIONS.md B-001) -- is the difference between tested and untested.

// ---------------------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------------------

const servicesKey = `SYSTEM\CurrentControlSet\Services`

var serviceStartTypes = map[uint64]string{
	0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled",
}

var serviceTypes = map[uint64]string{
	1: "kernel_driver", 2: "file_system_driver", 16: "own_process",
	32: "share_process", 272: "own_process_interactive", 288: "share_process_interactive",
}

// WindowsServices enumerates services from the registry.
//
// Reading the registry rather than the Service Control Manager API is deliberate: it needs
// no extra native surface, it sees services whose SCM entry is hidden from enumeration, and
// it works identically against a fixture.
func WindowsServices(reg Registry) ([]Service, SourceResult) {
	res := SourceResult{
		Name:      "Windows service registry keys",
		Privilege: "HKLM\\SYSTEM services keys are readable by standard users",
	}
	if ok, reason := reg.Available(); !ok {
		res.Available = false
		res.Reason = reason
		return nil, res
	}

	root, err := reg.OpenKey("HKLM", servicesKey)
	if err != nil {
		res.Available = false
		if errors.Is(err, ErrPermission) {
			res.Reason = "permission denied reading HKLM\\" + servicesKey
		} else {
			res.Reason = fmt.Sprintf("cannot read HKLM\\%s: %v", servicesKey, err)
		}
		return nil, res
	}

	var out []Service
	for _, name := range root.SubKeys {
		info, err := reg.OpenKey("HKLM", servicesKey+`\`+name)
		if err != nil {
			if errors.Is(err, ErrPermission) {
				res.addErr("permission denied reading service key %q", name)
			}
			continue
		}
		svc := Service{Name: name, Source: info.Path, Extra: map[string]string{}}
		for _, v := range info.Values {
			switch strings.ToLower(v.Name) {
			case "imagepath":
				svc.ImagePath = v.String
			case "displayname":
				svc.DisplayName = v.String
			case "description":
				svc.Description = v.String
			case "objectname":
				svc.Account = v.String
			case "start":
				if s, ok := serviceStartTypes[v.Number]; ok {
					svc.StartType = s
				} else {
					svc.StartType = strconv.FormatUint(v.Number, 10)
				}
			case "type":
				if s, ok := serviceTypes[v.Number]; ok {
					svc.ServiceType = s
				} else {
					svc.ServiceType = strconv.FormatUint(v.Number, 10)
				}
			}
		}
		// A svchost-hosted service keeps its real payload in Parameters\ServiceDll, not in
		// ImagePath. A check that only reads ImagePath sees "svchost.exe -k netsvcs" and
		// misses the DLL entirely -- which is exactly where this persistence lives.
		if params, perr := reg.OpenKey("HKLM", servicesKey+`\`+name+`\Parameters`); perr == nil {
			for _, v := range params.Values {
				if strings.EqualFold(v.Name, "ServiceDll") {
					svc.Extra["ServiceDll"] = v.String
				}
			}
		}
		svc.ResolvedBinary = parseWindowsImagePath(svc.ImagePath)
		svc.EnabledKnown = svc.StartType != ""
		svc.Enabled = svc.StartType == "auto" || svc.StartType == "boot" ||
			svc.StartType == "system"
		out = append(out, svc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	res.Available = true
	res.ItemsSeen = len(out)
	return out, res
}

// parseWindowsImagePath extracts the executable from a service ImagePath, handling quoting
// and the \??\ and \SystemRoot\ prefixes the kernel uses.
func parseWindowsImagePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	for _, prefix := range []string{`\??\`, `\SystemRoot\`, `system32\`} {
		if strings.HasPrefix(strings.ToLower(p), strings.ToLower(prefix)) {
			p = p[len(prefix):]
		}
	}
	if strings.HasPrefix(p, `"`) {
		if j := strings.Index(p[1:], `"`); j >= 0 {
			return p[1 : 1+j]
		}
	}
	// Unquoted: the executable ends at the first space that follows a ".exe"/".sys".
	low := strings.ToLower(p)
	for _, ext := range []string{".exe", ".sys", ".dll"} {
		if i := strings.Index(low, ext); i >= 0 {
			return p[:i+len(ext)]
		}
	}
	if i := strings.IndexAny(p, " \t"); i > 0 {
		return p[:i]
	}
	return p
}

// ---------------------------------------------------------------------------------------
// Scheduled tasks
// ---------------------------------------------------------------------------------------

// TaskFolders are the on-disk locations of Task Scheduler definitions.
var TaskFolders = []string{
	`C:\Windows\System32\Tasks`,
	`C:\Windows\SysWOW64\Tasks`,
}

// taskXML mirrors the Task Scheduler schema. Go's encoding/xml matches on local names, so
// the schema namespace does not need to be declared.
type taskXML struct {
	RegistrationInfo struct {
		Author string `xml:"Author"`
		Date   string `xml:"Date"`
		URI    string `xml:"URI"`
	} `xml:"RegistrationInfo"`
	Triggers struct {
		Raw []byte `xml:",innerxml"`
	} `xml:"Triggers"`
	Principals struct {
		Principal []struct {
			ID        string `xml:"id,attr"`
			UserID    string `xml:"UserId"`
			GroupID   string `xml:"GroupId"`
			RunLevel  string `xml:"RunLevel"`
			LogonType string `xml:"LogonType"`
		} `xml:"Principal"`
	} `xml:"Principals"`
	Settings struct {
		Enabled bool `xml:"Enabled"`
		Hidden  bool `xml:"Hidden"`
	} `xml:"Settings"`
	Actions struct {
		Exec []struct {
			Command    string `xml:"Command"`
			Arguments  string `xml:"Arguments"`
			WorkingDir string `xml:"WorkingDirectory"`
		} `xml:"Exec"`
		ComHandler []struct {
			ClassID string `xml:"ClassId"`
			Data    string `xml:"Data"`
		} `xml:"ComHandler"`
	} `xml:"Actions"`
}

// WindowsScheduledTasks parses Task Scheduler XML definitions from disk.
func WindowsScheduledTasks(fs FileSystem, maxDepth int) ([]ScheduledTask, SourceResult) {
	res := SourceResult{
		Name: "Windows scheduled task definitions",
		Privilege: "C:\\Windows\\System32\\Tasks is readable by Administrators; " +
			"standard users can read only some subtrees",
	}
	anyFolder := false
	var out []ScheduledTask

	for _, folder := range TaskFolders {
		if !fs.Exists(folder) {
			continue
		}
		anyFolder = true
		err := fs.Walk(folder, maxDepth, func(fi FileInfo) error {
			if fi.IsDir {
				return nil
			}
			data, truncated, err := fs.ReadFile(fi.Path)
			if err != nil {
				if errors.Is(err, ErrPermission) {
					res.addErr("permission denied reading task %s", fi.Path)
				} else {
					res.addErr("reading %s: %v", fi.Path, err)
				}
				return nil
			}
			if truncated {
				res.Truncated = true
			}
			t, perr := parseTaskXML(fi.Path, folder, data)
			if perr != nil {
				// A task file that will not parse is reported, not skipped silently: a
				// malformed definition could itself be an evasion attempt.
				res.addErr("parsing task %s: %v", fi.Path, perr)
				return nil
			}
			out = append(out, t)
			return nil
		})
		if err != nil {
			if errors.Is(err, ErrPermission) {
				res.addErr("permission denied walking %s", folder)
			} else {
				res.addErr("walking %s: %v", folder, err)
			}
		}
	}

	if !anyFolder {
		res.Available = false
		res.Reason = "no Task Scheduler folder exists (searched " +
			strings.Join(TaskFolders, ", ") + ")"
		return nil, res
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	res.Available = true
	res.ItemsSeen = len(out)
	return out, res
}

func parseTaskXML(path, folder string, data []byte) (ScheduledTask, error) {
	// Task XML is UTF-16 with a BOM on a real host. Normalise before parsing.
	data = decodeMaybeUTF16(data)

	var x taskXML
	dec := xml.NewDecoder(bytes.NewReader(data))
	// Real task files carry <?xml version="1.0" encoding="UTF-16"?>. encoding/xml refuses a
	// non-UTF-8 encoding declaration unless a CharsetReader is supplied, even though the
	// bytes have already been converted above. Returning the reader unchanged tells the
	// decoder "this is already UTF-8" and is correct precisely because decodeMaybeUTF16 has
	// done the conversion.
	dec.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	if err := dec.Decode(&x); err != nil {
		return ScheduledTask{}, err
	}
	t := ScheduledTask{
		Name:    baseWindowsName(path),
		Path:    path,
		Source:  path,
		Author:  x.RegistrationInfo.Author,
		Enabled: x.Settings.Enabled,
		Hidden:  x.Settings.Hidden,
		Extra:   map[string]string{},
	}
	rel := strings.TrimPrefix(strings.ReplaceAll(path, "/", `\`),
		strings.ReplaceAll(folder, "/", `\`))
	t.Extra["task_path"] = strings.ReplaceAll(rel, `\`, `\`)
	t.Extra["registration_date"] = x.RegistrationInfo.Date
	t.Extra["uri"] = x.RegistrationInfo.URI

	for _, p := range x.Principals.Principal {
		id := p.UserID
		if id == "" {
			id = p.GroupID
		}
		if t.Principal == "" {
			t.Principal = id
		}
		if p.RunLevel != "" {
			t.Extra["run_level"] = p.RunLevel
		}
	}
	for _, e := range x.Actions.Exec {
		t.Actions = append(t.Actions, TaskAction{
			Command: strings.TrimSpace(e.Command), Arguments: strings.TrimSpace(e.Arguments),
			WorkDir: strings.TrimSpace(e.WorkingDir),
		})
	}
	for _, ch := range x.Actions.ComHandler {
		// A COM handler action runs an in-process COM object rather than an executable,
		// so it is recorded distinctly: a check looking only at <Exec> would see a task
		// with no action at all.
		t.Actions = append(t.Actions, TaskAction{
			Command:   "COM:" + ch.ClassID,
			Arguments: strings.TrimSpace(ch.Data),
		})
	}
	t.Triggers = extractTriggerNames(string(x.Triggers.Raw))
	return t, nil
}

// decodeMaybeUTF16 converts UTF-16LE/BE (with BOM) to UTF-8, leaving UTF-8 untouched.
// Real Task Scheduler files on disk are UTF-16LE with a BOM.
func decodeMaybeUTF16(b []byte) []byte {
	if len(b) >= 2 {
		if b[0] == 0xFF && b[1] == 0xFE {
			return utf16LEToUTF8(b[2:], false)
		}
		if b[0] == 0xFE && b[1] == 0xFF {
			return utf16LEToUTF8(b[2:], true)
		}
	}
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}

func utf16LEToUTF8(b []byte, bigEndian bool) []byte {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		if bigEndian {
			u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
		} else {
			u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
		}
	}
	return []byte(string(utf16Runes(u)))
}

func utf16Runes(u []uint16) []rune {
	out := make([]rune, 0, len(u))
	for i := 0; i < len(u); i++ {
		if u[i] >= 0xD800 && u[i] < 0xDC00 && i+1 < len(u) &&
			u[i+1] >= 0xDC00 && u[i+1] < 0xE000 {
			out = append(out, (rune(u[i]-0xD800)<<10)|rune(u[i+1]-0xDC00)+0x10000)
			i++
			continue
		}
		out = append(out, rune(u[i]))
	}
	return out
}

func extractTriggerNames(raw string) []string {
	var out []string
	for _, name := range []string{
		"BootTrigger", "LogonTrigger", "TimeTrigger", "CalendarTrigger",
		"EventTrigger", "IdleTrigger", "RegistrationTrigger", "SessionStateChangeTrigger",
	} {
		if strings.Contains(raw, "<"+name) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func baseWindowsName(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	if i := strings.LastIndex(p, `\`); i >= 0 {
		return p[i+1:]
	}
	return p
}
