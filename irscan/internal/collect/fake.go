package collect

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Fakes live in the non-test build on purpose: they are also how the --replay mode consumes
// fixtures captured from a real host (DECISIONS.md D-004), not only how unit tests work.

// ---------------------------------------------------------------------------------------
// FakeRegistry
// ---------------------------------------------------------------------------------------

// FakeRegistry implements Registry from an in-memory map, so Windows registry check LOGIC is
// fully testable on Linux. Given B-001 this is the only way Windows checks get tested at all.
type FakeRegistry struct {
	// Keys is indexed by "HIVE\\path" using backslashes, case-insensitively.
	Keys map[string]RegKeyInfo
	// Denied marks keys that must return ErrPermission, so the PERMISSION_DENIED path is
	// exercised rather than assumed.
	Denied map[string]bool
	// Unavailable makes Available() report false, for the no-data test case.
	Unavailable       bool
	UnavailableReason string
	Hives             []UserHive
}

func NewFakeRegistry() *FakeRegistry {
	return &FakeRegistry{Keys: map[string]RegKeyInfo{}, Denied: map[string]bool{}}
}

func (r *FakeRegistry) Name() string { return "registry:fake" }

func (r *FakeRegistry) Available() (bool, string) {
	if r.Unavailable {
		reason := r.UnavailableReason
		if reason == "" {
			reason = "registry source marked unavailable by fixture"
		}
		return false, reason
	}
	return true, ""
}

func regKey(hive, path string) string {
	return strings.ToLower(strings.TrimRight(hive, `\`) + `\` + strings.Trim(path, `\`))
}

func (r *FakeRegistry) Set(hive, path string, info RegKeyInfo) {
	if info.Path == "" {
		info.Path = strings.TrimRight(hive, `\`) + `\` + strings.Trim(path, `\`)
	}
	r.Keys[regKey(hive, path)] = info
}

func (r *FakeRegistry) Deny(hive, path string) { r.Denied[regKey(hive, path)] = true }

func (r *FakeRegistry) OpenKey(hive, path string) (RegKeyInfo, error) {
	if ok, reason := r.Available(); !ok {
		return RegKeyInfo{}, fmt.Errorf("%w: %s", ErrNotSupported, reason)
	}
	k := regKey(hive, path)
	if r.Denied[k] {
		return RegKeyInfo{}, fmt.Errorf("%w: reading %s", ErrPermission, k)
	}
	info, ok := r.Keys[k]
	if !ok {
		return RegKeyInfo{}, fmt.Errorf("registry key not found: %s\\%s", hive, path)
	}
	sort.Slice(info.Values, func(i, j int) bool { return info.Values[i].Name < info.Values[j].Name })
	sort.Strings(info.SubKeys)
	return info, nil
}

func (r *FakeRegistry) KeyExists(hive, path string) bool {
	_, ok := r.Keys[regKey(hive, path)]
	return ok
}

func (r *FakeRegistry) UserHives() ([]UserHive, error) {
	if ok, reason := r.Available(); !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotSupported, reason)
	}
	return r.Hives, nil
}

// ---------------------------------------------------------------------------------------
// FakeTelemetry
// ---------------------------------------------------------------------------------------

// FakeTelemetry implements TelemetrySource. It is what makes the telemetry matrix testable:
// the same check is run with a channel present/enabled, present/disabled and absent, and must
// produce DETECTED, INSUFFICIENT_DATA and INSUFFICIENT_DATA respectively -- never
// NOT_DETECTED.
type FakeTelemetry struct {
	Channels map[string]ChannelStatus
	Events   map[string][]LogEvent
	Denied   map[string]bool
	// ForceTruncate makes Query report truncation regardless of limit, to test that a
	// truncated read cannot yield NOT_DETECTED.
	ForceTruncate bool
}

func NewFakeTelemetry() *FakeTelemetry {
	return &FakeTelemetry{
		Channels: map[string]ChannelStatus{},
		Events:   map[string][]LogEvent{},
		Denied:   map[string]bool{},
	}
}

func (t *FakeTelemetry) Name() string { return "telemetry:fake" }

func (t *FakeTelemetry) Status(channel string) ChannelStatus {
	if s, ok := t.Channels[channel]; ok {
		s.Channel = channel
		return s
	}
	return ChannelStatus{
		Channel:     channel,
		Present:     false,
		Reason:      "channel not present in fixture",
		RecordCount: -1,
	}
}

func (t *FakeTelemetry) Query(q TelemetryQuery) ([]LogEvent, bool, error) {
	if t.Denied[q.Channel] {
		return nil, false, fmt.Errorf("%w: reading channel %s", ErrPermission, q.Channel)
	}
	st := t.Status(q.Channel)
	if !st.Present {
		return nil, false, fmt.Errorf("channel %s not present: %s", q.Channel, st.Reason)
	}
	var out []LogEvent
	for _, e := range t.Events[q.Channel] {
		if !matchesQuery(e, q) {
			continue
		}
		out = append(out, e)
	}
	truncated := t.ForceTruncate
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
		truncated = true
	}
	return out, truncated, nil
}

func matchesQuery(e LogEvent, q TelemetryQuery) bool {
	if len(q.EventIDs) > 0 {
		found := false
		for _, id := range q.EventIDs {
			if e.EventID == id {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if !q.Since.IsZero() && e.Time.Before(q.Since) {
		return false
	}
	if !q.Until.IsZero() && e.Time.After(q.Until) {
		return false
	}
	for _, c := range q.Contains {
		if !strings.Contains(e.Message, c) && !strings.Contains(e.Raw, c) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------------------
// ErrorFS
// ---------------------------------------------------------------------------------------

// ErrorFS wraps a FileSystem and injects failures for chosen logical paths.
//
// This exists because the permission-denied test case must be exercised deterministically on
// every platform. Relying on chmod 000 in a fixture tree does not work on Windows and does
// not work when tests run as root.
type ErrorFS struct {
	FileSystem
	// DenyPrefix: any logical path with one of these prefixes returns ErrPermission.
	DenyPrefix []string
	// MissingPrefix: any logical path with one of these prefixes behaves as absent.
	MissingPrefix []string
}

func (e *ErrorFS) match(list []string, path string) bool {
	norm := strings.ReplaceAll(path, `\`, "/")
	for _, p := range list {
		if strings.HasPrefix(norm, strings.ReplaceAll(p, `\`, "/")) {
			return true
		}
	}
	return false
}

func (e *ErrorFS) Name() string { return "errorfs(" + e.FileSystem.Name() + ")" }

func (e *ErrorFS) Stat(p string) (FileInfo, error) {
	if e.match(e.DenyPrefix, p) {
		return FileInfo{}, fmt.Errorf("%w: stat %s", ErrPermission, p)
	}
	if e.match(e.MissingPrefix, p) {
		return FileInfo{}, fmt.Errorf("no such file or directory: %s", p)
	}
	return e.FileSystem.Stat(p)
}

func (e *ErrorFS) Open(p string) (io.ReadCloser, error) {
	if e.match(e.DenyPrefix, p) {
		return nil, fmt.Errorf("%w: open %s", ErrPermission, p)
	}
	if e.match(e.MissingPrefix, p) {
		return nil, fmt.Errorf("no such file or directory: %s", p)
	}
	return e.FileSystem.Open(p)
}

func (e *ErrorFS) ReadFile(p string) ([]byte, bool, error) {
	if e.match(e.DenyPrefix, p) {
		return nil, false, fmt.Errorf("%w: read %s", ErrPermission, p)
	}
	if e.match(e.MissingPrefix, p) {
		return nil, false, fmt.Errorf("no such file or directory: %s", p)
	}
	return e.FileSystem.ReadFile(p)
}

func (e *ErrorFS) ReadDir(p string) ([]DirEntry, error) {
	if e.match(e.DenyPrefix, p) {
		return nil, fmt.Errorf("%w: readdir %s", ErrPermission, p)
	}
	if e.match(e.MissingPrefix, p) {
		return nil, fmt.Errorf("no such file or directory: %s", p)
	}
	return e.FileSystem.ReadDir(p)
}

// Exists returns TRUE for a denied path.
//
// A denied path EXISTS; the scanner simply cannot read it. Modelling denial as absence was
// the first implementation and it produced the wrong failure shape: collectors concluded
// "this subsystem is not installed" when the truth was "I was not allowed to look", which
// is exactly the confusion the INSUFFICIENT_DATA / PERMISSION_DENIED split exists to
// prevent.
func (e *ErrorFS) Exists(p string) bool {
	if e.match(e.MissingPrefix, p) {
		return false
	}
	if e.match(e.DenyPrefix, p) {
		return true
	}
	return e.FileSystem.Exists(p)
}

func (e *ErrorFS) Walk(root string, depth int, fn WalkFunc) error {
	if e.match(e.DenyPrefix, root) {
		return fmt.Errorf("%w: walk %s", ErrPermission, root)
	}
	if e.match(e.MissingPrefix, root) {
		return fmt.Errorf("no such file or directory: %s", root)
	}
	return e.FileSystem.Walk(root, depth, func(fi FileInfo) error {
		if e.match(e.DenyPrefix, fi.Path) || e.match(e.MissingPrefix, fi.Path) {
			return nil
		}
		return fn(fi)
	})
}

// ---------------------------------------------------------------------------------------
// UnavailableRegistry / UnavailableTelemetry
// ---------------------------------------------------------------------------------------

// UnavailableRegistry is the Registry implementation used on non-Windows hosts. It reports a
// clear reason rather than erroring per call, so checks emit INSUFFICIENT_DATA with an
// explanation an analyst can act on.
type UnavailableRegistry struct{ Reason string }

func (u UnavailableRegistry) Name() string { return "registry:unavailable" }
func (u UnavailableRegistry) Available() (bool, string) {
	r := u.Reason
	if r == "" {
		r = "Windows registry is not available on this host"
	}
	return false, r
}
func (u UnavailableRegistry) OpenKey(hive, path string) (RegKeyInfo, error) {
	return RegKeyInfo{}, fmt.Errorf("%w: %s", ErrNotSupported, u.Reason)
}
func (u UnavailableRegistry) KeyExists(string, string) bool { return false }
func (u UnavailableRegistry) UserHives() ([]UserHive, error) {
	return nil, fmt.Errorf("%w: %s", ErrNotSupported, u.Reason)
}

// NoTelemetry reports every channel absent, with a stated reason.
type NoTelemetry struct{ Reason string }

func (n NoTelemetry) Name() string { return "telemetry:none" }
func (n NoTelemetry) Status(channel string) ChannelStatus {
	r := n.Reason
	if r == "" {
		r = "no telemetry source configured for this host"
	}
	return ChannelStatus{Channel: channel, Present: false, Reason: r, RecordCount: -1}
}
func (n NoTelemetry) Query(q TelemetryQuery) ([]LogEvent, bool, error) {
	return nil, false, fmt.Errorf("%w: %s", ErrNotSupported, n.Reason)
}

var _ = time.Time{}
