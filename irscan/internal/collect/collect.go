// Package collect defines the collector interfaces and their implementations.
//
// Architecture rule (PLAN.md 5.1): checks never touch the OS. They receive data objects from
// these interfaces. That is what makes every check testable without a real host, and it is
// why Windows check LOGIC is unit-testable in an environment where no Windows binary can run
// (DECISIONS.md B-001).
//
// Read-only rule: nothing in this package opens anything for writing, creates, truncates,
// renames or removes. internal/check has a test (TestCollectorsAreReadOnly) that greps this
// package's source for write primitives, so the claim is enforced rather than asserted.
package collect

import (
	"errors"
	"io"
	"time"
)

// ErrNotSupported is returned by a source that cannot operate in the current environment
// (for example the Windows registry source on Linux). It is distinct from a permission error
// so that OutcomeFromSources maps it to INSUFFICIENT_DATA rather than PERMISSION_DENIED.
var ErrNotSupported = errors.New("source not supported in this environment")

// ErrPermission signals a genuine access denial.
var ErrPermission = errors.New("permission denied")

// ---------------------------------------------------------------------------------------
// Filesystem
// ---------------------------------------------------------------------------------------

// FileInfo is the OS-independent file description checks see.
type FileInfo struct {
	// Path is the LOGICAL path as it exists on the scanned host, never the fixture-root
	// path. Reports must only ever show logical paths.
	Path       string
	Name       string
	Size       int64
	Mode       uint32
	ModeString string
	IsDir      bool
	IsSymlink  bool
	LinkTarget string
	ModTime    time.Time
	// UID/GID are -1 when unknown (for example on a Windows host or a fixture tree).
	UID, GID int
	Owner    string
	Hidden   bool
	// WorldWritable is precomputed because several checks care and the bit arithmetic is
	// easy to get wrong.
	WorldWritable bool
	// SUID/SGID likewise.
	SUID, SGID bool
}

type DirEntry struct {
	Name      string
	IsDir     bool
	IsSymlink bool
}

// FileSystem is a read-only, root-relocatable view of a filesystem.
type FileSystem interface {
	// Name identifies the backing implementation for reports ("rootfs:/", "fixture:...").
	Name() string
	// Root returns the configured root. Empty means the live filesystem.
	Root() string
	// Synthetic reports whether this is a fixture tree rather than a live host.
	Synthetic() bool

	Stat(logicalPath string) (FileInfo, error)
	Open(logicalPath string) (io.ReadCloser, error)
	// ReadFile returns content bounded by the size limit. truncated is true when the file
	// was larger than the limit; a truncated read may never justify NOT_DETECTED.
	ReadFile(logicalPath string) (data []byte, truncated bool, err error)
	ReadDir(logicalPath string) ([]DirEntry, error)
	Exists(logicalPath string) bool

	// Walk visits logicalRoot recursively, bounded by maxDepth and the budget. fn returning
	// SkipDir skips the subtree.
	Walk(logicalRoot string, maxDepth int, fn WalkFunc) error

	// IsRemote reports whether the path lives on a network filesystem, and the type name.
	IsRemote(logicalPath string) (bool, string)
}

type WalkFunc func(info FileInfo) error

// SkipDir is returned by a WalkFunc to skip the current directory's subtree.
var SkipDir = errors.New("skip this directory")

// ---------------------------------------------------------------------------------------
// Windows registry
// ---------------------------------------------------------------------------------------

type RegValueType string

const (
	RegSZ          RegValueType = "REG_SZ"
	RegExpandSZ    RegValueType = "REG_EXPAND_SZ"
	RegMultiSZ     RegValueType = "REG_MULTI_SZ"
	RegDWord       RegValueType = "REG_DWORD"
	RegQWord       RegValueType = "REG_QWORD"
	RegBinary      RegValueType = "REG_BINARY"
	RegOtherType   RegValueType = "REG_OTHER"
)

type RegValue struct {
	Name string
	Type RegValueType
	// String holds the rendered value for string types and a decimal for numeric types.
	String string
	// Multi holds REG_MULTI_SZ entries.
	Multi []string
	// Number holds DWORD/QWORD values.
	Number uint64
	// BinaryLen is the length of REG_BINARY data; the bytes themselves are not retained
	// unless a check explicitly needs them, to keep evidence bounded.
	BinaryLen int
}

type RegKeyInfo struct {
	Path       string
	SubKeys    []string
	Values     []RegValue
	LastWrite  time.Time
	// LastWriteKnown is false where the backing implementation cannot supply it.
	LastWriteKnown bool
}

// Registry is a read-only view of the Windows registry. Hive names are the conventional
// short forms: HKLM, HKCU, HKU, HKCR, HKCC.
type Registry interface {
	Name() string
	// Available reports whether the registry can be read at all, with a reason when not.
	// On Linux this returns (false, "not a Windows host") rather than erroring per-call.
	Available() (bool, string)
	// OpenKey returns the key's subkeys and values. Returns ErrPermission on access denial
	// so the caller can emit PERMISSION_DENIED rather than mistaking it for absence.
	OpenKey(hive, path string) (RegKeyInfo, error)
	// KeyExists avoids the cost of enumerating values when only presence matters.
	KeyExists(hive, path string) bool
	// UserHives lists loaded per-user hives as (sid, hiveRoot) so HKCU-style checks can
	// cover every user rather than only the scanning user.
	UserHives() ([]UserHive, error)
}

type UserHive struct {
	SID      string
	Username string
	// Root is the path to use with OpenKey, e.g. hive "HKU", path "S-1-5-21-...".
	Root string
}

// ---------------------------------------------------------------------------------------
// Event logs / telemetry
// ---------------------------------------------------------------------------------------

type LogEvent struct {
	// Channel is the Windows channel name or the Linux log file / subsystem.
	Channel     string
	EventID     int
	Provider    string
	Time        time.Time
	Level       string
	Computer    string
	UserSID     string
	// Message is the rendered text, bounded by the excerpt limit before persistence.
	Message string
	// Fields holds parsed key/value data where available.
	Fields map[string]string
	// Raw is the unparsed line for file-backed sources; bounded before persistence.
	Raw string
}

// ChannelStatus describes whether a telemetry source is usable, which is the whole point of
// the telemetry matrix: a check must be able to say "auditing was off" rather than "clean".
type ChannelStatus struct {
	Channel string
	// Present means the channel/file exists.
	Present bool
	// Enabled means it is configured to collect (where that is knowable).
	Enabled bool
	// EnabledKnown is false when the implementation cannot determine Enabled.
	EnabledKnown bool
	// Reason explains a false Present/Enabled.
	Reason string
	// RecordCount is -1 when unknown.
	RecordCount int64
	// Oldest/Newest bound the retention window actually available. A check must not claim
	// "no evidence in the last 30 days" if the log only goes back 2 days.
	Oldest, Newest time.Time
	WindowKnown    bool
	// RequiredPrivilege names what is needed to read it, for --dry-run.
	RequiredPrivilege string
}

// TelemetrySource is a read-only view of host log data.
type TelemetrySource interface {
	Name() string
	// Status describes a channel without reading it, so a check can decide between
	// INSUFFICIENT_DATA and a real query cheaply.
	Status(channel string) ChannelStatus
	// Query returns events, bounded by limit. truncated is true when the limit was hit.
	Query(q TelemetryQuery) (events []LogEvent, truncated bool, err error)
}

type TelemetryQuery struct {
	Channel  string
	EventIDs []int
	Since    time.Time
	Until    time.Time
	Limit    int
	// Contains filters on substring of the raw/message text, for file-backed sources.
	Contains []string
}

// ---------------------------------------------------------------------------------------
// Derived sources
// ---------------------------------------------------------------------------------------
//
// Services and scheduled tasks are deliberately NOT separate native APIs. On Windows a
// service is a registry key under HKLM\SYSTEM\CurrentControlSet\Services and a scheduled
// task is an XML file under %SystemRoot%\System32\Tasks; on Linux both are files. Deriving
// them from FileSystem + Registry means they need no new native code and are fully
// fixture-testable -- which, given B-001, is the difference between tested and untested.

type Service struct {
	Name        string
	DisplayName string
	// ImagePath as configured, unexpanded.
	ImagePath string
	// ResolvedBinary is the parsed executable path with arguments stripped.
	ResolvedBinary string
	StartType      string
	ServiceType    string
	Account        string
	Description    string
	// Source records where this came from, for evidence (registry key or unit file path).
	Source string
	// Enabled is meaningful on Linux (symlinked into a .wants directory).
	Enabled      bool
	EnabledKnown bool

	// IsSymlink records that the unit path is a symbolic link rather than a regular file.
	// This matters more than it looks: a symlink's own mode is ALWAYS lrwxrwxrwx, so any
	// "world-writable" test applied to it is meaningless and fires on every link.
	IsSymlink  bool
	LinkTarget string
	// Masked is true for a unit symlinked to /dev/null, which is systemd's standard way of
	// DISABLING a unit. A masked unit cannot start, so it is the opposite of a persistence
	// signal and must never be reported as one.
	Masked bool

	Extra map[string]string
}

type ScheduledTask struct {
	Name string
	Path string
	// Actions are the commands the task runs.
	Actions []TaskAction
	Triggers []string
	Principal string
	Enabled   bool
	Hidden    bool
	Source    string
	Author    string
	Extra     map[string]string
}

type TaskAction struct {
	Command   string
	Arguments string
	WorkDir   string
}

type UserAccount struct {
	Name     string
	UID      string
	GID      string
	HomeDir  string
	Shell    string
	Disabled bool
	// PasswordState is "hashed", "locked", "empty" or "unknown". The hash itself is never
	// retained (credential-redaction rule).
	PasswordState string
	Groups        []string
	Source        string
}
