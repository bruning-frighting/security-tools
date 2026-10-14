// Package safety holds the production-safety envelope: resource limits, per-collector
// timeouts, process priority, and the write-confinement guard.
//
// This package exists because the tool runs on live customer servers. Every limit here is a
// promise to the operator: the scan will not consume the box, will not wander onto a network
// share, and will not write anywhere except the output directory.
package safety

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// Limits bounds everything a collector may consume. Zero values are not meaningful; use
// DefaultLimits and adjust.
type Limits struct {
	// MaxFilesPerCollector caps directory traversal breadth.
	MaxFilesPerCollector int
	// MaxFileSizeBytes: files larger than this are stat'd and hashed-by-prefix but not read
	// whole. Prevents a 40 GB log from being pulled into memory.
	MaxFileSizeBytes int64
	// MaxExcerptBytes bounds what is persisted per evidence item.
	MaxExcerptBytes int
	// MaxTotalExcerptBytes bounds the whole evidence manifest.
	MaxTotalExcerptBytes int
	// MaxDirDepth bounds recursion.
	MaxDirDepth int
	// MaxEventsPerQuery bounds event-log reads.
	MaxEventsPerQuery int
	// MaxSampleEvents bounds samples kept per telemetry aggregate.
	MaxSampleEvents int
	// CollectorTimeout is the per-collector wall-clock budget.
	CollectorTimeout time.Duration
	// TotalTimeout is the whole-scan budget.
	TotalTimeout time.Duration
	// SkipNetworkFilesystems skips remote mounts by default: scanning a DFS share from one
	// host is slow, noisy and usually wrong.
	SkipNetworkFilesystems bool
	// FollowSymlinks is false by default: following links out of the configured root breaks
	// the fixture-root abstraction and can escape into unintended trees.
	FollowSymlinks bool
	// LowPriority requests reduced CPU/IO scheduling priority.
	LowPriority bool
}

// DefaultLimits is tuned for an unattended run on a production server. The numbers are
// deliberately conservative; they are not derived from measurements on customer hardware and
// should be revisited with real data before anyone treats them as tuned.
func DefaultLimits() Limits {
	return Limits{
		MaxFilesPerCollector:   50000,
		MaxFileSizeBytes:       16 << 20, // 16 MiB
		MaxExcerptBytes:        4096,
		MaxTotalExcerptBytes:   8 << 20, // 8 MiB
		MaxDirDepth:            12,
		MaxEventsPerQuery:      20000,
		MaxSampleEvents:        5,
		CollectorTimeout:       90 * time.Second,
		TotalTimeout:           30 * time.Minute,
		SkipNetworkFilesystems: true,
		FollowSymlinks:         false,
		LowPriority:            true,
	}
}

// Budget tracks consumption against Limits for one collector run. Not safe for concurrent
// use by multiple goroutines without external synchronisation; the runner gives each
// collector its own.
type Budget struct {
	limits    Limits
	files     int
	excerpt   int
	truncated bool
	reasons   []string
}

func NewBudget(l Limits) *Budget { return &Budget{limits: l} }

// AllowFile reports whether another file may be examined, recording truncation when not.
func (b *Budget) AllowFile() bool {
	if b.files >= b.limits.MaxFilesPerCollector {
		b.markTruncated(fmt.Sprintf("file-count limit %d reached",
			b.limits.MaxFilesPerCollector))
		return false
	}
	b.files++
	return true
}

// ClampExcerpt bounds an excerpt against both per-item and total budgets, returning the
// clamped text and whether it was cut.
func (b *Budget) ClampExcerpt(s string) (string, bool) {
	cut := false
	if len(s) > b.limits.MaxExcerptBytes {
		s = s[:b.limits.MaxExcerptBytes]
		cut = true
	}
	if b.excerpt+len(s) > b.limits.MaxTotalExcerptBytes {
		remaining := b.limits.MaxTotalExcerptBytes - b.excerpt
		if remaining < 0 {
			remaining = 0
		}
		if remaining < len(s) {
			s = s[:remaining]
			cut = true
			b.markTruncated("total evidence excerpt budget exhausted")
		}
	}
	b.excerpt += len(s)
	return s, cut
}

func (b *Budget) markTruncated(reason string) {
	b.truncated = true
	for _, r := range b.reasons {
		if r == reason {
			return
		}
	}
	b.reasons = append(b.reasons, reason)
}

// Truncated reports whether any limit cut collection short. A truncated collection may never
// be reported as NOT_DETECTED.
func (b *Budget) Truncated() bool { return b.truncated }

// TruncationReasons explains what was cut, for the report.
func (b *Budget) TruncationReasons() []string { return b.reasons }

// FilesExamined is surfaced in DataSourceStatus.ItemsSeen.
func (b *Budget) FilesExamined() int { return b.files }

func (b *Budget) Limits() Limits { return b.limits }

// ---------------------------------------------------------------------------------------
// Write confinement
// ---------------------------------------------------------------------------------------

// OutputGuard enforces that the tool writes only inside the operator's output directory.
// The scanner has no other write path: there is no quarantine, no remediation, no deletion.
type OutputGuard struct {
	root string
}

func NewOutputGuard(outputDir string) (*OutputGuard, error) {
	abs, err := filepath.Abs(outputDir)
	if err != nil {
		return nil, fmt.Errorf("resolving output dir: %w", err)
	}
	return &OutputGuard{root: filepath.Clean(abs)}, nil
}

// Check returns an error if path is not inside the output directory. Callers must treat a
// non-nil error as a bug, not as a condition to recover from.
func (g *OutputGuard) Check(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolving %q: %w", path, err)
	}
	abs = filepath.Clean(abs)
	rel, err := filepath.Rel(g.root, abs)
	if err != nil {
		return fmt.Errorf("write outside output dir refused: %q", path)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("write outside output dir refused: %q is not under %q", abs, g.root)
	}
	return nil
}

func (g *OutputGuard) Root() string { return g.root }

// ---------------------------------------------------------------------------------------
// Network filesystem detection
// ---------------------------------------------------------------------------------------

// networkFSTypes are filesystem type names treated as remote. Used on Linux, where the type
// is read from the mount table.
var networkFSTypes = map[string]bool{
	"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "smbfs": true,
	"afs": true, "glusterfs": true, "ceph": true, "fuse.sshfs": true,
	"fuse.s3fs": true, "9p": true, "lustre": true, "afpfs": true, "davfs": true,
	"fuse.rclone": true, "beegfs": true, "ocfs2": true, "gpfs": true,
}

// IsNetworkFSType reports whether a filesystem type name is remote.
func IsNetworkFSType(fstype string) bool {
	return networkFSTypes[strings.ToLower(strings.TrimSpace(fstype))]
}

// IsUNCPath reports whether a Windows path is a UNC (network) path. Checked textually so it
// works identically on a fixture tree and on a live host.
func IsUNCPath(p string) bool {
	q := strings.ReplaceAll(p, "/", `\`)
	return strings.HasPrefix(q, `\\`) && !strings.HasPrefix(q, `\\?\`) &&
		!strings.HasPrefix(q, `\\.\`)
}
