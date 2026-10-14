package collect

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"irscan/internal/safety"
)

// RootFS is a read-only FileSystem rooted at an optional prefix.
//
// The root is what makes every filesystem-backed check testable without a real host: a
// fixture tree is mounted at the root and the check sees ordinary logical paths like
// /etc/systemd/system or C:\Windows\System32\Tasks.
//
// All reported paths are LOGICAL (host-relative). The fixture root never leaks into a report,
// because an analyst reading evidence must see where the artifact lives on the customer's
// server, not where it lived in a test tree.
type RootFS struct {
	root string
	// targetOS is "windows" or "linux" and controls drive-letter handling.
	targetOS  string
	budget    *safety.Budget
	limits    safety.Limits
	mounts    mountTable
	synthetic bool
}

// NewRootFS creates a filesystem view. root == "" means the live filesystem.
// synthetic must be true when root points at a fixture tree.
func NewRootFS(root, targetOS string, budget *safety.Budget, synthetic bool) *RootFS {
	fs := &RootFS{
		root:      filepath.Clean(root),
		targetOS:  strings.ToLower(targetOS),
		budget:    budget,
		limits:    budget.Limits(),
		synthetic: synthetic,
	}
	if root == "" {
		fs.root = ""
	}
	fs.mounts = loadMountTable()
	return fs
}

func (f *RootFS) Name() string {
	if f.root == "" {
		return "rootfs:live"
	}
	kind := "rootfs"
	if f.synthetic {
		kind = "fixture"
	}
	return kind + ":" + f.root
}

func (f *RootFS) Root() string    { return f.root }
func (f *RootFS) Synthetic() bool { return f.synthetic }

// translate maps a logical host path to a physical path under the root.
//
// Windows drive letters become a single path component ("C:\Windows" -> <root>/C/Windows) so
// a fixture tree can represent a Windows host on a Linux build machine.
func (f *RootFS) translate(logical string) (string, error) {
	if f.root == "" {
		return filepath.FromSlash(logical), nil
	}
	p := strings.ReplaceAll(logical, `\`, "/")
	if len(p) >= 2 && p[1] == ':' {
		p = p[:1] + p[2:] // "C:/Windows" -> "C/Windows"
	}
	p = strings.TrimPrefix(p, "/")
	joined := filepath.Join(f.root, filepath.FromSlash(p))

	// Refuse to escape the root. Without this, a "../.." in a logical path (or a crafted
	// fixture) would read outside the tree, which would both break the abstraction and
	// read host files during a fixture test.
	rel, err := filepath.Rel(f.root, joined)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes configured root", logical)
	}
	return joined, nil
}

// logicalOf reverses translate for paths discovered during a walk.
func (f *RootFS) logicalOf(physical string) string {
	if f.root == "" {
		return physical
	}
	rel, err := filepath.Rel(f.root, physical)
	if err != nil {
		return physical
	}
	s := filepath.ToSlash(rel)
	if f.targetOS == "windows" {
		// "C/Windows/System32" -> "C:\Windows\System32"
		parts := strings.SplitN(s, "/", 2)
		if len(parts[0]) == 1 {
			rest := ""
			if len(parts) > 1 {
				rest = `\` + strings.ReplaceAll(parts[1], "/", `\`)
			}
			return parts[0] + ":" + rest
		}
		return `\` + strings.ReplaceAll(s, "/", `\`)
	}
	return "/" + s
}

func (f *RootFS) Stat(logical string) (FileInfo, error) {
	phys, err := f.translate(logical)
	if err != nil {
		return FileInfo{}, err
	}
	// Lstat, not Stat: a symlink is itself an artifact several checks care about, and
	// following it silently would hide link-based persistence and masquerading.
	st, err := os.Lstat(phys)
	if err != nil {
		return FileInfo{}, classifyErr(err)
	}
	return f.infoFrom(logical, phys, st), nil
}

func (f *RootFS) infoFrom(logical, phys string, st os.FileInfo) FileInfo {
	fi := FileInfo{
		Path:       logical,
		Name:       st.Name(),
		Size:       st.Size(),
		Mode:       uint32(st.Mode().Perm()),
		ModeString: st.Mode().String(),
		IsDir:      st.IsDir(),
		IsSymlink:  st.Mode()&os.ModeSymlink != 0,
		ModTime:    st.ModTime(),
		UID:        -1,
		GID:        -1,
	}
	if fi.IsSymlink {
		if t, err := os.Readlink(phys); err == nil {
			fi.LinkTarget = t
		}
	}
	fi.WorldWritable = st.Mode().Perm()&0o002 != 0
	fi.SUID = st.Mode()&os.ModeSetuid != 0
	fi.SGID = st.Mode()&os.ModeSetgid != 0
	fi.Hidden = strings.HasPrefix(st.Name(), ".")
	fillOwner(&fi, st)
	return fi
}

func (f *RootFS) Open(logical string) (io.ReadCloser, error) {
	phys, err := f.translate(logical)
	if err != nil {
		return nil, err
	}
	// os.Open is read-only (O_RDONLY). Nothing in this package ever uses os.Create,
	// os.OpenFile with write flags, os.Remove, os.Rename or os.Chmod.
	fh, err := os.Open(phys)
	if err != nil {
		return nil, classifyErr(err)
	}
	return fh, nil
}

func (f *RootFS) ReadFile(logical string) ([]byte, bool, error) {
	phys, err := f.translate(logical)
	if err != nil {
		return nil, false, err
	}
	st, err := os.Lstat(phys)
	if err != nil {
		return nil, false, classifyErr(err)
	}
	if st.IsDir() {
		return nil, false, fmt.Errorf("%s is a directory", logical)
	}
	fh, err := os.Open(phys)
	if err != nil {
		return nil, false, classifyErr(err)
	}
	defer fh.Close()

	limit := f.limits.MaxFileSizeBytes
	truncated := st.Size() > limit
	data, err := io.ReadAll(io.LimitReader(fh, limit))
	if err != nil {
		return nil, truncated, classifyErr(err)
	}
	return data, truncated, nil
}

func (f *RootFS) ReadDir(logical string) ([]DirEntry, error) {
	phys, err := f.translate(logical)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(phys)
	if err != nil {
		return nil, classifyErr(err)
	}
	out := make([]DirEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, DirEntry{
			Name:      e.Name(),
			IsDir:     e.IsDir(),
			IsSymlink: e.Type()&os.ModeSymlink != 0,
		})
	}
	// Sorted so report output and tests are deterministic regardless of FS enumeration order.
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f *RootFS) Exists(logical string) bool {
	phys, err := f.translate(logical)
	if err != nil {
		return false
	}
	_, err = os.Lstat(phys)
	return err == nil
}

func (f *RootFS) Walk(logicalRoot string, maxDepth int, fn WalkFunc) error {
	if maxDepth <= 0 || maxDepth > f.limits.MaxDirDepth {
		maxDepth = f.limits.MaxDirDepth
	}
	if remote, typ := f.IsRemote(logicalRoot); remote && f.limits.SkipNetworkFilesystems {
		return fmt.Errorf("skipping network filesystem (%s) at %s: remote mounts are skipped "+
			"by default", typ, logicalRoot)
	}
	return f.walk(logicalRoot, 0, maxDepth, fn)
}

func (f *RootFS) walk(logical string, depth, maxDepth int, fn WalkFunc) error {
	if depth > maxDepth {
		return nil
	}
	entries, err := f.ReadDir(logical)
	if err != nil {
		return err
	}
	for _, e := range entries {
		child := joinLogical(logical, e.Name, f.targetOS)
		if !f.budget.AllowFile() {
			return nil // budget exhausted; budget records the truncation
		}
		info, err := f.Stat(child)
		if err != nil {
			// An unreadable entry is not fatal to the walk, but it must not be silently
			// treated as absent. The caller sees it via the budget/source status; here we
			// skip it so one denied file cannot abort a whole collector.
			continue
		}
		if err := fn(info); err != nil {
			if err == SkipDir {
				continue
			}
			return err
		}
		if info.IsDir && (!info.IsSymlink || f.limits.FollowSymlinks) {
			if err := f.walk(child, depth+1, maxDepth, fn); err != nil {
				return err
			}
		}
	}
	return nil
}

func joinLogical(base, name, targetOS string) string {
	if targetOS == "windows" && strings.Contains(base, `\`) {
		return strings.TrimRight(base, `\`) + `\` + name
	}
	if base == "/" {
		return "/" + name
	}
	return strings.TrimRight(base, "/") + "/" + name
}

func (f *RootFS) IsRemote(logical string) (bool, string) {
	// A fixture tree is never remote, whatever the logical path looks like.
	if f.synthetic {
		return false, ""
	}
	if f.targetOS == "windows" && safety.IsUNCPath(logical) {
		return true, "UNC"
	}
	return f.mounts.lookup(logical)
}

// classifyErr normalises OS errors so checks can distinguish "denied" from "absent" without
// importing syscall. Getting this wrong is how a scanner reports a locked-down host as clean.
func classifyErr(err error) error {
	if err == nil {
		return nil
	}
	if os.IsPermission(err) {
		return fmt.Errorf("%w: %v", ErrPermission, err)
	}
	return err
}

// Unused-time guard so the time import stays meaningful if ModTime handling changes.
var _ = time.Time{}
