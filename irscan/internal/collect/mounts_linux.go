//go:build linux

package collect

import (
	"os"
	"sort"
	"strings"

	"irscan/internal/safety"
)

// mountTable maps mount points to filesystem types so network mounts can be skipped.
type mountTable struct {
	points []mountPoint
}

type mountPoint struct {
	path   string
	fstype string
	remote bool
}

// loadMountTable reads /proc/self/mounts.
//
// Failure is not fatal and is not treated as "nothing is remote": an empty table simply means
// IsRemote cannot tell, and the walk proceeds. Checks that care report the uncertainty via
// their source status rather than silently assuming a local disk.
func loadMountTable() mountTable {
	data, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return mountTable{}
	}
	var mt mountTable
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// fields: device mountpoint fstype options ...
		mp := mountPoint{
			path:   unescapeMount(fields[1]),
			fstype: fields[2],
		}
		mp.remote = safety.IsNetworkFSType(mp.fstype)
		mt.points = append(mt.points, mp)
	}
	// Longest path first so the most specific mount wins.
	sort.Slice(mt.points, func(i, j int) bool {
		return len(mt.points[i].path) > len(mt.points[j].path)
	})
	return mt
}

// unescapeMount decodes the octal escapes the kernel uses for spaces and tabs in mount paths.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	r := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return r.Replace(s)
}

func (m mountTable) lookup(path string) (bool, string) {
	for _, p := range m.points {
		if path == p.path || strings.HasPrefix(path, strings.TrimRight(p.path, "/")+"/") {
			return p.remote, p.fstype
		}
	}
	return false, ""
}
