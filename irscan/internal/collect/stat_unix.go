//go:build unix

package collect

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// fillOwner populates UID/GID/Owner from the Unix stat structure.
//
// Owner name lookup is cached: a walk over /etc or /usr can hit thousands of files, and an
// uncached user.LookupId per file is a measurable cost on a production host.
func fillOwner(fi *FileInfo, st os.FileInfo) {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	fi.UID = int(sys.Uid)
	fi.GID = int(sys.Gid)
	fi.Owner = lookupUser(fi.UID)
}

var userCache = map[int]string{}

func lookupUser(uid int) string {
	if uid < 0 {
		return ""
	}
	if n, ok := userCache[uid]; ok {
		return n
	}
	name := ""
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		name = u.Username
	}
	userCache[uid] = name
	return name
}
