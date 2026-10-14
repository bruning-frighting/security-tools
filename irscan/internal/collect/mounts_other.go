//go:build !linux

package collect

// mountTable is a no-op outside Linux.
//
// On Windows, remote-path detection is done textually via safety.IsUNCPath in RootFS.IsRemote
// (a mapped drive letter backed by SMB is NOT caught by that and is a known limitation,
// recorded in the README: detecting it needs GetDriveType/WNetGetConnection, which cannot be
// exercised in this environment under B-001).
type mountTable struct{}

func loadMountTable() mountTable { return mountTable{} }

func (m mountTable) lookup(string) (bool, string) { return false, "" }
