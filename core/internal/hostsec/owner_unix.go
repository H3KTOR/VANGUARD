//go:build !windows

package hostsec

import (
	"io/fs"
	"syscall"
)

// ownerOf extracts the numeric owner/group of a stat result. Split out
// behind a build tag so the platform-neutral parsing/diff logic in this
// package stays compilable (and unit-testable) on non-Unix developer
// machines; production is Linux-only.
func ownerOf(info fs.FileInfo) (uid, gid uint32, ok bool) {
	st, isStat := info.Sys().(*syscall.Stat_t)
	if !isStat {
		return 0, 0, false
	}
	return st.Uid, st.Gid, true
}
