//go:build windows

package hostsec

import "io/fs"

// ownerOf has no meaning on Windows; VANGUARD only runs on Linux in
// production. Returning ok=false makes every owner-dependent check a
// safe no-op on a Windows developer machine.
func ownerOf(info fs.FileInfo) (uid, gid uint32, ok bool) { return 0, 0, false }
