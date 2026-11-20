//go:build unix

package store

import (
	"os"
	"syscall"
)

// alignOwnership hands any file this process just created in the data
// directory back to whoever owns that directory.
//
// Administration commands are run with sudo — peek doctor, peek backup,
// peek migrate — while the service runs as the peek user. Without this, the
// first root-run command creates peek.db (or its -wal and -shm companions)
// owned by root, and the service then fails with "attempt to write a readonly
// database". Found exactly that way on a Debian box.
func alignOwnership(dbPath string) {
	if dbPath == "" || os.Geteuid() != 0 {
		return
	}
	dir := dbPath
	if idx := lastSlash(dir); idx > 0 {
		dir = dir[:idx]
	} else {
		dir = "."
	}
	info, err := os.Stat(dir)
	if err != nil {
		return
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	uid, gid := int(stat.Uid), int(stat.Gid)
	if uid == 0 {
		// The directory belongs to root as well: nothing to hand over.
		return
	}
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		path := dbPath + suffix
		if _, err := os.Stat(path); err != nil {
			continue
		}
		_ = os.Chown(path, uid, gid)
	}
}

func lastSlash(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' || s[i] == '\\' {
			return i
		}
	}
	return -1
}
