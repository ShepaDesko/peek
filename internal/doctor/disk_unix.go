//go:build unix

package doctor

import (
	"errors"

	"golang.org/x/sys/unix"
)

// diskFree returns the free and total bytes of the filesystem holding dir.
func diskFree(dir string) (free, total uint64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	// Bsize is signed on some platforms; a negative or zero value means the
	// filesystem did not report a usable block size.
	if st.Bsize <= 0 {
		return 0, 0, errors.New("doctor: filesystem reported no block size")
	}
	bsize := uint64(st.Bsize) //nolint:gosec // guarded as positive just above
	return st.Bavail * bsize, st.Blocks * bsize, nil
}
