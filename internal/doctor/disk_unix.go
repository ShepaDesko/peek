//go:build unix

package doctor

import "golang.org/x/sys/unix"

// diskFree returns the free and total bytes of the filesystem holding dir.
func diskFree(dir string) (free, total uint64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	bsize := uint64(st.Bsize)
	return st.Bavail * bsize, st.Blocks * bsize, nil
}
