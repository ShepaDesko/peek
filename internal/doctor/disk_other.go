//go:build !unix

package doctor

import "errors"

// diskFree is only implemented on the platforms Peek is deployed on. The
// Windows path exists so the tooling builds on a developer machine.
func diskFree(string) (free, total uint64, err error) {
	return 0, 0, errors.New("disk usage is not available on this platform")
}
