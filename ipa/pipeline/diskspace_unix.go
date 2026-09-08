//go:build darwin || linux || freebsd || netbsd || openbsd

package pipeline

import "syscall"

// availableBytes reports the free space on the filesystem holding dir.
// The second result is false when the platform cannot report it.
func availableBytes(dir string) (uint64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, false
	}
	return uint64(st.Bavail) * uint64(st.Bsize), true
}
