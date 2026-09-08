//go:build !darwin && !linux && !freebsd && !netbsd && !openbsd

package pipeline

// availableBytes has no portable implementation on this platform, so the
// pre-flight space check is skipped rather than guessed at.
func availableBytes(string) (uint64, bool) { return 0, false }
