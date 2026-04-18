package cleanup

import (
	"log"
	"os"
)

// Tracker keeps track of temporary files/directories that should be deleted after signing.
type Tracker struct {
	paths []string
}

// New creates a new cleanup tracker.
func New() *Tracker {
	return &Tracker{}
}

// Track adds a path to be cleaned up later.
func (t *Tracker) Track(path string) {
	t.paths = append(t.paths, path)
}

// Run deletes all tracked files and directories.
// Errors are logged but not returned — cleanup is best-effort.
func (t *Tracker) Run() {
	for _, path := range t.paths {
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			continue
		}

		if info != nil && info.IsDir() {
			if err := os.RemoveAll(path); err != nil {
				log.Printf("[cleanup] failed to remove dir %s: %v", path, err)
			} else {
				log.Printf("[cleanup] removed dir: %s", path)
			}
		} else {
			if err := os.Remove(path); err != nil {
				log.Printf("[cleanup] failed to remove %s: %v", path, err)
			} else {
				log.Printf("[cleanup] removed: %s", path)
			}
		}
	}

	t.paths = nil
}
