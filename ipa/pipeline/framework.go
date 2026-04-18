package pipeline

// Framework and plugin signing is handled by signComponent in resign.go.
// This file contains helpers for parallel framework signing.

import (
	"fmt"
	"sync"
)

// signFrameworksParallel signs multiple frameworks concurrently.
func signFrameworksParallel(frameworkDirs []string, execNames []string, opts *ResignOptions, maxWorkers int) error {
	if len(frameworkDirs) == 0 {
		return nil
	}

	if maxWorkers < 1 {
		maxWorkers = 1
	}

	errChan := make(chan error, len(frameworkDirs))
	sem := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup

	for i, dir := range frameworkDirs {
		wg.Add(1)
		go func(fwDir string, execName string) {
			defer wg.Done()
			sem <- struct{}{} // Acquire
			defer func() { <-sem }() // Release

			if err := signComponent(fwDir, execName, opts, false); err != nil {
				errChan <- fmt.Errorf("framework %s: %w", fwDir, err)
			}
		}(dir, execNames[i])
	}

	wg.Wait()
	close(errChan)

	// Collect errors
	for err := range errChan {
		return err // Return first error
	}

	return nil
}
