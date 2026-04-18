package downloader

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxAttempts    = 3
	bufferSize     = 256 * 1024 // 256KB streaming buffer
	connectTimeout = 30 * time.Second
	totalTimeout   = 30 * time.Minute
	userAgent      = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"
)

// IsURL returns true if the path looks like a URL.
func IsURL(path string) bool {
	return strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://")
}

// DownloadToTemp downloads a file from URL to a temporary location with retry and resume.
// Mirrors the robust PHP/curl logic: retries on failure, resumes partial downloads,
// forces HTTP/1.1, and validates the result is a valid IPA (ZIP magic bytes).
func DownloadToTemp(url string) (localPath string, err error) {
	tmpDir := os.TempDir()
	filename := "gosigner_dl_" + randomHex(8) + ".ipa"
	localPath = filepath.Join(tmpDir, filename)

	// Remove any stale file
	os.Remove(localPath)

	var lastError error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		lastError = downloadWithResume(url, localPath)

		if lastError == nil {
			// Validate it's a real IPA (ZIP file starts with PK)
			if err := validateIPA(localPath); err != nil {
				lastError = err
				log.Printf("[downloader] attempt %d/%d: %v", attempt, maxAttempts, err)
				if attempt < maxAttempts {
					time.Sleep(time.Duration(attempt*2) * time.Second)
				}
				continue
			}

			log.Printf("[downloader] Downloaded successfully: %s (%s)", localPath, fileSize(localPath))
			return localPath, nil
		}

		log.Printf("[downloader] attempt %d/%d failed: %v", attempt, maxAttempts, lastError)

		// Keep partial file for resume on next attempt
		if attempt < maxAttempts {
			time.Sleep(time.Duration(attempt*2) * time.Second)
		}
	}

	// All attempts failed — cleanup
	os.Remove(localPath)
	return "", fmt.Errorf("download failed after %d attempts: %w", maxAttempts, lastError)
}

// downloadWithResume downloads a URL to a local file, resuming from existing partial data.
func downloadWithResume(url string, localPath string) error {
	// Check existing partial file size for resume
	var existingSize int64
	if info, err := os.Stat(localPath); err == nil {
		existingSize = info.Size()
	}

	transport := &http.Transport{
		// Force HTTP/1.1 to avoid HTTP/2 framing issues with some CDNs
		ForceAttemptHTTP2: false,
	}

	client := &http.Client{
		Timeout:   totalTimeout,
		Transport: transport,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")

	// Resume from partial download
	if existingSize > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", existingSize))
		log.Printf("[downloader] Resuming from byte %d", existingSize)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Full download — truncate any existing file
		existingSize = 0
	case http.StatusPartialContent:
		// Resume working
	case http.StatusRequestedRangeNotSatisfiable:
		// File might already be complete
		return nil
	default:
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Open file for writing (append if resuming, create if fresh)
	flags := os.O_CREATE | os.O_WRONLY
	if existingSize > 0 && resp.StatusCode == http.StatusPartialContent {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}

	f, err := os.OpenFile(localPath, flags, 0644)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	buf := make([]byte, bufferSize)
	_, err = io.CopyBuffer(f, resp.Body, buf)
	if err != nil {
		return fmt.Errorf("download stream: %w", err)
	}

	return nil
}

// validateIPA checks that the file starts with ZIP magic bytes (PK).
func validateIPA(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open for validation: %w", err)
	}
	defer f.Close()

	var magic [2]byte
	n, err := f.Read(magic[:])
	if err != nil || n < 2 {
		return fmt.Errorf("file too small or unreadable")
	}

	if magic[0] != 'P' || magic[1] != 'K' {
		info, _ := f.Stat()
		size := int64(0)
		if info != nil {
			size = info.Size()
		}
		return fmt.Errorf("not a valid IPA (magic: %02x%02x, size: %d)", magic[0], magic[1], size)
	}

	return nil
}

// RandomFilename generates a random hex filename with the given extension.
func RandomFilename(ext string) string {
	return randomHex(16) + ext
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func fileSize(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "unknown"
	}
	size := info.Size()
	switch {
	case size >= 1<<30:
		return fmt.Sprintf("%.1fGB", float64(size)/(1<<30))
	case size >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(size)/(1<<20))
	case size >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(size)/(1<<10))
	default:
		return fmt.Sprintf("%dB", size)
	}
}
