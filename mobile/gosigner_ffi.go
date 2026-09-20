// Package main is the on-device FFI surface for GoSigner, built as an iOS
// c-archive (`-buildmode=c-archive`, GOOS=ios GOARCH=arm64) and called from
// Flutter via dart:ffi. It exposes four C symbols: GoSignerRun (sign),
// GoSignerInspect (read metadata + icon), GoSignerExtractDylibs, GoSignerFree.
//
// The encrypted-certificate envelope is decrypted here, in native memory only:
// the plaintext p12 / password / mobileprovision never cross back to Dart or
// touch disk. The scheme mirrors the server's App\Services\V2\CertCrypto
// byte-for-byte — AES-256-GCM with a key from HKDF-SHA256(pepper, salt=udid,
// info=cert_id), blob = base64(nonce(12) || ciphertext || tag(16)), AAD =
// "<udid>|<cert_id>".
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"github.com/AzozzALFiras/GoSigner/engine/jsoninput"
	"github.com/AzozzALFiras/GoSigner/engine/worker"
	"github.com/AzozzALFiras/GoSigner/ipa/archive"
	"github.com/AzozzALFiras/GoSigner/ipa/bundle"
	"github.com/AzozzALFiras/GoSigner/plist/infoplist"
)

// pepperHex is injected at build time via
//
//	-ldflags "-X main.pepperHex=<64 hex chars>"
//
// It is a shared secret and is NEVER committed to source control. Empty means
// the encrypted-certificate path is unavailable (plaintext cert mode still works).
var pepperHex string

// ---------------------------------------------------------------------------
// Crypto — mirrors server App\Services\V2\CertCrypto exactly.
// ---------------------------------------------------------------------------

// certBundle is the JSON plaintext the server encrypts.
type certBundle struct {
	P12      string `json:"p12"`      // base64 of the .p12 bytes
	Password string `json:"password"` // p12 password
	MP       string `json:"mp"`       // base64 of the .mobileprovision bytes
}

// hkdf32 is HKDF-SHA256 (RFC 5869) yielding a single 32-byte block, equivalent
// to PHP hash_hkdf('sha256', ikm, 32, info, salt).
func hkdf32(ikm, salt, info []byte) []byte {
	extract := hmac.New(sha256.New, salt) // salt = udid
	extract.Write(ikm)                    // ikm  = pepper
	prk := extract.Sum(nil)

	expand := hmac.New(sha256.New, prk)
	expand.Write(info) // info = cert_id
	expand.Write([]byte{0x01})
	return expand.Sum(nil) // 32 bytes (one block covers the needed length)
}

func deriveKey(udid, certID string) ([]byte, error) {
	pepper, err := hex.DecodeString(strings.TrimSpace(pepperHex))
	if err != nil || len(pepper) != 32 {
		return nil, errors.New("signing key unavailable on this build")
	}
	return hkdf32(pepper, []byte(udid), []byte(certID)), nil
}

func decryptBundle(enc, udid, certID string) (*certBundle, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(enc))
	if err != nil {
		return nil, fmt.Errorf("decode enc: %w", err)
	}
	if len(raw) < 12+16 {
		return nil, errors.New("enc bundle truncated")
	}
	nonce := raw[:12]
	ctAndTag := raw[12:] // ciphertext || tag(16) — Go GCM wants the tag appended

	key, err := deriveKey(udid, certID)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block) // 12-byte nonce, 16-byte tag
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, nonce, ctAndTag, []byte(udid+"|"+certID))
	if err != nil {
		return nil, errors.New("cert bundle authentication failed")
	}
	var b certBundle
	if err := json.Unmarshal(pt, &b); err != nil {
		return nil, fmt.Errorf("cert bundle format: %w", err)
	}
	return &b, nil
}

// applyEncrypted decrypts any enc bundle into the in-memory signing material,
// then wipes enc/udid/cert_id so they never reach the pipeline or the logs.
func applyEncrypted(req *jsoninput.Request) error {
	for i := range req.Apps {
		a := &req.Apps[i]
		if a.Enc == "" {
			continue
		}
		b, err := decryptBundle(a.Enc, a.Udid, a.CertID)
		if err != nil {
			return fmt.Errorf("app %d: %w", i, err)
		}
		a.CertData = b.P12   // worker base64-decodes CertData
		a.ProfileData = b.MP // worker base64-decodes ProfileData
		a.CertPassword = b.Password
		a.Enc, a.Udid, a.CertID = "", "", ""
	}
	return nil
}

// ---------------------------------------------------------------------------
// Exported C surface.
// ---------------------------------------------------------------------------

//export GoSignerRun
func GoSignerRun(cfg *C.char) *C.char {
	in := C.GoString(cfg)

	// Capture engine logs so Dart can surface them in debug builds.
	var logBuf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	log.SetFlags(log.Lmicroseconds)
	defer func() { log.SetOutput(prev) }()

	var req jsoninput.Request
	if err := json.Unmarshal([]byte(in), &req); err != nil {
		return cjson(map[string]any{"success": false, "errors": []string{"bad config: " + err.Error()}})
	}
	if err := applyEncrypted(&req); err != nil {
		return cjson(map[string]any{"success": false, "errors": []string{err.Error()}})
	}

	resp := worker.Run(&req)
	return cjson(map[string]any{
		"success":    resp.Success,
		"results":    resp.Results,
		"errors":     resp.Errors,
		"engine_log": logBuf.String(),
	})
}

//export GoSignerInspect
func GoSignerInspect(ipaPath *C.char) *C.char {
	m, err := inspectIPA(C.GoString(ipaPath))
	if err != nil {
		return cjson(map[string]any{"error": err.Error()})
	}
	return cjson(m)
}

//export GoSignerExtractDylibs
func GoSignerExtractDylibs(ipaPath, outDir *C.char) *C.char {
	res, err := extractDylibs(C.GoString(ipaPath), C.GoString(outDir))
	if err != nil {
		return cjson(map[string]any{"dylibs": []any{}, "error": err.Error()})
	}
	return cjson(map[string]any{"dylibs": res})
}

// planCache keeps the last plan parsed, so serving a 3 GB archive in chunks
// does not re-read its description thousands of times.
var (
	planMu   sync.Mutex
	planPath string
	planHeld *archive.Plan
)

func cachedPlan(path string) (*archive.Plan, error) {
	planMu.Lock()
	defer planMu.Unlock()
	if planHeld != nil && planPath == path {
		return planHeld, nil
	}
	p, err := archive.LoadPlan(path)
	if err != nil {
		return nil, err
	}
	planPath, planHeld = path, p
	return p, nil
}

// Writes [offset, offset+length) of the planned archive into a freshly
// allocated buffer — the bytes iOS is asking for, generated from the source
// archive and the files signing produced, so the archive itself never exists.
// The caller frees the buffer with GoSignerFree.
//
//export GoSignerServe
func GoSignerServe(planPath *C.char, offset C.longlong, length C.longlong, outLen *C.int) *C.char {
	*outLen = 0
	plan, err := cachedPlan(C.GoString(planPath))
	if err != nil {
		log.Printf("[serve] load plan: %v", err)
		return nil
	}
	var buf bytes.Buffer
	buf.Grow(int(length))
	if err := plan.WriteRange(&buf, int64(offset), int64(length)); err != nil {
		log.Printf("[serve] range %d+%d: %v", int64(offset), int64(length), err)
		return nil
	}
	b := buf.Bytes()
	*outLen = C.int(len(b))
	return (*C.char)(C.CBytes(b))
}

//export GoSignerFree
func GoSignerFree(p *C.char) {
	C.free(unsafe.Pointer(p))
}

func main() {}

// ---------------------------------------------------------------------------
// Inspect / extract helpers.
// ---------------------------------------------------------------------------

func inspectIPA(ipaPath string) (map[string]any, error) {
	r, err := archive.OpenIPA(ipaPath)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	files := r.Files()
	app, err := bundle.Discover(files)
	if err != nil {
		return nil, err
	}
	appPath := app.AppPath // e.g. "Payload/MyApp.app"

	infoData, err := r.ReadFile(appPath + "/Info.plist")
	if err != nil {
		return nil, fmt.Errorf("read Info.plist: %w", err)
	}
	info, _ := infoplist.ReadFromBytes(infoData)
	raw, _ := infoplist.ReadRaw(infoData)

	name, bundleID, version := "", "", ""
	if info != nil {
		if info.BundleDisplayName != "" {
			name = info.BundleDisplayName
		} else {
			name = info.BundleName
		}
		bundleID = info.BundleID
		if info.ShortVersion != "" {
			version = info.ShortVersion
		} else {
			version = info.BundleVersion
		}
	}

	dylibs := make([]string, 0, len(app.Dylibs))
	for _, d := range app.Dylibs {
		dylibs = append(dylibs, path.Base(d))
	}

	hasAssets := false
	for _, f := range files {
		if f.Name == appPath+"/Assets.car" {
			hasAssets = true
			break
		}
	}

	return map[string]any{
		"name":           name,
		"bundle_id":      bundleID,
		"version":        version,
		"icon":           extractIcon(r, files, appPath, raw),
		"dylibs":         dylibs,
		"has_assets_car": hasAssets,
	}, nil
}

// extractIcon returns the app's primary icon as base64. It prefers the files
// declared under CFBundleIcons/CFBundlePrimaryIcon/CFBundleIconFiles, picking
// the largest matching PNG at the .app root; if none are declared it falls back
// to the largest AppIcon*.png there.
func extractIcon(r *archive.IPAReader, files []*zip.File, appPath string, raw map[string]any) string {
	var bases []string
	if raw != nil {
		if icons, ok := raw["CFBundleIcons"].(map[string]any); ok {
			if prim, ok := icons["CFBundlePrimaryIcon"].(map[string]any); ok {
				if list, ok := prim["CFBundleIconFiles"].([]any); ok {
					for _, it := range list {
						if s, ok := it.(string); ok {
							bases = append(bases, s)
						}
					}
				}
			}
		}
	}

	root := appPath + "/"
	var bestName string
	var bestSize uint64
	for _, f := range files {
		n := f.Name
		if !strings.HasPrefix(n, root) {
			continue
		}
		rest := n[len(root):]
		if strings.Contains(rest, "/") { // .app root only
			continue
		}
		if !strings.HasSuffix(strings.ToLower(rest), ".png") {
			continue
		}
		match := false
		if len(bases) == 0 {
			match = strings.HasPrefix(rest, "AppIcon")
		} else {
			for _, b := range bases {
				if strings.HasPrefix(rest, b) {
					match = true
					break
				}
			}
		}
		if match && f.UncompressedSize64 >= bestSize {
			bestSize = f.UncompressedSize64
			bestName = n
		}
	}
	if bestName == "" {
		return ""
	}
	data, err := r.ReadFile(bestName)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(data)
}

func extractDylibs(ipaPath, outDir string) ([]map[string]string, error) {
	r, err := archive.OpenIPA(ipaPath)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	app, err := bundle.Discover(r.Files())
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}

	out := make([]map[string]string, 0, len(app.Dylibs))
	for _, dp := range app.Dylibs {
		data, err := r.ReadFile(dp)
		if err != nil {
			continue
		}
		dest := filepath.Join(outDir, path.Base(dp))
		if err := os.WriteFile(dest, data, 0o644); err != nil {
			continue
		}
		out = append(out, map[string]string{"name": path.Base(dp), "path": dest})
	}
	return out, nil
}

func cjson(v any) *C.char {
	b, err := json.Marshal(v)
	if err != nil {
		return C.CString(`{"success":false,"errors":["marshal error"]}`)
	}
	return C.CString(string(b))
}
