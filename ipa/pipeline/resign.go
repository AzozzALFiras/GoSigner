package pipeline

import (
	"archive/zip"
	"bytes"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/AzozzALFiras/GoSigner/certificate"
	"github.com/AzozzALFiras/GoSigner/ipa/archive"
	"github.com/AzozzALFiras/GoSigner/ipa/bundle"
	"github.com/AzozzALFiras/GoSigner/plist/coderesources"
	"github.com/AzozzALFiras/GoSigner/plist/infoplist"
	"github.com/AzozzALFiras/GoSigner/provision"
)

// ResignOptions holds all options for the IPA re-signing pipeline.
type ResignOptions struct {
	InputPath       string
	OutputPath      string
	Identity        *certificate.SigningIdentity
	Profile         *provision.ProvisioningProfile
	BundleID        string   // Override bundle ID (empty = keep)
	BundleName      string   // Override display name (empty = keep)
	BundleVersion   string   // Override version (empty = keep)
	EntitlementsXML []byte   // Custom entitlements (nil = use profile)
	EntitlementsDER []byte   // Custom DER entitlements (nil = auto-generate)
	// SkipDEREntitlements suppresses the DER entitlements slot (0x7)
	// entirely. Set internally when signing frameworks / loose dylibs —
	// they must not carry DER entitlements, only an empty XML blob.
	SkipDEREntitlements bool
	InjectDylibs    []string // Dylib file paths to inject into executable
	BundlePaths     []string // .bundle directories to copy into Frameworks/
	RemoveDylibs    []string // Dylib names to remove
	WeakInject      bool     // Use weak loading for injected dylibs
	ForceSign       bool     // Skip caching
	ZipLevel        int      // Compression level (0-9)
	StripExtensions bool     // Remove app extensions
	StripWatch      bool     // Remove watch app
	StripProfile    bool     // Remove embedded profile
	MinOSVersion    string   // Set minimum OS version
	EnableDocs      bool     // Enable document sharing
	IconFiles       map[string][]byte // loose icon PNGs to write into the .app root
	IconName        string   // CFBundleIconFiles base name
	WorkDir         string   // base dir for the temp extraction (empty = os default)
	DeleteAssetsCar bool     // remove Assets.car (forces loose-PNG icon)
	IsAdhoc         bool     // Ad-hoc signing
}

// streamEntryToFile copies one zip entry to disk without ever holding it whole
// in memory: the decompressed stream is piped through a fixed 64 KiB buffer.
func streamEntryToFile(f *zip.File, destPath string, perm os.FileMode) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	buf := make([]byte, 64*1024)
	if _, err := io.CopyBuffer(out, rc, buf); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// crc32OfFile streams a file through the IEEE CRC32 that zip stores, so an
// unchanged entry can be recognised without loading it into memory.
func crc32OfFile(path string) (uint32, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	h := crc32.NewIEEE()
	buf := make([]byte, 64*1024)
	if _, err := io.CopyBuffer(h, f, buf); err != nil {
		return 0, err
	}
	return h.Sum32(), nil
}

// Resign performs the complete IPA re-signing pipeline.
func Resign(opts *ResignOptions) error {
	log.Printf("[GoSigner] Opening IPA: %s", opts.InputPath)

	// Step 1: Open IPA and discover app bundle
	ipaReader, err := archive.OpenIPA(opts.InputPath)
	if err != nil {
		return fmt.Errorf("open ipa: %w", err)
	}
	defer ipaReader.Close()

	appBundle, err := bundle.Discover(ipaReader.Files())
	if err != nil {
		return fmt.Errorf("discover bundle: %w", err)
	}

	log.Printf("[GoSigner] Found app: %s (Bundle ID: %s, Executable: %s)",
		appBundle.AppPath, appBundle.BundleID, appBundle.ExecutableName)
	log.Printf("[GoSigner] Frameworks: %d, Plugins: %d, Dylibs: %d",
		len(appBundle.Frameworks), len(appBundle.Plugins), len(appBundle.Dylibs))

	// Step 2: Extract to temp directory for signing
	tempDir, err := os.MkdirTemp(opts.WorkDir, "gosigner-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	log.Printf("[GoSigner] Extracting to: %s", tempDir)

	// Extract all files. Each entry is streamed from the zip straight to disk
	// with a fixed buffer — never read whole into memory — so peak RAM stays
	// bounded regardless of file size. This is what lets multi-GB IPAs sign
	// without tripping iOS jetsam. See docs/streaming-resign.md.
	for _, f := range ipaReader.Files() {
		if f.FileInfo().IsDir() {
			dirPath := filepath.Join(tempDir, f.Name)
			os.MkdirAll(dirPath, 0755)
			continue
		}

		destPath := filepath.Join(tempDir, f.Name)
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(destPath), err)
		}

		perm := os.FileMode(0644)
		if f.Mode()&0111 != 0 {
			perm = 0755
		}

		if err := streamEntryToFile(f, destPath, perm); err != nil {
			return fmt.Errorf("extract %s: %w", f.Name, err)
		}
	}

	appDir := filepath.Join(tempDir, appBundle.AppPath)

	// Step 3: Always modify Info.plist — applies iOS 26 compatibility fixes
	// (bump MinimumOSVersion to 10.0 if lower, remove UISupportedDevices) plus
	// any user overrides (bundle ID, name, version, etc.).
	log.Printf("[GoSigner] Modifying Info.plist (compatibility + user overrides)")
	if err := modifyInfoPlist(appDir, opts); err != nil {
		return fmt.Errorf("modify info.plist: %w", err)
	}

	// Replace app icon (loose PNGs referenced by CFBundleIconFiles).
	if len(opts.IconFiles) > 0 {
		log.Printf("[GoSigner] Replacing app icon (%d files)", len(opts.IconFiles))
		for name, data := range opts.IconFiles {
			if err := os.WriteFile(filepath.Join(appDir, name), data, 0644); err != nil {
				return fmt.Errorf("write icon %s: %w", name, err)
			}
		}
	}
	// Delete Assets.car when asked, or whenever we replace the icon.
	if opts.DeleteAssetsCar || len(opts.IconFiles) > 0 {
		if err := os.Remove(filepath.Join(appDir, "Assets.car")); err == nil {
			log.Printf("[GoSigner] Removed Assets.car")
		}
	}

	// Step 4: Handle provisioning profile (NEVER delete unless explicitly asked)
	if opts.Profile != nil {
		log.Printf("[GoSigner] Embedding provisioning profile: %s (UUID: %s)",
			opts.Profile.Name, opts.Profile.UUID)
		profilePath := filepath.Join(appDir, "embedded.mobileprovision")
		if err := os.WriteFile(profilePath, opts.Profile.RawData, 0644); err != nil {
			return fmt.Errorf("embed profile: %w", err)
		}
	} else if opts.StripProfile {
		log.Printf("[GoSigner] Stripping provisioning profile (--strip-profile)")
		os.Remove(filepath.Join(appDir, "embedded.mobileprovision"))
	}
	// If neither: keep existing profile untouched

	// Step 5: Copy .bundle directories into app's Frameworks/
	if len(opts.BundlePaths) > 0 {
		fwDir := filepath.Join(appDir, "Frameworks")
		os.MkdirAll(fwDir, 0755)
		for _, bundlePath := range opts.BundlePaths {
			bundleName := filepath.Base(bundlePath)
			destPath := filepath.Join(fwDir, bundleName)
			log.Printf("[GoSigner] Copying bundle: %s → Frameworks/%s", bundlePath, bundleName)
			if err := copyDir(bundlePath, destPath); err != nil {
				return fmt.Errorf("copy bundle %s: %w", bundleName, err)
			}
		}
	}

	// Step 5b: Copy dylib files into app's Frameworks/ (so they exist before injection)
	if len(opts.InjectDylibs) > 0 {
		fwDir := filepath.Join(appDir, "Frameworks")
		os.MkdirAll(fwDir, 0755)
		for i, dylibPath := range opts.InjectDylibs {
			dylibName := filepath.Base(dylibPath)
			destPath := filepath.Join(fwDir, dylibName)

			// Only copy if the dylib is not already inside the extracted IPA
			if _, err := os.Stat(destPath); os.IsNotExist(err) {
				log.Printf("[GoSigner] Copying dylib: %s → Frameworks/%s", dylibPath, dylibName)
				data, err := os.ReadFile(dylibPath)
				if err != nil {
					return fmt.Errorf("read dylib %s: %w", dylibPath, err)
				}
				if err := os.WriteFile(destPath, data, 0755); err != nil {
					return fmt.Errorf("write dylib %s: %w", dylibPath, err)
				}
			}

			// Update the inject path to use @rpath/ for the load command
			opts.InjectDylibs[i] = "@rpath/" + dylibName
		}
	}

	// Step 6: Strip extensions/watch if requested
	if opts.StripExtensions {
		log.Printf("[GoSigner] Removing app extensions")
		os.RemoveAll(filepath.Join(appDir, "PlugIns"))
		appBundle.Plugins = nil
	}
	if opts.StripWatch {
		log.Printf("[GoSigner] Removing watch app")
		os.RemoveAll(filepath.Join(appDir, "Watch"))
		appBundle.WatchApps = nil
	}

	// Step 6: Sign frameworks. Each framework's code signature identifier
	// MUST be the framework's own CFBundleIdentifier (e.g.
	// "org.cocoapods.FirebaseCore"), not the host app's. iOS 26 rejects
	// any component whose CD identifier is empty or doesn't match its
	// bundle plist — this was the silent-install trigger.
	for _, fw := range appBundle.Frameworks {
		log.Printf("[GoSigner] Signing framework: %s", fw.Path)
		fwDir := filepath.Join(tempDir, fw.Path)
		if err := signComponent(fwDir, fw.ExecutableName, opts, false); err != nil {
			return fmt.Errorf("sign framework %s: %w", fw.Path, err)
		}
	}

	// Step 7: Sign loose dylibs. Dylibs have no Info.plist — esign/zsign
	// use the dylib's own filename (e.g. "Enjoy.dylib") as the CD
	// identifier. Not a main binary; execSegFlags stays 0.
	for _, dylibPath := range appBundle.Dylibs {
		log.Printf("[GoSigner] Signing dylib: %s", dylibPath)
		fullPath := filepath.Join(tempDir, dylibPath)
		if err := signDylib(fullPath, opts); err != nil {
			return fmt.Errorf("sign dylib %s: %w", dylibPath, err)
		}
	}

	// Step 8: Sign plugins (.appex). Each plugin has its own Info.plist
	// with its own bundle ID. A plugin IS a main binary in its own
	// container, so execSegFlags must have CS_EXECSEG_MAIN_BINARY (0x1)
	// set — otherwise iOS treats the appex like a helper library and
	// rejects the enclosing app on 26.
	for _, plugin := range appBundle.Plugins {
		log.Printf("[GoSigner] Signing plugin: %s", plugin.Path)
		plugDir := filepath.Join(tempDir, plugin.Path)
		if err := signComponent(plugDir, plugin.ExecutableName, opts, true); err != nil {
			return fmt.Errorf("sign plugin %s: %w", plugin.Path, err)
		}
	}

	// Step 9: Handle dylib injection/removal on main executable
	mainExecPath := filepath.Join(appDir, appBundle.ExecutableName)
	if len(opts.InjectDylibs) > 0 || len(opts.RemoveDylibs) > 0 {
		log.Printf("[GoSigner] Modifying dylibs in main executable")
		if err := modifyDylibs(mainExecPath, opts); err != nil {
			return fmt.Errorf("modify dylibs: %w", err)
		}
		// delete removed dylib files from the bundle root
		for _, n := range opts.RemoveDylibs {
			os.Remove(filepath.Join(appDir, filepath.Base(n)))
		}
	}

	// Step 10: Generate CodeResources
	log.Printf("[GoSigner] Generating CodeResources")
	codeResourcesData, err := coderesources.Generate(appDir, appBundle.ExecutableName)
	if err != nil {
		return fmt.Errorf("generate code resources: %w", err)
	}

	// Write CodeResources
	csDir := filepath.Join(appDir, "_CodeSignature")
	os.MkdirAll(csDir, 0755)
	if err := os.WriteFile(filepath.Join(csDir, "CodeResources"), codeResourcesData, 0644); err != nil {
		return fmt.Errorf("write code resources: %w", err)
	}

	// Step 11: Sign main executable
	log.Printf("[GoSigner] Signing main executable: %s", appBundle.ExecutableName)
	if err := signMainExecutable(mainExecPath, appDir, codeResourcesData, opts); err != nil {
		return fmt.Errorf("sign main executable: %w", err)
	}

	// Step 12: Repackage IPA
	log.Printf("[GoSigner] Repackaging IPA: %s", opts.OutputPath)
	if err := repackageIPA(tempDir, opts.OutputPath, opts.ZipLevel, ipaReader); err != nil {
		return fmt.Errorf("repackage ipa: %w", err)
	}

	log.Printf("[GoSigner] Done! Signed IPA: %s", opts.OutputPath)
	return nil
}

func modifyInfoPlist(appDir string, opts *ResignOptions) error {
	plistPath := filepath.Join(appDir, "Info.plist")
	data, err := os.ReadFile(plistPath)
	if err != nil {
		return err
	}

	modified, err := infoplist.Modify(data, &infoplist.ModifyOptions{
		BundleID:      opts.BundleID,
		BundleName:    opts.BundleName,
		BundleVersion: opts.BundleVersion,
		MinOSVersion:  opts.MinOSVersion,
		EnableDocs:    opts.EnableDocs,
		IconName:      opts.IconName,
	})
	if err != nil {
		return err
	}

	return os.WriteFile(plistPath, modified, 0644)
}

func repackageIPA(sourceDir string, outputPath string, zipLevel int, src *archive.IPAReader) error {
	writer, err := archive.CreateIPA(outputPath, zipLevel)
	if err != nil {
		return err
	}
	defer writer.Close()

	// Index the source entries so untouched files can be copied verbatim.
	srcEntries := map[string]*zip.File{}
	if src != nil {
		for _, f := range src.Files() {
			srcEntries[f.Name] = f
		}
	}

	return filepath.Walk(sourceDir, func(absPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(sourceDir, absPath)
		if err != nil {
			return err
		}

		if relPath == "." {
			return nil
		}

		// Use forward slashes in ZIP
		relPath = strings.ReplaceAll(relPath, string(filepath.Separator), "/")

		if info.IsDir() {
			return writer.AddDirectory(relPath)
		}

		// Untouched by signing? Copy the original compressed bytes verbatim —
		// no decompress, no recompress, and the entry keeps its compression
		// (a Store-only rewrite inflates an already-compressed IPA a lot).
		// Matching CRC32 *and* size proves the content is byte-identical, so
		// this fast path is self-verifying: anything the pipeline changed
		// falls through to the normal add below.
		if orig, ok := srcEntries[relPath]; ok && orig.UncompressedSize64 == uint64(info.Size()) {
			if sum, cerr := crc32OfFile(absPath); cerr == nil && sum == orig.CRC32 {
				return writer.AddRaw(orig)
			}
		}

		// Modified or new — stream it in, never whole-file into memory, so a
		// multi-GB asset can't trip iOS jetsam. AddFileFromReader sets the same
		// 0755 mode as AddFile/AddExecutable, so permissions are unchanged.
		f, err := os.Open(absPath)
		if err != nil {
			return fmt.Errorf("open %s: %w", relPath, err)
		}
		defer f.Close()

		if err := writer.AddFileFromReader(relPath, f, info.Size()); err != nil {
			return fmt.Errorf("add %s: %w", relPath, err)
		}
		return nil
	})
}

// emptyEntitlementsXML is the minimal entitlements plist embedded into
// sub-binaries that are NOT the main app or an app extension (i.e.
// frameworks and loose dylibs). zsign and esign emit this exact shape.
// Embedding the host app's real entitlements into a framework is
// rejected by iOS 26 with "Integrität konnte nicht verifiziert werden"
// — a framework cannot claim `application-identifier`,
// `keychain-access-groups`, etc.
var emptyEntitlementsXML = []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict/>
</plist>
`)

// signComponent signs a framework or plugin bundle. It reads the
// component's own Info.plist so we sign with the right CD identifier
// (which must be the component's CFBundleIdentifier — e.g.
// "org.cocoapods.FBLPromises" — not the host app's). isMainBinary must
// be true for .appex plugins: they are main binaries of their own
// container, so (a) they keep the host's real entitlements and (b)
// their execSegFlags gets CS_EXECSEG_MAIN_BINARY (0x1).
//
// Frameworks (isMainBinary=false) get an empty <dict/> entitlements
// blob and NO DER entitlements.
func signComponent(componentDir, executableName string, opts *ResignOptions, isMainBinary bool) error {
	if executableName == "" {
		return nil
	}

	execPath := filepath.Join(componentDir, executableName)
	if _, err := os.Stat(execPath); os.IsNotExist(err) {
		return nil
	}

	compInfoPath := filepath.Join(componentDir, "Info.plist")
	compInfoData, _ := os.ReadFile(compInfoPath)

	// Generate CodeResources FIRST — the component's Mach-O code signature
	// must hash _CodeSignature/CodeResources into special slot -3. Signing
	// before generating it leaves that slot zero and iOS 26 rejects.
	crData, err := coderesources.Generate(componentDir, executableName)
	if err != nil {
		return fmt.Errorf("generate code resources: %w", err)
	}
	csDir := filepath.Join(componentDir, "_CodeSignature")
	if err := os.MkdirAll(csDir, 0755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(csDir, "CodeResources"), crData, 0644); err != nil {
		return fmt.Errorf("write code resources: %w", err)
	}

	local := *opts
	if !isMainBinary {
		local.EntitlementsXML = emptyEntitlementsXML
		local.EntitlementsDER = nil
		local.SkipDEREntitlements = true
	}

	return signBinaryWithSlots(execPath, compInfoData, crData, &local, isMainBinary)
}

// signDylib signs a loose dylib. Dylibs have no bundle or Info.plist so
// we use the dylib's filename (e.g. "Enjoy.dylib") as the CD identifier,
// matching esign/zsign. Loose dylibs also get empty entitlements and no
// DER entitlements — same reason as frameworks.
func signDylib(path string, opts *ResignOptions) error {
	local := *opts
	local.BundleID = filepath.Base(path)
	local.EntitlementsXML = emptyEntitlementsXML
	local.EntitlementsDER = nil
	local.SkipDEREntitlements = true
	return signBinaryWithSlots(path, nil, nil, &local, false)
}

// signBinary signs a standalone Mach-O binary file (framework, dylib, plugin).
// Uses a two-pass approach: write modified binary first, then hash and sign it.
func signBinary(path string, opts *ResignOptions) error {
	return signBinaryWithSlots(path, nil, nil, opts, false)
}

// signMainExecutable signs the main app executable with special slot hashes.
// Marks it as main binary so CS_EXECSEG_MAIN_BINARY is set in execSegFlags.
func signMainExecutable(execPath string, appDir string, codeResourcesData []byte, opts *ResignOptions) error {
	infoPlistData, _ := os.ReadFile(filepath.Join(appDir, "Info.plist"))
	return signBinaryWithSlots(execPath, infoPlistData, codeResourcesData, opts, true)
}

// signBinaryWithSlots is the core signing function that uses the correct two-pass approach:
// Pass 1: Write the modified binary (with updated header/load commands, without signature) to get correct bytes.
// Pass 2: Hash the written binary, generate the code signature, append it.
func signBinaryWithSlots(path string, infoPlistData []byte, codeResourcesData []byte, opts *ResignOptions, isMainBinary bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	r := bytes.NewReader(data)
	machO, err := machoOpen(r, int64(len(data)))
	if err != nil {
		return fmt.Errorf("parse mach-o: %w", err)
	}

	// Determine bundle ID
	bundleID := opts.BundleID
	if bundleID == "" && infoPlistData != nil {
		if info, err := infoplist.ReadFromBytes(infoPlistData); err == nil {
			bundleID = info.BundleID
		}
	}

	teamID := ""
	if opts.Identity != nil {
		teamID = opts.Identity.TeamID
	}
	if teamID == "" && opts.Profile != nil {
		teamID = opts.Profile.GetTeamID()
	}

	// CRITICAL: The LC_CODE_SIGNATURE.datasize and __LINKEDIT.filesize affect
	// page 0's hash (since they're stored in the header). We MUST know the
	// final signature size BEFORE computing page hashes, otherwise the first
	// page hash won't match what iOS computes from the installed binary.
	//
	// Strategy: 3 passes
	//   Pass A: Write binary with placeholder cs_size=0, generate signature
	//           to DISCOVER the actual signature size.
	//   Pass B: Re-write binary with cs_size = actualSize and __LINKEDIT updated.
	//           This produces the FINAL header that iOS will see.
	//   Pass C: Hash Pass B's binary, regenerate signature (identical size).
	//           Append to the file.

	// ===== PASS A: Discover signature size =====
	for i := range machO.Slices {
		slice := &machO.Slices[i]
		codeLimit := calculateCodeLimit(slice)
		machoSetCodeSig(slice, codeLimit, 0)
	}

	tmpPathA := path + ".gosigner_tmpA"
	if err := machoWriteToFile(tmpPathA, machO, nil); err != nil {
		return fmt.Errorf("pass A write: %w", err)
	}
	defer os.Remove(tmpPathA)

	tmpDataA, err := os.ReadFile(tmpPathA)
	if err != nil {
		return fmt.Errorf("pass A read: %w", err)
	}
	tmpReaderA := bytes.NewReader(tmpDataA)
	tmpMachOA, err := machoOpen(tmpReaderA, int64(len(tmpDataA)))
	if err != nil {
		return fmt.Errorf("pass A parse: %w", err)
	}

	// Generate discovery signatures to learn size
	discoverySizes := make([]uint32, len(tmpMachOA.Slices))
	for i := range tmpMachOA.Slices {
		slice := &tmpMachOA.Slices[i]
		codeLimit := calculateCodeLimit(slice)

		signerOpts := buildSignerOptions(opts, infoPlistData, codeResourcesData)
		signerOpts.BundleID = bundleID
		signerOpts.TeamID = teamID
		signerOpts.EntitlementsXML = opts.EntitlementsXML
		signerOpts.EntitlementsDER = opts.EntitlementsDER
		signerOpts.SkipDEREntitlements = opts.SkipDEREntitlements
		execBase, execLimit, execFlags := getExecSegInfo(slice, isMainBinary)
		signerOpts.ExecSegBase = execBase
		signerOpts.ExecSegLimit = execLimit
		signerOpts.ExecSegFlags = execFlags

		sig, err := signerSign(tmpReaderA, slice.Offset, codeLimit, opts.Identity, signerOpts)
		if err != nil {
			return fmt.Errorf("pass A sign slice %d: %w", i, err)
		}
		discoverySizes[i] = uint32(len(sig))
	}

	// ===== PASS B: Write binary with CORRECT cs_size in header =====
	for i := range machO.Slices {
		slice := &machO.Slices[i]
		codeLimit := calculateCodeLimit(slice)
		// Now set the actual size — header will match final file layout
		machoSetCodeSig(slice, codeLimit, discoverySizes[i])
		updateLinkeditForSignature(slice, codeLimit, discoverySizes[i])
	}

	tmpPathB := path + ".gosigner_tmpB"
	if err := machoWriteToFile(tmpPathB, machO, nil); err != nil {
		return fmt.Errorf("pass B write: %w", err)
	}
	defer os.Remove(tmpPathB)

	tmpDataB, err := os.ReadFile(tmpPathB)
	if err != nil {
		return fmt.Errorf("pass B read: %w", err)
	}
	tmpReaderB := bytes.NewReader(tmpDataB)
	tmpMachOB, err := machoOpen(tmpReaderB, int64(len(tmpDataB)))
	if err != nil {
		return fmt.Errorf("pass B parse: %w", err)
	}

	// ===== PASS C: Hash the final binary layout, generate final signatures =====
	signatures := make([][]byte, len(tmpMachOB.Slices))
	for i := range tmpMachOB.Slices {
		slice := &tmpMachOB.Slices[i]
		codeLimit := calculateCodeLimit(slice)

		signerOpts := buildSignerOptions(opts, infoPlistData, codeResourcesData)
		signerOpts.BundleID = bundleID
		signerOpts.TeamID = teamID
		signerOpts.EntitlementsXML = opts.EntitlementsXML
		signerOpts.EntitlementsDER = opts.EntitlementsDER
		signerOpts.SkipDEREntitlements = opts.SkipDEREntitlements
		execBase, execLimit, execFlags := getExecSegInfo(slice, isMainBinary)
		signerOpts.ExecSegBase = execBase
		signerOpts.ExecSegLimit = execLimit
		signerOpts.ExecSegFlags = execFlags

		sig, err := signerSign(tmpReaderB, slice.Offset, codeLimit, opts.Identity, signerOpts)
		if err != nil {
			return fmt.Errorf("pass C sign slice %d: %w", i, err)
		}

		// Signature size MUST match what we predicted. If slightly smaller due to
		// random timestamp variations in CMS, pad with zeros. If larger, error.
		actualSize := uint32(len(sig))
		if actualSize > discoverySizes[i] {
			// Size mismatch — the signature structure changed unexpectedly.
			// Fall back to using actual size (header will be slightly stale but
			// generally safe because signatureSize doesn't affect code hashing).
			return fmt.Errorf("signature size grew: pass A=%d, pass C=%d", discoverySizes[i], actualSize)
		}
		if actualSize < discoverySizes[i] {
			// Pad with zeros to match predicted size so cs_size in header is correct
			padding := make([]byte, discoverySizes[i]-actualSize)
			sig = append(sig, padding...)
		}

		signatures[i] = sig
	}

	// Use tmpMachOB as the final machO (has correct headers)
	tmpMachO := tmpMachOB

	// PASS 3: Write the final binary with correct signatures
	return machoWriteToFile(path, tmpMachO, signatures)
}

// copyDir recursively copies a directory tree.
func copyDir(src string, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		destPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			return os.MkdirAll(destPath, 0755)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}

		perm := os.FileMode(0644)
		if info.Mode()&0111 != 0 {
			perm = 0755
		}

		return os.WriteFile(destPath, data, perm)
	})
}

func modifyDylibs(execPath string, opts *ResignOptions) error {
	data, err := os.ReadFile(execPath)
	if err != nil {
		return err
	}

	r := bytes.NewReader(data)
	machO, err := machoOpen(r, int64(len(data)))
	if err != nil {
		return err
	}

	for i := range machO.Slices {
		slice := &machO.Slices[i]

		// Remove dylibs
		if len(opts.RemoveDylibs) > 0 {
			machoRemoveDylibs(slice, opts.RemoveDylibs)
		}

		// Inject dylibs
		for _, dylib := range opts.InjectDylibs {
			machoInjectDylib(slice, dylib, opts.WeakInject)
		}
	}

	// Write modified binary without signatures (they'll be added during signing)
	return machoWriteToFile(execPath, machO, nil)
}
