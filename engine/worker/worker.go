package worker

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/AzozzALFiras/GoSigner/certificate/loader"
	"github.com/AzozzALFiras/GoSigner/engine/cleanup"
	"github.com/AzozzALFiras/GoSigner/engine/downloader"
	"github.com/AzozzALFiras/GoSigner/engine/installplist"
	"github.com/AzozzALFiras/GoSigner/engine/jsoninput"
	"github.com/AzozzALFiras/GoSigner/ipa/pipeline"
	plTypes "github.com/AzozzALFiras/GoSigner/plist"
	"github.com/AzozzALFiras/GoSigner/plist/infoplist"
	"github.com/AzozzALFiras/GoSigner/provision/entitlements"
	"github.com/AzozzALFiras/GoSigner/provision/parser"
)

// Run processes all app signing requests concurrently.
func Run(req *jsoninput.Request) *jsoninput.Response {
	resp := &jsoninput.Response{
		Results: make([]jsoninput.AppResult, len(req.Apps)),
	}

	if len(req.Apps) == 0 {
		resp.Success = true
		return resp
	}

	maxWorkers := runtime.NumCPU()
	if maxWorkers > len(req.Apps) {
		maxWorkers = len(req.Apps)
	}
	if maxWorkers < 1 {
		maxWorkers = 1
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxWorkers)

	for i := range req.Apps {
		wg.Add(1)
		go func(idx int, app jsoninput.AppRequest) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			resp.Results[idx] = processApp(app)
		}(i, req.Apps[i])
	}

	wg.Wait()

	allSuccess := true
	for _, r := range resp.Results {
		if !r.Success {
			allSuccess = false
			resp.Errors = append(resp.Errors, r.Error)
		}
	}
	resp.Success = allSuccess
	return resp
}

func processApp(app jsoninput.AppRequest) jsoninput.AppResult {
	start := time.Now()
	cleaner := cleanup.New()
	defer cleaner.Run()

	result := jsoninput.AppResult{
		IPA:      app.IPA,
		Name:     app.Name,
		BundleID: app.BundleID,
	}

	done := func() jsoninput.AppResult {
		result.Duration = time.Since(start).Round(time.Millisecond).String()
		runtime.GC()
		return result
	}

	// --- Step 1: Resolve IPA (download if URL) ---
	ipaPath := app.IPA
	if downloader.IsURL(ipaPath) {
		log.Printf("[worker] Downloading IPA: %s", ipaPath)
		localPath, err := downloader.DownloadToTemp(ipaPath)
		if err != nil {
			result.Error = fmt.Sprintf("download ipa: %v", err)
			return done()
		}
		ipaPath = localPath
		cleaner.Track(localPath)
	}

	if _, err := os.Stat(ipaPath); os.IsNotExist(err) {
		result.Error = fmt.Sprintf("ipa not found: %s", ipaPath)
		return done()
	}

	// --- Step 2: Generate shared random ID for IPA + plist ---
	randomID := downloader.RandomFilename("")
	// Remove the empty extension dot
	randomID = strings.TrimSuffix(randomID, ".")
	if randomID == "" {
		randomID = downloader.RandomFilename("x")
		randomID = strings.TrimSuffix(randomID, ".x")
	}

	ipaFileName := randomID + ".ipa"
	plistFileName := randomID + ".plist"

	// --- Step 3: Prepare output directories ---
	outputDir := app.Output
	if outputDir == "" {
		outputDir = os.TempDir()
	}
	os.MkdirAll(outputDir, 0755)
	outputPath := filepath.Join(outputDir, ipaFileName)

	plistOutputDir := app.PlistOutput
	if plistOutputDir == "" {
		plistOutputDir = outputDir
	}
	os.MkdirAll(plistOutputDir, 0755)

	// --- Step 4: Load certificate ---
	if app.Cert == "" {
		result.Error = "cert is required"
		return done()
	}
	identity, err := loader.LoadP12(app.Cert, app.CertPassword)
	if err != nil {
		result.Error = fmt.Sprintf("load certificate: %v", err)
		return done()
	}
	log.Printf("[worker] Certificate: %s (Team: %s)", identity.SubjectCN, identity.TeamID)

	// --- Step 5: Build resign options ---
	opts := &pipeline.ResignOptions{
		InputPath:    ipaPath,
		OutputPath:   outputPath,
		Identity:     identity,
		BundleID:     app.BundleID,
		BundleName:   app.Name,
		ZipLevel:     1,
		StripProfile: app.RemoveProfile,
	}

	// --- Step 6: Load provisioning profile ---
	if app.Profile != "" {
		profile, err := parser.ParseFile(app.Profile)
		if err != nil {
			result.Error = fmt.Sprintf("load profile: %v", err)
			return done()
		}
		opts.Profile = profile
		log.Printf("[worker] Profile: %s (Team: %s)", profile.Name, profile.GetTeamID())

		xmlEnts, err := entitlements.Extract(profile)
		if err == nil {
			opts.EntitlementsXML = xmlEnts
		}
	}

	// --- Step 7: Prepare dylibs ---
	var dylibPaths []string
	var bundlePaths []string
	for _, d := range app.Dylibs {
		if d.FullDylib != "" {
			dylibPaths = append(dylibPaths, d.FullDylib)
		}
		if d.FullBundle != "" {
			bundlePaths = append(bundlePaths, d.FullBundle)
		}
	}
	opts.InjectDylibs = dylibPaths
	opts.BundlePaths = bundlePaths

	// --- Step 8: Sign! ---
	log.Printf("[worker] Signing: %s → %s", ipaPath, outputPath)
	if err := pipeline.Resign(opts); err != nil {
		result.Error = fmt.Sprintf("sign failed: %v", err)
		return done()
	}

	result.OutputIPA = outputPath
	result.Success = true

	// --- Step 9: Read final bundle ID and name from signed IPA ---
	if finalInfo := readSignedAppInfo(outputPath); finalInfo != nil {
		if result.BundleID == "" {
			result.BundleID = finalInfo.BundleID
		}
		if result.Name == "" {
			result.Name = finalInfo.BundleName
			if result.Name == "" {
				result.Name = finalInfo.BundleDisplayName
			}
		}
	}

	// --- Step 10: Generate install plist ---
	if app.CreatePlist {
		// Build the full IPA URL: base_url + filename
		ipaURL := app.IPABaseURL + ipaFileName

		version := "1.0"
		if v := getAppVersion(ipaPath); v != "" {
			version = v
		}

		// Use final values for plist
		plistBundleID := result.BundleID
		plistName := result.Name
		if plistBundleID == "" {
			plistBundleID = app.BundleID
		}
		if plistName == "" {
			plistName = app.Name
		}

		plistOpts := &installplist.Options{
			IPAURL:    ipaURL,
			IconURL:   app.URLIcon,
			BundleID:  plistBundleID,
			AppName:   plistName,
			Version:   version,
			PlistName: plistFileName,
		}

		plistPath, err := installplist.Generate(plistOpts, plistOutputDir)
		if err != nil {
			log.Printf("[worker] Warning: plist generation failed: %v", err)
		} else {
			result.OutputPlist = plistPath
			// Build plist URL: base_url + filename
			if app.PlistBaseURL != "" {
				result.PlistURL = app.PlistBaseURL + plistFileName
			}
			log.Printf("[worker] Plist: %s", plistPath)
		}
	}

	log.Printf("[worker] Done: %s (took %s)", outputPath, time.Since(start).Round(time.Millisecond))
	return done()
}

// readSignedAppInfo reads Info.plist from a signed IPA to get the final bundle ID and name.
func readSignedAppInfo(ipaPath string) *plTypes.InfoPlistData {
	ipaReader, err := ipaArchiveOpen(ipaPath)
	if err != nil {
		return nil
	}
	defer ipaReader.Close()

	for _, f := range ipaReader.Files() {
		name := f.Name
		if filepath.Base(name) == "Info.plist" && strings.HasPrefix(name, "Payload/") && strings.Count(name, "/") == 2 {
			data, err := ipaReader.ReadFile(name)
			if err != nil {
				return nil
			}
			info, err := infoplist.ReadFromBytes(data)
			if err != nil {
				return nil
			}
			return info
		}
	}
	return nil
}

func getAppVersion(ipaPath string) string {
	ipaReader, err := ipaArchiveOpen(ipaPath)
	if err != nil {
		return ""
	}
	defer ipaReader.Close()

	for _, f := range ipaReader.Files() {
		if filepath.Base(f.Name) == "Info.plist" && strings.HasPrefix(f.Name, "Payload/") && strings.Count(f.Name, "/") == 2 {
			data, err := ipaReader.ReadFile(f.Name)
			if err != nil {
				return ""
			}
			info, err := infoplist.ReadFromBytes(data)
			if err != nil {
				return ""
			}
			if info.ShortVersion != "" {
				return info.ShortVersion
			}
			return info.BundleVersion
		}
	}
	return ""
}
