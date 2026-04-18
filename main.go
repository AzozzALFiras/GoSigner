package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/AzozzALFiras/GoSigner/cli"
	"github.com/AzozzALFiras/GoSigner/engine/jsoninput"
	"github.com/AzozzALFiras/GoSigner/engine/worker"
)

func main() {
	log.SetFlags(log.Ltime)

	// Check for --data='JSON' mode first (primary mode)
	dataJSON := extractDataFlag(os.Args)

	if dataJSON != "" {
		runJSONMode(dataJSON)
		return
	}

	// Fallback to CLI subcommand mode
	cmd := cli.NewRootCommand()
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// extractDataFlag finds --data='{...}' or --data '{...}' in args.
func extractDataFlag(args []string) string {
	for i, arg := range args {
		// --data='...' or --data="..."
		if strings.HasPrefix(arg, "--data=") {
			return strings.TrimPrefix(arg, "--data=")
		}
		// --data '...'
		if arg == "--data" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// runJSONMode processes the JSON input and outputs JSON result.
func runJSONMode(rawJSON string) {
	var req jsoninput.Request
	if err := json.Unmarshal([]byte(rawJSON), &req); err != nil {
		outputError(fmt.Sprintf("invalid JSON input: %v", err))
		return
	}

	if len(req.Apps) == 0 {
		outputError("no apps specified in JSON input")
		return
	}

	log.Printf("[GoSigner] Processing %d app(s) concurrently...", len(req.Apps))

	resp := worker.Run(&req)

	// Output JSON result to stdout
	out, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		outputError(fmt.Sprintf("marshal response: %v", err))
		return
	}

	fmt.Println(string(out))

	if !resp.Success {
		os.Exit(1)
	}
}

func outputError(msg string) {
	resp := jsoninput.Response{
		Success: false,
		Errors:  []string{msg},
	}
	out, _ := json.MarshalIndent(resp, "", "  ")
	fmt.Println(string(out))
	os.Exit(1)
}
