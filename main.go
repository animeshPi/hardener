package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/animeshPi/hardener/utils"
	"github.com/animeshPi/hardener/utils/admin"
	policies "github.com/animeshPi/hardener/utils/policy"
)

func EnsureElevatedOrRelaunch() error {
	elevated, err := admin.IsElevated()
	if err != nil {
		return err
	}
	if elevated {
		return nil
	}
	if err := admin.RequestElevation(); err != nil {
		return err
	}
	// If elevation was successfully requested, the elevated copy should take over.
	// Exit this instance to avoid duplicate runs.
	os.Exit(0)
	return nil
}

func main() {
	if err := EnsureElevatedOrRelaunch(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to obtain elevated privileges: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Running with elevated privileges.")
	fmt.Println(utils.DetectOS())

	// Load policy bundle
	var policiesPath string
	if utils.DetectOS() == "windows" {
		policiesPath = "policies/windows_policies.yaml"
	} else if utils.DetectOS() == "ubuntu" || utils.DetectOS() == "centos" {
		policiesPath = "policies/linux_policies.yaml"
		if _, err := os.Stat(policiesPath); os.IsNotExist(err) {
			log.Fatalf("Error: Policy file not found for Linux at %s\n", policiesPath)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Unsupported OS: %s\n", utils.DetectOS())
		os.Exit(1)
	}
	bundle, err := policies.LoadBundle(policiesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load policies: %v\n", err)
		os.Exit(1)
	}

	// Context for audit/snapshot
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// 1) AUDIT
	auditResults, err := policies.Audit(ctx, bundle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Audit error: %v\n", err)
		os.Exit(1)
	}
	for _, r := range auditResults {
		cur, exp, det := extractDetails(r.Parsed)
		fmt.Printf("[AUDIT] %s (%s): status=%s compliant=%v current=%s expected=%s details=%s err=%s\n",
			r.PolicyID, r.Title, r.Status, valueOrNil(r.Compliant), cur, exp, det, safeStr(r.Error))
	}

	// 2) SNAPSHOT (print and save to file)
	snapResults, err := policies.Snapshot(ctx, bundle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Snapshot error: %v\n", err)
		os.Exit(1)
	}
	for _, r := range snapResults {
		fmt.Printf("[SNAPSHOT] %s (%s): err=%s\n", r.PolicyID, r.Title, safeStr(r.Error))
	}

	// Write snapshot results to file with timestamped name
	snapshotDir := "snapshots"

	// Ensure the snapshots directory exists
	if err := os.MkdirAll(snapshotDir, os.ModePerm); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create snapshot directory: %v\n", err)
		os.Exit(1)
	}

	// Build the output file path
	snapshotOut := filepath.Join(snapshotDir, "snapshot-"+time.Now().Format("20060102-150405")+".json")

	// Write the snapshot JSON
	if err := writeJSON(snapshotOut, snapResults); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write snapshot file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Snapshot written to %s\n", snapshotOut)

	// Pause on Windows (optional interactive behavior)
	// if os := runtime.GOOS; os == "windows" {
	// 	fmt.Println("Press Enter to exit...")
	// 	fmt.Scanln()
	// }
}

func valueOrNil(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

func extractDetails(parsed map[string]any) (current, expected, details string) {
	if parsed == nil {
		return "", "", ""
	}
	if v, ok := parsed["current"]; ok {
		current = fmt.Sprintf("%v", v)
	}
	if v, ok := parsed["expected"]; ok {
		expected = fmt.Sprintf("%v", v)
	}
	if v, ok := parsed["details"]; ok {
		details = fmt.Sprintf("%v", v)
	}
	return
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func safeStr(s string) string {
	if s == "" {
		return ""
	}
	return s
}
