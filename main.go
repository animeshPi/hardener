package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
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

func valueOrNil(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

func main() {
	if err := EnsureElevatedOrRelaunch(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to obtain elevated privileges: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Running with elevated privileges.")
	// ... your privileged logic here ...
	fmt.Println(utils.DetectOS())

	// Load policies and perform audit + snapshot
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	bundle, err := policies.LoadBundle("policies/windows.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load policies: %v\n", err)
		os.Exit(1)
	}

	auditResults, err := policies.Audit(ctx, bundle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Audit error: %v\n", err)
		os.Exit(1)
	}
	for _, r := range auditResults {
		fmt.Printf("[AUDIT] %s (%s): status=%s compliant=%v err=%s\n", r.PolicyID, r.Title, r.Status, valueOrNil(r.Compliant), r.Error)
	}

	snapshotResults, err := policies.Snapshot(ctx, bundle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Snapshot error: %v\n", err)
		os.Exit(1)
	}
	for _, r := range snapshotResults {
		fmt.Printf("[SNAPSHOT] %s (%s): err=%s\n", r.PolicyID, r.Title, r.Error)
	}

	// Use Go's runtime package to check for Windows OS
	if os := runtime.GOOS; os == "windows" {
		fmt.Println("Press Enter to exit...")
		fmt.Scanln()
	}
}
