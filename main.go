package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/animeshPi/hardener/utils"
	"github.com/animeshPi/hardener/utils/admin"
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
	// ... your privileged logic here ...
	fmt.Println(utils.DetectOS())
	// Use Go's runtime package to check for Windows OS
	if os := runtime.GOOS; os == "windows" {
		fmt.Println("Press Enter to exit...")
		fmt.Scanln()
	}
}
