//go:build !windows

package admin

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func IsElevated() (bool, error) {
	// On Unix-like systems, effective UID 0 == root
	return os.Geteuid() == 0, nil
}

func RequestElevation() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("os.Executable: %w", err)
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return fmt.Errorf("filepath.Abs: %w", err)
	}

	// Prefer pkexec (Polkit) for GUI environments; fall back to sudo.
	if hasCommand("pkexec") {
		cmd := exec.Command("pkexec", append([]string{exe}, os.Args[1:]...)...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	if hasCommand("sudo") {
		cmd := exec.Command("sudo", append([]string{exe}, os.Args[1:]...)...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	return errors.New("neither pkexec nor sudo is available to request elevation")
}

func hasCommand(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
