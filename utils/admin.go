package utils

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var ErrAlreadyElevated = errors.New("already elevated")

// IsElevated reports whether the current process has administrative/root privileges.
func IsElevated() (bool, error) {
	if runtime.GOOS != "windows" {
		return os.Geteuid() == 0, nil
	}
	return isElevatedWindows()
}

// RequestElevation launches a new elevated instance of the current executable (non-waiting on Windows).
// If already elevated it returns ErrAlreadyElevated.
// On success, your caller should normally exit the current (non-elevated) process.
func RequestElevation() error {
	return RequestElevationWait(false)
}

// RequestElevationWait is like RequestElevation but can optionally wait for the elevated child.
// wait only changes behavior on Windows; on Unix the call always waits anyway.
func RequestElevationWait(wait bool) error {
	elev, err := IsElevated()
	if err != nil {
		return fmt.Errorf("IsElevated: %w", err)
	}
	if elev {
		return ErrAlreadyElevated
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("os.Executable: %w", err)
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return fmt.Errorf("filepath.Abs: %w", err)
	}

	if runtime.GOOS != "windows" {
		// Prefer pkexec; fallback to sudo.
		if hasCommand("pkexec") {
			cmd := exec.Command("pkexec", append([]string{exe}, os.Args[1:]...)...)
			cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
			return cmd.Run()
		}
		if hasCommand("sudo") {
			cmd := exec.Command("sudo", append([]string{exe}, os.Args[1:]...)...)
			cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
			return cmd.Run()
		}
		return errors.New("neither pkexec nor sudo is available to request elevation")
	}

	// Windows path.
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("os.Getwd: %w", err)
	}

	args := os.Args[1:]
	var argListJoined string
	if len(args) > 0 {
		argListJoined = joinWindowsCmdArgs(args)
	}

	psQuote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

	var b strings.Builder
	b.WriteString("Start-Process -FilePath ")
	b.WriteString(psQuote(exe))
	if len(argListJoined) > 0 {
		b.WriteString(" -ArgumentList ")
		b.WriteString(psQuote(argListJoined))
	}
	b.WriteString(" -WorkingDirectory ")
	b.WriteString(psQuote(cwd))
	b.WriteString(" -Verb RunAs")
	if wait {
		// -Wait returns after child exits; then exit with child's code.
		b.WriteString(" -Wait; exit $LASTEXITCODE")
	}

	psCmd := b.String()

	cmd := exec.Command("powershell.exe",
		"-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psCmd)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	return cmd.Run()
}

// Helper: presence of an executable in PATH.
func hasCommand(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// Windows elevation detection using commands that require admin.
func isElevatedWindows() (bool, error) {
	// Try fltmc (common & requires elevation).
	if hasCommand("fltmc") {
		if err := exec.Command("fltmc").Run(); err == nil {
			return true, nil
		} else if _, ok := err.(*exec.ExitError); ok {
			return false, nil
		}
	}
	// Fallback: "net session" also requires elevation.
	if hasCommand("net") {
		if err := exec.Command("net", "session").Run(); err == nil {
			return true, nil
		} else if _, ok := err.(*exec.ExitError); ok {
			return false, nil
		}
	}
	return false, errors.New("unable to determine elevation (probing commands unavailable)")
}

// Windows command-line argument quoting.
func joinWindowsCmdArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = quoteWindowsArg(a)
	}
	return strings.Join(quoted, " ")
}

func needsQuotingWindows(s string) bool {
	if s == "" {
		return true
	}
	return strings.ContainsAny(s, " \t\"")
}

func quoteWindowsArg(s string) string {
	if !needsQuotingWindows(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	backslashes := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' {
			backslashes++
			continue
		}
		if c == '"' {
			b.WriteString(strings.Repeat("\\", backslashes*2))
			backslashes = 0
			b.WriteString("\\\"")
			continue
		}
		if backslashes > 0 {
			b.WriteString(strings.Repeat("\\", backslashes))
			backslashes = 0
		}
		b.WriteByte(c)
	}
	if backslashes > 0 {
		b.WriteString(strings.Repeat("\\", backslashes*2))
	}
	b.WriteByte('"')
	return b.String()
}
