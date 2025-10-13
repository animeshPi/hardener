package policies

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// defaultTimeoutSec used when a script block doesn't specify a timeout
const defaultTimeoutSec = 60

type execResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

// runScriptBlock executes the provided script block and returns stdout/stderr.
func runScriptBlock(parentCtx context.Context, block *ScriptBlock) execResult {
	if block == nil {
		return execResult{Err: errors.New("no script block provided")}
	}

	switch block.Kind {
	case "powershell":
		return runPowerShell(parentCtx, block.Script, block.Timeout)
	default:
		return execResult{Err: fmt.Errorf("unsupported script kind: %s", block.Kind)}
	}
}

func runPowerShell(parentCtx context.Context, script string, timeoutSec int) execResult {
	if runtime.GOOS != "windows" {
		return execResult{Err: errors.New("powershell execution requires Windows")}
	}

	// Resolve timeout
	if timeoutSec <= 0 {
		timeoutSec = defaultTimeoutSec
	}
	ctx, cancel := context.WithTimeout(parentCtx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	// Write script to a temp .ps1 file to avoid quoting/escaping issues.
	tmp, err := os.CreateTemp("", "policy-*.ps1")
	if err != nil {
		return execResult{Err: fmt.Errorf("create temp script: %w", err)}
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString(script); err != nil {
		tmp.Close()
		return execResult{Err: fmt.Errorf("write temp script: %w", err)}
	}
	_ = tmp.Close()

	// Execute PowerShell script
	// Using -File <temp.ps1> avoids quoting issues with -Command.
	cmd := exec.CommandContext(
		ctx,
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-File", tmp.Name(),
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	exitCode := 0
	if ee, ok := runErr.(*exec.ExitError); ok {
		exitCode = ee.ExitCode()
	} else if runErr == context.DeadlineExceeded || errors.Is(runErr, context.DeadlineExceeded) {
		exitCode = -1
	} else if runErr != nil {
		exitCode = -1
	}

	return execResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Err:      runErr,
	}
}
