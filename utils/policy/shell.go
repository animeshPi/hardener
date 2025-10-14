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
	case "bash", "shell", "sh": //maybe add zsh
		return runBash(parentCtx, block.Script, block.Timeout)
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

	// Write script to a temp file
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

	cmd := exec.CommandContext(
		ctx,
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-File", tmp.Name(),
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	runErr := cmd.Run()
	exitCode := 0
	if ee, ok := runErr.(*exec.ExitError); ok {
		exitCode = ee.ExitCode()
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

func runBash(parentCtx context.Context, script string, timeoutSec int) execResult {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		// Allow macOS for development; bundle OS gating will still skip non-Linux runs.
		// If you want to hard-fail on non-Linux, change this to linux only.
	}

	if timeoutSec <= 0 {
		timeoutSec = defaultTimeoutSec
	}
	ctx, cancel := context.WithTimeout(parentCtx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	tmp, err := os.CreateTemp("", "policy-*.sh")
	if err != nil {
		return execResult{Err: fmt.Errorf("create temp script: %w", err)}
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(script); err != nil {
		tmp.Close()
		return execResult{Err: fmt.Errorf("write temp script: %w", err)}
	}
	_ = tmp.Close()

	cmd := exec.CommandContext(
		ctx,
		"/bin/bash",
		"-o", "pipefail",
		tmp.Name(),
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	runErr := cmd.Run()
	exitCode := 0
	if ee, ok := runErr.(*exec.ExitError); ok {
		exitCode = ee.ExitCode()
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
