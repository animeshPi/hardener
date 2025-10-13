//go:build windows

package admin

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func IsElevated() (bool, error) {
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false, fmt.Errorf("CreateWellKnownSid: %w", err)
	}
	token := windows.GetCurrentProcessToken()
	isMember, err := token.IsMember(adminSID)
	if err != nil {
		return false, fmt.Errorf("Token.IsMember: %w", err)
	}
	return isMember, nil
}

var (
	modShell32        = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteW = modShell32.NewProc("ShellExecuteW")
)

func RequestElevation() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("os.Executable: %w", err)
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return fmt.Errorf("filepath.Abs: %w", err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("os.Getwd: %w", err)
	}

	params := joinWindowsCmdArgs(os.Args[1:])

	verb := syscall.StringToUTF16Ptr("runas")
	exeW := syscall.StringToUTF16Ptr(exe)
	paramsW := syscall.StringToUTF16Ptr(params)
	cwdW := syscall.StringToUTF16Ptr(cwd)

	r, _, callErr := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(exeW)),
		uintptr(unsafe.Pointer(paramsW)),
		uintptr(unsafe.Pointer(cwdW)),
		uintptr(1), // SW_SHOWNORMAL
	)
	if r <= 32 {
		return fmt.Errorf("ShellExecuteW failed, code=%d, err=%v", r, callErr)
	}
	return nil
}

func joinWindowsCmdArgs(args []string) string {
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

func init() {
	_ = runtime.Version()
}
