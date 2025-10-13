package utils

import (
	"bufio"
	"os"
	"runtime"
	"strings"
)

// DetectOS returns "windows", "ubuntu", "centos", or "unknown".
func DetectOS() string {
	goos := runtime.GOOS
	if goos == "windows" {
		return "windows"
	}
	if goos == "linux" {
		id := getLinuxID()
		switch id {
		case "ubuntu":
			return "ubuntu"
		case "centos":
			return "centos"
		default:
			return "unknown"
		}
	}
	// Treat everything else (darwin, freebsd, etc) as unknown
	return "unknown"
}

// getLinuxID reads /etc/os-release and returns the value of ID in lowercase.
func getLinuxID() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ID=") {
			id := strings.TrimPrefix(line, "ID=")
			id = strings.Trim(id, "\"")
			id = strings.ToLower(id)
			return id
		}
	}
	return ""
}
