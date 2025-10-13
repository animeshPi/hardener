package policies

import (
	"context"
	"fmt"
	"runtime"
)

// Audit runs the check block for each policy and collects results.
func Audit(ctx context.Context, b *Bundle) ([]AuditResult, error) {
	results := make([]AuditResult, 0, len(b.Policies))

	for _, p := range b.Policies {
		r := AuditResult{
			PolicyID: p.ID,
			Title:    p.Title,
			Kind:     kindOf(p.Check),
			Status:   "skipped",
		}

		// Skip if OS mismatch
		if b.OS != "" && runtime.GOOS != "" {
			// Bundle is "windows" and runtime.GOOS is "windows" too in lowercase
			// Normalize: bundle uses "windows" in your example.
			if !osMatchesBundle(runtime.GOOS, b.OS) {
				r.Status = "skipped"
				r.Error = fmt.Sprintf("bundle OS=%q does not match runtime=%q", b.OS, runtime.GOOS)
				results = append(results, r)
				continue
			}
		}

		if p.Check == nil {
			r.Status = "skipped"
			r.Error = "no check block"
			results = append(results, r)
			continue
		}

		er := runScriptBlock(ctx, p.Check)
		r.Raw = er.Stdout
		r.Stderr = er.Stderr

		if er.Err != nil || er.ExitCode != 0 {
			r.Status = "error"
			if er.Err != nil {
				r.Error = er.Err.Error()
			} else {
				r.Error = fmt.Sprintf("non-zero exit code: %d", er.ExitCode)
			}
			results = append(results, r)
			continue
		}

		// Try parse JSON
		if parsed, err := TryParseJSON(r.Raw); err == nil {
			r.Parsed = parsed
			// If compliant present and bool, set status accordingly
			if v, ok := parsed["compliant"]; ok {
				if b, ok := v.(bool); ok {
					r.Compliant = &b
					if b {
						r.Status = "ok"
					} else {
						r.Status = "noncompliant"
					}
				} else {
					r.Status = "ok"
				}
			} else {
				r.Status = "ok"
			}
		} else {
			// Not JSON; still consider ok if script succeeded
			r.Status = "ok"
		}

		results = append(results, r)
	}

	return results, nil
}

// Snapshot runs the snapshot block for each policy and collects results.
func Snapshot(ctx context.Context, b *Bundle) ([]SnapshotResult, error) {
	results := make([]SnapshotResult, 0, len(b.Policies))

	for _, p := range b.Policies {
		r := SnapshotResult{
			PolicyID: p.ID,
			Title:    p.Title,
			Kind:     kindOf(p.Snapshot),
		}

		// Skip if OS mismatch
		if b.OS != "" && runtime.GOOS != "" {
			if !osMatchesBundle(runtime.GOOS, b.OS) {
				r.Error = fmt.Sprintf("bundle OS=%q does not match runtime=%q", b.OS, runtime.GOOS)
				results = append(results, r)
				continue
			}
		}

		if p.Snapshot == nil {
			r.Error = "no snapshot block"
			results = append(results, r)
			continue
		}

		er := runScriptBlock(ctx, p.Snapshot)
		r.Raw = er.Stdout
		r.Stderr = er.Stderr

		if er.Err != nil || er.ExitCode != 0 {
			if er.Err != nil {
				r.Error = er.Err.Error()
			} else {
				r.Error = fmt.Sprintf("non-zero exit code: %d", er.ExitCode)
			}
			results = append(results, r)
			continue
		}

		// Try parse JSON
		if parsed, err := TryParseJSON(r.Raw); err == nil {
			r.Parsed = parsed
		}
		results = append(results, r)
	}

	return results, nil
}

func kindOf(b *ScriptBlock) string {
	if b == nil {
		return ""
	}
	return b.Kind
}

func osMatchesBundle(runtimeGOOS, bundleOS string) bool {
	// Normalize "windows" -> "windows", "darwin"->"macos" if ever needed.
	// For now, simple case-insensitive compare for "windows".
	switch bundleOS {
	case "windows", "Windows", "WINDOWS":
		return runtimeGOOS == "windows"
	default:
		// If unspecified or unknown, allow
		return true
	}
}
