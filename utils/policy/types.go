package policies

import (
	"encoding/json"
)

// Bundle represents the top-level YAML document with OS + policies
type Bundle struct {
	OS       string   `yaml:"os" json:"os"`
	Policies []Policy `yaml:"policies" json:"policies"`
}

// ScriptBlock represents a check/snapshot/remediate/rollback block
type ScriptBlock struct {
	Kind    string `yaml:"kind" json:"kind"`
	Timeout int    `yaml:"timeout,omitempty" json:"timeout,omitempty"` // seconds
	Script  string `yaml:"script" json:"script"`
}

// Policy represents a single security policy
type Policy struct {
	ID          string   `yaml:"id" json:"id"`
	Title       string   `yaml:"title" json:"title"`
	Category    string   `yaml:"category" json:"category"`
	Subcategory string   `yaml:"subcategory" json:"subcategory"`
	Severity    string   `yaml:"severity" json:"severity"`
	Levels      []string `yaml:"levels" json:"levels"`
	Tags        []string `yaml:"tags" json:"tags"`

	Check     *ScriptBlock `yaml:"check" json:"check"`
	Snapshot  *ScriptBlock `yaml:"snapshot" json:"snapshot"`
	Remediate *ScriptBlock `yaml:"remediate" json:"remediate"`
	Rollback  *ScriptBlock `yaml:"rollback" json:"rollback"`
}

// AuditResult captures the result of running a policy's check script
type AuditResult struct {
	PolicyID  string         `json:"policy_id"`
	Title     string         `json:"title"`
	Kind      string         `json:"kind"`
	Status    string         `json:"status"` // ok | noncompliant | error | skipped
	Compliant *bool          `json:"compliant,omitempty"`
	Raw       string         `json:"raw"` // raw stdout from the script
	Parsed    map[string]any `json:"parsed,omitempty"`
	Stderr    string         `json:"stderr,omitempty"`
	Error     string         `json:"error,omitempty"`
}

// SnapshotResult captures the result of running a policy's snapshot script
type SnapshotResult struct {
	PolicyID string         `json:"policy_id"`
	Title    string         `json:"title"`
	Kind     string         `json:"kind"`
	Raw      string         `json:"raw"` // raw stdout from the script
	Parsed   map[string]any `json:"parsed,omitempty"`
	Stderr   string         `json:"stderr,omitempty"`
	Error    string         `json:"error,omitempty"`
}

// TryParseJSON tries to unmarshal stdout as JSON into map[string]any
func TryParseJSON(stdout string) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(stdout), &m); err != nil {
		return nil, err
	}
	return m, nil
}
