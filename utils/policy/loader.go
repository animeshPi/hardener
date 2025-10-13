package policies

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadBundle loads a YAML bundle from filePath.
func LoadBundle(filePath string) (*Bundle, error) {
	bs, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read bundle: %w", err)
	}
	var b Bundle
	if err := yaml.Unmarshal(bs, &b); err != nil {
		return nil, fmt.Errorf("parse bundle yaml: %w", err)
	}
	return &b, nil
}
