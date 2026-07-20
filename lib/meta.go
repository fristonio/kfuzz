package lib

import (
	"encoding/json"
	"fmt"
)

type FuzzScope string

// Next returns the next scope based on the provided name.
func (s FuzzScope) Next(name string) FuzzScope {
	if s == "" {
		return FuzzScope(name)
	}
	return FuzzScope(fmt.Sprintf("%s.%s", s, name))
}

type RawConfig = json.RawMessage
type StructConfig map[string]RawConfig

type FuzzMeta struct {
	Scope  FuzzScope
	Config RawConfig
}
