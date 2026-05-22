// Package version resolves the sfw-mcp binary version at runtime from
// the embedded Go build info. `go install ...@v0.1.2` populates
// debug.ReadBuildInfo().Main.Version with the tag; a local `go run`
// or `go build` without a tag leaves it as "(devel)".
//
// The implementation mirrors semantic_firewall/pkg/version so a
// downstream user looking at either binary's `version` output sees
// the same shape.
package version

import (
	"fmt"
	"runtime/debug"

	sfw "github.com/BlackVectorOps/semantic_firewall/v4/pkg/version"
)

// fallback is the version string returned when build info is
// unavailable or carries no module version. Matches the sfw engine's
// fallback for consistency.
const fallback = "(devel)"

// Build returns the version of the sfw-mcp binary itself.
func Build() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return fallback
}

// Engine returns the version of the semantic_firewall engine library
// linked into this binary, including its feature-flag suffix. Useful
// in audit logs so an operator can correlate a verdict with both the
// agent (sfw-mcp) and the underlying analysis library (sfw).
func Engine() string {
	return sfw.EngineVersion()
}

// String formats both versions for the `sfw-mcp version` subcommand.
// The two-line layout is chosen to match v3's `sfw version` output so
// muscle memory carries over.
func String() string {
	return fmt.Sprintf("Semantic Firewall MCP\nBuild: %s\nEngine: %s", Build(), Engine())
}
