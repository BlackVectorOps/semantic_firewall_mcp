// Package version resolves the sfw-mcp binary version and its linked
// semantic_firewall engine version at runtime from the embedded Go
// build info. `go install ...@v0.1.2` populates
// debug.ReadBuildInfo().Main.Version with the binary's own tag and
// debug.ReadBuildInfo().Deps with the resolved dependency versions;
// a local `go run` or `go build` without a tag leaves both as
// "(devel)".
package version

import (
	"fmt"
	"runtime/debug"
)

// fallback is the version string returned when build info is
// unavailable or carries no usable module version. Matches the sfw
// engine's fallback for consistency across `sfw version` and
// `sfw-mcp version` output.
const fallback = "(devel)"

// enginePath is the canonical import path of the semantic_firewall
// engine library. Walking info.Deps for this path is the only
// reliable way to get the dep's version when sfw-mcp -- not sfw --
// is the main module being executed.
const enginePath = "github.com/BlackVectorOps/semantic_firewall/v4"

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
// linked into this binary. We deliberately do NOT call
// sfw/pkg/version.EngineVersion here: that helper reports
// info.Main.Version, which is the sfw-mcp tag whenever sfw-mcp is
// the main module -- giving downstream operators a misleading
// "Engine: <mcp-tag>" reading. Walking info.Deps for the engine path
// returns the real linked dependency.
func Engine() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep == nil {
				continue
			}
			if dep.Path == enginePath {
				if dep.Version != "" {
					return dep.Version
				}
				break
			}
		}
	}
	return fallback
}

// String formats both versions for the `sfw-mcp version` subcommand.
// The two-line layout is chosen to match v3's `sfw version` output
// so muscle memory carries over.
func String() string {
	return fmt.Sprintf("Semantic Firewall MCP\nBuild: %s\nEngine: %s", Build(), Engine())
}
