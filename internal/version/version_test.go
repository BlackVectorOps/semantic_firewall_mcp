package version

import (
	"strings"
	"testing"
)

// TestBuild_NeverEmpty pins the invariant that callers can always
// print the result without a nil/empty check. Under `go test` the
// module version is empty so we expect the "(devel)" fallback; under
// `go install ...@vX` the same code returns the tag. The test
// validates only the "never empty" guarantee, not the specific
// value, because that depends on how the binary was built.
func TestBuild_NeverEmpty(t *testing.T) {
	if got := Build(); got == "" {
		t.Errorf("Build() = %q; want a non-empty string (fallback or tag)", got)
	}
}

// TestEngine_NeverEmpty mirrors Build's invariant for the linked sfw
// engine version. semantic_firewall/pkg/version.EngineVersion always
// returns a non-empty string in the same shape ("<version> (<flags>)").
func TestEngine_NeverEmpty(t *testing.T) {
	got := Engine()
	if got == "" {
		t.Fatal("Engine() returned empty string")
	}
	if !strings.Contains(got, "(") || !strings.Contains(got, ")") {
		t.Errorf("Engine() = %q; expected feature-flag suffix in parentheses", got)
	}
}

// TestString_IncludesBothVersions ensures the public-facing format
// surfaces the binary build AND the engine library version. Under
// `go test` both will be (devel) / (devel)+flags but the labels
// "Build:" and "Engine:" must still appear so the format is stable
// for log scrapers.
func TestString_IncludesBothVersions(t *testing.T) {
	got := String()
	for _, want := range []string{"Semantic Firewall MCP", "Build:", "Engine:"} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q; want to contain %q", got, want)
		}
	}
}
