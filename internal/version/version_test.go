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
// engine version. Engine() walks build info for the sfw dependency;
// when the test binary itself has no usable build info (the typical
// `go test` case) it must still return the fallback string rather
// than empty, so callers can print without a nil check.
func TestEngine_NeverEmpty(t *testing.T) {
	if got := Engine(); got == "" {
		t.Errorf("Engine() = %q; want non-empty (fallback or dep version)", got)
	}
}

// TestEngine_NotMainModule pins the regression behind v0.1.2: when
// debug.ReadBuildInfo's Main.Version differs from the sfw dep's
// version, Engine() must report the dep version, not Main. We can't
// stage a synthetic BuildInfo from a test (the runtime owns it), so
// the test only enforces that Engine() does NOT echo Build(); they
// might both be the (devel) fallback under `go test`, but if either
// reports a real version they must differ.
func TestEngine_NotMainModule(t *testing.T) {
	build := Build()
	engine := Engine()
	if build != fallback && engine != fallback && build == engine {
		t.Errorf("Engine() = Build() = %q; Engine must report the linked sfw dep, not the binary itself", engine)
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
