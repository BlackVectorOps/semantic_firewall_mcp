package risk

import (
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/models"
)

// TestClassify_PrecedenceRules pins the verdict precedence so the
// MIT/paid product line cannot drift without tripping a test.
// SignatureMatch must strictly dominate Escalation when both fire.
func TestClassify_PrecedenceRules(t *testing.T) {
	cases := []struct {
		name string
		in   Evidence
		want Verdict
	}{
		{"empty", Evidence{}, VerdictClean},
		{
			"high-risk only",
			Evidence{HighRiskFunctions: []FunctionRisk{{RiskScore: 20}}},
			VerdictEscalation,
		},
		{
			"signature only",
			Evidence{SignatureHits: []SignatureHit{{SignatureID: "SFW-X-1"}}},
			VerdictSignatureMatch,
		},
		{
			"both -- signature wins",
			Evidence{
				HighRiskFunctions: []FunctionRisk{{RiskScore: 100}},
				SignatureHits:     []SignatureHit{{SignatureID: "SFW-X-1"}},
			},
			VerdictSignatureMatch,
		},
	}
	for _, tc := range cases {
		if got := Classify(tc.in); got != tc.want {
			t.Errorf("Classify(%s) = %q; want %q", tc.name, got, tc.want)
		}
	}
}

// TestRiskScoreEscalation_Boundary pins the threshold value. Changing
// this constant changes what counts as "high risk" for every gate
// keyed on the deterministic_verdict field. The test exists so that
// move shows up in code review as an intentional change, not a
// quiet drift.
func TestRiskScoreEscalation_Boundary(t *testing.T) {
	if RiskScoreEscalation != 15 {
		t.Fatalf("RiskScoreEscalation = %d; want 15 (matches engine's high-risk label). "+
			"If you changed this on purpose, update the threat-intel feed schema and "+
			"the marketplace listing copy together with this constant.", RiskScoreEscalation)
	}

	below := models.DiffOutput{Functions: []models.FunctionDiff{{Function: "f", RiskScore: RiskScoreEscalation - 1}}}
	if v := FromDiff(&below).DeterministicVerdict; v != VerdictClean {
		t.Errorf("score just below threshold should classify CLEAN; got %q", v)
	}

	at := models.DiffOutput{Functions: []models.FunctionDiff{{Function: "f", RiskScore: RiskScoreEscalation}}}
	if v := FromDiff(&at).DeterministicVerdict; v != VerdictEscalation {
		t.Errorf("score at threshold should classify ESCALATION; got %q", v)
	}
}

func TestFromDiff_NilSafe(t *testing.T) {
	got := FromDiff(nil)
	if got.DeterministicVerdict != VerdictClean {
		t.Errorf("nil diff should classify CLEAN; got %q", got.DeterministicVerdict)
	}
	if got.HighRiskFunctions == nil || got.SignatureHits == nil {
		t.Error("slices must be non-nil so JSON output is [] not null")
	}
}

func TestFromDiff_OrderingIsStable(t *testing.T) {
	diff := &models.DiffOutput{
		Functions: []models.FunctionDiff{
			{Function: "b", RiskScore: 30},
			{Function: "a", RiskScore: 30}, // ties broken by name ascending
			{Function: "c", RiskScore: 50}, // highest score first
			{Function: "d", RiskScore: 5},  // below threshold; excluded
		},
	}
	got := FromDiff(diff).HighRiskFunctions
	if len(got) != 3 {
		t.Fatalf("expected 3 entries (d below threshold), got %d", len(got))
	}
	wantOrder := []string{"c", "a", "b"}
	for i, want := range wantOrder {
		if got[i].Function != want {
			t.Errorf("order[%d] = %q; want %q (full: %+v)", i, got[i].Function, want, got)
		}
	}
}

func TestFromDiff_CapsRunawayDiffs(t *testing.T) {
	fns := make([]models.FunctionDiff, MaxHighRiskFunctionsReported+10)
	for i := range fns {
		fns[i] = models.FunctionDiff{Function: "f", RiskScore: 100}
	}
	got := FromDiff(&models.DiffOutput{Functions: fns}).HighRiskFunctions
	if len(got) != MaxHighRiskFunctionsReported {
		t.Errorf("HighRiskFunctions len = %d; want cap of %d", len(got), MaxHighRiskFunctionsReported)
	}
}
