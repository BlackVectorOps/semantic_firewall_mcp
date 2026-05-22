package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall_mcp/internal/provider"
	"github.com/BlackVectorOps/semantic_firewall_mcp/internal/risk"
)

// goSourceA is a benign source; the diff against goSourceB introduces
// a goroutine which alone trips RiskScoreEscalation. That makes it a
// natural fixture for the seeded-diff and risk_evidence assertions.
const auditSourceA = `package x

func F() int {
	return 1
}
`

const auditSourceB = `package x

func F() int {
	go helper()
	return 2
}

func helper() {}
`

// writeAuditFixtures lays goSourceA and goSourceB into a tempdir
// and returns the two paths. Several tests need the same setup so
// the helper hides the boilerplate.
func writeAuditFixtures(t *testing.T) (oldPath, newPath string) {
	t.Helper()
	dir := t.TempDir()
	oldPath = filepath.Join(dir, "a.go")
	newPath = filepath.Join(dir, "b.go")
	if err := os.WriteFile(oldPath, []byte(auditSourceA), 0o644); err != nil {
		t.Fatalf("write a: %v", err)
	}
	if err := os.WriteFile(newPath, []byte(auditSourceB), 0o644); err != nil {
		t.Fatalf("write b: %v", err)
	}
	return oldPath, newPath
}

// TestRunAudit_OutputShape_HappyPath drives the full pipeline with
// a scripted provider that emits a clean MATCH verdict. Asserts on
// every top-level field of AuditOutput so any future schema change
// trips a deliberate test update.
func TestRunAudit_OutputShape_HappyPath(t *testing.T) {
	oldPath, newPath := writeAuditFixtures(t)

	p := &scriptedProvider{
		t: t,
		responses: []*provider.Response{
			{
				StopReason: provider.StopReasonEndTurn,
				Content: []provider.ContentBlock{
					{Type: provider.BlockText, Text: `{"verdict":"MATCH","evidence":"goroutine added but commit message says so"}`},
				},
				Usage: provider.Usage{InputTokens: 1500, OutputTokens: 80},
			},
		},
	}

	out := RunAudit(context.Background(), p, "scripted-model", oldPath, newPath, "add goroutine for parallel helper", LoopOptions{})

	if out.Inputs.OldFile != oldPath {
		t.Errorf("Inputs.OldFile = %q; want %q", out.Inputs.OldFile, oldPath)
	}
	if out.Inputs.NewFile != newPath {
		t.Errorf("Inputs.NewFile = %q; want %q", out.Inputs.NewFile, newPath)
	}

	// risk_evidence must be populated from the pre-computed diff
	// regardless of what the LLM said.
	if out.RiskEvidence.DeterministicVerdict != risk.VerdictEscalation {
		t.Errorf("RiskEvidence.DeterministicVerdict = %q; want %q (goroutine adds +15 score)",
			out.RiskEvidence.DeterministicVerdict, risk.VerdictEscalation)
	}
	if len(out.RiskEvidence.HighRiskFunctions) == 0 {
		t.Errorf("RiskEvidence.HighRiskFunctions empty; expected the goroutine-spawning F to surface")
	}

	// llm_assessments is an array shape now -- exactly one entry
	// in single-provider mode.
	if len(out.LLMAssessments) != 1 {
		t.Fatalf("LLMAssessments len = %d; want 1 in single-provider mode", len(out.LLMAssessments))
	}
	a := out.LLMAssessments[0]
	if a.Provider != "scripted" || a.Model != "scripted-model" {
		t.Errorf("assessment provider/model lost: %+v", a)
	}
	if a.Verdict != VerdictMatch {
		t.Errorf("assessment.Verdict = %q; want MATCH", a.Verdict)
	}
	if a.Error != "" {
		t.Errorf("assessment.Error populated on happy path: %q", a.Error)
	}

	// cost is always populated; the scripted Usage hands us specific
	// token counts that must round-trip.
	if out.Cost.ModelSteps != 1 {
		t.Errorf("Cost.ModelSteps = %d; want 1", out.Cost.ModelSteps)
	}
	if out.Cost.InputTokens != 1500 || out.Cost.OutputTokens != 80 {
		t.Errorf("Cost tokens lost: %+v", out.Cost)
	}
}

// TestRunAudit_SeededDiffPreventsDivergence is the headline
// regression guard: the model never has to call sfw_diff on the
// audit's primary pair because the result is already in the seed.
// We assert that (a) the first provider request includes the seeded
// assistant tool_use + user tool_result, (b) the tool_result content
// is the same DiffOutput JSON risk_evidence was computed from. If
// either fails, "risk_evidence and what the model sees can diverge"
// is back on the table.
func TestRunAudit_SeededDiffPreventsDivergence(t *testing.T) {
	oldPath, newPath := writeAuditFixtures(t)

	p := &scriptedProvider{
		t: t,
		responses: []*provider.Response{
			{
				StopReason: provider.StopReasonEndTurn,
				Content: []provider.ContentBlock{
					{Type: provider.BlockText, Text: `{"verdict":"MATCH","evidence":"ok"}`},
				},
			},
		},
	}

	out := RunAudit(context.Background(), p, "scripted-model", oldPath, newPath, "msg", LoopOptions{})

	if len(p.captured) != 1 {
		t.Fatalf("expected 1 provider call, got %d", len(p.captured))
	}
	msgs := p.captured[0].Messages

	// Expect: user (audit request) + assistant (seed tool_use) +
	// user (seed tool_result). If seed placement regressed those
	// three turns would not be in this order.
	if len(msgs) != 3 {
		t.Fatalf("expected 3 seeded messages, got %d (%+v)", len(msgs), msgs)
	}
	if msgs[1].Role != provider.RoleAssistant {
		t.Fatalf("msg[1] role = %q; want assistant", msgs[1].Role)
	}
	if len(msgs[1].Content) == 0 || msgs[1].Content[0].Type != provider.BlockToolUse || msgs[1].Content[0].ToolName != "sfw_diff" {
		t.Fatalf("seed assistant turn must be a sfw_diff tool_use; got %+v", msgs[1].Content)
	}
	if msgs[1].Content[0].ToolUseID != seedToolUseID {
		t.Errorf("seed tool_use_id = %q; want %q (constant so tests can pin it)", msgs[1].Content[0].ToolUseID, seedToolUseID)
	}

	if msgs[2].Role != provider.RoleUser {
		t.Fatalf("msg[2] role = %q; want user", msgs[2].Role)
	}
	if len(msgs[2].Content) == 0 || msgs[2].Content[0].Type != provider.BlockToolResult {
		t.Fatalf("seed user turn must be a tool_result; got %+v", msgs[2].Content)
	}
	if msgs[2].Content[0].ToolResultID != seedToolUseID {
		t.Errorf("seed tool_result_id = %q; want %q", msgs[2].Content[0].ToolResultID, seedToolUseID)
	}

	// The single-source-of-truth invariant: the seeded payload must
	// describe the same diff that risk_evidence was derived from.
	// We unmarshal the seeded payload and check the summary's
	// add/modify counts match what risk_evidence carries.
	var seededDiff struct {
		Summary struct {
			Added    int `json:"added"`
			Modified int `json:"modified"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(msgs[2].Content[0].ToolResult), &seededDiff); err != nil {
		t.Fatalf("seeded tool_result is not parseable JSON: %v", err)
	}
	if seededDiff.Summary.Added != out.RiskEvidence.AddedFunctions {
		t.Errorf("divergence: seeded.added=%d, risk_evidence.added=%d", seededDiff.Summary.Added, out.RiskEvidence.AddedFunctions)
	}
	if seededDiff.Summary.Modified != out.RiskEvidence.ModifiedFunctions {
		t.Errorf("divergence: seeded.modified=%d, risk_evidence.modified=%d", seededDiff.Summary.Modified, out.RiskEvidence.ModifiedFunctions)
	}
}

// TestRunAudit_LLMErrorPreservesRiskEvidence pins the most important
// behaviour on the failure path: even when the LLM blows up
// completely, risk_evidence remains valid because it is derived
// before the model is called. The math-only operator's gate keeps
// working through provider outages.
func TestRunAudit_LLMErrorPreservesRiskEvidence(t *testing.T) {
	oldPath, newPath := writeAuditFixtures(t)

	// No scripted responses -- any model call would fall off the
	// end of the list. We instead bypass scriptedProvider with a
	// provider that returns an error immediately.
	p := &erroringProvider{name: "broken"}
	out := RunAudit(context.Background(), p, "doesnt-matter", oldPath, newPath, "msg", LoopOptions{})

	if out.RiskEvidence.DeterministicVerdict != risk.VerdictEscalation {
		t.Errorf("RiskEvidence lost on provider error; got %q", out.RiskEvidence.DeterministicVerdict)
	}
	if len(out.LLMAssessments) != 1 {
		t.Fatalf("LLMAssessments len = %d; want 1 even on failure", len(out.LLMAssessments))
	}
	if out.LLMAssessments[0].Verdict != VerdictError {
		t.Errorf("expected VerdictError on provider failure; got %q", out.LLMAssessments[0].Verdict)
	}
	if out.LLMAssessments[0].Error == "" {
		t.Errorf("assessment.Error empty on failure; should carry the provider error")
	}
}

// TestExitCode_TriState pins the v0.2 exit-code contract. The
// distinction between "tool has an opinion" (1) and "tool broke"
// (2) is what lets workflows fail-soft on infra outages without
// suppressing real LIE / SUSPICIOUS verdicts.
func TestExitCode_TriState(t *testing.T) {
	mk := func(verdict string) AuditOutput {
		return AuditOutput{LLMAssessments: []LLMAssessment{{Verdict: verdict}}}
	}
	cases := []struct {
		verdict string
		want    int
	}{
		{VerdictMatch, 0},
		{VerdictLie, 1},
		{VerdictSuspicious, 1},
		{VerdictError, 2},
		{"GIBBERISH", 2},
	}
	for _, tc := range cases {
		if got := mk(tc.verdict).ExitCode(); got != tc.want {
			t.Errorf("ExitCode(%q) = %d; want %d", tc.verdict, got, tc.want)
		}
	}
	// Empty assessments must collapse to ERROR (2), not panic.
	if got := (AuditOutput{}).ExitCode(); got != 2 {
		t.Errorf("ExitCode on empty assessments = %d; want 2 (ERROR)", got)
	}
}

// erroringProvider returns an error on every Complete call. Used to
// exercise the LLM-failure branch of RunAudit without needing a
// scripted-response setup.
type erroringProvider struct{ name string }

func (e *erroringProvider) Name() string { return e.name }

func (e *erroringProvider) Complete(_ context.Context, _ provider.Request) (*provider.Response, error) {
	return nil, &auditTestErr{msg: "synthetic provider outage"}
}

type auditTestErr struct{ msg string }

func (e *auditTestErr) Error() string { return e.msg }

// Sanity: make sure none of our test helpers depend on imports the
// build would otherwise drop. strings is used by the verdict-parser
// tests next door but referenced here only via this side-effect.
var _ = strings.HasPrefix
