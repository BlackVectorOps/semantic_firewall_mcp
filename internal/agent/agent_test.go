package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall_mcp/internal/provider"
)

// scriptedProvider drives the agent through a pre-recorded sequence
// of responses. Each Complete call returns the next entry. This is
// the cheapest way to test the loop end-to-end without hitting an
// LLM -- the loop sees a real ContentBlock list, the tools really
// run, and the final-text extraction goes through the same code as
// production.
type scriptedProvider struct {
	t         *testing.T
	responses []*provider.Response
	calls     int
	captured  []provider.Request // every Request the loop emitted, for assertions
}

func (s *scriptedProvider) Name() string { return "scripted" }

func (s *scriptedProvider) Complete(_ context.Context, req provider.Request) (*provider.Response, error) {
	s.captured = append(s.captured, req)
	if s.calls >= len(s.responses) {
		s.t.Fatalf("scriptedProvider ran out of responses after %d calls", s.calls)
	}
	r := s.responses[s.calls]
	s.calls++
	return r, nil
}

func TestRun_EndTurnImmediately(t *testing.T) {
	p := &scriptedProvider{
		t: t,
		responses: []*provider.Response{
			{
				StopReason: provider.StopReasonEndTurn,
				Content: []provider.ContentBlock{
					{Type: provider.BlockText, Text: "all good"},
				},
			},
		},
	}
	got, _, err := Run(context.Background(), p, "sys", "user", nil, LoopOptions{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got != "all good" {
		t.Errorf("final text = %q; want %q", got, "all good")
	}
	if p.calls != 1 {
		t.Errorf("expected 1 provider call, got %d", p.calls)
	}
	// First request should carry the system prompt, the user turn, and
	// the full tool registry (5 tools as of the read-only set).
	req := p.captured[0]
	if req.System != "sys" {
		t.Errorf("system = %q; want sys", req.System)
	}
	if len(req.Messages) != 1 || req.Messages[0].Role != provider.RoleUser {
		t.Errorf("first request messages = %+v; want one user turn", req.Messages)
	}
	if len(req.Tools) < 5 {
		t.Errorf("expected at least 5 tools wired (diff/scan/check/topology/stats); got %d", len(req.Tools))
	}
	// Every tool spec must carry a non-empty schema, otherwise the
	// provider will reject the request.
	for _, ts := range req.Tools {
		if len(ts.InputSchema) == 0 {
			t.Errorf("tool %q has empty InputSchema", ts.Name)
		}
	}
}

func TestRun_ToolUseRoundTrip(t *testing.T) {
	// Build a real Go source so sfw_diff has something to work on.
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "a.go")
	newPath := filepath.Join(dir, "b.go")
	if err := os.WriteFile(oldPath, []byte("package x\n\nfunc F() int { return 1 }\n"), 0o644); err != nil {
		t.Fatalf("write a: %v", err)
	}
	if err := os.WriteFile(newPath, []byte("package x\n\nfunc F() int { return 2 }\n"), 0o644); err != nil {
		t.Fatalf("write b: %v", err)
	}

	toolInput, _ := json.Marshal(map[string]string{"old_path": oldPath, "new_path": newPath})

	p := &scriptedProvider{
		t: t,
		responses: []*provider.Response{
			// Turn 1: model asks to call sfw_diff.
			{
				StopReason: provider.StopReasonToolUse,
				Content: []provider.ContentBlock{
					{
						Type:      provider.BlockToolUse,
						ToolUseID: "tu_1",
						ToolName:  "sfw_diff",
						ToolInput: toolInput,
					},
				},
			},
			// Turn 2: model emits final verdict text after seeing the
			// tool result.
			{
				StopReason: provider.StopReasonEndTurn,
				Content: []provider.ContentBlock{
					{Type: provider.BlockText, Text: "diff observed"},
				},
			},
		},
	}

	got, usage, err := Run(context.Background(), p, "sys", "audit", nil, LoopOptions{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got != "diff observed" {
		t.Errorf("final text = %q; want %q", got, "diff observed")
	}
	if p.calls != 2 {
		t.Errorf("expected 2 provider calls, got %d", p.calls)
	}

	// Second request must include the assistant turn (the tool_use)
	// and a user turn containing the matching tool_result. Without
	// that round-trip the provider would reject the request.
	req := p.captured[1]
	if len(req.Messages) != 3 {
		t.Fatalf("turn 2 messages = %d; want 3 (user, assistant, tool_result)", len(req.Messages))
	}
	if req.Messages[1].Role != provider.RoleAssistant {
		t.Errorf("turn 2 message[1] role = %q; want assistant", req.Messages[1].Role)
	}
	last := req.Messages[2]
	if last.Role != provider.RoleUser {
		t.Errorf("turn 2 message[2] role = %q; want user", last.Role)
	}
	if len(last.Content) != 1 || last.Content[0].Type != provider.BlockToolResult {
		t.Fatalf("turn 2 tail must be one tool_result; got %+v", last.Content)
	}
	if last.Content[0].ToolResultID != "tu_1" {
		t.Errorf("tool_result id = %q; want tu_1", last.Content[0].ToolResultID)
	}
	if last.Content[0].IsError {
		t.Errorf("tool_result marked IsError; payload: %s", last.Content[0].ToolResult)
	}
	// The tool result should be JSON the model can parse -- sfw_diff
	// always returns a DiffOutput.
	if !strings.Contains(last.Content[0].ToolResult, `"old_file"`) {
		t.Errorf("tool_result not a DiffOutput JSON: %s", last.Content[0].ToolResult)
	}

	// Usage must reflect the two model calls plus the one tool_use
	// the model emitted across them. Token counts are zero (the
	// scripted provider does not populate Usage) but the counters
	// must still be accurate.
	if usage.ModelSteps != 2 {
		t.Errorf("usage.ModelSteps = %d; want 2", usage.ModelSteps)
	}
	if usage.ToolCalls != 1 {
		t.Errorf("usage.ToolCalls = %d; want 1", usage.ToolCalls)
	}
}

func TestRun_UnknownToolReportsErrorResult(t *testing.T) {
	p := &scriptedProvider{
		t: t,
		responses: []*provider.Response{
			{
				StopReason: provider.StopReasonToolUse,
				Content: []provider.ContentBlock{
					{
						Type:      provider.BlockToolUse,
						ToolUseID: "tu_x",
						ToolName:  "sfw_does_not_exist",
						ToolInput: json.RawMessage(`{}`),
					},
				},
			},
			{
				StopReason: provider.StopReasonEndTurn,
				Content:    []provider.ContentBlock{{Type: provider.BlockText, Text: "ok"}},
			},
		},
	}
	if _, _, err := Run(context.Background(), p, "sys", "audit", nil, LoopOptions{}); err != nil {
		t.Fatalf("Run should swallow unknown-tool as a tool_result, not error: %v", err)
	}
	// The second turn must contain a tool_result marked IsError.
	last := p.captured[1].Messages[len(p.captured[1].Messages)-1]
	if !last.Content[0].IsError {
		t.Errorf("unknown tool should yield IsError=true tool_result")
	}
	if !strings.Contains(last.Content[0].ToolResult, "unknown tool") {
		t.Errorf("error result should mention 'unknown tool'; got %q", last.Content[0].ToolResult)
	}
}

func TestRun_StepBudgetExhausted(t *testing.T) {
	// Model loops forever asking for the same tool. Three steps in,
	// budget runs out and the loop aborts with a clear error.
	toolUseTurn := &provider.Response{
		StopReason: provider.StopReasonToolUse,
		Content: []provider.ContentBlock{
			{
				Type:      provider.BlockToolUse,
				ToolUseID: "tu_loop",
				ToolName:  "sfw_stats",
				ToolInput: json.RawMessage(`{"db_path":"/tmp/nope"}`),
			},
		},
	}
	p := &scriptedProvider{
		t:         t,
		responses: []*provider.Response{toolUseTurn, toolUseTurn, toolUseTurn},
	}
	_, usage, err := Run(context.Background(), p, "sys", "audit", nil, LoopOptions{MaxSteps: 3})
	if err == nil {
		t.Fatal("expected step-budget exhaustion error, got nil")
	}
	if !strings.Contains(err.Error(), "step budget") {
		t.Errorf("error should mention step budget; got: %v", err)
	}
	// Usage must survive the abort: 3 model steps and 3 tool_use
	// blocks the model emitted before the budget tripped. This is
	// the "runaway-bill hides in the failure path" hole closing.
	if usage.ModelSteps != 3 {
		t.Errorf("usage.ModelSteps after abort = %d; want 3", usage.ModelSteps)
	}
	if usage.ToolCalls != 3 {
		t.Errorf("usage.ToolCalls after abort = %d; want 3", usage.ToolCalls)
	}
}

// TestRun_UsageSurvivesMaxTokens pins the second failure path -- a
// model emits StopReasonMaxTokens before producing a final verdict
// and we must still surface the usage accumulated up to that point.
// Without this guarantee, an audit that died at step 7 of 8 would
// report zero cost, which is the worst possible reporting bug for a
// paid CI tool.
func TestRun_UsageSurvivesMaxTokens(t *testing.T) {
	p := &scriptedProvider{
		t: t,
		responses: []*provider.Response{
			{
				StopReason: provider.StopReasonMaxTokens,
				Content:    []provider.ContentBlock{{Type: provider.BlockText, Text: "I was about to"}},
				Usage:      provider.Usage{InputTokens: 1234, OutputTokens: 2048},
			},
		},
	}
	_, usage, err := Run(context.Background(), p, "sys", "audit", nil, LoopOptions{})
	if err == nil {
		t.Fatal("expected max_tokens error, got nil")
	}
	if usage.ModelSteps != 1 {
		t.Errorf("usage.ModelSteps = %d; want 1", usage.ModelSteps)
	}
	if usage.ProviderUsage.InputTokens != 1234 || usage.ProviderUsage.OutputTokens != 2048 {
		t.Errorf("token counts lost across abort: in=%d out=%d", usage.ProviderUsage.InputTokens, usage.ProviderUsage.OutputTokens)
	}
}

// TestRun_SeedInjectedAfterUserTurn pins the contract that
// audit.RunAudit relies on: seed messages land between the initial
// user turn and the first provider call. If the placement ever
// regresses to "before user" or "appended at end", the model would
// see a fabricated tool call without the context that motivated it
// and the conversation becomes invalid for OpenAI / Gemini.
func TestRun_SeedInjectedAfterUserTurn(t *testing.T) {
	seed := []provider.Message{
		{Role: provider.RoleAssistant, Content: []provider.ContentBlock{
			{Type: provider.BlockToolUse, ToolUseID: "seed_1", ToolName: "sfw_diff", ToolInput: json.RawMessage(`{}`)},
		}},
		{Role: provider.RoleUser, Content: []provider.ContentBlock{
			{Type: provider.BlockToolResult, ToolResultID: "seed_1", ToolResult: "seeded payload"},
		}},
	}
	p := &scriptedProvider{
		t: t,
		responses: []*provider.Response{
			{StopReason: provider.StopReasonEndTurn, Content: []provider.ContentBlock{{Type: provider.BlockText, Text: "ok"}}},
		},
	}
	if _, _, err := Run(context.Background(), p, "sys", "user-msg", seed, LoopOptions{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(p.captured) != 1 {
		t.Fatalf("expected 1 captured request, got %d", len(p.captured))
	}
	msgs := p.captured[0].Messages
	if len(msgs) != 3 {
		t.Fatalf("expected user + seed-assistant + seed-user, got %d messages", len(msgs))
	}
	if msgs[0].Role != provider.RoleUser || msgs[0].Content[0].Text != "user-msg" {
		t.Errorf("msg[0] = %+v; want the user turn first", msgs[0])
	}
	if msgs[1].Role != provider.RoleAssistant || msgs[1].Content[0].Type != provider.BlockToolUse {
		t.Errorf("msg[1] = %+v; want seed assistant tool_use", msgs[1])
	}
	if msgs[2].Role != provider.RoleUser || msgs[2].Content[0].Type != provider.BlockToolResult {
		t.Errorf("msg[2] = %+v; want seed user tool_result", msgs[2])
	}
}

func TestParseVerdict_PlainObject(t *testing.T) {
	got, err := parseVerdict(`{"verdict":"MATCH","evidence":"all good"}`)
	if err != nil {
		t.Fatalf("parseVerdict: %v", err)
	}
	if got.Verdict != "MATCH" || got.Evidence != "all good" {
		t.Errorf("parsed = %+v", got)
	}
}

func TestParseVerdict_FencedJSON(t *testing.T) {
	got, err := parseVerdict("```json\n{\"verdict\":\"LIE\",\"evidence\":\"x\"}\n```")
	if err != nil {
		t.Fatalf("parseVerdict: %v", err)
	}
	if got.Verdict != "LIE" {
		t.Errorf("parsed = %+v", got)
	}
}

func TestParseVerdict_EmbeddedInProse(t *testing.T) {
	got, err := parseVerdict(`After investigation I conclude:
{"verdict":"SUSPICIOUS","evidence":"vague message"}
Hope this helps!`)
	if err != nil {
		t.Fatalf("parseVerdict: %v", err)
	}
	if got.Verdict != "SUSPICIOUS" {
		t.Errorf("parsed = %+v", got)
	}
}

func TestParseVerdict_BracesInsideString(t *testing.T) {
	// The depth tracker must not be fooled by braces inside the
	// evidence string.
	got, err := parseVerdict(`{"verdict":"LIE","evidence":"oh look: {fake brace}"}`)
	if err != nil {
		t.Fatalf("parseVerdict: %v", err)
	}
	if got.Evidence != "oh look: {fake brace}" {
		t.Errorf("evidence corrupted by string-aware parser: %q", got.Evidence)
	}
}

func TestParseVerdict_Empty(t *testing.T) {
	if _, err := parseVerdict(""); err == nil {
		t.Error("empty response should error")
	}
}
