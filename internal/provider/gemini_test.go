package provider

import (
	"encoding/json"
	"testing"

	"google.golang.org/genai"
)

func TestGeminiContentsFromMessages_RoleMapping(t *testing.T) {
	got, err := geminiContentsFromMessages([]Message{
		{Role: RoleUser, Content: []ContentBlock{{Type: BlockText, Text: "audit"}}},
		{Role: RoleAssistant, Content: []ContentBlock{{Type: BlockText, Text: "investigating"}}},
	})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 contents, got %d", len(got))
	}
	if got[0].Role != genai.RoleUser {
		t.Errorf("user role mapped to %q; want %q", got[0].Role, genai.RoleUser)
	}
	if got[1].Role != genai.RoleModel {
		t.Errorf("assistant role mapped to %q; want %q (Gemini's name for assistant)", got[1].Role, genai.RoleModel)
	}
}

func TestGeminiContentsFromMessages_ToolUseAndToolResult(t *testing.T) {
	got, err := geminiContentsFromMessages([]Message{
		{
			Role: RoleAssistant,
			Content: []ContentBlock{
				{
					Type:      BlockToolUse,
					ToolUseID: "call_1",
					ToolName:  "sfw_diff",
					ToolInput: json.RawMessage(`{"old_path":"a","new_path":"b"}`),
				},
			},
		},
		{
			Role: RoleUser,
			Content: []ContentBlock{
				{
					Type:         BlockToolResult,
					ToolResultID: "call_1",
					ToolName:     "sfw_diff",
					ToolResult:   `{"summary":{"modified":1}}`,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 contents, got %d", len(got))
	}
	if fc := got[0].Parts[0].FunctionCall; fc == nil || fc.Name != "sfw_diff" {
		t.Errorf("turn[0].part[0] is not the expected function call: %+v", got[0].Parts[0])
	} else if v, ok := fc.Args["old_path"].(string); !ok || v != "a" {
		t.Errorf("function call args lost: %+v", fc.Args)
	}
	if fr := got[1].Parts[0].FunctionResponse; fr == nil || fr.Name != "sfw_diff" {
		t.Errorf("turn[1].part[0] is not the expected function response: %+v", got[1].Parts[0])
	} else {
		// Response must be the JSON object the tool returned.
		if _, ok := fr.Response["summary"]; !ok {
			t.Errorf("function response did not preserve tool output object: %+v", fr.Response)
		}
	}
}

func TestGeminiContentsFromMessages_NonObjectToolResultWrapsUnderOutput(t *testing.T) {
	// A tool that returned a plain string (not JSON object) should
	// still be representable as FunctionResponse.Response, which must
	// be a map. Verify the "output" wrapping kicks in.
	got, err := geminiContentsFromMessages([]Message{
		{
			Role: RoleUser,
			Content: []ContentBlock{
				{
					Type:         BlockToolResult,
					ToolResultID: "x",
					ToolName:     "x",
					ToolResult:   `plain string, not JSON`,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	fr := got[0].Parts[0].FunctionResponse
	if fr == nil {
		t.Fatal("missing function response")
	}
	if v, ok := fr.Response["output"].(string); !ok || v != "plain string, not JSON" {
		t.Errorf("non-JSON tool output not wrapped under 'output': %+v", fr.Response)
	}
}

func TestGeminiContentsFromMessages_ErrorToolResultLandsUnderError(t *testing.T) {
	got, err := geminiContentsFromMessages([]Message{
		{
			Role: RoleUser,
			Content: []ContentBlock{
				{
					Type:         BlockToolResult,
					ToolResultID: "x",
					ToolName:     "x",
					ToolResult:   "tool failed",
					IsError:      true,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	fr := got[0].Parts[0].FunctionResponse
	if fr == nil {
		t.Fatal("missing function response")
	}
	if got, ok := fr.Response["error"].(string); !ok || got != "tool failed" {
		t.Errorf("IsError tool_result not surfaced under 'error': %+v", fr.Response)
	}
}

func TestGeminiContentsFromMessages_StructuredErrorPreservesPayload(t *testing.T) {
	// Regression: when IsError=true AND the tool returned valid
	// structured JSON, the original payload must survive under the
	// "error" key rather than being coerced back to a raw string.
	got, err := geminiContentsFromMessages([]Message{
		{
			Role: RoleUser,
			Content: []ContentBlock{
				{
					Type:         BlockToolResult,
					ToolResultID: "x",
					ToolName:     "x",
					ToolResult:   `{"status":"failed","detail":"db locked"}`,
					IsError:      true,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	fr := got[0].Parts[0].FunctionResponse
	if fr == nil {
		t.Fatal("missing function response")
	}
	inner, ok := fr.Response["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected fr.Response[\"error\"] to be a map; got %T: %+v", fr.Response["error"], fr.Response)
	}
	if got := inner["status"]; got != "failed" {
		t.Errorf("structured error payload lost: inner=%+v", inner)
	}
}

func TestGeminiContentsFromMessages_ToolUseOnWrongRoleErrors(t *testing.T) {
	_, err := geminiContentsFromMessages([]Message{
		{
			Role: RoleUser,
			Content: []ContentBlock{
				{Type: BlockToolUse, ToolUseID: "x", ToolName: "y", ToolInput: json.RawMessage(`{}`)},
			},
		},
	})
	if err == nil {
		t.Fatal("expected error on tool_use under RoleUser")
	}
}

func TestGemini_Name(t *testing.T) {
	if got := NewGemini("k").Name(); got != "gemini" {
		t.Errorf("Name() = %q; want gemini", got)
	}
}
