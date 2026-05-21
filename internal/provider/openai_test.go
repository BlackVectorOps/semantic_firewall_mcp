package provider

import (
	"encoding/json"
	"testing"

	"github.com/openai/openai-go/responses"
)

func TestOpenAIInputFromMessages_TextThenToolUseThenToolResult(t *testing.T) {
	items, err := openaiInputFromMessages([]Message{
		{
			Role:    RoleUser,
			Content: []ContentBlock{{Type: BlockText, Text: "audit"}},
		},
		{
			Role: RoleAssistant,
			Content: []ContentBlock{
				{Type: BlockText, Text: "I'll call the diff tool."},
				{
					Type:      BlockToolUse,
					ToolUseID: "call_42",
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
					ToolResultID: "call_42",
					ToolResult:   `{"summary":{"modified":1}}`,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("openaiInputFromMessages: %v", err)
	}

	// Expect: user "audit", assistant "I'll call the diff tool.",
	// function_call call_42, function_call_output call_42.
	if len(items) != 4 {
		t.Fatalf("expected 4 items, got %d (%+v)", len(items), items)
	}
	if items[0].OfMessage == nil || items[0].OfMessage.Role != responses.EasyInputMessageRoleUser {
		t.Errorf("item[0] not a user EasyInputMessage; got %+v", items[0])
	}
	if items[1].OfMessage == nil || items[1].OfMessage.Role != responses.EasyInputMessageRoleAssistant {
		t.Errorf("item[1] not an assistant EasyInputMessage; got %+v", items[1])
	}
	if items[2].OfFunctionCall == nil || items[2].OfFunctionCall.CallID != "call_42" {
		t.Errorf("item[2] not a function_call with id call_42; got %+v", items[2])
	}
	if items[3].OfFunctionCallOutput == nil || items[3].OfFunctionCallOutput.CallID != "call_42" {
		t.Errorf("item[3] not a function_call_output with id call_42; got %+v", items[3])
	}
}

func TestOpenAIInputFromMessages_ToolUseOnWrongRoleErrors(t *testing.T) {
	_, err := openaiInputFromMessages([]Message{
		{
			Role: RoleUser, // tool_use on user is invalid
			Content: []ContentBlock{
				{Type: BlockToolUse, ToolUseID: "x", ToolName: "y", ToolInput: json.RawMessage(`{}`)},
			},
		},
	})
	if err == nil {
		t.Fatal("expected error on tool_use under RoleUser")
	}
}

func TestOpenAIInputFromMessages_TextMergesAcrossBlocks(t *testing.T) {
	items, err := openaiInputFromMessages([]Message{
		{
			Role: RoleUser,
			Content: []ContentBlock{
				{Type: BlockText, Text: "line 1"},
				{Type: BlockText, Text: "line 2"},
			},
		},
	})
	if err != nil {
		t.Fatalf("openaiInputFromMessages: %v", err)
	}
	if len(items) != 1 || items[0].OfMessage == nil {
		t.Fatalf("expected one message item; got %+v", items)
	}
	got := items[0].OfMessage.Content.OfString.Value
	if got != "line 1\nline 2" {
		t.Errorf("merged content = %q; want %q", got, "line 1\nline 2")
	}
}

func TestOpenAI_NameAndOverride(t *testing.T) {
	p := NewOpenAI("key")
	if p.Name() != "openai" {
		t.Errorf("Name() = %q; want openai", p.Name())
	}
	p.nameOverride = "openai-compatible"
	if p.Name() != "openai-compatible" {
		t.Errorf("Name override not applied: got %q", p.Name())
	}
}
