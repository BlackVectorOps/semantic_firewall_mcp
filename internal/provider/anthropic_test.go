package provider

import (
	"encoding/json"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
)

func TestAnthropicBlocksFromProvider_TextToolUseToolResult(t *testing.T) {
	blocks, err := anthropicBlocksFromProvider([]ContentBlock{
		{Type: BlockText, Text: "hello"},
		{
			Type:      BlockToolUse,
			ToolUseID: "tu_1",
			ToolName:  "sfw_diff",
			ToolInput: json.RawMessage(`{"old_path":"a.go","new_path":"b.go"}`),
		},
		{
			Type:         BlockToolResult,
			ToolResultID: "tu_1",
			ToolResult:   `{"summary":{"modified":1}}`,
			IsError:      false,
		},
	})
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if len(blocks) != 3 {
		t.Fatalf("expected 3 blocks, got %d", len(blocks))
	}
	if blocks[0].OfText == nil || blocks[0].OfText.Text != "hello" {
		t.Errorf("block[0] not a text block with 'hello'; got %+v", blocks[0])
	}
	if blocks[1].OfToolUse == nil || blocks[1].OfToolUse.Name != "sfw_diff" || blocks[1].OfToolUse.ID != "tu_1" {
		t.Errorf("block[1] not the expected tool_use; got %+v", blocks[1])
	}
	if blocks[2].OfToolResult == nil || blocks[2].OfToolResult.ToolUseID != "tu_1" {
		t.Errorf("block[2] not the expected tool_result; got %+v", blocks[2])
	}
}

func TestAnthropicBlocksFromProvider_InvalidToolInput(t *testing.T) {
	_, err := anthropicBlocksFromProvider([]ContentBlock{{
		Type:      BlockToolUse,
		ToolUseID: "bad",
		ToolName:  "x",
		ToolInput: json.RawMessage(`{not json`),
	}})
	if err == nil {
		t.Fatal("expected error on malformed tool_use input JSON")
	}
}

func TestAnthropicSchemaFromJSON_PreservesPropertiesAndRequired(t *testing.T) {
	raw := json.RawMessage(`{
		"type":"object",
		"properties":{"old_path":{"type":"string"},"new_path":{"type":"string"}},
		"required":["old_path","new_path"],
		"additionalProperties":false
	}`)
	schema, err := anthropicSchemaFromJSON(raw)
	if err != nil {
		t.Fatalf("schema parse: %v", err)
	}
	props, ok := schema.Properties.(map[string]any)
	if !ok {
		t.Fatalf("properties not map[string]any: %T", schema.Properties)
	}
	if _, ok := props["old_path"]; !ok {
		t.Errorf("old_path lost from schema properties: %+v", props)
	}
	if len(schema.Required) != 2 {
		t.Errorf("required count = %d; want 2", len(schema.Required))
	}
	// additionalProperties wasn't a known field on ToolInputSchemaParam,
	// so it should ride along in ExtraFields untouched.
	if schema.ExtraFields["additionalProperties"] != false {
		t.Errorf("additionalProperties dropped or mangled: %+v", schema.ExtraFields)
	}
}

func TestAnthropicStopReasonToProvider(t *testing.T) {
	cases := []struct {
		in   anthropic.StopReason
		want StopReason
	}{
		{anthropic.StopReasonEndTurn, StopReasonEndTurn},
		{anthropic.StopReasonToolUse, StopReasonToolUse},
		{anthropic.StopReasonMaxTokens, StopReasonMaxTokens},
		{anthropic.StopReason("stop_sequence"), StopReasonOther},
		{anthropic.StopReason(""), StopReasonOther},
	}
	for _, tc := range cases {
		if got := anthropicStopReasonToProvider(tc.in); got != tc.want {
			t.Errorf("anthropicStopReasonToProvider(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

func TestAnthropic_Name(t *testing.T) {
	p := NewAnthropic("")
	if p.Name() != "anthropic" {
		t.Errorf("Name() = %q; want anthropic", p.Name())
	}
}
