package server_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall_mcp/internal/server"
	"github.com/mark3labs/mcp-go/mcp"
)

const goSourceA = `package x

func Add(a, b int) int {
	return a + b
}
`

const goSourceB = `package x

func Add(a, b int) int {
	if a < 0 {
		return -1
	}
	return a + b
}
`

// callTool exercises the server end-to-end through its JSON-RPC handler,
// so the test catches schema/registration mistakes that a direct
// handler invocation would miss.
func callTool(t *testing.T, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()

	s := server.New()

	reqMsg := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      name,
			"arguments": args,
		},
	}
	raw, err := json.Marshal(reqMsg)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	resp := s.HandleMessage(context.Background(), raw)
	respBytes, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}

	var envelope struct {
		Result mcp.CallToolResult `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBytes, &envelope); err != nil {
		t.Fatalf("unmarshal envelope: %v\nraw: %s", err, respBytes)
	}
	if envelope.Error != nil {
		t.Fatalf("JSON-RPC error: code=%d msg=%s", envelope.Error.Code, envelope.Error.Message)
	}
	return &envelope.Result
}

// textPayload pulls the single text content block out of a tool result.
// The diff/scan/etc. tools all return one TextContent with a JSON body.
func textPayload(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) != 1 {
		t.Fatalf("expected 1 content block, got %d", len(res.Content))
	}
	tc, ok := res.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Content[0])
	}
	return tc.Text
}

func TestDiffTool_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.go")
	newPath := filepath.Join(dir, "new.go")
	if err := os.WriteFile(oldPath, []byte(goSourceA), 0o644); err != nil {
		t.Fatalf("write old: %v", err)
	}
	if err := os.WriteFile(newPath, []byte(goSourceB), 0o644); err != nil {
		t.Fatalf("write new: %v", err)
	}

	res := callTool(t, "sfw_diff", map[string]any{
		"old_path": oldPath,
		"new_path": newPath,
	})
	if res.IsError {
		t.Fatalf("sfw_diff returned IsError=true: %s", textPayload(t, res))
	}

	body := textPayload(t, res)

	// We don't assert on exact fingerprints (those depend on the
	// canonicalizer and would couple this test to an upstream impl
	// detail). Instead we check the shape and that the tool actually
	// noticed a change in Add.
	var got struct {
		OldFile   string `json:"old_file"`
		NewFile   string `json:"new_file"`
		Summary   struct {
			TotalFunctions int `json:"total_functions"`
			Modified       int `json:"modified"`
			Preserved      int `json:"preserved"`
		} `json:"summary"`
		Functions []struct {
			Function string `json:"function"`
			Status   string `json:"status"`
		} `json:"functions"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("diff JSON unmarshal: %v\nbody:\n%s", err, body)
	}
	if got.OldFile != oldPath || got.NewFile != newPath {
		t.Errorf("paths not echoed back: old=%q new=%q", got.OldFile, got.NewFile)
	}
	if got.Summary.TotalFunctions == 0 {
		t.Errorf("expected at least one function, got 0; body:\n%s", body)
	}

	var addFn *struct {
		Function string `json:"function"`
		Status   string `json:"status"`
	}
	for i := range got.Functions {
		if strings.HasSuffix(got.Functions[i].Function, "Add") {
			addFn = &got.Functions[i]
			break
		}
	}
	if addFn == nil {
		t.Fatalf("Add not found in diff; body:\n%s", body)
	}
	if addFn.Status != "modified" {
		t.Errorf("expected Add status=modified, got %q", addFn.Status)
	}
}

func TestDiffTool_MissingArg(t *testing.T) {
	res := callTool(t, "sfw_diff", map[string]any{
		"old_path": "/tmp/x.go",
		// new_path intentionally omitted
	})
	if !res.IsError {
		t.Fatalf("expected IsError=true on missing arg; got body:\n%s", textPayload(t, res))
	}
	if got := textPayload(t, res); !strings.Contains(strings.ToLower(got), "new_path") {
		t.Errorf("error should mention missing new_path, got: %s", got)
	}
}
