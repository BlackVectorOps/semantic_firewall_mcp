package server_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/storage/pebbledb"
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

func TestStatsTool_EmptyPebbleDB(t *testing.T) {
	// NewPebbleScanner on a fresh tempdir creates an empty DB with the
	// current schema; closing it then re-opening read-only via the
	// tool exercises the same path the CLI takes.
	dbPath := t.TempDir()
	ps, err := pebbledb.NewPebbleScanner(dbPath, pebbledb.DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("seed pebbledb: %v", err)
	}
	ps.Close()

	res := callTool(t, "sfw_stats", map[string]any{"db_path": dbPath})
	if res.IsError {
		t.Fatalf("sfw_stats returned IsError=true: %s", textPayload(t, res))
	}

	var got struct {
		Backend        string `json:"backend"`
		Database       string `json:"database"`
		SignatureCount int    `json:"signature_count"`
		FileSizeBytes  int64  `json:"file_size_bytes"`
	}
	if err := json.Unmarshal([]byte(textPayload(t, res)), &got); err != nil {
		t.Fatalf("stats JSON unmarshal: %v", err)
	}
	if got.Backend != "pebbledb" {
		t.Errorf("backend = %q; want pebbledb", got.Backend)
	}
	if got.Database != dbPath {
		t.Errorf("database = %q; want %q", got.Database, dbPath)
	}
	if got.SignatureCount != 0 {
		t.Errorf("signature_count = %d; want 0 for empty DB", got.SignatureCount)
	}
	if got.FileSizeBytes <= 0 {
		t.Errorf("file_size_bytes should be > 0 for an initialised DB, got %d", got.FileSizeBytes)
	}
}

// goSourceWithGoroutine exercises the "has_goroutine" digest field
// and the multi-function case so the topology listing path is not
// skipped by an empty file.
const goSourceWithGoroutine = `package x

func plain() int {
	return 1
}

func spawner() {
	go plain()
}
`

func TestTopologyTool_DigestMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "src.go")
	if err := os.WriteFile(path, []byte(goSourceWithGoroutine), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	res := callTool(t, "sfw_topology", map[string]any{"file_path": path})
	if res.IsError {
		t.Fatalf("sfw_topology returned IsError=true: %s", textPayload(t, res))
	}

	var got []struct {
		Function string `json:"function"`
		HasGo    bool   `json:"has_goroutine"`
	}
	if err := json.Unmarshal([]byte(textPayload(t, res)), &got); err != nil {
		t.Fatalf("topology digest unmarshal: %v\nbody: %s", err, textPayload(t, res))
	}
	if len(got) < 2 {
		t.Fatalf("expected at least 2 functions in digest, got %d", len(got))
	}

	var spawnerHasGo bool
	var sawSpawner bool
	for _, fn := range got {
		if fn.Function == "spawner" {
			sawSpawner = true
			spawnerHasGo = fn.HasGo
		}
	}
	if !sawSpawner {
		t.Fatalf("spawner missing from digest: %+v", got)
	}
	if !spawnerHasGo {
		t.Errorf("spawner.has_goroutine = false; want true (it `go plain()`s)")
	}
}

func TestTopologyTool_SingleFunctionMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "src.go")
	if err := os.WriteFile(path, []byte(goSourceWithGoroutine), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	res := callTool(t, "sfw_topology", map[string]any{
		"file_path":     path,
		"function_name": "spawner",
	})
	if res.IsError {
		t.Fatalf("sfw_topology returned IsError=true: %s", textPayload(t, res))
	}

	// We don't assert on the exact FunctionTopology shape (it's wide and
	// upstream may add fields); we just confirm the response is the
	// single-function blob, not the array of digests.
	body := textPayload(t, res)
	if strings.HasPrefix(strings.TrimSpace(body), "[") {
		t.Fatalf("single-function mode returned an array; expected object:\n%s", body)
	}
	if !strings.Contains(body, `"HasGo": true`) && !strings.Contains(body, `"has_go":true`) && !strings.Contains(body, `"HasGo":true`) {
		t.Errorf("spawner topology should report a goroutine; body:\n%s", body)
	}
}

func TestTopologyTool_FunctionNotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "src.go")
	if err := os.WriteFile(path, []byte(goSourceWithGoroutine), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	res := callTool(t, "sfw_topology", map[string]any{
		"file_path":     path,
		"function_name": "doesNotExist",
	})
	if !res.IsError {
		t.Fatalf("expected IsError=true for unknown function; got body:\n%s", textPayload(t, res))
	}
	if got := textPayload(t, res); !strings.Contains(got, "not found") {
		t.Errorf("error should mention 'not found', got: %s", got)
	}
}

func TestStatsTool_JSONBackend(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "sigs.json")
	body := []byte(`{"version":"1.0","signatures":[{"id":"X1"},{"id":"X2"}]}`)
	if err := os.WriteFile(dbPath, body, 0o600); err != nil {
		t.Fatalf("write json db: %v", err)
	}

	res := callTool(t, "sfw_stats", map[string]any{"db_path": dbPath})
	if res.IsError {
		t.Fatalf("sfw_stats returned IsError=true: %s", textPayload(t, res))
	}

	var got struct {
		Backend        string `json:"backend"`
		SignatureCount int    `json:"signature_count"`
		Version        string `json:"version"`
	}
	if err := json.Unmarshal([]byte(textPayload(t, res)), &got); err != nil {
		t.Fatalf("stats JSON unmarshal: %v", err)
	}
	if got.Backend != "json" {
		t.Errorf("backend = %q; want json", got.Backend)
	}
	if got.SignatureCount != 2 {
		t.Errorf("signature_count = %d; want 2", got.SignatureCount)
	}
	if got.Version != "1.0" {
		t.Errorf("version = %q; want 1.0", got.Version)
	}
}
