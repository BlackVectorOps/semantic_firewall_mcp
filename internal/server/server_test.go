package server_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/detection"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/diff"
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

// seedDBForFunction fingerprints the supplied Go source, extracts the
// topology of the first function with a body, and stores it as a
// signature in a fresh PebbleDB. The returned dbPath has exactly one
// signature -- the same topology the test will then re-scan, so we
// know the scanner pipeline is wired correctly when an alert fires.
func seedDBForFunction(t *testing.T, source string, sigName string) string {
	t.Helper()

	dir := t.TempDir()
	src := filepath.Join(dir, "src.go")
	if err := os.WriteFile(src, []byte(source), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	results, err := diff.FingerprintSource(src, source, ir.DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}

	var topo *topology.FunctionTopology
	for _, r := range results {
		if fn := r.GetSSAFunction(); fn != nil {
			topo = topology.ExtractTopology(fn)
			if topo != nil {
				break
			}
		}
	}
	if topo == nil {
		t.Fatalf("no extractable topology in source")
	}

	dbPath := filepath.Join(dir, "sigs.db")
	ps, err := pebbledb.NewPebbleScanner(dbPath, pebbledb.DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	sig := detection.IndexFunction(topo, sigName, "test seed", "HIGH", "test")
	sig.ID = "TEST-SEED-1"
	if err := ps.AddSignatures([]*detection.Signature{&sig}); err != nil {
		ps.Close()
		t.Fatalf("add sig: %v", err)
	}
	ps.Close()
	return dbPath
}

func TestScanTool_SelfMatch(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "target.go")
	if err := os.WriteFile(srcPath, []byte(goSourceWithGoroutine), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	dbPath := seedDBForFunction(t, goSourceWithGoroutine, "GoroutineSpawner")

	res := callTool(t, "sfw_scan", map[string]any{
		"target":    srcPath,
		"db_path":   dbPath,
		"threshold": 0.5,
	})
	if res.IsError {
		t.Fatalf("sfw_scan returned IsError=true: %s", textPayload(t, res))
	}

	var got struct {
		Backend      string `json:"backend"`
		TotalScanned int    `json:"total_functions_scanned"`
		Alerts       []struct {
			SignatureName   string  `json:"signature_name"`
			MatchedFunction string  `json:"matched_function"`
			Confidence      float64 `json:"confidence"`
			Severity        string  `json:"severity"`
		} `json:"alerts"`
		Summary struct {
			TotalAlerts int `json:"total_alerts"`
			HighAlerts  int `json:"high"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(textPayload(t, res)), &got); err != nil {
		t.Fatalf("scan unmarshal: %v\nbody:\n%s", err, textPayload(t, res))
	}

	if got.Backend != "pebbledb" {
		t.Errorf("backend = %q; want pebbledb", got.Backend)
	}
	if got.TotalScanned == 0 {
		t.Errorf("total_functions_scanned should be > 0; got 0")
	}
	if got.Summary.TotalAlerts == 0 {
		t.Fatalf("expected at least one alert from a self-match; got 0\nbody:\n%s", textPayload(t, res))
	}
	if got.Summary.HighAlerts == 0 {
		t.Errorf("summary.high = 0; want >= 1 (seed signature severity=HIGH)")
	}

	var sawSeed bool
	for _, a := range got.Alerts {
		if strings.Contains(a.SignatureName, "GoroutineSpawner") {
			sawSeed = true
		}
	}
	if !sawSeed {
		t.Errorf("seed signature name absent from alerts: %+v", got.Alerts)
	}
}

func TestScanTool_NoAlertsAgainstEmptyDB(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "target.go")
	if err := os.WriteFile(srcPath, []byte(goSourceWithGoroutine), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	dbPath := filepath.Join(dir, "empty.db")
	ps, err := pebbledb.NewPebbleScanner(dbPath, pebbledb.DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	ps.Close()

	res := callTool(t, "sfw_scan", map[string]any{
		"target":  srcPath,
		"db_path": dbPath,
	})
	if res.IsError {
		t.Fatalf("sfw_scan returned IsError=true: %s", textPayload(t, res))
	}
	if !strings.Contains(textPayload(t, res), `"total_alerts": 0`) {
		t.Errorf("expected total_alerts: 0 for empty DB; body:\n%s", textPayload(t, res))
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

func TestCheckTool_FingerprintsOnly(t *testing.T) {
	dir := t.TempDir()
	// Two files so we can verify directory recursion and the per-file
	// FileOutput shape both work.
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(goSourceWithGoroutine), 0o644); err != nil {
		t.Fatalf("write a: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.go"), []byte("package x\n\nfunc Add(a,b int) int { return a + b }\n"), 0o644); err != nil {
		t.Fatalf("write b: %v", err)
	}
	// _test.go files must be skipped to match CLI behaviour.
	if err := os.WriteFile(filepath.Join(dir, "z_test.go"), []byte("package x\n\nfunc IgnoreMe() {}\n"), 0o644); err != nil {
		t.Fatalf("write test: %v", err)
	}

	res := callTool(t, "sfw_check", map[string]any{"target": dir})
	if res.IsError {
		t.Fatalf("sfw_check returned IsError=true: %s", textPayload(t, res))
	}

	var got []struct {
		File      string `json:"file"`
		Functions []struct {
			Function    string `json:"function"`
			Fingerprint string `json:"fingerprint"`
		} `json:"functions"`
		ScanResults  []any  `json:"scan_results"`
		ErrorMessage string `json:"error"`
	}
	if err := json.Unmarshal([]byte(textPayload(t, res)), &got); err != nil {
		t.Fatalf("check unmarshal: %v\nbody:\n%s", err, textPayload(t, res))
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 files (test file skipped), got %d", len(got))
	}

	var sawIgnoreMe bool
	for _, fo := range got {
		if fo.ErrorMessage != "" {
			t.Errorf("unexpected error on %s: %s", fo.File, fo.ErrorMessage)
		}
		if fo.ScanResults != nil {
			t.Errorf("scan_results populated without db_path on %s", fo.File)
		}
		for _, fn := range fo.Functions {
			if fn.Fingerprint == "" {
				t.Errorf("missing fingerprint for %s::%s", fo.File, fn.Function)
			}
			if fn.Function == "IgnoreMe" {
				sawIgnoreMe = true
			}
		}
	}
	if sawIgnoreMe {
		t.Errorf("test file was scanned despite the _test.go filter")
	}
}

func TestCheckTool_NoGoFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# nope"), 0o644); err != nil {
		t.Fatalf("write readme: %v", err)
	}

	res := callTool(t, "sfw_check", map[string]any{"target": dir})
	if !res.IsError {
		t.Fatalf("expected IsError for directory with no Go files; body:\n%s", textPayload(t, res))
	}
	if got := textPayload(t, res); !strings.Contains(got, "no Go files") {
		t.Errorf("error should mention 'no Go files', got: %s", got)
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
