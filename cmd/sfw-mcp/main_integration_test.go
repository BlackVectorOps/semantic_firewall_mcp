package main_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestServeStdio_EndToEnd boots the real sfw-mcp binary in `serve`
// mode, drives it over actual stdin/stdout using line-delimited JSON
// (the wire format mcp-go's stdio transport speaks), and asserts on
// the responses. This is the test that catches anything an
// in-process server_test.go would miss: stdin scanner buffering,
// missing newlines on output, environment leakage, the shutdown
// path on EOF, etc.
//
// Skipped if "go build" is unavailable in the test environment.
func TestServeStdio_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped under -short")
	}

	// Build a fresh binary into a tempdir so the test isolates from
	// whatever sfw-mcp the developer has on PATH.
	bin := filepath.Join(t.TempDir(), "sfw-mcp")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build sfw-mcp failed: %v\n%s", err, out)
	}

	// Prepare two Go files for the diff tool to chew on.
	srcDir := t.TempDir()
	oldPath := filepath.Join(srcDir, "a.go")
	newPath := filepath.Join(srcDir, "b.go")
	if err := os.WriteFile(oldPath, []byte("package x\n\nfunc F() int { return 1 }\n"), 0o644); err != nil {
		t.Fatalf("write a: %v", err)
	}
	if err := os.WriteFile(newPath, []byte("package x\n\nfunc F() int { return 2 }\n"), 0o644); err != nil {
		t.Fatalf("write b: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "serve")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start sfw-mcp: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
		if t.Failed() && stderr.Len() > 0 {
			t.Logf("sfw-mcp stderr:\n%s", stderr.String())
		}
	})

	scanner := bufio.NewScanner(stdout)
	// MCP messages can be larger than the default 64KB scan token.
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	// readResponse consumes the next JSON-RPC line from stdout.
	readResponse := func() map[string]any {
		t.Helper()
		// stdio mcp-go writes one JSON message per line. Wait for
		// the next one with a soft deadline so a hang turns into a
		// readable failure instead of timing the whole suite out.
		done := make(chan bool, 1)
		var line string
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			if scanner.Scan() {
				line = scanner.Text()
				done <- true
			} else {
				done <- false
			}
		}()
		select {
		case ok := <-done:
			if !ok {
				t.Fatalf("stdout closed before response; stderr:\n%s", stderr.String())
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("timed out waiting for response; stderr so far:\n%s", stderr.String())
		}
		var msg map[string]any
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Fatalf("unmarshal response %q: %v", line, err)
		}
		return msg
	}

	send := func(payload map[string]any) {
		t.Helper()
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		if _, err := io.WriteString(stdin, string(raw)+"\n"); err != nil {
			t.Fatalf("write request: %v", err)
		}
	}

	// 1. initialize handshake. mcp-go's stdio server requires this
	// before any tools/call requests are accepted.
	send(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo": map[string]any{
				"name":    "sfw-mcp-integration-test",
				"version": "0.0.0",
			},
		},
	})
	resp := readResponse()
	if errObj, ok := resp["error"]; ok {
		t.Fatalf("initialize errored: %v", errObj)
	}
	if _, ok := resp["result"]; !ok {
		t.Fatalf("initialize response missing result: %+v", resp)
	}

	// initialized notification (no response).
	send(map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
		"params":  map[string]any{},
	})

	// 2. tools/list -- the server should advertise all five sfw tools.
	send(map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
	})
	resp = readResponse()
	if errObj, ok := resp["error"]; ok {
		t.Fatalf("tools/list errored: %v", errObj)
	}
	result, _ := resp["result"].(map[string]any)
	toolsRaw, _ := result["tools"].([]any)
	if len(toolsRaw) < 5 {
		t.Fatalf("expected >=5 tools, got %d: %+v", len(toolsRaw), toolsRaw)
	}
	want := map[string]bool{
		"sfw_diff": false, "sfw_check": false, "sfw_scan": false,
		"sfw_topology": false, "sfw_stats": false,
	}
	for _, raw := range toolsRaw {
		tm, _ := raw.(map[string]any)
		if name, ok := tm["name"].(string); ok {
			if _, expected := want[name]; expected {
				want[name] = true
			}
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("tools/list missing %q", name)
		}
	}

	// 3. tools/call sfw_diff and confirm the result is a parseable
	// DiffOutput.
	send(map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "sfw_diff",
			"arguments": map[string]any{
				"old_path": oldPath,
				"new_path": newPath,
			},
		},
	})
	resp = readResponse()
	if errObj, ok := resp["error"]; ok {
		t.Fatalf("sfw_diff errored: %v", errObj)
	}
	result, _ = resp["result"].(map[string]any)
	contentRaw, _ := result["content"].([]any)
	if len(contentRaw) != 1 {
		t.Fatalf("expected 1 content block, got %d", len(contentRaw))
	}
	contentBlock, _ := contentRaw[0].(map[string]any)
	bodyText, _ := contentBlock["text"].(string)
	if !strings.Contains(bodyText, `"old_file"`) {
		t.Fatalf("sfw_diff body is not a DiffOutput: %s", bodyText)
	}

	// Close stdin -- mcp-go shuts down on EOF. The Cleanup waits the
	// process out.
	if err := stdin.Close(); err != nil {
		t.Logf("close stdin: %v", err)
	}
}

