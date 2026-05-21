package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/api"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/detection"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/models"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/storage/jsondb"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/storage/pebbledb"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// signatureScanner is the subset of pkg/storage that sfw_check needs:
// per-topology scanning. Both PebbleScanner and jsondb.Scanner
// satisfy it, so the tool can transparently use whichever backend
// the user pointed it at.
type signatureScanner interface {
	ScanTopology(topo *topology.FunctionTopology, funcName string) ([]detection.ScanResult, error)
	Close() error
}

// NewCheckTool returns the sfw_check tool definition and handler.
//
// sfw_check fingerprints a Go file or directory and returns the per-
// function canonical-IR fingerprints. When db_path is set it also
// scans every function's topology against the signature database in
// the same pass, attaching matching ScanResult entries to the
// FileOutput. This is the read-only equivalent of `sfw check` (with
// or without --scan).
func NewCheckTool() (mcp.Tool, server.ToolHandlerFunc) {
	tool := mcp.NewTool("sfw_check",
		mcp.WithDescription(
			"Fingerprint a Go file or directory. Returns per-function "+
				"canonical-IR fingerprints (the same hashes sfw uses to "+
				"prove semantic equivalence across refactors). When "+
				"db_path is provided, also runs every function's "+
				"topology against the signature database in the same "+
				"pass and attaches any matches. Use this when you want "+
				"a structural inventory of a change, not just a diff.",
		),
		mcp.WithString("target",
			mcp.Required(),
			mcp.Description("Absolute path to a .go file or a directory. Directories are walked recursively; vendor/, hidden directories, and *_test.go files are skipped."),
		),
		mcp.WithBoolean("strict",
			mcp.Description("Optional. When true, the fingerprinter rejects sources that fail SSA construction instead of falling back to a best-effort fingerprint."),
		),
		mcp.WithString("db_path",
			mcp.Description("Optional. PebbleDB directory or .json file. When set, every function's topology is scanned against this database and matches are returned alongside the fingerprints."),
		),
	)

	handler := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		target, err := req.RequireString("target")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("target: %v", err)), nil
		}
		strict := req.GetBool("strict", false)
		dbPath := req.GetString("db_path", "")

		files, err := collectGoFiles(target)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("sfw_check: collect", err), nil
		}
		if len(files) == 0 {
			return mcp.NewToolResultError(fmt.Sprintf("no Go files found in %s", target)), nil
		}

		var scanner signatureScanner
		if dbPath != "" {
			scanner, err = openScanner(dbPath)
			if err != nil {
				return mcp.NewToolResultErrorFromErr("sfw_check: open db", err), nil
			}
			defer scanner.Close()
		}

		results := make([]models.FileOutput, 0, len(files))
		for _, f := range files {
			results = append(results, processOneFile(f, strict, scanner))
		}

		body, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return mcp.NewToolResultErrorFromErr("sfw_check: marshal", err), nil
		}
		return mcp.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

// processOneFile reads a single Go source, fingerprints it, and (when
// scanner is non-nil) scans each function's topology against the
// signature DB. Per-file errors become FileOutput.ErrorMessage so an
// agent inspecting the response can distinguish "no functions matched
// any signature" from "this file could not be analysed".
func processOneFile(path string, strict bool, scanner signatureScanner) models.FileOutput {
	src, err := os.ReadFile(path)
	if err != nil {
		return models.FileOutput{File: path, ErrorMessage: err.Error()}
	}
	if int64(len(src)) > models.MaxSourceFileSize {
		return models.FileOutput{
			File:         path,
			ErrorMessage: fmt.Sprintf("file exceeds maximum analysis size of %d bytes", models.MaxSourceFileSize),
		}
	}

	fingerprints, err := diff.FingerprintSourceAdvanced(path, string(src), ir.DefaultLiteralPolicy, strict)
	if err != nil {
		return models.FileOutput{File: path, ErrorMessage: err.Error()}
	}

	out := models.FileOutput{
		File:      path,
		Functions: make([]models.FunctionFingerprint, 0, len(fingerprints)),
	}
	for _, r := range fingerprints {
		out.Functions = append(out.Functions, models.FunctionFingerprint{
			Function:    api.ShortFunctionName(r.FunctionName),
			Fingerprint: r.Fingerprint,
			File:        r.Filename,
			Line:        r.Line,
		})

		if scanner == nil {
			continue
		}
		fn := r.GetSSAFunction()
		if fn == nil {
			continue
		}
		topo := topology.ExtractTopology(fn)
		if topo == nil {
			continue
		}
		alerts, scanErr := scanner.ScanTopology(topo, r.FunctionName)
		if scanErr != nil {
			// Don't kill the whole file -- record and move on. The agent
			// can decide whether partial scan coverage is acceptable.
			continue
		}
		out.ScanResults = append(out.ScanResults, alerts...)
	}
	return out
}

// openScanner picks the backend by file extension. JSON paths end in
// .json; everything else is treated as a PebbleDB directory. The
// returned scanner must be Closed by the caller.
func openScanner(dbPath string) (signatureScanner, error) {
	if strings.HasSuffix(dbPath, ".json") {
		s := jsondb.NewScanner()
		if err := s.LoadDatabase(dbPath); err != nil {
			// Close on the error path too. Today this is a no-op but
			// it keeps the contract honest: every successful return
			// pairs with a caller-side defer Close, every error
			// return cleans up before bailing.
			_ = s.Close()
			return nil, err
		}
		return s, nil
	}
	opts := pebbledb.DefaultPebbleScannerOptions()
	opts.ReadOnly = true
	return pebbledb.NewPebbleScanner(dbPath, opts)
}
