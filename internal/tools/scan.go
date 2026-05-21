package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
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

// scanScanner extends signatureScanner with ScanTopologyExact, which
// sfw_scan needs when the caller requested exact-only matching.
type scanScanner interface {
	signatureScanner
	ScanTopologyExact(topo *topology.FunctionTopology, funcName string) (*detection.ScanResult, error)
}

// NewScanTool returns the sfw_scan tool definition and handler.
//
// sfw_scan walks the target (file or directory), fingerprints every
// non-test Go source, and scans each function's topology against the
// signature database. Returns a models.ScanOutput with aggregated
// alerts sorted by severity, plus a per-severity summary that mirrors
// what `sfw scan` printed in v3.
//
// Dependency scanning (--deps in v3) is intentionally out of scope for
// the read-only v4 surface: it needs `go/packages` loading which
// reaches outside the immediate target tree and complicates the
// security story.
func NewScanTool() (mcp.Tool, server.ToolHandlerFunc) {
	tool := mcp.NewTool("sfw_scan",
		mcp.WithDescription(
			"Scan a Go file or directory against a Semantic Firewall "+
				"signature database. Returns matched alerts grouped "+
				"by severity (critical/high/medium/low) with the "+
				"matched function, signature ID, and confidence "+
				"score. Use this to confirm or rule out known "+
				"malware patterns after sfw_diff or sfw_topology "+
				"surfaced something suspicious.",
		),
		mcp.WithString("target",
			mcp.Required(),
			mcp.Description("Absolute path to a .go file or a directory. Directories are walked recursively; vendor/, hidden directories, and *_test.go files are skipped."),
		),
		mcp.WithString("db_path",
			mcp.Required(),
			mcp.Description("Path to the signature database. PebbleDB stores are directories; legacy JSON stores end in .json."),
		),
		mcp.WithNumber("threshold",
			mcp.Description("Optional. Match confidence threshold in [0,1]. Defaults to 0.75 (the same default as the v3 CLI). 1.0 demands an exact match."),
		),
		mcp.WithBoolean("exact",
			mcp.Description("Optional. When true, bypass the fuzzy index entirely and only report exact topology-hash matches. Faster on large databases; misses obfuscated variants."),
		),
	)

	handler := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		target, err := req.RequireString("target")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("target: %v", err)), nil
		}
		dbPath, err := req.RequireString("db_path")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("db_path: %v", err)), nil
		}
		threshold := req.GetFloat("threshold", 0.75)
		exactOnly := req.GetBool("exact", false)

		files, err := collectGoFiles(target)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("sfw_scan: collect", err), nil
		}
		if len(files) == 0 {
			return mcp.NewToolResultError(fmt.Sprintf("no Go files found in %s", target)), nil
		}

		scanner, backend, err := openScanScanner(dbPath, threshold, exactOnly)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("sfw_scan: open db", err), nil
		}
		defer scanner.Close()

		var (
			allAlerts      []detection.ScanResult
			totalFunctions int
		)
		for _, f := range files {
			alerts, count := scanOneFile(f, scanner, exactOnly)
			allAlerts = append(allAlerts, alerts...)
			totalFunctions += count
		}

		// Deterministic ordering: alerts first by matched function,
		// then by signature ID. Stable output keeps test diffs and
		// audit logs sane.
		sort.Slice(allAlerts, func(i, j int) bool {
			if allAlerts[i].MatchedFunction != allAlerts[j].MatchedFunction {
				return allAlerts[i].MatchedFunction < allAlerts[j].MatchedFunction
			}
			return allAlerts[i].SignatureName < allAlerts[j].SignatureName
		})

		summary := models.ScanSummary{TotalAlerts: len(allAlerts)}
		for _, a := range allAlerts {
			switch strings.ToUpper(a.Severity) {
			case "CRITICAL":
				summary.CriticalAlerts++
			case "HIGH":
				summary.HighAlerts++
			case "MEDIUM":
				summary.MediumAlerts++
			case "LOW":
				summary.LowAlerts++
			}
		}

		out := models.ScanOutput{
			Target:       target,
			Database:     dbPath,
			Backend:      backend,
			Threshold:    threshold,
			TotalScanned: totalFunctions,
			Alerts:       allAlerts,
			Summary:      summary,
		}
		body, mErr := json.MarshalIndent(out, "", "  ")
		if mErr != nil {
			return mcp.NewToolResultErrorFromErr("sfw_scan: marshal", mErr), nil
		}
		return mcp.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

// scanOneFile fingerprints a single file and runs each function's
// topology through the scanner. A per-file read or fingerprint error
// is swallowed (and the function count returns 0) so a single
// corrupted source does not bring down a directory scan; the agent
// will see a missing function in the count if it cares.
func scanOneFile(path string, s scanScanner, exactOnly bool) ([]detection.ScanResult, int) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, 0
	}
	if int64(len(src)) > models.MaxSourceFileSize {
		return nil, 0
	}
	results, err := diff.FingerprintSource(path, string(src), ir.DefaultLiteralPolicy)
	if err != nil {
		return nil, 0
	}

	var alerts []detection.ScanResult
	count := 0
	for _, r := range results {
		fn := r.GetSSAFunction()
		if fn == nil {
			continue
		}
		topo := topology.ExtractTopology(fn)
		if topo == nil {
			continue
		}
		count++
		funcName := api.ShortFunctionName(r.FunctionName)

		if exactOnly {
			if alert, err := s.ScanTopologyExact(topo, funcName); err == nil && alert != nil {
				alerts = append(alerts, *alert)
			}
			continue
		}
		if matched, err := s.ScanTopology(topo, funcName); err == nil {
			alerts = append(alerts, matched...)
		}
	}
	return alerts, count
}

// openScanScanner constructs a scanner pre-configured with the
// requested threshold. PebbleDB applies it via the options struct at
// open time (cheaper than SetThreshold post-hoc); JSON calls
// SetThreshold afterwards because that backend rejects values
// outside [0,1] explicitly. exactOnly bumps the JSON threshold to 1.0
// to mirror the CLI's `sfw scan --exact` behaviour for the JSON path.
func openScanScanner(dbPath string, threshold float64, exactOnly bool) (scanScanner, string, error) {
	if strings.HasSuffix(dbPath, ".json") {
		s := jsondb.NewScanner()
		if err := s.LoadDatabase(dbPath); err != nil {
			return nil, "", err
		}
		t := threshold
		if exactOnly {
			t = 1.0
		}
		if err := s.SetThreshold(t); err != nil {
			s.Close()
			return nil, "", err
		}
		return s, "json", nil
	}

	opts := pebbledb.DefaultPebbleScannerOptions()
	opts.MatchThreshold = threshold
	opts.ReadOnly = true
	ps, err := pebbledb.NewPebbleScanner(dbPath, opts)
	if err != nil {
		return nil, "", err
	}
	return ps, "pebbledb", nil
}
