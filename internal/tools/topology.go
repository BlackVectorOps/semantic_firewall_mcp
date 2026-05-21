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
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/diff"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// topologySummary is the per-function digest returned when the caller
// did not pin a single function_name. It is intentionally narrow:
// enough for an agent to spot the suspicious entries (goroutines,
// panics, high entropy) without paging the full topology blob over.
type topologySummary struct {
	Function     string  `json:"function"`
	Line         int     `json:"line"`
	Fingerprint  string  `json:"fingerprint"`
	LoopCount    int     `json:"loop_count"`
	BranchCount  int     `json:"branch_count"`
	CallCount    int     `json:"call_count"`
	HasGo        bool    `json:"has_goroutine"`
	HasPanic     bool    `json:"has_panic"`
	HasDefer     bool    `json:"has_defer"`
	EntropyScore float64 `json:"entropy_score"`
}

// NewTopologyTool returns the sfw_topology tool definition and
// handler.
//
// Two modes:
//
//   - file_path only: list every function in the file with a slim
//     per-function digest (name, line, fingerprint, key control-flow
//     counts and flags, entropy score).
//   - file_path + function_name: return the full FunctionTopology
//     struct -- call signatures, instruction counts, string
//     literals, entropy profile, the lot -- for the matched
//     function.
//
// Function matching uses ShortFunctionName, so "main", "(*Server).Run",
// and "pkg.helper" all work without needing the fully-qualified SSA
// name the engine emits internally.
func NewTopologyTool() (mcp.Tool, server.ToolHandlerFunc) {
	tool := mcp.NewTool("sfw_topology",
		mcp.WithDescription(
			"Inspect the behavioural topology of Go functions. Without "+
				"function_name, returns a per-function digest of the "+
				"whole file (loop/branch/call counts, goroutine/panic/"+
				"defer flags, entropy score) so an agent can spot which "+
				"functions warrant a closer look. With function_name, "+
				"returns the full FunctionTopology struct for that one "+
				"function -- call signatures, instruction histogram, "+
				"string literals, entropy profile.",
		),
		mcp.WithString("file_path",
			mcp.Required(),
			mcp.Description("Absolute path to the Go source file to analyse."),
		),
		mcp.WithString("function_name",
			mcp.Description("Optional. Short name like \"main\" or \"(*Type).Method\". When set, returns the full topology for the matched function; when omitted, returns the per-function digest."),
		),
	)

	handler := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		filePath, err := req.RequireString("file_path")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("file_path: %v", err)), nil
		}
		funcName := req.GetString("function_name", "")

		src, err := os.ReadFile(filePath)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("sfw_topology: read", err), nil
		}

		results, err := diff.FingerprintSource(filePath, string(src), ir.DefaultLiteralPolicy)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("sfw_topology: fingerprint", err), nil
		}

		if funcName == "" {
			out := make([]topologySummary, 0, len(results))
			for _, r := range results {
				fn := r.GetSSAFunction()
				if fn == nil {
					continue
				}
				topo := topology.ExtractTopology(fn)
				if topo == nil {
					continue
				}
				out = append(out, topologySummary{
					Function:     api.ShortFunctionName(r.FunctionName),
					Line:         r.Line,
					Fingerprint:  r.Fingerprint,
					LoopCount:    topo.LoopCount,
					BranchCount:  topo.BranchCount,
					CallCount:    len(topo.CallSignatures),
					HasGo:        topo.HasGo,
					HasPanic:     topo.HasPanic,
					HasDefer:     topo.HasDefer,
					EntropyScore: topo.EntropyScore,
				})
			}
			body, mErr := json.MarshalIndent(out, "", "  ")
			if mErr != nil {
				return mcp.NewToolResultErrorFromErr("sfw_topology: marshal", mErr), nil
			}
			return mcp.NewToolResultText(string(body)), nil
		}

		// Single-function mode. Match by short name to spare the model
		// from needing to know the SSA mangling.
		want := strings.TrimSpace(funcName)
		for _, r := range results {
			if api.ShortFunctionName(r.FunctionName) != want {
				continue
			}
			fn := r.GetSSAFunction()
			if fn == nil {
				return mcp.NewToolResultError(fmt.Sprintf("function %q has no SSA body (likely external/synthetic)", want)), nil
			}
			topo := topology.ExtractTopology(fn)
			if topo == nil {
				return mcp.NewToolResultError(fmt.Sprintf("topology extraction failed for %q", want)), nil
			}
			body, mErr := json.MarshalIndent(topo, "", "  ")
			if mErr != nil {
				return mcp.NewToolResultErrorFromErr("sfw_topology: marshal", mErr), nil
			}
			return mcp.NewToolResultText(string(body)), nil
		}

		return mcp.NewToolResultError(fmt.Sprintf("function %q not found in %s", want, filePath)), nil
	}

	return tool, handler
}
