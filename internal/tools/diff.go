// Package tools holds the MCP tool implementations that wrap sfw's
// analysis library. Each file owns one tool: a New<Name>Tool constructor
// returning (mcp.Tool, server.ToolHandlerFunc) so the registry can
// attach the pair atomically.
package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/api"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// NewDiffTool returns the sfw_diff tool definition and handler.
//
// sfw_diff compares two Go source files and returns the semantic delta:
// preserved/modified/added/removed functions, topology changes, risk
// scores, and per-function fingerprints. It is the read-only equivalent
// of the `sfw diff` CLI subcommand.
func NewDiffTool() (mcp.Tool, server.ToolHandlerFunc) {
	tool := mcp.NewTool("sfw_diff",
		mcp.WithDescription(
			"Compute the semantic diff between two Go source files. "+
				"Returns structured JSON with preserved/modified/added/removed "+
				"functions, topology deltas, risk scores, and fingerprints. "+
				"Use this to investigate what a commit actually changed "+
				"behaviourally, not just textually. Either path may point at "+
				"/dev/null (or a non-existent file) to represent an added or "+
				"removed file.",
		),
		mcp.WithString("old_path",
			mcp.Required(),
			mcp.Description("Absolute path to the pre-change Go file. Use /dev/null for newly added files."),
		),
		mcp.WithString("new_path",
			mcp.Required(),
			mcp.Description("Absolute path to the post-change Go file. Use /dev/null for deleted files."),
		),
	)

	handler := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		oldPath, err := req.RequireString("old_path")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("old_path: %v", err)), nil
		}
		newPath, err := req.RequireString("new_path")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("new_path: %v", err)), nil
		}

		// api.Diff returns the same DiffOutput shape the CLI emits; we
		// marshal it to JSON so the model gets structured evidence it
		// can reason about (and downstream tool_results can re-parse).
		out, err := api.Diff(oldPath, newPath)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("sfw_diff failed", err), nil
		}

		body, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return mcp.NewToolResultErrorFromErr("sfw_diff: marshal", err), nil
		}
		return mcp.NewToolResultText(string(body)), nil
	}

	return tool, handler
}
