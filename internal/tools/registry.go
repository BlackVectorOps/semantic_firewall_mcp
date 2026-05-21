package tools

import (
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// All returns every sfw tool the package ships, paired with its
// handler. Both surfaces consume this list:
//
//   - server.registerTools iterates it to attach the tools to the
//     MCP server boot path.
//   - agent.Loop iterates it to build the provider-side ToolSpec list
//     and to dispatch tool_use blocks received from the LLM.
//
// Keeping a single registry means a new tool becomes available on
// the MCP serve surface and the in-process agent simultaneously --
// the agent can never drift behind the published tool list.
func All() []server.ServerTool {
	return []server.ServerTool{
		wrap(NewDiffTool()),
		wrap(NewStatsTool()),
		wrap(NewTopologyTool()),
		wrap(NewCheckTool()),
		wrap(NewScanTool()),
	}
}

func wrap(t mcp.Tool, h server.ToolHandlerFunc) server.ServerTool {
	return server.ServerTool{Tool: t, Handler: h}
}
