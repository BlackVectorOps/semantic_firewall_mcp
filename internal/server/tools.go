package server

import (
	"github.com/BlackVectorOps/semantic_firewall_mcp/internal/tools"
	"github.com/mark3labs/mcp-go/server"
)

// registerTools attaches the canonical tool list to the MCP server.
// The list itself lives in internal/tools.All so the in-process agent
// can iterate it too and never drift from the published surface.
func registerTools(s *server.MCPServer) {
	s.AddTools(tools.All()...)
}
