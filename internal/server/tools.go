package server

import (
	"github.com/BlackVectorOps/semantic_firewall_mcp/internal/tools"
	"github.com/mark3labs/mcp-go/server"
)

// registerTools is the single place where every sfw tool gets attached
// to the MCP server. Each tool constructor in internal/tools returns
// the (Tool, Handler) pair; doing the wiring here keeps server.go
// transport-only and lets tests register a subset by hand.
func registerTools(s *server.MCPServer) {
	s.AddTool(tools.NewDiffTool())
	// sfw_scan, sfw_check, sfw_topology, sfw_stats land in subsequent
	// commits.
}
