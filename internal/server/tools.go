package server

import "github.com/mark3labs/mcp-go/server"

// registerTools is the single place where every sfw tool gets attached to
// the MCP server. Tool implementations live in internal/tools and are
// wired up incrementally; the scaffold deliberately starts empty and is
// filled in one tool per commit.
func registerTools(_ *server.MCPServer) {
	// sfw_diff, sfw_scan, sfw_check, sfw_topology, sfw_stats land in
	// subsequent commits.
}
