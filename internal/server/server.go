// Package server boots the Semantic Firewall MCP server over stdio and
// registers the sfw analysis tools. Tools themselves live in
// internal/tools and are wired up in tools.go.
package server

import (
	"github.com/mark3labs/mcp-go/server"
)

const (
	serverName    = "semantic-firewall"
	serverVersion = "4.0.0-dev"
)

// New constructs an MCPServer with all sfw tools registered but does not
// start any transport. Useful for tests that want to drive the server in
// process without spinning up stdio.
func New() *server.MCPServer {
	s := server.NewMCPServer(
		serverName,
		serverVersion,
		server.WithToolCapabilities(true),
	)
	registerTools(s)
	return s
}

// ServeStdio starts the MCP server on stdin/stdout. Blocks until the
// client disconnects or stdin closes.
func ServeStdio() error {
	return server.ServeStdio(New())
}
