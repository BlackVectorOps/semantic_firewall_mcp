package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/BlackVectorOps/semantic_firewall_mcp/internal/server"
)

func usage() {
	fmt.Fprint(os.Stderr, `sfw-mcp - Semantic Firewall MCP server and agent

Usage:
  sfw-mcp serve                              Start MCP server on stdio
  sfw-mcp audit <old> <new> "<message>"      Run the audit agent loop (one-shot)
  sfw-mcp version                            Print version

The serve mode exposes sfw's analysis tools (diff, scan, check, topology,
stats) over MCP/stdio. Any MCP-aware agent (Claude Code, Cursor, Zed,
Continue, etc.) can drive it.

The audit mode runs an internal agent loop against the chosen LLM
provider to verify whether a commit message matches the structural code
changes. It is the v4 replacement for the old "sfw audit" command.

Flags for "audit":
  --provider   anthropic | openai | gemini | openai-compatible
  --model      Provider-specific model identifier
  --api-key    API key (prefer the provider env var instead)
  --api-base   Override the API base URL (required for openai-compatible)
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		if err := fs.Parse(os.Args[2:]); err != nil {
			exit(err)
		}
		if err := server.ServeStdio(); err != nil {
			exit(err)
		}

	case "audit":
		// Wired up in a later commit once the provider layer + agent loop land.
		fmt.Fprintln(os.Stderr, "audit: not implemented yet (lands with the provider + agent commits)")
		os.Exit(2)

	case "version", "-v", "--version":
		fmt.Println("sfw-mcp v4.0.0-dev")

	case "-h", "--help":
		usage()

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func exit(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
