package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/BlackVectorOps/semantic_firewall_mcp/internal/agent"
	"github.com/BlackVectorOps/semantic_firewall_mcp/internal/provider"
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
		if err := runAudit(os.Args[2:]); err != nil {
			exit(err)
		}

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

// runAudit parses the audit-specific flags, resolves the provider
// adapter, and invokes the agent loop. Exit code mirrors v3's
// `sfw audit`: 0 for MATCH, 1 for SUSPICIOUS / LIE / ERROR so a CI
// gate keyed on the exit code keeps working.
func runAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	providerName := fs.String("provider", "anthropic", "LLM provider: anthropic | openai | gemini | openai-compatible")
	model := fs.String("model", "", "Provider-specific model identifier (required)")
	apiKey := fs.String("api-key", "", "API key (prefer the provider's env var: ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY)")
	apiBase := fs.String("api-base", "", "Override the API base URL (required for openai-compatible)")
	maxSteps := fs.Int("max-steps", 0, "Maximum tool-use iterations (default 8)")
	maxTokens := fs.Int("max-tokens", 0, "Maximum tokens per assistant turn (default 2048)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 3 {
		fmt.Fprintln(os.Stderr, "usage: sfw-mcp audit <old.go> <new.go> \"<commit message>\" [flags]")
		os.Exit(2)
	}
	oldPath := fs.Arg(0)
	newPath := fs.Arg(1)
	commitMsg := fs.Arg(2)

	if *model == "" {
		return fmt.Errorf("--model is required (e.g. claude-opus-4-7, gpt-4o, gemini-2.5-pro)")
	}

	p, err := buildProvider(*providerName, *apiKey, *apiBase)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	verdict, err := agent.RunAudit(ctx, p, *model, oldPath, newPath, commitMsg, agent.LoopOptions{
		MaxSteps:  *maxSteps,
		MaxTokens: *maxTokens,
	})
	if err != nil {
		// agent.RunAudit already populated verdict with an ERROR
		// payload; emit it so the caller still gets the structured
		// JSON, then surface the underlying error via exit code.
		writeVerdict(verdict)
		return err
	}
	writeVerdict(verdict)

	// Exit code mirrors v3's `sfw audit`: 0 only when the verdict
	// is MATCH; SUSPICIOUS, LIE, and ERROR all exit 1 so an
	// existing CI gate keeps tripping the same way.
	if verdict.Verdict != agent.VerdictMatch {
		os.Exit(1)
	}
	return nil
}

// buildProvider picks the adapter and resolves the API key from the
// flag or the provider-specific env var.
//
//   anthropic            -> ANTHROPIC_API_KEY
//   openai               -> OPENAI_API_KEY
//   gemini               -> GEMINI_API_KEY
//   openai-compatible    -> OPENAI_API_KEY (or OPENAI_COMPAT_API_KEY)
func buildProvider(name, apiKey, apiBase string) (provider.Provider, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "anthropic", "claude":
		if apiKey == "" {
			apiKey = os.Getenv("ANTHROPIC_API_KEY")
		}
		if apiKey == "" {
			return nil, fmt.Errorf("anthropic: ANTHROPIC_API_KEY not set (or pass --api-key)")
		}
		return provider.NewAnthropic(apiKey), nil
	case "openai", "gpt":
		if apiKey == "" {
			apiKey = os.Getenv("OPENAI_API_KEY")
		}
		if apiKey == "" {
			return nil, fmt.Errorf("openai: OPENAI_API_KEY not set (or pass --api-key)")
		}
		return provider.NewOpenAIWithBase(apiKey, apiBase), nil
	case "gemini", "google":
		if apiKey == "" {
			apiKey = os.Getenv("GEMINI_API_KEY")
		}
		if apiKey == "" {
			apiKey = os.Getenv("GOOGLE_API_KEY")
		}
		if apiKey == "" {
			return nil, fmt.Errorf("gemini: GEMINI_API_KEY (or GOOGLE_API_KEY) not set (or pass --api-key)")
		}
		return provider.NewGemini(apiKey), nil
	case "openai-compatible", "compat":
		if apiKey == "" {
			apiKey = os.Getenv("OPENAI_COMPAT_API_KEY")
		}
		if apiKey == "" {
			apiKey = os.Getenv("OPENAI_API_KEY")
		}
		if apiKey == "" {
			return nil, fmt.Errorf("openai-compatible: OPENAI_COMPAT_API_KEY (or OPENAI_API_KEY) not set (or pass --api-key)")
		}
		return provider.NewOpenAICompatible(apiKey, apiBase)
	default:
		return nil, fmt.Errorf("unknown provider %q (want: anthropic, openai, gemini, openai-compatible)", name)
	}
}

// writeVerdict prints the audit JSON to stdout. We do it from the
// command rather than from inside agent.RunAudit so the agent stays
// stdout-agnostic and can be reused from a future programmatic
// caller without forcing them to capture stdout.
func writeVerdict(v agent.AuditVerdict) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

