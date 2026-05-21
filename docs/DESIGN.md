# Semantic Firewall MCP — Design

## Why a separate repo

`semantic_firewall` (v4) is the analysis engine: AST → SSA →
canonicalized IR → topology fingerprints → signature index. It must
keep building as a self-contained Go library and CLI with no LLM or
network surface in its hot path. The agentic surface lives here so it
can iterate on providers, prompts, and tool-use protocols without
churning the engine.

## Architecture

```
            ┌───────────────────────────────────────────────┐
            │            sfw-mcp (this repo)                │
            │                                                │
   stdio    │  ┌────────────┐    ┌──────────────────────┐   │
  ◄────────►│  │ MCP server │    │      agent loop       │   │
            │  │  (serve)   │    │  (audit subcommand)   │   │
            │  └─────┬──────┘    └──────────┬───────────┘   │
            │        │                       │              │
            │        ▼                       ▼              │
            │  ┌─────────────────────────────────────────┐  │
            │  │            tools (read-only)            │  │
            │  │ sfw_diff  sfw_scan  sfw_check           │  │
            │  │ sfw_topology  sfw_stats                 │  │
            │  └────────────────────┬────────────────────┘  │
            │                       │                       │
            │                       ▼                       │
            │      ┌──────────────────────────────┐         │
            │      │  github.com/BlackVectorOps/  │         │
            │      │   semantic_firewall/v4 (lib) │         │
            │      └──────────────────────────────┘         │
            │                                                │
            │  ┌──────────────────────────────────────────┐ │
            │  │              provider                     │ │
            │  │  anthropic │ openai │ gemini │ compat   │ │
            │  └──────────────────────────────────────────┘ │
            └───────────────────────────────────────────────┘
```

Two front-end surfaces share the same `tools` and `provider` cores:

- **`sfw-mcp serve`** — MCP server on stdio. External agents (Claude
  Code, Cursor, Zed, Continue) call tools directly. No internal LLM
  involvement.
- **`sfw-mcp audit`** — one-shot agent loop. Uses the same `tools`
  registry, but the LLM is driven internally via a `provider`
  adapter, replacing the v3 `sfw audit` subcommand.

## Tools (v4 scope: read-only)

| Tool          | Wraps                              | Purpose                                            |
|---------------|------------------------------------|----------------------------------------------------|
| `sfw_diff`    | `pkg/diff` + `cli.ComputeDiff`     | Semantic diff between two Go files                  |
| `sfw_scan`    | `cli.RunScanLogic`                 | Signature scan a file/dir against the malware DB    |
| `sfw_check`   | `cli.RunCheckLogic`                | Fingerprint a file/dir; optional inline scan       |
| `sfw_topology`| `pkg/analysis/topology`            | Extract topology of a specific function             |
| `sfw_stats`   | `cli.RunStats`                     | Inspect a signature database                        |

No mutating tools (`sfw_index`, `sfw_migrate`) in v4. Adding them
later is a deliberate scope expansion and needs authorization on
each call.

## Provider abstraction

All providers expose the same surface so the agent loop can stay
provider-agnostic:

```go
type Provider interface {
    Name() string
    Complete(ctx context.Context, req Request) (*Response, error)
}

type Request struct {
    System      string
    Messages    []Message
    Tools       []ToolSpec
    Model       string
    MaxTokens   int
    Temperature float64
}

type Response struct {
    Content    []ContentBlock  // text + tool_use blocks
    StopReason StopReason      // end_turn | tool_use | max_tokens
    Usage      Usage
}
```

Adapter notes:

- **Anthropic** — reference implementation. Uses native tool_use
  blocks and prompt caching. Reads `ANTHROPIC_API_KEY`.
- **OpenAI** — Responses API + structured outputs. Reads
  `OPENAI_API_KEY`. Carried over from sfw v3's `internal/llm`
  with the same retry logic.
- **Gemini** — `google/genai` SDK with function calling. Reads
  `GEMINI_API_KEY`.
- **OpenAI-compatible** — covers DeepSeek, Mistral, Groq, Ollama,
  vLLM, llama.cpp server, anything that speaks the chat completions
  schema. Just OpenAI adapter pointed at `--api-base` and using
  `OPENAI_API_KEY` (or `OPENAI_COMPAT_API_KEY` if set).

The v3 home-brewed "AI Security Sentinel" pre-call is dropped.
Structured outputs + tool use eliminate the prompt-injection class
the Sentinel was meant to mitigate; relying on a model to police its
own input was always a weak defense.

## Agent loop (audit)

1. Receive `(old_path, new_path, commit_message, provider, model)`.
2. Bootstrap: system prompt explains the task; user message contains
   only the commit message and file paths — *no* pre-computed
   evidence.
3. Loop until `stop_reason == end_turn` or step cap reached:
   - Call provider.
   - For each `tool_use` block in the response, dispatch to the
     `tools` registry and append the result as a `tool_result`.
4. Final response must parse as `{verdict: MATCH|SUSPICIOUS|LIE,
   evidence: string}`. Provider-specific structured output enforces
   the schema where supported.

The agent decides what to look at — `sfw_diff` first, then `sfw_scan`
on the diff if anything is suspicious, then `sfw_topology` on
specific functions. Trivial PRs never need the LLM to call beyond
`sfw_diff` (or even at all if structural risk is zero).

## Non-goals (v4)

- No HTTP/SSE transport. stdio only.
- No agent-driven mutation of the signature database.
- No agent-driven shell access. The model can only touch sfw tools.
- No remote/hosted deployment story. Each user runs their own
  `sfw-mcp` locally; the GitHub Action ships a binary the same way
  it does today.
