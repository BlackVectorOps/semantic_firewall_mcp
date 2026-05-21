# Semantic Firewall MCP

MCP server and agent harness for [Semantic Firewall](https://github.com/BlackVectorOps/semantic_firewall).

Exposes sfw's behavioral analysis tools (`diff`, `scan`, `check`,
`topology`, `stats`) over MCP/stdio so any MCP-aware agent — Claude
Code, Cursor, Zed, Continue — can drive them directly. Also ships a
one-shot `audit` mode that runs an internal agent loop against the
LLM provider of your choice (Anthropic, OpenAI, Gemini, or any
OpenAI-compatible endpoint) to investigate whether a commit message
matches its structural changes.

> **Status:** unreleased. Built against `semantic_firewall` v4, which
> itself is gated on this server landing. During development the
> module uses a local `replace` directive against
> `../semantic_firewall`; the v4.0.0 tag will drop the replace and
> pin the real version.

## Install

```bash
go install github.com/BlackVectorOps/semantic_firewall_mcp/cmd/sfw-mcp@latest
```

## Use it as an MCP server

```bash
sfw-mcp serve
```

`serve` speaks MCP over stdio. Any MCP-aware client can connect.
Example configuration for Claude Code's `~/.claude.json`:

```json
{
  "mcpServers": {
    "semantic-firewall": {
      "command": "sfw-mcp",
      "args": ["serve"]
    }
  }
}
```

Tools published over MCP:

| Tool          | Purpose                                                                  |
|---------------|--------------------------------------------------------------------------|
| `sfw_diff`    | Semantic diff between two Go files                                        |
| `sfw_check`   | Fingerprint a file or directory; optional inline signature scan          |
| `sfw_scan`    | Scan a target against a malware signature database                        |
| `sfw_topology`| Per-function topology digest, or full topology for one named function    |
| `sfw_stats`   | Inspect a signature database (backend, counts, on-disk size)              |

Every tool is read-only — no signature mutations, no shell access, no
package loading outside the immediate target tree. The blast radius
of an LLM tool call is bounded to "compute something and return JSON".

## Use it as a one-shot audit

`audit` runs an internal agent loop against the provider you select.
The agent calls the same tools an external MCP client would, then
emits a verdict JSON on stdout.

```bash
sfw-mcp audit old.go new.go "fix typo" \
  --provider anthropic \
  --model claude-opus-4-7
```

Exit code mirrors v3's `sfw audit`: **0 for MATCH**, **1 for
SUSPICIOUS / LIE / ERROR**.

### Provider matrix

| `--provider`          | API                              | Env var                                  | Models                                                       |
|-----------------------|----------------------------------|------------------------------------------|--------------------------------------------------------------|
| `anthropic`           | Messages API                     | `ANTHROPIC_API_KEY`                      | `claude-opus-4-7`, `claude-sonnet-4-6`, `claude-haiku-4-5`   |
| `openai`              | Responses API                    | `OPENAI_API_KEY`                         | `gpt-5`, `gpt-4o`, `o3`, anything supported by your account  |
| `gemini`              | google.golang.org/genai          | `GEMINI_API_KEY` or `GOOGLE_API_KEY`     | `gemini-2.5-pro`, `gemini-3-pro-preview`, etc.               |
| `openai-compatible`   | OpenAI Responses (custom base)   | `OPENAI_COMPAT_API_KEY` or `OPENAI_API_KEY` | DeepSeek, Groq, Mistral, vLLM, Ollama, llama.cpp server, etc. |

The `openai-compatible` provider requires `--api-base`:

```bash
sfw-mcp audit old.go new.go "fix typo" \
  --provider openai-compatible \
  --model deepseek-reasoner \
  --api-base https://api.deepseek.com/v1
```

### Tuning the loop

```
--max-steps   Maximum tool-use iterations (default 8)
--max-tokens  Maximum tokens per assistant turn (default 2048)
```

The defaults are sized for an audit that investigates a handful of
files at varying depth. Raise `--max-steps` for diff inputs that
warrant deeper recursion; raise `--max-tokens` only if your evidence
field is consistently being clipped.

## Architecture

```
            ┌───────────────────────────────────────────────┐
            │            sfw-mcp                            │
            │                                                │
   stdio    │  ┌────────────┐    ┌──────────────────────┐   │
  ◄────────►│  │ MCP server │    │      agent loop       │   │
            │  │  (serve)   │    │  (audit subcommand)   │   │
            │  └─────┬──────┘    └──────────┬───────────┘   │
            │        │                       │              │
            │        ▼                       ▼              │
            │  ┌─────────────────────────────────────────┐  │
            │  │       tool registry (tools.All)         │  │
            │  │ diff scan check topology stats          │  │
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

See [`docs/DESIGN.md`](docs/DESIGN.md) for the full design rationale,
including why this is a separate repo and what is intentionally out
of scope for v4.

## License

MIT — see [LICENSE](LICENSE).
