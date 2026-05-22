# Semantic Firewall MCP

MCP server and agent harness for [Semantic Firewall](https://github.com/BlackVectorOps/semantic_firewall).

Exposes sfw's behavioral analysis tools (`diff`, `scan`, `check`,
`topology`, `stats`) over MCP/stdio so any MCP-aware agent — Claude
Code, Cursor, Zed, Continue — can drive them directly. Also ships a
one-shot `audit` mode that runs an internal agent loop against the
LLM provider of your choice (Anthropic, OpenAI, Gemini, or any
OpenAI-compatible endpoint) to investigate whether a commit message
matches its structural changes.

Pairs with [`semantic_firewall`](https://github.com/BlackVectorOps/semantic_firewall) `v4.0.0+`.

## Install

```bash
go install github.com/BlackVectorOps/semantic_firewall_mcp/cmd/sfw-mcp@latest
```

Confirm the install:

```bash
$ sfw-mcp version
Semantic Firewall MCP
Build: v0.2.1
Engine: v4.0.0
```

`Build` is this binary; `Engine` is the linked `semantic_firewall`
library version. Both come from the embedded Go build info — no
hardcoded constants, no separate release manifest. (Your `Build`
value will be whichever tag you installed; the version banner is
not a release-note placeholder.)

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
emits a structured JSON report on stdout.

```bash
sfw-mcp audit old.go new.go "fix typo" \
  --provider anthropic \
  --model claude-opus-4-7
```

### Output shape

The audit response separates **deterministic, math-only signals**
from **non-deterministic LLM judgment** so operators can choose how
much of each they want to act on:

```json
{
  "inputs": {
    "old_file": "old.go",
    "new_file": "new.go",
    "commit_message": "fix typo"
  },
  "risk_evidence": {
    "added_functions": 1,
    "modified_functions": 1,
    "removed_functions": 0,
    "high_risk_functions": [
      {
        "function": "F",
        "risk_score": 15,
        "topology_delta": "Calls+1, Goroutine",
        "status": "modified"
      }
    ],
    "signature_hits": [],
    "deterministic_verdict": "ESCALATION"
  },
  "llm_assessments": [
    {
      "provider": "anthropic",
      "model": "claude-opus-4-7",
      "verdict": "LIE",
      "evidence": "Commit message claims 'fix typo' but the diff introduces a goroutine."
    }
  ],
  "cost": {
    "tool_calls": 2,
    "model_steps": 3,
    "input_tokens": 6420,
    "output_tokens": 184,
    "cache_read_tokens": 4096
  }
}
```

Three things to know about the shape:

- **`risk_evidence` is computed without invoking an LLM.** The
  `deterministic_verdict` field is `CLEAN`, `ESCALATION`, or
  `SIGNATURE_MATCH` — a math-only operator can gate on this alone
  and never pay for a model call. `SIGNATURE_MATCH` strictly
  dominates `ESCALATION` when both fire.
- **`llm_assessments` is an array even though only one provider runs
  today.** Cross-provider mode (planned) appends a second entry; the
  array shape is intentional so that addition is purely additive
  rather than another breaking schema change.
- **`cost` is populated on every return path**, including provider
  outages, max-token aborts, and step-budget exhaustion. The
  runaway-bill failure mode (an audit that died at step 7 reporting
  zero spend) does not exist.

### Exit codes

Tri-state, so a CI workflow can distinguish a real verdict from an
infrastructure failure:

| Code | Meaning |
|------|---------|
| `0`  | `MATCH` — commit message accurately describes the change. |
| `1`  | `LIE` or `SUSPICIOUS` — the tool has an opinion. |
| `2`  | `ERROR` — the tool itself broke (provider outage, parse failure, step budget exhausted). |

A workflow that wants to fail-soft on infra outages keys on
`exit == 2`. A workflow that strictly trusts the tool treats `!= 0`
as a block, same as before.

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

**Deterministic / LLM boundary.** The `audit` output's `risk_evidence`
side is computed by `internal/risk`, which is a sealed package: it
cannot import `internal/provider` or `internal/agent`. The Go
compiler enforces that boundary, not a comment — anything in
`risk_evidence` is provably free of LLM context, so the math-only
operator's gate continues to function during provider outages.
That separation is also the structural line between the free
analysis core (`internal/risk` + the open-source engine in
`semantic_firewall`) and any future paid surface (curated intel
feeds, premium judgment modes).

See [`docs/DESIGN.md`](docs/DESIGN.md) for the full design rationale,
including why this is a separate repo and what is intentionally out
of scope for v4.

## License

MIT — see [LICENSE](LICENSE).
