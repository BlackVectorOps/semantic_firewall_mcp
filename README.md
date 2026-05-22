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

Five things to know about the shape:

- **`risk_evidence` is computed without invoking an LLM.** The
  `deterministic_verdict` field is `CLEAN`, `ESCALATION`, or
  `SIGNATURE_MATCH` — a math-only operator can gate on this alone
  and never pay for a model call. (The computation lives in a
  sealed Go package that cannot import the LLM path; see
  [Deterministic / LLM boundary](#deterministic--llm-boundary)
  below for the structural enforcement.) `SIGNATURE_MATCH` strictly
  dominates `ESCALATION` when both fire — a named-pattern match is
  a stronger claim than a heuristic score.
- **`high_risk_functions[].status` is one of `added`, `modified`,
  or `renamed`.** Note the asymmetry against the top-level
  `removed_functions` count: that count tallies every removed
  function in the diff, while `high_risk_functions[]` is the
  filtered list of entries that crossed the risk threshold.
  Removed functions are *counted* but not *scored* (we cannot
  meaningfully assign risk to a topology that no longer exists in
  the diff), so `removed_functions` can be non-zero while no entry
  in `high_risk_functions[]` carries `status: removed`. `preserved`
  functions similarly score 0 by definition and never reach the
  list.
- **Known limitation: deletion-attack blind spot.** The
  deterministic verdict scores what a commit *added*, not what it
  *removed*. A backdoor introduced by deleting a guard — removing
  a bounds check, stripping an auth verification, dropping a TLS
  validation — does not surface in `high_risk_functions[]`, and
  `deterministic_verdict` will not flag it. The LLM assessment may
  catch it if the model investigates the deletion, but that is not
  a deterministic guarantee. To audit suspicious deletions
  manually, point `sfw_topology` at the pre-change file (`old.go`)
  and look for calls or guards the commit message did not justify
  removing. Closing this gap properly requires scoring loss of
  structure, which the v0 engine does not yet do; naming it here
  rather than hiding it is the honest posture until the engine can
  catch it deterministically.
- **`llm_assessments` is an array even though only one provider runs
  today.** Cross-provider mode (planned) appends a second entry; the
  array shape is intentional so that addition is purely additive
  rather than another breaking schema change.
- **`cost` is populated on every return path**, including provider
  outages, max-token aborts, and step-budget exhaustion. The
  runaway-bill failure mode (an audit that died at step 7 reporting
  zero spend) does not exist.

When the signature database is populated (the curated threat-intel
feed; not yet shipped) and a function's topology matches a known
malware family, the output shape looks like this:

```json
{
  "risk_evidence": {
    "added_functions": 0,
    "modified_functions": 1,
    "removed_functions": 0,
    "high_risk_functions": [
      {
        "function": "init",
        "risk_score": 32,
        "topology_delta": "Calls+3, Goroutine, Entropy+4.2",
        "status": "modified"
      }
    ],
    "signature_hits": [
      {
        "function": "init",
        "signature_id": "SFW-MAL-COBALT-Beacon-2026-01",
        "signature_name": "CobaltStrike_Beacon_v1",
        "severity": "CRITICAL",
        "confidence": 0.94
      }
    ],
    "deterministic_verdict": "SIGNATURE_MATCH"
  },
  "llm_assessments": [ /* ... */ ],
  "cost": { /* ... */ }
}
```

Note that the function appears in both `high_risk_functions` (the
topology delta crosses the heuristic threshold) and
`signature_hits` (a named pattern matched). The dominance rule
applies only to `deterministic_verdict`, not to the lists — both
arrays carry the same function so the operator can see the
heuristic reasoning that corroborated the signature.

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
as a block.

**Migration note from v0.1.x:** Gates written as `if exit == 1`
will no longer catch ERROR cases, which moved to exit `2` in v0.2.
The v0.1 README actively encouraged that one-equals-blocked shape
("0 for MATCH, 1 for SUSPICIOUS / LIE / ERROR"), so the breakage
is real and silent — your CI will keep reporting green on provider
outages it used to flag. Rewrite as `if exit != 0` to preserve the
v0.1 block-everything behaviour, or as `if exit != 0 && exit != 2`
to opt into the new fail-soft-on-infra semantics. This breakage is
the load-bearing reason for the v0.2.0 semver-major bump.

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

### Deterministic / LLM boundary

The `audit` output's `risk_evidence` side is computed by
`internal/risk`, which is a sealed Go package: it cannot import
`internal/provider` or `internal/agent`. The Go compiler enforces
that boundary, not a comment — anything in `risk_evidence` is
provably free of LLM context, so the math-only operator's gate
continues to function during provider outages.

That separation is also the structural line between the free
analysis core (`internal/risk` + the open-source engine in
`semantic_firewall`) and any future paid surface (curated intel
feeds, premium judgment modes). A future contributor who tried to
cross the line would not get a code-review nit; they would get a
build failure.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the full design rationale,
including why this is a separate repo and what is intentionally out
of scope for v4.

## License

MIT — see [LICENSE](LICENSE).
