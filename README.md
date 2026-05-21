# Semantic Firewall MCP

MCP server and agent harness for [Semantic Firewall](https://github.com/BlackVectorOps/semantic_firewall).

Exposes sfw's behavioral-analysis tools (`diff`, `scan`, `check`,
`topology`, `stats`) over MCP/stdio so any MCP-aware agent — Claude
Code, Cursor, Zed, Continue — can drive them. Also ships a one-shot
`audit` mode that runs an internal agent loop against your LLM of
choice (Anthropic, OpenAI, Gemini, or any OpenAI-compatible endpoint)
to investigate whether a commit message matches its structural changes.

> **Status:** unreleased. Built against `semantic_firewall` v4, which
> itself is gated on this server landing. The module currently uses a
> local `replace` directive against `../semantic_firewall`; the v4.0.0
> tag drops the replace and pins the real version.

## Install

```bash
go install github.com/BlackVectorOps/semantic_firewall_mcp/cmd/sfw-mcp@latest
```

## Run

```bash
# As an MCP server (Claude Code, Cursor, etc. connect over stdio)
sfw-mcp serve

# As a one-shot audit (replaces v3's `sfw audit`)
sfw-mcp audit old.go new.go "fix typo" --provider anthropic --model claude-opus-4-7
```

## License

MIT — see [LICENSE](LICENSE).
