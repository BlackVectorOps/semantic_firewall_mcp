// Package provider abstracts the LLM behind a tool-use loop. The
// agent in internal/agent is provider-agnostic: it builds Requests in
// the shape defined here and feeds them through whichever Provider
// implementation the caller selected on the command line. Each
// provider package (anthropic.go, openai.go, gemini.go, compat.go)
// converts to and from the upstream SDK's own request/response types.
//
// Why a shared shape: every modern tool-use API converges on the same
// abstract flow -- a system prompt, a conversation of typed content
// blocks, a tool registry, and a stop reason that signals whether the
// model wants another tool call or is done. Mapping into this shape
// at the adapter boundary keeps the agent loop a few dozen lines and
// makes it trivial to add or swap providers without rewriting the
// orchestration.
package provider

import (
	"context"
	"encoding/json"
)

// Provider is the single seam between the agent and an LLM. An
// implementation must be safe to call concurrently from independent
// goroutines; the agent does not assume any per-call sticky state on
// the provider side beyond what the underlying SDK already provides
// (HTTP keep-alive, prompt cache, etc.).
type Provider interface {
	// Name returns a short identifier ("anthropic", "openai",
	// "gemini", "openai-compatible") used in logs and error messages.
	Name() string

	// Complete runs one round-trip against the model. The agent loop
	// is responsible for repeated calls when StopReasonToolUse comes
	// back; the provider only owns the single network call.
	Complete(ctx context.Context, req Request) (*Response, error)
}

// Request is the abstract conversation handed to the model. System
// goes into whichever first-class field the provider exposes
// (system, system instruction, developer role) rather than being
// stuffed into the message list -- providers cache the system prompt
// differently from user turns and we want them to.
type Request struct {
	System    string
	Messages  []Message
	Tools     []ToolSpec
	Model     string
	MaxTokens int
}

// Role enumerates who produced a Message. Tool results travel under
// RoleUser because every provider treats them as user-supplied input
// to the model regardless of MCP's "tool" role concept.
type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// Message is a single turn in the conversation. Content carries one
// or more typed blocks so a single assistant turn can interleave
// natural-language reasoning with tool_use blocks the way Anthropic
// and the OpenAI Responses API natively do.
type Message struct {
	Role    Role
	Content []ContentBlock
}

// BlockType discriminates the union in ContentBlock. We do not try
// to encode every provider-specific block type (image, thinking,
// citations) because the audit agent does not need them; if a
// future feature requires it, add a new BlockType here and a fresh
// case in the adapter conversions.
type BlockType string

const (
	BlockText       BlockType = "text"
	BlockToolUse    BlockType = "tool_use"
	BlockToolResult BlockType = "tool_result"
)

// ContentBlock is the tagged union for one piece of message content.
// Only the fields relevant to Type are populated; consumers must
// switch on Type before reading provider-specific fields.
type ContentBlock struct {
	Type BlockType

	// Type == BlockText
	Text string

	// Type == BlockToolUse (assistant turn)
	ToolUseID string
	ToolName  string
	ToolInput json.RawMessage

	// Type == BlockToolResult (user turn following a tool_use)
	ToolResultID string
	ToolResult   string
	IsError      bool
}

// ToolSpec is the schema we advertise for one tool. InputSchema is
// the raw JSON Schema object the provider will forward to the
// model; each adapter knows how to embed it in its native request
// shape.
type ToolSpec struct {
	Name        string
	Description string
	InputSchema json.RawMessage
}

// StopReason tells the agent loop why the model stopped. EndTurn and
// ToolUse are the two important cases; MaxTokens and Other surface so
// the agent can record a useful error rather than retrying blindly.
type StopReason string

const (
	StopReasonEndTurn   StopReason = "end_turn"
	StopReasonToolUse   StopReason = "tool_use"
	StopReasonMaxTokens StopReason = "max_tokens"
	StopReasonOther     StopReason = "other"
)

// Response is what a single Complete call produced. Content carries
// the same ContentBlock union, this time populated by the provider
// (an assistant turn). Usage is best-effort -- some providers do not
// report per-call usage at all.
type Response struct {
	Content    []ContentBlock
	StopReason StopReason
	Usage      Usage
}

// Usage is best-effort token accounting. Zero values mean "provider
// did not report"; the agent must not treat zero as "free".
type Usage struct {
	InputTokens         int
	OutputTokens        int
	CacheCreationTokens int
	CacheReadTokens     int
}
