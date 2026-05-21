// Package agent runs the provider-agnostic tool-use loop that backs
// `sfw-mcp audit`. It pulls tool specs and handlers from
// internal/tools so the agent never drifts from the MCP serve
// surface: anything an external Claude Code / Cursor / Zed agent can
// call, the in-process agent can call too, and vice versa.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/BlackVectorOps/semantic_firewall_mcp/internal/provider"
	"github.com/BlackVectorOps/semantic_firewall_mcp/internal/tools"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// DefaultMaxSteps caps the tool-use loop so a runaway plan can not
// rack up unbounded LLM bills or block forever. Each step is one
// model call plus all the tool calls that came back from it; eight
// is enough head-room for an audit to investigate a handful of files
// at varying depth without being remotely loose.
const DefaultMaxSteps = 8

// DefaultMaxTokens is the per-turn output cap. Sized for an audit
// verdict + a few hundred bytes of evidence; the agent ends a turn
// when the model emits its final verdict object, not when it bumps
// max_tokens.
const DefaultMaxTokens = 2048

// LoopOptions tunes the run. Both fields fall back to the Default*
// constants when zero so a caller can pass a partially-set struct
// and still get sensible behaviour.
type LoopOptions struct {
	MaxSteps  int
	MaxTokens int
}

// Run executes the tool-use loop until the model emits end_turn,
// the step budget is exhausted, or a tool call returns a fatal
// error. The accumulated assistant text from the final turn is
// returned; intermediate text is intentionally discarded -- only the
// model's final answer is part of the agent's contract with its
// caller.
//
// Tools come from tools.All() so the agent automatically inherits
// every tool the MCP server publishes. A separate "agent-only" tool
// list would invite drift; we explicitly want one source of truth.
func Run(ctx context.Context, p provider.Provider, system, user string, opts LoopOptions) (string, error) {
	if opts.MaxSteps <= 0 {
		opts.MaxSteps = DefaultMaxSteps
	}
	if opts.MaxTokens <= 0 {
		opts.MaxTokens = DefaultMaxTokens
	}

	registry := tools.All()
	specs, dispatch, err := buildToolDispatch(registry)
	if err != nil {
		return "", err
	}

	messages := []provider.Message{
		{
			Role:    provider.RoleUser,
			Content: []provider.ContentBlock{{Type: provider.BlockText, Text: user}},
		},
	}

	var finalText strings.Builder

	for step := 0; step < opts.MaxSteps; step++ {
		resp, err := p.Complete(ctx, provider.Request{
			System:    system,
			Messages:  messages,
			Tools:     specs,
			Model:     modelFromContext(ctx),
			MaxTokens: opts.MaxTokens,
		})
		if err != nil {
			return "", fmt.Errorf("provider %s step %d: %w", p.Name(), step, err)
		}

		// Replay the assistant turn verbatim into the conversation so
		// the next request sees its own prior tool_use blocks. Every
		// provider rejects a tool_result that does not have a
		// matching tool_use earlier in the conversation.
		messages = append(messages, provider.Message{
			Role:    provider.RoleAssistant,
			Content: resp.Content,
		})

		switch resp.StopReason {
		case provider.StopReasonEndTurn:
			for _, b := range resp.Content {
				if b.Type == provider.BlockText {
					finalText.WriteString(b.Text)
				}
			}
			return finalText.String(), nil

		case provider.StopReasonMaxTokens:
			return "", fmt.Errorf("provider %s step %d: max_tokens reached before end_turn", p.Name(), step)

		case provider.StopReasonToolUse:
			// fall through to tool dispatch

		default:
			return "", fmt.Errorf("provider %s step %d: unexpected stop reason %q", p.Name(), step, resp.StopReason)
		}

		// Execute every tool_use block the model emitted in this
		// turn, in order, and append a single user turn containing
		// every matching tool_result.
		results, err := dispatchToolUses(ctx, dispatch, resp.Content)
		if err != nil {
			return "", err
		}
		if len(results) == 0 {
			// tool_use stop reason with no tool_use blocks should not
			// happen but if it does, abort instead of spinning.
			return "", fmt.Errorf("provider %s step %d: tool_use stop reason but no tool blocks emitted", p.Name(), step)
		}
		messages = append(messages, provider.Message{
			Role:    provider.RoleUser,
			Content: results,
		})
	}

	return "", fmt.Errorf("provider %s: step budget %d exhausted before end_turn", p.Name(), opts.MaxSteps)
}

// buildToolDispatch returns the provider-facing ToolSpec list and a
// name->handler map ready to call. The schema for each tool is
// derived from its mcp.Tool.RawInputSchema (raw JSON) when set,
// otherwise from InputSchema (typed); we forward exactly what the
// model needs to produce valid arguments.
func buildToolDispatch(reg []server.ServerTool) ([]provider.ToolSpec, map[string]server.ToolHandlerFunc, error) {
	specs := make([]provider.ToolSpec, 0, len(reg))
	dispatch := make(map[string]server.ToolHandlerFunc, len(reg))
	for _, st := range reg {
		schema, err := schemaFromTool(st.Tool)
		if err != nil {
			return nil, nil, fmt.Errorf("tool %q: %w", st.Tool.Name, err)
		}
		specs = append(specs, provider.ToolSpec{
			Name:        st.Tool.Name,
			Description: st.Tool.Description,
			InputSchema: schema,
		})
		dispatch[st.Tool.Name] = st.Handler
	}
	return specs, dispatch, nil
}

// schemaFromTool prefers a tool's raw JSON Schema when present
// (callers who hand-rolled one know exactly what they want) and
// falls back to marshalling the typed InputSchema. Both paths
// produce the same on-the-wire JSON.
func schemaFromTool(t mcp.Tool) (json.RawMessage, error) {
	if len(t.RawInputSchema) > 0 {
		return json.RawMessage(t.RawInputSchema), nil
	}
	return json.Marshal(t.InputSchema)
}

// dispatchToolUses iterates the assistant turn, runs every tool_use
// block against the registry, and returns the matching tool_result
// blocks. A missing-tool case is reported as a tool_result with
// IsError=true rather than aborting the loop -- the model can read
// the error and choose another tool.
func dispatchToolUses(ctx context.Context, dispatch map[string]server.ToolHandlerFunc, content []provider.ContentBlock) ([]provider.ContentBlock, error) {
	var results []provider.ContentBlock
	for _, b := range content {
		if b.Type != provider.BlockToolUse {
			continue
		}
		handler, ok := dispatch[b.ToolName]
		if !ok {
			results = append(results, provider.ContentBlock{
				Type:         provider.BlockToolResult,
				ToolResultID: b.ToolUseID,
				ToolResult:   fmt.Sprintf("unknown tool: %s", b.ToolName),
				IsError:      true,
			})
			continue
		}
		var args map[string]any
		if len(b.ToolInput) > 0 {
			if err := json.Unmarshal(b.ToolInput, &args); err != nil {
				results = append(results, provider.ContentBlock{
					Type:         provider.BlockToolResult,
					ToolResultID: b.ToolUseID,
					ToolResult:   fmt.Sprintf("invalid tool arguments JSON: %v", err),
					IsError:      true,
				})
				continue
			}
		}
		req := mcp.CallToolRequest{}
		req.Params.Name = b.ToolName
		req.Params.Arguments = args

		callResult, callErr := handler(ctx, req)
		if callErr != nil {
			if errors.Is(callErr, context.Canceled) || errors.Is(callErr, context.DeadlineExceeded) {
				return nil, callErr
			}
			results = append(results, provider.ContentBlock{
				Type:         provider.BlockToolResult,
				ToolResultID: b.ToolUseID,
				ToolResult:   fmt.Sprintf("tool error: %v", callErr),
				IsError:      true,
			})
			continue
		}
		text, isErr := textFromToolResult(callResult)
		results = append(results, provider.ContentBlock{
			Type:         provider.BlockToolResult,
			ToolResultID: b.ToolUseID,
			ToolResult:   text,
			IsError:      isErr,
		})
	}
	return results, nil
}

// textFromToolResult flattens the CallToolResult's content array into
// a single string -- every sfw tool emits exactly one TextContent
// block, but we walk the slice defensively in case a future tool
// emits multiple. IsError is honoured if the tool flagged the result.
func textFromToolResult(res *mcp.CallToolResult) (string, bool) {
	if res == nil {
		return "tool returned nil result", true
	}
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String(), res.IsError
}

// modelKey scopes model selection in context.Context so callers (the
// audit command) can pin a specific Claude / GPT / Gemini model
// without having to thread it through every layer.
type modelKey struct{}

// WithModel returns ctx tagged with the requested model name.
func WithModel(ctx context.Context, model string) context.Context {
	return context.WithValue(ctx, modelKey{}, model)
}

func modelFromContext(ctx context.Context) string {
	if m, ok := ctx.Value(modelKey{}).(string); ok {
		return m
	}
	return ""
}
