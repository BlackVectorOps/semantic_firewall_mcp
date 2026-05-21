package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// NewAnthropic constructs a Provider backed by Anthropic's Messages
// API. apiKey is required (empty string surfaces an error on the
// first Complete call rather than at construction; this lets callers
// build the provider once and resolve credentials lazily). Model
// names are passed through verbatim -- the SDK accepts every current
// Claude model string ("claude-opus-4-7", "claude-sonnet-4-6", ...)
// without us mapping them.
func NewAnthropic(apiKey string) *Anthropic {
	client := anthropic.NewClient(option.WithAPIKey(apiKey))
	return &Anthropic{client: &client, apiKey: apiKey}
}

// Anthropic is the reference Provider implementation. It maps the
// provider.Request/Response abstraction directly to Anthropic's
// native tool-use protocol, which is the shape the abstraction was
// designed around -- the conversion is mostly field-renaming.
type Anthropic struct {
	client *anthropic.Client
	apiKey string
}

func (a *Anthropic) Name() string { return "anthropic" }

func (a *Anthropic) Complete(ctx context.Context, req Request) (*Response, error) {
	if a.apiKey == "" {
		return nil, fmt.Errorf("anthropic: ANTHROPIC_API_KEY not set")
	}
	if req.Model == "" {
		return nil, fmt.Errorf("anthropic: model is required")
	}

	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(req.Model),
		MaxTokens: int64(req.MaxTokens),
	}
	if req.MaxTokens == 0 {
		// The API requires a positive max_tokens. 4096 matches the
		// default the SDK examples use; the agent loop sets a
		// deliberate value but a forgetful caller should still get a
		// usable request.
		params.MaxTokens = 4096
	}

	if req.System != "" {
		// Place a cache breakpoint at the end of the system prompt.
		// The audit system prompt is large and reused across every
		// turn; caching it cuts the per-turn input bill dramatically
		// for any workload that exercises the agent more than once.
		params.System = []anthropic.TextBlockParam{
			{
				Text:         req.System,
				CacheControl: anthropic.CacheControlEphemeralParam{},
			},
		}
	}

	for _, t := range req.Tools {
		toolParam := anthropic.ToolParam{
			Name:        t.Name,
			Description: anthropic.String(t.Description),
		}
		// InputSchema arrives as raw JSON Schema; unmarshal it into
		// the SDK's typed shape so the SDK can validate before
		// sending. Tools without a schema (no parameters) become a
		// minimal object schema with no properties.
		if len(t.InputSchema) > 0 {
			schema, err := anthropicSchemaFromJSON(t.InputSchema)
			if err != nil {
				return nil, fmt.Errorf("anthropic: tool %q schema: %w", t.Name, err)
			}
			toolParam.InputSchema = schema
		} else {
			toolParam.InputSchema = anthropic.ToolInputSchemaParam{}
		}
		params.Tools = append(params.Tools, anthropic.ToolUnionParam{OfTool: &toolParam})
	}

	for _, m := range req.Messages {
		blocks, err := anthropicBlocksFromProvider(m.Content)
		if err != nil {
			return nil, err
		}
		switch m.Role {
		case RoleUser:
			params.Messages = append(params.Messages, anthropic.NewUserMessage(blocks...))
		case RoleAssistant:
			params.Messages = append(params.Messages, anthropic.NewAssistantMessage(blocks...))
		default:
			return nil, fmt.Errorf("anthropic: unknown role %q", m.Role)
		}
	}

	msg, err := a.client.Messages.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("anthropic: %w", err)
	}

	resp := &Response{
		StopReason: anthropicStopReasonToProvider(msg.StopReason),
		Usage: Usage{
			InputTokens:         int(msg.Usage.InputTokens),
			OutputTokens:        int(msg.Usage.OutputTokens),
			CacheCreationTokens: int(msg.Usage.CacheCreationInputTokens),
			CacheReadTokens:     int(msg.Usage.CacheReadInputTokens),
		},
	}
	for _, block := range msg.Content {
		switch block.Type {
		case "text":
			resp.Content = append(resp.Content, ContentBlock{
				Type: BlockText,
				Text: block.Text,
			})
		case "tool_use":
			resp.Content = append(resp.Content, ContentBlock{
				Type:      BlockToolUse,
				ToolUseID: block.ID,
				ToolName:  block.Name,
				ToolInput: block.Input,
			})
		}
		// thinking, redacted_thinking, server_* etc. are not used by
		// the audit agent; ignoring them is correct, not a bug.
	}
	return resp, nil
}

// anthropicBlocksFromProvider converts agent-side ContentBlocks into
// the SDK's union type. The agent only ever emits the three block
// kinds we wire here; any other Type would be a programming bug.
func anthropicBlocksFromProvider(content []ContentBlock) ([]anthropic.ContentBlockParamUnion, error) {
	out := make([]anthropic.ContentBlockParamUnion, 0, len(content))
	for _, b := range content {
		switch b.Type {
		case BlockText:
			out = append(out, anthropic.NewTextBlock(b.Text))
		case BlockToolUse:
			var input any
			if len(b.ToolInput) > 0 {
				if err := json.Unmarshal(b.ToolInput, &input); err != nil {
					return nil, fmt.Errorf("anthropic: tool_use input: %w", err)
				}
			}
			out = append(out, anthropic.NewToolUseBlock(b.ToolUseID, input, b.ToolName))
		case BlockToolResult:
			out = append(out, anthropic.NewToolResultBlock(b.ToolResultID, b.ToolResult, b.IsError))
		default:
			return nil, fmt.Errorf("anthropic: unsupported block type %q", b.Type)
		}
	}
	return out, nil
}

// anthropicSchemaFromJSON parses a raw JSON Schema into the SDK's
// ToolInputSchemaParam shape. We pluck out Properties and Required
// because that is all the SDK exposes structurally; any other top-
// level schema keywords go into ExtraFields so they ride along
// untouched.
func anthropicSchemaFromJSON(raw json.RawMessage) (anthropic.ToolInputSchemaParam, error) {
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return anthropic.ToolInputSchemaParam{}, err
	}
	schema := anthropic.ToolInputSchemaParam{}
	if p, ok := generic["properties"]; ok {
		schema.Properties = p
		delete(generic, "properties")
	}
	if r, ok := generic["required"].([]any); ok {
		for _, item := range r {
			if s, ok := item.(string); ok {
				schema.Required = append(schema.Required, s)
			}
		}
		delete(generic, "required")
	}
	delete(generic, "type") // SDK fixes this to "object" at the wire level.
	if len(generic) > 0 {
		schema.ExtraFields = generic
	}
	return schema, nil
}

func anthropicStopReasonToProvider(s anthropic.StopReason) StopReason {
	switch s {
	case anthropic.StopReasonEndTurn:
		return StopReasonEndTurn
	case anthropic.StopReasonToolUse:
		return StopReasonToolUse
	case anthropic.StopReasonMaxTokens:
		return StopReasonMaxTokens
	default:
		return StopReasonOther
	}
}
