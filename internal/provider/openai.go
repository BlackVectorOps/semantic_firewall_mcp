package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/openai/openai-go/responses"
	"github.com/openai/openai-go/shared"
)

// NewOpenAI constructs a Provider backed by the OpenAI Responses
// API. apiKey is the only required parameter; pass an empty apiBase
// to hit api.openai.com. The same factory powers NewOpenAICompatible,
// which simply forwards a non-empty apiBase so DeepSeek, Groq,
// Mistral, vLLM, Ollama, and any other OpenAI-compatible endpoint
// can use the identical Request/Response conversion code.
func NewOpenAI(apiKey string) *OpenAI {
	return NewOpenAIWithBase(apiKey, "")
}

// NewOpenAIWithBase mirrors NewOpenAI but lets the caller pin the
// API base URL. Empty apiBase means "use the SDK default", which is
// api.openai.com.
func NewOpenAIWithBase(apiKey, apiBase string) *OpenAI {
	opts := []option.RequestOption{option.WithAPIKey(apiKey)}
	if apiBase != "" {
		opts = append(opts, option.WithBaseURL(apiBase))
	}
	client := openai.NewClient(opts...)
	return &OpenAI{
		client:  &client,
		apiKey:  apiKey,
		apiBase: apiBase,
	}
}

// OpenAI maps provider.Request/Response to the Responses API. It
// covers the canonical openai.com endpoint and every OpenAI-
// compatible service that speaks the same wire shape.
type OpenAI struct {
	client  *openai.Client
	apiKey  string
	apiBase string
	// nameOverride lets the OpenAI-compatible variant report
	// "openai-compatible" without duplicating the conversion code.
	nameOverride string
}

func (o *OpenAI) Name() string {
	if o.nameOverride != "" {
		return o.nameOverride
	}
	return "openai"
}

func (o *OpenAI) Complete(ctx context.Context, req Request) (*Response, error) {
	if o.apiKey == "" {
		return nil, fmt.Errorf("%s: API key not set", o.Name())
	}
	if req.Model == "" {
		return nil, fmt.Errorf("%s: model is required", o.Name())
	}

	params := responses.ResponseNewParams{
		Model: shared.ResponsesModel(req.Model),
	}
	if req.System != "" {
		params.Instructions = openai.String(req.System)
	}
	if req.MaxTokens > 0 {
		params.MaxOutputTokens = openai.Int(int64(req.MaxTokens))
	}

	for _, t := range req.Tools {
		var schema map[string]any
		if len(t.InputSchema) > 0 {
			if err := json.Unmarshal(t.InputSchema, &schema); err != nil {
				return nil, fmt.Errorf("%s: tool %q schema: %w", o.Name(), t.Name, err)
			}
		}
		// Responses API requires additionalProperties=false on every
		// schema when strict mode is on. We do not opt into strict
		// mode here because the JSON Schema mcp-go emits is not
		// strict-clean (it does not declare additionalProperties);
		// leaving Strict unset keeps the API permissive without
		// crashing on schemas that omit the field.
		params.Tools = append(params.Tools, responses.ToolUnionParam{
			OfFunction: &responses.FunctionToolParam{
				Name:        t.Name,
				Description: openai.String(t.Description),
				Parameters:  schema,
			},
		})
	}

	items, err := openaiInputFromMessages(req.Messages)
	if err != nil {
		return nil, err
	}
	params.Input = responses.ResponseNewParamsInputUnion{
		OfInputItemList: items,
	}

	resp, err := o.client.Responses.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", o.Name(), err)
	}

	out := &Response{
		Usage: Usage{
			InputTokens:     int(resp.Usage.InputTokens),
			OutputTokens:    int(resp.Usage.OutputTokens),
			CacheReadTokens: int(resp.Usage.InputTokensDetails.CachedTokens),
		},
	}

	sawToolCall := false
	for _, item := range resp.Output {
		switch item.Type {
		case "message":
			for _, c := range item.Content {
				if c.Type == "output_text" && c.Text != "" {
					out.Content = append(out.Content, ContentBlock{
						Type: BlockText,
						Text: c.Text,
					})
				}
				// "refusal" content is rare and the agent should treat
				// it as end_turn with no useful text; leaving it out
				// of Content is the simplest signal.
			}
		case "function_call":
			sawToolCall = true
			out.Content = append(out.Content, ContentBlock{
				Type:      BlockToolUse,
				ToolUseID: item.CallID,
				ToolName:  item.Name,
				ToolInput: json.RawMessage(item.Arguments),
			})
		}
		// reasoning / mcp_* / etc. items are ignored deliberately --
		// the audit agent does not need them and dropping them is
		// what the SDK's high-level helpers do too.
	}

	// Responses API has no explicit stop_reason. We synthesise one
	// from the output: any function_call item means the agent loop
	// must run tools; otherwise the model emitted its final answer.
	// "incomplete" status maps to max_tokens because that is the only
	// reason the loop can encounter that is not an outright error.
	switch resp.Status {
	case responses.ResponseStatusIncomplete:
		out.StopReason = StopReasonMaxTokens
	case responses.ResponseStatusFailed, responses.ResponseStatusCancelled:
		out.StopReason = StopReasonOther
	default:
		if sawToolCall {
			out.StopReason = StopReasonToolUse
		} else {
			out.StopReason = StopReasonEndTurn
		}
	}
	return out, nil
}

// openaiInputFromMessages flattens the abstract conversation into the
// Responses API's input-item list. Each Message becomes one or more
// items: a plain text user/assistant turn collapses to a single
// EasyInputMessage; an assistant turn containing tool_use blocks
// becomes one ResponseFunctionToolCall item per block; a user turn
// containing tool_result blocks becomes one
// ResponseInputItemFunctionCallOutput item per block.
func openaiInputFromMessages(messages []Message) (responses.ResponseInputParam, error) {
	var out responses.ResponseInputParam
	for _, m := range messages {
		// Bucket the blocks by kind so we can emit the right item
		// types in the right order.
		var textBuf string
		for _, b := range m.Content {
			switch b.Type {
			case BlockText:
				if textBuf != "" {
					textBuf += "\n"
				}
				textBuf += b.Text
			}
		}
		if textBuf != "" {
			role := openaiRoleFromProvider(m.Role)
			out = append(out, responses.ResponseInputItemUnionParam{
				OfMessage: &responses.EasyInputMessageParam{
					Role: role,
					Content: responses.EasyInputMessageContentUnionParam{
						OfString: openai.String(textBuf),
					},
				},
			})
		}

		for _, b := range m.Content {
			switch b.Type {
			case BlockToolUse:
				if m.Role != RoleAssistant {
					return nil, fmt.Errorf("openai: tool_use block on non-assistant role %q", m.Role)
				}
				out = append(out, responses.ResponseInputItemUnionParam{
					OfFunctionCall: &responses.ResponseFunctionToolCallParam{
						CallID:    b.ToolUseID,
						Name:      b.ToolName,
						Arguments: string(b.ToolInput),
					},
				})
			case BlockToolResult:
				if m.Role != RoleUser {
					return nil, fmt.Errorf("openai: tool_result block on non-user role %q", m.Role)
				}
				out = append(out, responses.ResponseInputItemUnionParam{
					OfFunctionCallOutput: &responses.ResponseInputItemFunctionCallOutputParam{
						CallID: b.ToolResultID,
						Output: b.ToolResult,
					},
				})
				// IsError has no direct field on the Responses API
				// function_call_output item; we surface it implicitly
				// in the JSON text and let the model decide.
			}
		}
	}
	return out, nil
}

func openaiRoleFromProvider(r Role) responses.EasyInputMessageRole {
	switch r {
	case RoleAssistant:
		return responses.EasyInputMessageRoleAssistant
	default:
		return responses.EasyInputMessageRoleUser
	}
}
