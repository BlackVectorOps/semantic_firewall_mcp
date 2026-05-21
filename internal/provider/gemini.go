package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"google.golang.org/genai"
)

// NewGemini constructs a Provider backed by Google's Gemini API.
// apiKey lands in genai.ClientConfig.APIKey; we always force
// BackendGeminiAPI rather than letting the SDK auto-detect Vertex --
// the audit agent is firmly a Gemini API consumer and an accidental
// switch to Vertex would silently change auth semantics.
//
// Network errors and bad credentials surface only at the first
// Complete call, not here; the underlying genai.Client also does
// lazy authentication.
func NewGemini(apiKey string) *Gemini {
	return &Gemini{apiKey: apiKey}
}

// Gemini maps the provider abstraction onto google.golang.org/genai.
// Each Complete call constructs a fresh client; the SDK is cheap to
// reinitialise and statelessness avoids leaking a long-lived HTTP
// connection across audit runs that may use different credentials.
type Gemini struct {
	apiKey string
}

func (g *Gemini) Name() string { return "gemini" }

func (g *Gemini) Complete(ctx context.Context, req Request) (*Response, error) {
	if g.apiKey == "" {
		return nil, fmt.Errorf("gemini: GEMINI_API_KEY not set")
	}
	if req.Model == "" {
		return nil, fmt.Errorf("gemini: model is required")
	}

	client, err := genai.NewClient(ctx, &genai.ClientConfig{
		APIKey:  g.apiKey,
		Backend: genai.BackendGeminiAPI,
	})
	if err != nil {
		return nil, fmt.Errorf("gemini: client: %w", err)
	}

	contents, err := geminiContentsFromMessages(req.Messages)
	if err != nil {
		return nil, err
	}

	cfg := &genai.GenerateContentConfig{}
	if req.System != "" {
		cfg.SystemInstruction = &genai.Content{
			Parts: []*genai.Part{{Text: req.System}},
		}
	}
	if req.MaxTokens > 0 {
		cfg.MaxOutputTokens = int32(req.MaxTokens)
	}

	if len(req.Tools) > 0 {
		decls := make([]*genai.FunctionDeclaration, 0, len(req.Tools))
		for _, t := range req.Tools {
			fd := &genai.FunctionDeclaration{
				Name:        t.Name,
				Description: t.Description,
			}
			if len(t.InputSchema) > 0 {
				// ParametersJsonSchema is the "raw JSON Schema"
				// escape hatch -- preferred over Parameters because
				// it accepts the same keywords we already use
				// elsewhere (additionalProperties, etc) without
				// per-keyword mapping.
				var schema any
				if err := json.Unmarshal(t.InputSchema, &schema); err != nil {
					return nil, fmt.Errorf("gemini: tool %q schema: %w", t.Name, err)
				}
				fd.ParametersJsonSchema = schema
			}
			decls = append(decls, fd)
		}
		cfg.Tools = []*genai.Tool{{FunctionDeclarations: decls}}
	}

	resp, err := client.Models.GenerateContent(ctx, req.Model, contents, cfg)
	if err != nil {
		return nil, fmt.Errorf("gemini: %w", err)
	}
	if len(resp.Candidates) == 0 || resp.Candidates[0].Content == nil {
		return &Response{StopReason: StopReasonOther}, nil
	}

	cand := resp.Candidates[0]
	out := &Response{}
	if resp.UsageMetadata != nil {
		out.Usage = Usage{
			InputTokens:     int(resp.UsageMetadata.PromptTokenCount),
			OutputTokens:    int(resp.UsageMetadata.CandidatesTokenCount),
			CacheReadTokens: int(resp.UsageMetadata.CachedContentTokenCount),
		}
	}

	sawCall := false
	for _, p := range cand.Content.Parts {
		switch {
		case p.FunctionCall != nil:
			sawCall = true
			args, mErr := json.Marshal(p.FunctionCall.Args)
			if mErr != nil {
				return nil, fmt.Errorf("gemini: marshal function args: %w", mErr)
			}
			// Gemini does not emit a per-call ID for function calls
			// the way Anthropic does; fall back to the function name
			// as the correlation key. The dispatch table in the
			// agent loop only needs the ToolUseID for echoing back
			// to the provider, and Gemini accepts any matching
			// FunctionResponse.Name without an ID match.
			id := p.FunctionCall.ID
			if id == "" {
				id = p.FunctionCall.Name
			}
			out.Content = append(out.Content, ContentBlock{
				Type:      BlockToolUse,
				ToolUseID: id,
				ToolName:  p.FunctionCall.Name,
				ToolInput: args,
			})
		case p.Text != "" && !p.Thought:
			out.Content = append(out.Content, ContentBlock{
				Type: BlockText,
				Text: p.Text,
			})
		}
		// Thought parts and other side-channel parts (code execution,
		// file refs) are ignored deliberately -- the audit agent does
		// not consume them.
	}

	switch cand.FinishReason {
	case genai.FinishReasonMaxTokens:
		out.StopReason = StopReasonMaxTokens
	case genai.FinishReasonStop, "":
		if sawCall {
			out.StopReason = StopReasonToolUse
		} else {
			out.StopReason = StopReasonEndTurn
		}
	default:
		out.StopReason = StopReasonOther
	}
	return out, nil
}

// geminiContentsFromMessages flattens the abstract conversation into
// Gemini's []*Content. Role mapping is the only twist: Gemini uses
// "user" / "model" instead of "user" / "assistant"; tool_result
// blocks must travel as Content with role=user and a FunctionResponse
// Part. We collapse adjacent text and function_call parts inside the
// same Message into one Content per Message to match the SDK's
// expectations.
func geminiContentsFromMessages(messages []Message) ([]*genai.Content, error) {
	out := make([]*genai.Content, 0, len(messages))
	for _, m := range messages {
		var parts []*genai.Part
		for _, b := range m.Content {
			switch b.Type {
			case BlockText:
				if b.Text != "" {
					parts = append(parts, &genai.Part{Text: b.Text})
				}
			case BlockToolUse:
				if m.Role != RoleAssistant {
					return nil, fmt.Errorf("gemini: tool_use block on non-assistant role %q", m.Role)
				}
				var args map[string]any
				if len(b.ToolInput) > 0 {
					if err := json.Unmarshal(b.ToolInput, &args); err != nil {
						return nil, fmt.Errorf("gemini: tool_use input: %w", err)
					}
				}
				parts = append(parts, &genai.Part{
					FunctionCall: &genai.FunctionCall{
						ID:   b.ToolUseID,
						Name: b.ToolName,
						Args: args,
					},
				})
			case BlockToolResult:
				if m.Role != RoleUser {
					return nil, fmt.Errorf("gemini: tool_result block on non-user role %q", m.Role)
				}
				// Gemini's FunctionResponse.Response is a JSON object
				// keyed by convention. We try to round-trip the
				// tool's JSON output into that object; if the tool
				// emitted a non-object (a primitive or array), wrap
				// it under "output" so the SDK accepts the shape.
				var resp map[string]any
				if err := json.Unmarshal([]byte(b.ToolResult), &resp); err != nil {
					resp = map[string]any{"output": b.ToolResult}
				}
				if b.IsError {
					resp = map[string]any{"error": b.ToolResult}
				}
				parts = append(parts, &genai.Part{
					FunctionResponse: &genai.FunctionResponse{
						ID:       b.ToolResultID,
						Name:     toolNameForResponse(b),
						Response: resp,
					},
				})
			}
		}
		if len(parts) == 0 {
			continue
		}
		role := genai.RoleUser
		if m.Role == RoleAssistant {
			role = genai.RoleModel
		}
		out = append(out, &genai.Content{Parts: parts, Role: role})
	}
	return out, nil
}

// toolNameForResponse pulls the original tool name out of the
// agent's ContentBlock when it is available. The agent loop sets
// ToolResultID to the same value the provider emitted as ToolUseID
// (which for Gemini is the function name when no API-side ID is
// present), so passing it as the FunctionResponse.Name is correct
// for the no-ID case and harmless when an ID was set.
func toolNameForResponse(b ContentBlock) string {
	if b.ToolName != "" {
		return b.ToolName
	}
	return b.ToolResultID
}
