package provider

import "fmt"

// NewOpenAICompatible builds a Provider for any service that speaks
// the OpenAI Responses API at a different base URL: DeepSeek, Groq,
// Mistral's la-plateforme, vLLM, Ollama, llama.cpp's server, etc.
//
// The implementation is the OpenAI adapter with the base URL pinned
// to apiBase and the reported provider name overridden so logs and
// error messages distinguish "openai-compatible" from the canonical
// "openai" path -- otherwise a misconfigured api-base would look
// like a real OpenAI failure.
//
// apiBase is required; an empty base would silently fall back to
// api.openai.com, which is almost certainly not what the operator
// asked for when they selected --provider openai-compatible.
func NewOpenAICompatible(apiKey, apiBase string) (*OpenAI, error) {
	if apiBase == "" {
		return nil, fmt.Errorf("openai-compatible: --api-base is required (point it at the endpoint, e.g. https://api.deepseek.com/v1)")
	}
	p := NewOpenAIWithBase(apiKey, apiBase)
	p.nameOverride = "openai-compatible"
	return p, nil
}
