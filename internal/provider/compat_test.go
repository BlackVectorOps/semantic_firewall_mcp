package provider

import (
	"strings"
	"testing"
)

func TestNewOpenAICompatible_RequiresAPIBase(t *testing.T) {
	if _, err := NewOpenAICompatible("key", ""); err == nil {
		t.Fatal("expected error when apiBase is empty; got nil")
	} else if !strings.Contains(err.Error(), "--api-base is required") {
		t.Errorf("error should mention --api-base; got: %v", err)
	}
}

func TestNewOpenAICompatible_SetsNameOverride(t *testing.T) {
	p, err := NewOpenAICompatible("key", "https://api.deepseek.com/v1")
	if err != nil {
		t.Fatalf("NewOpenAICompatible: %v", err)
	}
	if got := p.Name(); got != "openai-compatible" {
		t.Errorf("Name() = %q; want openai-compatible (override should kick in)", got)
	}
	if p.apiBase != "https://api.deepseek.com/v1" {
		t.Errorf("apiBase = %q; want https://api.deepseek.com/v1", p.apiBase)
	}
}
