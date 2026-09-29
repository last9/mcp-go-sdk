package mcp

import (
	"context"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func samplingRequest() *sdkmcp.CreateMessageRequest {
	return &sdkmcp.CreateMessageRequest{Params: &sdkmcp.CreateMessageParams{
		ModelPreferences: &sdkmcp.ModelPreferences{
			Hints: []*sdkmcp.ModelHint{{Name: ""}, {Name: "claude-sonnet"}, {Name: "gpt-4o"}},
		},
	}}
}

func TestHandleSamplingCreate_RecordsFirstNamedModelHint(t *testing.T) {
	s, exp := testInfra(t)
	ctx := withTestClient(context.Background(), s, "c1", "cursor")

	if _, err := s.handleSamplingCreate(ctx, noop, samplingRequest()); err != nil {
		t.Fatalf("handleSamplingCreate: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %v", spanNames(spans))
	}
	requireAttr(t, spans[0].Attributes, keyMCPSamplingModel, "claude-sonnet")
	requireAttr(t, spans[0].Attributes, keyGenAIRequestModel, "claude-sonnet")
}

func TestHandleSamplingCreate_ModelHintNotCaptured_WhenDisabled(t *testing.T) {
	s, exp := testInfra(t)
	s.cfg.captureSamplingArgs = false
	ctx := withTestClient(context.Background(), s, "c1", "cursor")

	if _, err := s.handleSamplingCreate(ctx, noop, samplingRequest()); err != nil {
		t.Fatalf("handleSamplingCreate: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %v", spanNames(spans))
	}
	if _, ok := findAttr(spans[0].Attributes, keyMCPSamplingModel); ok {
		t.Errorf("unexpected %s attribute", keyMCPSamplingModel)
	}
	if _, ok := findAttr(spans[0].Attributes, keyGenAIRequestModel); ok {
		t.Errorf("unexpected %s attribute", keyGenAIRequestModel)
	}
}
