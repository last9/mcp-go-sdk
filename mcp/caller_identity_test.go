package mcp

import (
	"context"
	"net/http"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestRegisterInstrumentedToolAddsForwardedCallerIdentity(t *testing.T) {
	s, exp := testInfra(t)
	s.setTransport("streamable")

	req := &sdkmcp.CallToolRequest{
		Params: &sdkmcp.CallToolParamsRaw{Name: "search"},
		Extra: &sdkmcp.RequestExtra{Header: http.Header{
			"User-Agent":         []string{"last9-mcp/1.0"},
			"X-Last9-Source":     []string{"chatgpt"},
			"X-Last9-User":       []string{"user@example.com"},
			"X-Last9-Token-Kind": []string{"oauth"},
		}},
	}

	original := func(context.Context, *sdkmcp.CallToolRequest, struct{}) (*sdkmcp.CallToolResult, any, error) {
		return &sdkmcp.CallToolResult{}, nil, nil
	}
	instrumented := instrumentHandler(s, original)
	next := func(ctx context.Context, _ string, request sdkmcp.Request) (sdkmcp.Result, error) {
		result, _, err := instrumented(ctx, request.(*sdkmcp.CallToolRequest), struct{}{})
		return result, err
	}

	if _, err := s.requestMiddleware(next)(context.Background(), opToolsCall, req); err != nil {
		t.Fatalf("tools/call: %v", err)
	}

	span := toolSpan(t, exp.GetSpans(), "search")
	requireAttr(t, span.Attributes, keyUserAgentOriginal, "last9-mcp/1.0")
	requireAttr(t, span.Attributes, keyMCPSource, "chatgpt")
	requireAttr(t, span.Attributes, keyUserEmail, "user@example.com")
	requireAttr(t, span.Attributes, keyTokenKind, "oauth")
	requireAttr(t, span.Attributes, keyMCPClientName, "last9-mcp/1.0")
}

func TestForwardedCallerIdentityDoesNotOverrideExplicitClientName(t *testing.T) {
	s, exp := testInfra(t)
	s.setTransport("streamable")
	req := &sdkmcp.CallToolRequest{
		Params: &sdkmcp.CallToolParamsRaw{
			Name: "search",
			Meta: sdkmcp.Meta{sdkmcp.MetaKeyClientInfo: map[string]any{"name": "cursor", "version": "1.0"}},
		},
		Extra: &sdkmcp.RequestExtra{Header: http.Header{"User-Agent": []string{"last9-mcp/1.0"}}},
	}

	if _, err := s.requestMiddleware(noop)(context.Background(), opToolsCall, req); err != nil {
		t.Fatalf("tools/call: %v", err)
	}

	span := toolSpan(t, exp.GetSpans(), "search")
	requireAttr(t, span.Attributes, keyMCPClientName, "cursor")
}

func TestForwardedCallerIdentityAbsentHeadersAndStdio(t *testing.T) {
	for _, tt := range []struct {
		name      string
		transport string
		extra     *sdkmcp.RequestExtra
	}{
		{name: "streamable without headers", transport: "streamable", extra: &sdkmcp.RequestExtra{}},
		{name: "stdio", transport: "stdio"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, exp := testInfra(t)
			s.setTransport(tt.transport)
			req := &sdkmcp.CallToolRequest{Params: &sdkmcp.CallToolParamsRaw{Name: "search"}, Extra: tt.extra}

			if _, err := s.requestMiddleware(noop)(context.Background(), opToolsCall, req); err != nil {
				t.Fatalf("tools/call: %v", err)
			}

			span := toolSpan(t, exp.GetSpans(), "search")
			requireAttr(t, span.Attributes, keyMCPClientName, "unknown_client")
			for _, key := range []attribute.Key{keyUserAgentOriginal, keyMCPSource, keyUserEmail, keyTokenKind} {
				for _, attr := range span.Attributes {
					if attr.Key == key {
						t.Errorf("unexpected empty attribute %q", key)
					}
				}
			}
		})
	}
}

func toolSpan(t *testing.T, spans tracetest.SpanStubs, toolName string) *tracetest.SpanStub {
	t.Helper()
	for i := range spans {
		if spans[i].Name == toolSpanName(toolName) {
			return &spans[i]
		}
	}
	t.Fatalf("span %q not found", toolSpanName(toolName))
	return nil
}
