package mcp

import (
	"context"
	"net/http"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

var (
	testKeyUserAgentOriginal = attribute.Key("user_agent.original")
	testKeyMCPSource         = attribute.Key("mcp.source")
	testKeyUserID            = attribute.Key("user.id")
	testKeyTokenKind         = attribute.Key("token.kind")
)

func TestToolsCallRecordsForwardedCallerIdentity(t *testing.T) {
	span := callToolSpan(t, "streamable", "cursor", http.Header{
		"User-Agent":         {"last9-mcp-server/1.2.3"},
		"X-Last9-Source":     {"chatgpt"},
		"X-Last9-User":       {"user-123"},
		"X-Last9-Token-Kind": {"oauth"},
		"X-Last9-User-Email": {"person@example.com"},
	})

	requireAttr(t, span.Attributes, testKeyUserAgentOriginal, "last9-mcp-server/1.2.3")
	requireAttr(t, span.Attributes, testKeyMCPSource, "chatgpt")
	requireAttr(t, span.Attributes, testKeyUserID, "user-123")
	requireAttr(t, span.Attributes, testKeyTokenKind, "oauth")
	if _, ok := findAttr(span.Attributes, attribute.Key("user.email")); ok {
		t.Error("user.email must not be recorded")
	}
}

func TestToolsCallUsesUserAgentWhenClientNameIsUnknown(t *testing.T) {
	span := callToolSpan(t, "streamable", "", http.Header{
		"User-Agent": {"last9-mcp-server/1.2.3"},
	})

	requireAttr(t, span.Attributes, keyMCPClientName, "last9-mcp-server/1.2.3")
}

func TestToolsCallPreservesExplicitClientName(t *testing.T) {
	span := callToolSpan(t, "streamable", "cursor", http.Header{
		"User-Agent": {"last9-mcp-server/1.2.3"},
	})

	requireAttr(t, span.Attributes, keyMCPClientName, "cursor")
}

func TestToolsCallOmitsAbsentCallerIdentity(t *testing.T) {
	for _, tc := range []struct {
		name      string
		transport string
		headers   http.Header
	}{
		{name: "empty HTTP headers", transport: "streamable", headers: http.Header{
			"User-Agent":         {""},
			"X-Last9-Source":     {""},
			"X-Last9-User":       {""},
			"X-Last9-Token-Kind": {""},
		}},
		{name: "stdio", transport: "stdio"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			span := callToolSpan(t, tc.transport, "", tc.headers)

			requireAttr(t, span.Attributes, keyMCPClientName, "unknown_client")
			for _, key := range []attribute.Key{testKeyUserAgentOriginal, testKeyMCPSource, testKeyUserID, testKeyTokenKind} {
				if _, ok := findAttr(span.Attributes, key); ok {
					t.Errorf("attribute %q should be absent", key)
				}
			}
		})
	}
}

func callToolSpan(t *testing.T, transport, clientName string, headers http.Header) tracetest.SpanStub {
	t.Helper()

	s, exp := testInfra(t)
	s.setTransport(transport)
	params := &sdkmcp.CallToolParamsRaw{Name: "search"}
	if clientName != "" {
		params.Meta = sdkmcp.Meta{
			sdkmcp.MetaKeyClientInfo: map[string]any{"name": clientName, "version": "1.0"},
		}
	}
	req := &sdkmcp.CallToolRequest{Params: params}
	if headers != nil {
		req.Extra = &sdkmcp.RequestExtra{Header: headers}
	}

	called := false
	next := func(_ context.Context, method string, got sdkmcp.Request) (sdkmcp.Result, error) {
		called = true
		if method != opToolsCall {
			t.Errorf("method: got %q, want %q", method, opToolsCall)
		}
		if got != req {
			t.Error("middleware replaced the request passed to the tool handler")
		}
		return &sdkmcp.CallToolResult{}, nil
	}
	if _, err := s.requestMiddleware(next)(context.Background(), opToolsCall, req); err != nil {
		t.Fatalf("tools/call: %v", err)
	}
	if !called {
		t.Fatal("tool handler was not called")
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got spans %v, want one tool span", spanNames(spans))
	}
	return spans[0]
}
