package mcp

import (
	"context"
	"errors"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// testClientInfra creates an isolated Last9MCPClient backed by synchronous
// in-memory OTel providers.  Server name and transport are pre-populated so
// that attribute assertions don't need a live connection.
func testClientInfra(t *testing.T) (*Last9MCPClient, *tracetest.InMemoryExporter) {
	t.Helper()

	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	otel.SetTracerProvider(tp)

	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(sdkmetric.NewManualReader()))
	otel.SetMeterProvider(mp)

	c, err := NewClientWithOptions("test-client", "1.0.0", WithSkipProviderInit())
	if err != nil {
		t.Fatalf("NewClientWithOptions: %v", err)
	}

	// Pre-populate connection info so spans carry server identity.
	c.mu.Lock()
	c.serverName = "test-server"
	c.transport = "stdio"
	c.mu.Unlock()

	t.Cleanup(func() {
		exp.Reset()
		_ = tp.Shutdown(context.Background())
	})
	return c, exp
}

// clientNoop is a MethodHandler that succeeds immediately.
func clientNoop(_ context.Context, _ string, _ sdkmcp.Request) (sdkmcp.Result, error) {
	return &sdkmcp.CallToolResult{}, nil
}

// clientErrHandler is a MethodHandler that always fails.
func clientErrHandler(_ context.Context, _ string, _ sdkmcp.Request) (sdkmcp.Result, error) {
	return nil, errors.New("downstream error")
}

// ── tools/call ────────────────────────────────────────────────────────────────

func TestClientHandleToolCall_SpanHasGenAIAttributes(t *testing.T) {
	c, exp := testClientInfra(t)

	req := &sdkmcp.CallToolRequest{Params: &sdkmcp.CallToolParams{Name: "search"}}
	if _, err := c.handleClientToolCall(context.Background(), clientNoop, req); err != nil {
		t.Fatalf("handleClientToolCall: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least 1 span")
	}

	var toolSpan *tracetest.SpanStub
	for i := range spans {
		if spans[i].Name == toolSpanName("search") {
			toolSpan = &spans[i]
			break
		}
	}
	if toolSpan == nil {
		t.Fatalf("span %q not found in %v", toolSpanName("search"), spanNames(spans))
	}

	requireAttr(t, toolSpan.Attributes, keyGenAISystem, "mcp")
	requireAttr(t, toolSpan.Attributes, keyGenAIOperationName, opToolsCall)
	requireAttr(t, toolSpan.Attributes, keyGenAIToolName, "search")
	requireAttr(t, toolSpan.Attributes, keyMCPToolName, "search")
	requireAttr(t, toolSpan.Attributes, keyMCPServerName, "test-server")
	requireAttr(t, toolSpan.Attributes, keyMCPServerTransport, "stdio")
	requireAttr(t, toolSpan.Attributes, keyMCPClientName, "test-client")
}

func TestClientHandleToolCall_OperationStatusSuccess(t *testing.T) {
	c, exp := testClientInfra(t)

	req := &sdkmcp.CallToolRequest{Params: &sdkmcp.CallToolParams{Name: "ping"}}
	if _, err := c.handleClientToolCall(context.Background(), clientNoop, req); err != nil {
		t.Fatalf("handleClientToolCall: %v", err)
	}

	spans := exp.GetSpans()
	for _, sp := range spans {
		if sp.Name == toolSpanName("ping") {
			requireAttr(t, sp.Attributes, keyMCPOperationStatus, statusSuccess)
			return
		}
	}
	t.Fatal("tool span not found")
}

func TestClientHandleToolCall_OperationStatusError(t *testing.T) {
	c, exp := testClientInfra(t)

	req := &sdkmcp.CallToolRequest{Params: &sdkmcp.CallToolParams{Name: "fail"}}
	_, _ = c.handleClientToolCall(context.Background(), clientErrHandler, req)

	spans := exp.GetSpans()
	for _, sp := range spans {
		if sp.Name == toolSpanName("fail") {
			requireAttr(t, sp.Attributes, keyMCPOperationStatus, statusError)
			return
		}
	}
	t.Fatal("tool span not found")
}

func TestClientHandleToolCall_EmptyToolName(t *testing.T) {
	c, exp := testClientInfra(t)

	// When the request carries no params (or nil Name), the span must still be created.
	req := &sdkmcp.CallToolRequest{Params: &sdkmcp.CallToolParams{}}
	_, _ = c.handleClientToolCall(context.Background(), clientNoop, req)

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least 1 span even for empty tool name")
	}
}

// ── resources/read ────────────────────────────────────────────────────────────

func TestClientHandleResourceRead_SpanAttributes(t *testing.T) {
	c, exp := testClientInfra(t)

	req := &sdkmcp.ReadResourceRequest{Params: &sdkmcp.ReadResourceParams{URI: "file:///data.txt"}}
	if _, err := c.handleClientResourceRead(context.Background(), clientNoop, req); err != nil {
		t.Fatalf("handleClientResourceRead: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least 1 span")
	}
	sp := spans[0]

	requireAttr(t, sp.Attributes, keyGenAISystem, "mcp")
	requireAttr(t, sp.Attributes, keyGenAIOperationName, opResourcesRead)
	requireAttr(t, sp.Attributes, keyMCPResourceURI, "file:///data.txt")
	requireAttr(t, sp.Attributes, keyMCPOperationStatus, statusSuccess)
}

func TestClientHandleResourceRead_URINotCaptured_WhenDisabled(t *testing.T) {
	c, exp := testClientInfra(t)
	c.cfg.captureResourceBody = false

	req := &sdkmcp.ReadResourceRequest{Params: &sdkmcp.ReadResourceParams{URI: "secret:///pii"}}
	_, _ = c.handleClientResourceRead(context.Background(), clientNoop, req)

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least 1 span")
	}
	if _, ok := findAttr(spans[0].Attributes, keyMCPResourceURI); ok {
		t.Error("mcp.resource.uri must be absent when captureResourceBody=false")
	}
}

func TestClientHandleResourceRead_OperationStatusError(t *testing.T) {
	c, exp := testClientInfra(t)

	req := &sdkmcp.ReadResourceRequest{Params: &sdkmcp.ReadResourceParams{URI: "file:///x"}}
	_, _ = c.handleClientResourceRead(context.Background(), clientErrHandler, req)

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least 1 span")
	}
	requireAttr(t, spans[0].Attributes, keyMCPOperationStatus, statusError)
}

// ── prompts/get ───────────────────────────────────────────────────────────────

func TestClientHandlePromptGet_SpanAttributes(t *testing.T) {
	c, exp := testClientInfra(t)

	req := &sdkmcp.GetPromptRequest{Params: &sdkmcp.GetPromptParams{Name: "system-prompt"}}
	if _, err := c.handleClientPromptGet(context.Background(), clientNoop, req); err != nil {
		t.Fatalf("handleClientPromptGet: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least 1 span")
	}
	sp := spans[0]

	requireAttr(t, sp.Attributes, keyGenAISystem, "mcp")
	requireAttr(t, sp.Attributes, keyGenAIOperationName, opPromptsGet)
	requireAttr(t, sp.Attributes, keyMCPPromptName, "system-prompt")
	requireAttr(t, sp.Attributes, keyMCPOperationStatus, statusSuccess)
}

func TestClientHandlePromptGet_SpanName_IncludesPromptName(t *testing.T) {
	c, exp := testClientInfra(t)

	req := &sdkmcp.GetPromptRequest{Params: &sdkmcp.GetPromptParams{Name: "greeting"}}
	_, _ = c.handleClientPromptGet(context.Background(), clientNoop, req)

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least 1 span")
	}
	want := promptGetSpanName("greeting")
	if got := spans[0].Name; got != want {
		t.Errorf("span name: got %q, want %q", got, want)
	}
}

func TestClientHandlePromptGet_OperationStatusError(t *testing.T) {
	c, exp := testClientInfra(t)

	req := &sdkmcp.GetPromptRequest{Params: &sdkmcp.GetPromptParams{Name: "bad"}}
	_, _ = c.handleClientPromptGet(context.Background(), clientErrHandler, req)

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least 1 span")
	}
	requireAttr(t, spans[0].Attributes, keyMCPOperationStatus, statusError)
}

// ── handleClientSimpleOp ─────────────────────────────────────────────────────

func TestClientHandleSimpleOp_SetsOperationStatusSuccess(t *testing.T) {
	c, exp := testClientInfra(t)

	_, _ = c.handleClientSimpleOp(context.Background(), clientNoop, opToolsList, nil)

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least 1 span")
	}
	requireAttr(t, spans[0].Attributes, keyMCPOperationStatus, statusSuccess)
}

func TestClientHandleSimpleOp_SetsOperationStatusError(t *testing.T) {
	c, exp := testClientInfra(t)

	_, _ = c.handleClientSimpleOp(context.Background(), clientErrHandler, opToolsList, nil)

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least 1 span")
	}
	requireAttr(t, spans[0].Attributes, keyMCPOperationStatus, statusError)
}

func TestClientHandleSimpleOp_SpanName(t *testing.T) {
	c, exp := testClientInfra(t)

	_, _ = c.handleClientSimpleOp(context.Background(), clientNoop, opInitialize, nil)

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least 1 span")
	}
	want := spanName(opInitialize)
	if got := spans[0].Name; got != want {
		t.Errorf("span name: got %q, want %q", got, want)
	}
}

// ── WithSkipProviderInit ──────────────────────────────────────────────────────

func TestNewClientWithOptions_SkipProviderInit_ProvidersAreNil(t *testing.T) {
	tp := sdktrace.NewTracerProvider()
	otel.SetTracerProvider(tp)
	mp := sdkmetric.NewMeterProvider()
	otel.SetMeterProvider(mp)

	c, err := NewClientWithOptions("skip-test", "1.0.0", WithSkipProviderInit())
	if err != nil {
		t.Fatalf("NewClientWithOptions: %v", err)
	}

	if c.traceProvider != nil {
		t.Error("traceProvider should be nil with WithSkipProviderInit()")
	}
	if c.metricProvider != nil {
		t.Error("metricProvider should be nil with WithSkipProviderInit()")
	}
	if c.logProvider != nil {
		t.Error("logProvider should be nil with WithSkipProviderInit()")
	}

	_ = tp.Shutdown(context.Background())
	_ = mp.Shutdown(context.Background())
}
