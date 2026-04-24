package mcp

import (
	"context"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// testInfra creates an isolated server with synchronous in-memory OTel providers.
// WithSyncer guarantees that spans are available in the exporter the moment
// span.End() returns — no flush needed.
func testInfra(t *testing.T) (*Last9MCPServer, *tracetest.InMemoryExporter) {
	t.Helper()

	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	otel.SetTracerProvider(tp)

	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(sdkmetric.NewManualReader()))
	otel.SetMeterProvider(mp)

	s, err := NewServerWithOptions("test-server", "1.0.0", WithSkipProviderInit())
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}
	s.serverTransport = "stdio"

	t.Cleanup(func() {
		_ = s.Shutdown(context.Background())
		exp.Reset()
		_ = tp.Shutdown(context.Background())
	})
	return s, exp
}

// withTestClient registers a client session and returns a context carrying
// the client identity, mirroring what attachClientContext does at runtime.
func withTestClient(ctx context.Context, s *Last9MCPServer, clientID, clientName string) context.Context {
	info := ClientInfo{Name: clientName, Version: "1.0", Transport: "stdio"}
	s.sessions.create(clientID, info)
	s.mu.Lock()
	s.currentClientID = clientID
	s.mu.Unlock()
	ctx = context.WithValue(ctx, contextKeyClientID, clientID)
	ctx = context.WithValue(ctx, contextKeyClientInfo, info)
	return ctx
}

// ── tools/call ────────────────────────────────────────────────────────────────

func TestHandleToolsCall_SpanHasGenAIAttributes(t *testing.T) {
	s, exp := testInfra(t)
	ctx := withTestClient(context.Background(), s, "c1", "cursor")

	req := &sdkmcp.CallToolRequest{Params: &sdkmcp.CallToolParamsRaw{Name: "search"}}
	if _, err := s.handleToolsCall(ctx, noop, req); err != nil {
		t.Fatalf("handleToolsCall: %v", err)
	}

	spans := exp.GetSpans()
	// Expect at least the tool span; a root query span may also be present.
	if len(spans) < 1 {
		t.Fatalf("expected at least 1 span, got %d", len(spans))
	}

	// Find the tool-named span.
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
	requireAttr(t, toolSpan.Attributes, keyMCPClientName, "cursor")
	requireAttr(t, toolSpan.Attributes, keyMCPServerTransport, "stdio")
}

func TestHandleToolsCall_OperationStatusSuccess(t *testing.T) {
	s, exp := testInfra(t)
	ctx := withTestClient(context.Background(), s, "c1", "test-client")

	req := &sdkmcp.CallToolRequest{Params: &sdkmcp.CallToolParamsRaw{Name: "ping"}}
	if _, err := s.handleToolsCall(ctx, noop, req); err != nil {
		t.Fatalf("handleToolsCall: %v", err)
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

func TestHandleToolsCall_OperationStatusError(t *testing.T) {
	s, exp := testInfra(t)
	ctx := withTestClient(context.Background(), s, "c1", "test-client")

	req := &sdkmcp.CallToolRequest{Params: &sdkmcp.CallToolParamsRaw{Name: "fail"}}
	// errHandler returns an error — span should reflect mcp.operation.status=error
	_, _ = s.handleToolsCall(ctx, errHandler, req)

	spans := exp.GetSpans()
	for _, sp := range spans {
		if sp.Name == toolSpanName("fail") {
			requireAttr(t, sp.Attributes, keyMCPOperationStatus, statusError)
			return
		}
	}
	t.Fatal("tool span not found")
}

func TestHandleToolsCall_QueryCorrelation_SameTraceID(t *testing.T) {
	s, exp := testInfra(t)

	// Create the session once — re-creating would wipe stored query spans.
	clientID := "c-corr"
	info := ClientInfo{Name: "corr-client", Version: "1.0", Transport: "stdio"}
	s.sessions.create(clientID, info)
	s.mu.Lock()
	s.currentClientID = clientID
	s.mu.Unlock()

	makeCtx := func() context.Context {
		ctx := context.WithValue(context.Background(), contextKeyClientID, clientID)
		return context.WithValue(ctx, contextKeyClientInfo, info)
	}

	// First call — creates the root query span and stores it.
	req1 := &sdkmcp.CallToolRequest{Params: &sdkmcp.CallToolParamsRaw{Name: "tool-a"}}
	_, _ = s.handleToolsCall(makeCtx(), noop, req1)

	// Second call — should re-use the stored query span (query correlation).
	req2 := &sdkmcp.CallToolRequest{Params: &sdkmcp.CallToolParamsRaw{Name: "tool-b"}}
	_, _ = s.handleToolsCall(makeCtx(), noop, req2)

	allSpans := exp.GetSpans()
	var traceIDs []string
	for _, sp := range allSpans {
		if sp.Name == toolSpanName("tool-a") || sp.Name == toolSpanName("tool-b") {
			traceIDs = append(traceIDs, sp.SpanContext.TraceID().String())
		}
	}

	if len(traceIDs) != 2 {
		t.Fatalf("expected 2 tool spans, got %d (spans: %v)", len(traceIDs), spanNames(allSpans))
	}
	if traceIDs[0] != traceIDs[1] {
		t.Errorf("query correlation broken: tool-a traceID %q != tool-b traceID %q",
			traceIDs[0], traceIDs[1])
	}
}

// ── resources/read ────────────────────────────────────────────────────────────

func TestHandleResourcesRead_SpanAttributes(t *testing.T) {
	s, exp := testInfra(t)
	ctx := withTestClient(context.Background(), s, "c1", "res-client")

	req := &sdkmcp.ReadResourceRequest{Params: &sdkmcp.ReadResourceParams{URI: "file:///data.txt"}}
	if _, err := s.handleResourcesRead(ctx, noop, req); err != nil {
		t.Fatalf("handleResourcesRead: %v", err)
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

func TestHandleResourcesRead_URINotCaptured_WhenDisabled(t *testing.T) {
	s, exp := testInfra(t)
	s.cfg.captureResourceBody = false
	ctx := withTestClient(context.Background(), s, "c1", "res-client")

	req := &sdkmcp.ReadResourceRequest{Params: &sdkmcp.ReadResourceParams{URI: "secret:///pii"}}
	_, _ = s.handleResourcesRead(ctx, noop, req)

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least 1 span")
	}
	if _, ok := findAttr(spans[0].Attributes, keyMCPResourceURI); ok {
		t.Error("mcp.resource.uri should be absent when captureResourceBody=false")
	}
}

// ── prompts/get ───────────────────────────────────────────────────────────────

func TestHandlePromptsGet_SpanAttributes(t *testing.T) {
	s, exp := testInfra(t)
	ctx := withTestClient(context.Background(), s, "c1", "prompt-client")

	req := &sdkmcp.GetPromptRequest{Params: &sdkmcp.GetPromptParams{Name: "system-prompt"}}
	if _, err := s.handlePromptsGet(ctx, noop, req); err != nil {
		t.Fatalf("handlePromptsGet: %v", err)
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

func TestHandlePromptsGet_SpanName_IncludesPromptName(t *testing.T) {
	s, exp := testInfra(t)
	ctx := withTestClient(context.Background(), s, "c1", "prompt-client")

	req := &sdkmcp.GetPromptRequest{Params: &sdkmcp.GetPromptParams{Name: "greeting"}}
	_, _ = s.handlePromptsGet(ctx, noop, req)

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least 1 span")
	}
	want := promptGetSpanName("greeting")
	if got := spans[0].Name; got != want {
		t.Errorf("span name: got %q, want %q", got, want)
	}
}

// ── prompts/get — L3 fix: empty prompt name must not emit mcp.prompt.name attr ─

func TestPromptAttrs_EmptyNameOmitted(t *testing.T) {
	attrs := promptAttrs("", "stdio", "test-client")
	if _, ok := findAttr(attrs, keyMCPPromptName); ok {
		t.Error("mcp.prompt.name must be absent when promptName is empty (L3 fix)")
	}
}

func TestPromptAttrs_NameIncluded(t *testing.T) {
	attrs := promptAttrs("my-prompt", "stdio", "test-client")
	requireAttr(t, attrs, keyMCPPromptName, "my-prompt")
}

// ── handleSimpleOp — M4 fix: operation status must be set ────────────────────

func TestHandleSimpleOp_SetsOperationStatusSuccess(t *testing.T) {
	s, exp := testInfra(t)
	ctx := withTestClient(context.Background(), s, "c1", "test-client")

	_, _ = s.handleSimpleOp(ctx, noop, opToolsList, nil)

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least 1 span")
	}
	requireAttr(t, spans[0].Attributes, keyMCPOperationStatus, statusSuccess)
}

func TestHandleSimpleOp_SetsOperationStatusError(t *testing.T) {
	s, exp := testInfra(t)
	ctx := withTestClient(context.Background(), s, "c1", "test-client")

	_, _ = s.handleSimpleOp(ctx, errHandler, opToolsList, nil)

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least 1 span")
	}
	requireAttr(t, spans[0].Attributes, keyMCPOperationStatus, statusError)
}

// ── instrumentHandler — arg capture ──────────────────────────────────────────

func TestInstrumentHandler_ArgCapture_Enabled(t *testing.T) {
	s, exp := testInfra(t)
	ctx := withTestClient(context.Background(), s, "c1", "test-client")

	type Input struct {
		Query string `json:"query"`
	}
	handler := instrumentHandler(s, func(_ context.Context, _ *sdkmcp.CallToolRequest, args Input) (*sdkmcp.CallToolResult, any, error) {
		return &sdkmcp.CallToolResult{}, nil, nil
	})

	// Build a tool span so there is an active span in context.
	ctx, span := s.tracer.Start(ctx, "test-tool-span")
	req := &sdkmcp.CallToolRequest{Params: &sdkmcp.CallToolParamsRaw{Name: "search"}}
	_, _, _ = handler(ctx, req, Input{Query: "hello"})
	span.End()

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least 1 span")
	}
	val, ok := findAttr(spans[0].Attributes, attribute.Key("mcp.arg.query"))
	if !ok {
		t.Error("mcp.arg.query should be present when captureToolArgs=true")
	} else if val.AsString() != "hello" {
		t.Errorf("mcp.arg.query: got %q, want %q", val.AsString(), "hello")
	}
}

func TestInstrumentHandler_ArgCapture_Disabled(t *testing.T) {
	s, exp := testInfra(t)
	s.cfg.captureToolArgs = false
	ctx := withTestClient(context.Background(), s, "c1", "test-client")

	type Input struct {
		Secret string `json:"secret"`
	}
	handler := instrumentHandler(s, func(_ context.Context, _ *sdkmcp.CallToolRequest, args Input) (*sdkmcp.CallToolResult, any, error) {
		return &sdkmcp.CallToolResult{}, nil, nil
	})

	ctx, span := s.tracer.Start(ctx, "test-tool-span")
	req := &sdkmcp.CallToolRequest{Params: &sdkmcp.CallToolParamsRaw{Name: "sensitive"}}
	_, _, _ = handler(ctx, req, Input{Secret: "my-password"})
	span.End()

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least 1 span")
	}
	for _, a := range spans[0].Attributes {
		if string(a.Key) == "mcp.arg.secret" {
			t.Error("mcp.arg.secret must be absent when captureToolArgs=false (PII protection)")
		}
	}
}

// ── WithSkipProviderInit — M6 fix ─────────────────────────────────────────────

func TestNewServerWithOptions_SkipProviderInit_ProvidersAreNil(t *testing.T) {
	// Set up a minimal global provider so otel.Tracer/Meter don't panic.
	tp := sdktrace.NewTracerProvider()
	otel.SetTracerProvider(tp)
	mp := sdkmetric.NewMeterProvider()
	otel.SetMeterProvider(mp)

	s, err := NewServerWithOptions("skip-test", "1.0.0", WithSkipProviderInit())
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}

	// The server must not own any OTel provider — it must not call Shutdown on
	// providers it didn't create (M6 fix).
	if s.traceProvider != nil {
		t.Error("traceProvider should be nil with WithSkipProviderInit()")
	}
	if s.metricProvider != nil {
		t.Error("metricProvider should be nil with WithSkipProviderInit()")
	}
	if s.logProvider != nil {
		t.Error("logProvider should be nil with WithSkipProviderInit()")
	}

	_ = tp.Shutdown(context.Background())
	_ = mp.Shutdown(context.Background())
}

