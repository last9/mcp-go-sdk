package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
)

// ClientInfo contains information about the connected client
type ClientInfo struct {
	Name         string
	Version      string
	Transport    string
	Capabilities mcp.ClientCapabilities
}

// HubManager manages multiple client hubs
type HubManager struct {
	hubs       map[string]*Hub // clientID -> Hub
	mu         sync.RWMutex
	currentHub *Hub // for stdio, there's only one hub
}

type Hub struct {
	ClientInfo   ClientInfo
	currentTrace trace.Span
}

type Last9MCPServer struct {
	Server          *mcp.Server
	serverName      string
	serverTransport string
	hubManager      *HubManager
	tracer          trace.Tracer
	meter           metric.Meter

	// Metrics instruments
	callCounter  metric.Int64Counter
	callDuration metric.Float64Histogram
	errorCounter metric.Int64Counter
}

// parseArguments is a helper function to handle the any type of req.Params.Arguments
// and unmarshal it into the provided struct
func parseArguments(arguments any, target interface{}) error {
	switch args := arguments.(type) {
	case json.RawMessage:
		// Arguments come as raw JSON bytes
		return json.Unmarshal(args, target)
	case map[string]interface{}:
		// Arguments are already parsed into a map
		// Convert back to JSON and unmarshal to get proper types
		jsonBytes, err := json.Marshal(args)
		if err != nil {
			return fmt.Errorf("failed to marshal map to JSON: %w", err)
		}
		return json.Unmarshal(jsonBytes, target)
	case nil:
		// No arguments provided
		return fmt.Errorf("no arguments provided")
	default:
		// Try to marshal and unmarshal as a fallback for any other type
		jsonBytes, err := json.Marshal(args)
		if err != nil {
			return fmt.Errorf("failed to marshal arguments to JSON: %w", err)
		}
		return json.Unmarshal(jsonBytes, target)
	}
}

func mapServerTransport(transport mcp.Transport) string {
	switch transport.(type) {
	case *mcp.StdioTransport:
		return "stdio"
	case *mcp.StreamableServerTransport:
		return "streamable"
	case *mcp.SSEServerTransport:
		return "sse"
	default:
		return "stdio"
	}
}

// initOpenTelemetry sets up OpenTelemetry SDK
func initOpenTelemetry(serviceName, version string) error {
	ctx := context.Background()
	traceExp, err := otlptracehttp.New(ctx, otlptracehttp.WithInsecure())
	if err != nil {
		return fmt.Errorf("creating stdout exporter: %w", err)
	}

	// Create resource
	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(serviceName),
		semconv.ServiceVersion(version),
		attribute.String("mcp.server.type", "golang"),
	)
	if err != nil {
		return fmt.Errorf("creating resource: %w", err)
	}

	// Create trace provider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	otel.SetTracerProvider(tp)

	// Register W3C Trace Context propagator as the global so any imported
	// instrumentation in the future will default to using it.
	otel.SetTextMapPropagator(propagation.TraceContext{})

	metricExp, err := otlpmetrichttp.New(ctx, otlpmetrichttp.WithInsecure())
	if err != nil {
		return fmt.Errorf("creating stdout metric exporter: %w", err)
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(
			metricExp, sdkmetric.WithInterval(10*time.Second))),
	)

	otel.SetMeterProvider(mp)

	return nil
}

// initMetrics initializes OpenTelemetry metrics instruments
func (w *Last9MCPServer) initMetrics() error {
	var err error

	// Counter for total tool calls
	w.callCounter, err = w.meter.Int64Counter(
		"mcp_tool_calls_total",
		metric.WithDescription("Total number of MCP tool calls"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return fmt.Errorf("creating call counter: %w", err)
	}

	// Histogram for call duration
	w.callDuration, err = w.meter.Float64Histogram(
		"mcp_tool_call_duration_seconds",
		metric.WithDescription("Duration of MCP tool calls in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return fmt.Errorf("creating duration histogram: %w", err)
	}

	// Counter for errors
	w.errorCounter, err = w.meter.Int64Counter(
		"mcp_tool_errors_total",
		metric.WithDescription("Total number of MCP tool call errors"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return fmt.Errorf("creating error counter: %w", err)
	}

	log.Println("📊 OpenTelemetry metrics instruments initialized")

	return nil
}

// NewServer creates a new wrapper with OpenTelemetry instrumentation
func NewServer(serverName, version string) (*Last9MCPServer, error) {
	// Initialize OpenTelemetry
	if err := initOpenTelemetry(serverName, version); err != nil {
		return nil, fmt.Errorf("failed to initialize OpenTelemetry: %w", err)
	}

	// Create tracer and meter
	tracer := otel.Tracer("last9-mcp-server")
	meter := otel.Meter("last9-mcp-server")

	info := mcp.Implementation{
		Name:    serverName,
		Version: version,
	}

	server := &Last9MCPServer{
		Server:     mcp.NewServer(&info, nil),
		serverName: serverName,
		tracer:     tracer,
		meter:      meter,
		hubManager: &HubManager{
			hubs: make(map[string]*Hub),
		},
	}

	server.Server.AddReceivingMiddleware(server.requestStartMiddleware)

	// Initialize metrics instruments
	if err := server.initMetrics(); err != nil {
		return nil, fmt.Errorf("failed to initialize metrics: %w", err)
	}

	return server, nil
}

func (s *Last9MCPServer) requestStartMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		var hub *Hub

		if method == "initialize" {
			hub = s.handleInitializeAndCreateHub(req)
		} else {
			hub = s.GetCurrentHub(ctx, req)
		}

		// Add hub context to the request context for tools
		ctx = context.WithValue(ctx, "hub", hub)

		ctx, span := s.addTrace(ctx, method, req)
		if span != nil {
			defer span.End()
		}

		resp, err := next(ctx, method, req)
		return resp, err
	}
}

// GetCurrentHub retrieves the current hub for the client from context
func (s *Last9MCPServer) GetCurrentHub(ctx context.Context, req mcp.Request) *Hub {
	// Try to get hub from context
	if hub, ok := ctx.Value("hub").(*Hub); ok {
		return hub
	}

	// Fallback to currentHub in HubManager (for stdio transport)
	if s.hubManager.currentHub != nil {
		return s.hubManager.currentHub
	}

	return &Hub{
		ClientInfo: ClientInfo{
			Name:      "unknown_client",
			Version:   "unknown",
			Transport: "unknown",
		},
	}
}

// handleInitializeAndCreateHub extracts client info from initialize request and creates appropriate hub
func (s *Last9MCPServer) handleInitializeAndCreateHub(req mcp.Request) *Hub {
	// Try to extract client information from initialize request
	clientInfo := s.extractClientInfo(req)

	// Generate client ID based on client info and process
	clientID := s.getOrGenerateClientID(clientInfo)

	// Create hub for this client
	hub := s.hubManager.CreateHub(clientID, clientInfo)

	// Set as current hub for stdio transport
	// TODO: Add handling for http
	s.hubManager.currentHub = hub

	log.Printf("🎯 Created hub %s for client %s v%s via %s transport",
		clientID, clientInfo.Name, clientInfo.Version, clientInfo.Transport)

	return hub
}

// extractClientInfo extracts client information from MCP initialize request
func (s *Last9MCPServer) extractClientInfo(req mcp.Request) ClientInfo {
	clientInfo := ClientInfo{
		Name:      "unknown_client",
		Version:   "unknown",
		Transport: "stdio",
	}

	log.Printf("🔍 Extracting client info from request of type %T", req)

	if initParams, ok := req.GetParams().(*mcp.InitializeParams); ok {
		clientInfo.Name = initParams.ClientInfo.Name
		clientInfo.Version = initParams.ClientInfo.Version
		log.Printf("Protocol Version: %s\n", initParams.ProtocolVersion)

		if initParams.Capabilities != nil {
			clientInfo.Capabilities = *initParams.Capabilities
		}

		// Detect transport type (stdio is default for subprocess)
		clientInfo.Transport = "stdio"

		log.Printf("📋 Extracted client info: %s v%s", clientInfo.Name, clientInfo.Version)
		return clientInfo
	}

	return clientInfo
}

// generateClientID creates a unique client identifier
func (s *Last9MCPServer) getOrGenerateClientID(clientInfo ClientInfo) string {
	// For stdio transport, use client name + process info
	if clientInfo.Transport == "stdio" {
		// In stdio, each subprocess = unique client
		return fmt.Sprintf("%s_stdio", clientInfo.Name)
	}

	// For future HTTP/SSE transport, could include connection info
	return fmt.Sprintf("%s_%s_%d",
		clientInfo.Name,
		clientInfo.Transport)
}

// CreateHub creates a new hub for a client
func (hm *HubManager) CreateHub(clientID string, clientInfo ClientInfo) *Hub {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	hub := &Hub{
		ClientInfo: clientInfo,
	}

	hm.hubs[clientID] = hub

	log.Printf("🔄 Created new hub for client %s", clientID)
	return hub
}

// RegisterInstrumentedTool registers a tool with OpenTelemetry instrumentation
func (w *Last9MCPServer) RegisterInstrumentedTool(name string, tool mcp.Tool, handler mcp.ToolHandler) {
	// Wrap the handler with OpenTelemetry instrumentation
	instrumentedHandler := w.instrumentHandler(name, handler)
	w.Server.AddTool(&tool, instrumentedHandler)
}

// addParentSpanToContext adds a span to the context
func (s *Last9MCPServer) addParentSpanToContext(ctx context.Context, parent trace.Span) context.Context {
	if parent == nil {
		return ctx
	}
	ctx = trace.ContextWithSpan(ctx, parent)
	return ctx
}

func (s *Last9MCPServer) createNewTrace(ctx context.Context, method string, hub *Hub) (context.Context, trace.Span) {
	ctx, span := s.tracer.Start(ctx, fmt.Sprintf("mcp.tool.%s", method))
	hub.currentTrace = span
	ctx = s.addParentSpanToContext(ctx, span)
	return ctx, span
}

func (s *Last9MCPServer) addTrace(ctx context.Context, method string, req mcp.Request) (context.Context, trace.Span) {
	hub, _ := ctx.Value("hub").(*Hub)

	methodCall := method
	ctr, ok := req.(*mcp.CallToolRequest)
	if ok {
		methodCall = ctr.Params.Name
		if ctr.Params.Name == "last9-telemetry" {
			// Ending trace handled in tool handler
			return ctx, nil
		}
	}

	if hub.currentTrace == nil {
		ctx, _ := s.createNewTrace(ctx, methodCall, hub)
		return ctx, nil
	}

	// add current trace as parent
	ctx = s.addParentSpanToContext(ctx, hub.currentTrace)

	// Start a new child span for this method call
	ctx, childSpan := s.tracer.Start(ctx, fmt.Sprintf("mcp.tool.%s", methodCall),
		trace.WithAttributes(
			attribute.String("mcp.tool.name", methodCall),
		))

	log.Printf("🔍 [addTrace] Started child span from ctx: %v", trace.SpanFromContext(ctx))
	return ctx, childSpan
}

// instrumentHandler wraps a tool handler with OpenTelemetry tracing and metrics
func (w *Last9MCPServer) instrumentHandler(toolName string, originalHandler mcp.ToolHandler) mcp.ToolHandler {
	return func(ctx context.Context, mcpReq *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		span := trace.SpanFromContext(ctx)
		span.SetAttributes(attribute.String("mcp.server.transport", w.serverTransport))

		var p interface{}
		err := parseArguments(mcpReq.Params.Arguments, &p)

		// Add parameters to span (be careful not to log sensitive data)
		w.addParamsToSpan(span, p)

		// Record start time for metrics
		startTime := time.Now()

		// Create metric attributes
		metricAttrs := []attribute.KeyValue{
			attribute.String("tool_name", toolName),
			attribute.String("server_transport", w.serverTransport),
		}

		w.callCounter.Add(ctx, 1, metric.WithAttributes(metricAttrs...))

		// Call the original handler
		result, err := originalHandler(ctx, mcpReq)

		// Calculate duration
		duration := time.Since(startTime)

		// Record metrics
		w.callDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(metricAttrs...))

		// Handle errors and success
		success := err == nil && (result == nil || !result.IsError)

		if success {
			span.SetStatus(codes.Ok, "Tool call completed successfully")
			span.SetAttributes(attribute.String("mcp.result.status", "success"))
		} else {
			// Record error metrics
			errorAttrs := append(metricAttrs, attribute.String("error_type", "tool_error"))
			w.errorCounter.Add(ctx, 1, metric.WithAttributes(errorAttrs...))

			// Set span status
			span.SetStatus(codes.Error, "Tool call failed")
			span.SetAttributes(attribute.String("mcp.result.status", "error"))

			if err != nil {
				span.RecordError(err)
				span.SetAttributes(attribute.String("mcp.error.message", err.Error()))
			} else if result.IsError {
				errMsg := "unknown error"
				if len(result.Content) > 0 {
					// Attempt to extract error message from result content
					if msg, ok := result.Content[0].(*mcp.TextContent); ok {
						errMsg = msg.Text
					}
				}
				span.SetAttributes(attribute.String("mcp.error.message", string(errMsg)))
			}
		}

		// Add more span attributes
		span.SetAttributes(
			attribute.Float64("mcp.duration.seconds", duration.Seconds()),
			attribute.Int64("mcp.duration.milliseconds", duration.Milliseconds()),
			attribute.Bool("mcp.success", success),
		)

		log.Printf("🏁 [OTel] Completed tool call: %s (duration: %v, success: %v)",
			toolName, duration, success)

		return result, err
	}
}

// addParamsToSpan safely adds parameters to the span (avoiding sensitive data)
func (w *Last9MCPServer) addParamsToSpan(span trace.Span, params interface{}) {
	if params == nil {
		return
	}
	args := params.(map[string]interface{})
	// Add parameter count
	span.SetAttributes(attribute.Int("mcp.params.count", len(args)))

	if len(args) > 0 {
		for key := range args {
			span.SetAttributes(attribute.String(fmt.Sprintf("mcp.param.%s", key), fmt.Sprintf("%v", args[key])))
		}
	}
}

func endParentTrace(ctx context.Context) {
	span := trace.SpanFromContext(ctx)
	span.End()

	hub, _ := ctx.Value("hub").(*Hub)
	if hub != nil && hub.currentTrace != nil {
		hub.currentTrace.End()
		hub.currentTrace = nil
	}
}

// Serve starts the MCP server
func (w *Last9MCPServer) Serve(ctx context.Context, transport mcp.Transport) error {
	log.Println("🚀 Starting instrumented MCP server...")

	w.serverTransport = mapServerTransport(transport)
	w.Server.AddTool(&mcp.Tool{
		Name:        "last9-telemetry",
		Description: "After all calls of tools are done, this should be called necessarily without skipping. It will never be called as the first tool in a trace.",
		InputSchema: &jsonschema.Schema{
			Type:       "object",
			Properties: map[string]*jsonschema.Schema{},
			Required:   []string{},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		endParentTrace(ctx)
		return &mcp.CallToolResult{
			IsError: false,
			Content: []mcp.Content{&mcp.TextContent{Text: "Trace ended"}},
		}, nil
	})
	err := w.Server.Run(ctx, transport)
	if err != nil {
		log.Printf("❌ MCP server encountered an error: %v", err)
		span := trace.SpanFromContext(ctx)
		span.SetAttributes(attribute.String("mcp.server.error", err.Error()))
		endParentTrace(ctx)
	}
	return err
}
