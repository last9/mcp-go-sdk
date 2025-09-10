package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
)

// OtelMCPWrapper wraps an MCP server with OpenTelemetry instrumentation
type OtelMCPWrapper struct {
	Server          *mcp.Server
	serverTransport string
	tracer          trace.Tracer
	meter           metric.Meter
	currentTrace    trace.Span

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

// NewServerWithOtel creates a new wrapper with OpenTelemetry instrumentation
func NewServerWithOtel(serverName, version string) (*OtelMCPWrapper, error) {
	// Initialize OpenTelemetry
	if err := initOpenTelemetry(serverName, version); err != nil {
		return nil, fmt.Errorf("failed to initialize OpenTelemetry: %w", err)
	}

	// Create tracer and meter
	tracer := otel.Tracer("mcp-server")
	meter := otel.Meter("mcp-server")

	info := mcp.Implementation{
		Name:    serverName,
		Version: version,
	}
	wrapper := &OtelMCPWrapper{
		Server: mcp.NewServer(&info, nil),
		tracer: tracer,
		meter:  meter,
	}

	// Initialize metrics instruments
	if err := wrapper.initMetrics(); err != nil {
		return nil, fmt.Errorf("failed to initialize metrics: %w", err)
	}

	return wrapper, nil
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
func (w *OtelMCPWrapper) initMetrics() error {
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

func (w *OtelMCPWrapper) isNewQuery(method string) bool {
	queryMethods := []string{
		"initialize",
		"tools/list",
		"resources/list",
		"prompts/list",
	}
	for _, newQueryMethod := range queryMethods {
		if method == newQueryMethod {
			return true
		}
	}

	// No active trace means new query
	if w.currentTrace == nil {
		return true
	}

	return false
}

// RegisterInstrumentedTool registers a tool with OpenTelemetry instrumentation
func (w *OtelMCPWrapper) RegisterInstrumentedTool(name string, tool mcp.Tool, handler mcp.ToolHandler) {
	// Wrap the handler with OpenTelemetry instrumentation
	instrumentedHandler := w.instrumentHandler(name, handler)
	w.Server.AddTool(&tool, instrumentedHandler)
}

func (w *OtelMCPWrapper) requestStartMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		var newCtx context.Context
		var span trace.Span

		startTrace := fmt.Sprintf("mcp.request.%s.start", method)
		if ctr, ok := req.(*mcp.CallToolRequest); ok {
			startTrace = fmt.Sprintf("mcp.tool.%s.start", ctr.Params.Name)
		}

		if w.isNewQuery(method) {
			if method == "tools/list" {
				newCtx, span = w.tracer.Start(ctx, startTrace)
				if w.currentTrace != nil {
					w.currentTrace = nil
					w.currentTrace.End()
				}
				w.currentTrace = span
			}
		} else {
			ctx = trace.ContextWithSpan(ctx, w.currentTrace)
			newCtx, span = w.tracer.Start(ctx, startTrace, trace.WithAttributes(
				attribute.String("mcp.server.transport", w.serverTransport),
			))
		}

		if span != nil {
			defer span.End()
		}

		resp, err := next(newCtx, method, req)

		return resp, err
	}
}

// instrumentHandler wraps a tool handler with OpenTelemetry tracing and metrics
func (w *OtelMCPWrapper) instrumentHandler(toolName string, originalHandler mcp.ToolHandler) mcp.ToolHandler {
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

		log.Printf("🔧 [OTel] Starting tool call: %s", toolName)

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
func (w *OtelMCPWrapper) addParamsToSpan(span trace.Span, params interface{}) {
	args := params.(map[string]interface{})
	// Add parameter count
	span.SetAttributes(attribute.Int("mcp.params.count", len(args)))

	// Add safe parameter keys (avoid logging values that might be sensitive)
	if len(args) > 0 {
		keys := make([]string, 0, len(args))
		for key := range args {
			keys = append(keys, key)
		}
		span.SetAttributes(attribute.StringSlice("mcp.params.keys", keys))
	}
}

// Serve starts the MCP server
func (w *OtelMCPWrapper) Serve(ctx context.Context, transport mcp.Transport) error {
	log.Println("🚀 Starting instrumented MCP server...")

	w.serverTransport = mapServerTransport(transport)
	w.Server.AddReceivingMiddleware(w.requestStartMiddleware)
	// w.Server.AddSendingMiddleware(w.requestEndMiddleware)
	err := w.Server.Run(ctx, transport)
	return err
}
