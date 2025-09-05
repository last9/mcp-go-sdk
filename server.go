package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
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
	server          *mcp.Server
	serverTransport string
	tracer          trace.Tracer
	meter           metric.Meter

	// Metrics instruments
	callCounter  metric.Int64Counter
	callDuration metric.Float64Histogram
	errorCounter metric.Int64Counter
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
		server: mcp.NewServer(&info, nil),
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

// RegisterInstrumentedTool registers a tool with OpenTelemetry instrumentation
func (w *OtelMCPWrapper) RegisterInstrumentedTool(name string, tool mcp.Tool, handler mcp.ToolHandler) {
	// Register the tool with the underlying server
	// w.server.AddTool(&tool, handler)

	// Wrap the handler with OpenTelemetry instrumentation
	instrumentedHandler := w.instrumentHandler(name, handler)
	w.server.AddTool(&tool, instrumentedHandler)
}

// instrumentHandler wraps a tool handler with OpenTelemetry tracing and metrics
func (w *OtelMCPWrapper) instrumentHandler(toolName string, originalHandler mcp.ToolHandler) mcp.ToolHandler {
	return func(ctx context.Context, mcpReq *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Start a new span for this tool call
		ctx, span := w.tracer.Start(ctx, fmt.Sprintf("mcp.tool.%s", toolName),
			trace.WithAttributes(
				attribute.String("mcp.tool.name", toolName),
				attribute.String("mcp.operation", "tool_call"),
				attribute.String("mcp.server.transport", w.serverTransport),
			),
		)
		defer span.End()

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

		// Call the original handler
		result, err := originalHandler(ctx, mcpReq)

		// Calculate duration
		duration := time.Since(startTime)

		// Record metrics
		w.callCounter.Add(ctx, 1, metric.WithAttributes(metricAttrs...))
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
				span.SetAttributes(attribute.String("mcp.error.message", "Tool returned error result"))
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
	// Start a span for the server lifecycle
	ctx, span := w.tracer.Start(ctx, "mcp.server.serve",
		trace.WithAttributes(
			attribute.String("mcp.operation", "serve"),
		),
	)
	defer span.End()

	log.Println("🚀 Starting instrumented MCP server...")

	w.serverTransport = mapServerTransport(transport)
	err := w.server.Run(ctx, transport)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Server failed")
	} else {
		span.SetStatus(codes.Ok, "Server completed")
	}

	return err
}

// Example usage demonstrating OpenTelemetry instrumentation
func main() {
	// Create OpenTelemetry instrumented MCP server
	wrapper, err := NewServerWithOtel("otel-mcp-demo", "1.0.0")
	if err != nil {
		log.Fatalf("Failed to create wrapper: %v", err)
	}

	registerTools(wrapper)

	// Start the server
	if err := wrapper.Serve(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// registerTools registers demonstration tools
func registerTools(wrapper *OtelMCPWrapper) {
	// 1. Simple hello world tool
	helloTool := mcp.Tool{
		Name:        "hello_world",
		Description: "Returns a greeting message",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"name": {
					Type:        "string",
					Description: "Name to greet",
				},
			},
			Required: []string{"name"},
		},
	}

	wrapper.RegisterInstrumentedTool("hello_world", helloTool, handleHelloWorld)

	// 2. Math operation tool (with error cases for instrumentation demo)
	mathTool := mcp.Tool{
		Name:        "math_operation",
		Description: "Perform mathematical operations",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"operation": {
					Type: "string",
					Enum: []interface{}{"add", "subtract", "multiply", "divide"},
				},
				"a": {
					Type: "number",
				},
				"b": {
					Type: "number",
				},
			},
			Required: []string{"operation", "a", "b"},
		},
	}

	wrapper.RegisterInstrumentedTool("math_operation", mathTool, handleMathOperation)

	// 3. Slow task tool (for timing demonstration)
	slowTool := mcp.Tool{
		Name:        "slow_task",
		Description: "Simulates a slow operation for timing instrumentation",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"duration_ms": {
					Type:        "integer",
					Description: "How long to sleep in milliseconds",
				},
			},
			Required: []string{"duration_ms"},
		},
	}

	wrapper.RegisterInstrumentedTool("slow_task", slowTool, handleSlowTask)
}

func handleHelloWorld(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Get the current span to add custom attributes
	span := trace.SpanFromContext(ctx)

	// Use the helper function to parse arguments
	var params struct {
		Name string `json:"name"`
	}

	if err := parseArguments(req.Params.Arguments, &params); err != nil {
		span.SetAttributes(attribute.String("error.type", "argument_parse_error"))
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{
				&mcp.TextContent{Text: fmt.Sprintf("Failed to parse arguments: %v", err)},
			},
		}, nil
	}

	if params.Name == "" {
		span.SetAttributes(attribute.String("error.type", "missing_parameter"))
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{
				&mcp.TextContent{Text: "name parameter is required"},
			},
		}, nil
	}

	// Add custom span attributes
	span.SetAttributes(
		attribute.String("greeting.name", params.Name),
		attribute.Int("greeting.name_length", len(params.Name)),
	)

	message := fmt.Sprintf("Hello, %s! This greeting was instrumented with OpenTelemetry 🔍", params.Name)

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: message},
		},
	}, nil
}

func handleMathOperation(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	span := trace.SpanFromContext(ctx)

	// Use the helper function to parse arguments
	var params struct {
		Operation string  `json:"operation"`
		A         float64 `json:"a"`
		B         float64 `json:"b"`
	}

	if err := parseArguments(req.Params.Arguments, &params); err != nil {
		span.SetAttributes(attribute.String("error.type", "argument_parse_error"))
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{
				&mcp.TextContent{Text: fmt.Sprintf("Failed to parse arguments: %v", err)},
			},
		}, nil
	}

	// Add operation details to span
	span.SetAttributes(
		attribute.String("math.operation", params.Operation),
		attribute.Float64("math.operand.a", params.A),
		attribute.Float64("math.operand.b", params.B),
	)

	var result float64

	switch params.Operation {
	case "add":
		result = params.A + params.B
	case "subtract":
		result = params.A - params.B
	case "multiply":
		result = params.A * params.B
	case "divide":
		if params.B == 0 {
			span.SetAttributes(attribute.String("math.error", "division_by_zero"))
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{
					&mcp.TextContent{Text: "Error: Cannot divide by zero"},
				},
			}, nil
		}
		result = params.A / params.B
	default:
		span.SetAttributes(attribute.String("math.error", "unknown_operation"))
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{
				&mcp.TextContent{Text: fmt.Sprintf("Unknown operation: %s", params.Operation)},
			},
		}, nil
	}

	// Add result to span
	span.SetAttributes(attribute.Float64("math.result", result))

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: fmt.Sprintf("%.2f %s %.2f = %.2f", params.A, params.Operation, params.B, result)},
		},
	}, nil
}

func handleSlowTask(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	span := trace.SpanFromContext(ctx)

	// Use the helper function to parse arguments
	var params struct {
		DurationMs int `json:"duration_ms"`
	}

	if err := parseArguments(req.Params.Arguments, &params); err != nil {
		span.SetAttributes(attribute.String("error.type", "argument_parse_error"))
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{
				&mcp.TextContent{Text: fmt.Sprintf("Failed to parse arguments: %v", err)},
			},
		}, nil
	}

	duration := time.Duration(params.DurationMs) * time.Millisecond

	// Add timing details to span
	span.SetAttributes(
		attribute.Int("task.duration_ms", params.DurationMs),
		attribute.String("task.type", "sleep_simulation"),
	)

	log.Printf("😴 [SlowTask] Sleeping for %v...", duration)

	// Create a child span for the sleep operation
	_, sleepSpan := trace.SpanFromContext(ctx).TracerProvider().Tracer("mcp-server").Start(
		ctx, "slow_task.sleep",
		trace.WithAttributes(
			attribute.Int64("sleep.duration_ms", int64(params.DurationMs)),
		),
	)

	time.Sleep(duration)
	sleepSpan.End()

	message := fmt.Sprintf("⏰ Completed slow task after %dms. This timing was captured by OpenTelemetry!", params.DurationMs)

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: message},
		},
	}, nil
}
