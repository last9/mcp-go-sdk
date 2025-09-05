package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	last9mcp "github.com/last9/mcp-go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

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

// Example usage demonstrating OpenTelemetry instrumentation
func main() {
	// Create OpenTelemetry instrumented MCP server
	wrapper, err := last9mcp.NewServerWithOtel("otel-mcp-demo", "1.0.0")
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
func registerTools(wrapper *last9mcp.OtelMCPWrapper) {
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
