package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/trace"

	last9mcp "github.com/last9/mcp-go-sdk/mcp"
)

// ExampleServer demonstrates how to use the OtelMCPWrapper
type ExampleServer struct {
	wrapper *last9mcp.Last9MCPServer
}

// TestToolArgs represents arguments for the test tool
type TestToolArgs struct {
	Message string `json:"message"`
	Delay   *int   `json:"delay,omitempty"` // Optional delay in milliseconds
	Error   *bool  `json:"error,omitempty"` // Optional flag to trigger an error
}

// CalculatorArgs represents arguments for the calculator tool
type CalculatorArgs struct {
	Operation string  `json:"operation"` // add, subtract, multiply, divide
	A         float64 `json:"a"`
	B         float64 `json:"b"`
}

// DataProcessorArgs represents arguments for the data processor tool
type DataProcessorArgs struct {
	Data      []string `json:"data"`
	Operation string   `json:"operation"` // count, reverse, sort, uppercase
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

// NewExampleServer creates a new example server
func NewExampleServer() (*ExampleServer, error) {
	wrapper, err := last9mcp.NewServer("example-mcp-server", "1.0.0")
	if err != nil {
		return nil, fmt.Errorf("failed to create wrapper: %w", err)
	}

	server := &ExampleServer{
		wrapper: wrapper,
	}

	// Register all the tools
	server.registerTools()

	return server, nil
}

// registerTools registers all available tools with the server
func (s *ExampleServer) registerTools() {
	// Register test tool
	testTool := &mcp.Tool{
		Name:        "test-tool",
		Description: "A simple test tool that echoes messages with optional delay and error simulation",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"message": {
					Type:        "string",
					Description: "The message to echo back",
				},
				"delay": {
					Type:        "integer",
					Description: "Optional delay in milliseconds before responding",
				},
				"error": {
					Type:        "boolean",
					Description: "Optional flag to trigger an error for testing",
				},
			},
			Required: []string{"message"},
		},
	}

	last9mcp.RegisterInstrumentedTool(s.wrapper, testTool, s.handleTestTool)

	// Register calculator tool
	calculatorTool := &mcp.Tool{
		Name:        "calculator",
		Description: "Performs basic mathematical operations",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"operation": {
					Type:        "string",
					Description: "The operation to perform: add, subtract, multiply, divide",
					Enum:        []interface{}{"add", "subtract", "multiply", "divide"},
				},
				"a": {
					Type:        "number",
					Description: "First number",
				},
				"b": {
					Type:        "number",
					Description: "Second number",
				},
			},
			Required: []string{"operation", "a", "b"},
		},
	}

	last9mcp.RegisterInstrumentedTool(s.wrapper, calculatorTool, s.handleCalculator)

	// Register data processor tool
	dataProcessorTool := &mcp.Tool{
		Name:        "data-processor",
		Description: "Processes arrays of strings with various operations",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"data": {
					Type: "array",
					Items: &jsonschema.Schema{
						Type: "string",
					},
					Description: "Array of strings to process",
				},
				"operation": {
					Type:        "string",
					Description: "Operation to perform: count, reverse, sort, uppercase",
					Enum:        []interface{}{"count", "reverse", "sort", "uppercase"},
				},
			},
			Required: []string{"data", "operation"},
		},
	}

	last9mcp.RegisterInstrumentedTool(s.wrapper, dataProcessorTool, s.handleDataProcessor)

	// Register random generator tool
	randomTool := &mcp.Tool{
		Name:        "random-generator",
		Description: "Generates random data for testing",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"type": {
					Type:        "string",
					Description: "Type of random data: number, string, boolean",
					Enum:        []interface{}{"number", "string", "boolean"},
				},
				"count": {
					Type:        "integer",
					Description: "Number of items to generate (default: 1)",
				},
			},
			Required: []string{"type"},
		},
	}

	last9mcp.RegisterInstrumentedTool(s.wrapper, randomTool, s.handleRandomGenerator)

	// Register HTTP API tool to demonstrate HTTP tracing
	httpTool := &mcp.Tool{
		Name:        "http-api-call",
		Description: "Makes HTTP requests to external APIs with automatic tracing",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"url": {
					Type:        "string",
					Description: "The URL to make the HTTP request to",
				},
				"method": {
					Type:        "string",
					Description: "HTTP method (GET, POST, PUT, DELETE)",
					Enum:        []interface{}{"GET", "POST", "PUT", "DELETE"},
				},
				"timeout": {
					Type:        "integer",
					Description: "Timeout in seconds (default: 10)",
				},
			},
			Required: []string{"url", "method"},
		},
	}

	last9mcp.RegisterInstrumentedTool(s.wrapper, httpTool, s.handleHTTPAPICall)

	log.Println("🔧 Registered all tools successfully")
}

func (s *ExampleServer) Serve(ctx context.Context) error {
	// Create stdio transport
	transport := mcp.StdioTransport{}

	log.Println("🚀 Starting example MCP server with OpenTelemetry...")
	log.Println("📊 OpenTelemetry traces and metrics will be exported")
	log.Println("🔧 Available tools: test-tool, calculator, data-processor, random-generator, http-api-call, last9-telemetry")

	return s.wrapper.Serve(ctx, &transport)
}

func main() {
	// Seed random number generator
	rand.Seed(time.Now().UnixNano())

	// Create context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("🛑 Received shutdown signal")
		cancel()
	}()

	// Create and start the server
	server, err := NewExampleServer()
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := server.Serve(ctx); err != nil {
		log.Fatalf("Server error: %v", err)
	}

	log.Println("👋 Server shutdown complete")
}

// handler versions for RegisterInstrumentedTool
func (s *ExampleServer) handleTestTool(ctx context.Context, req *mcp.CallToolRequest, args TestToolArgs) (*mcp.CallToolResult, interface{}, error) {
	// Simulate delay if requested
	if args.Delay != nil && *args.Delay > 0 {
		time.Sleep(time.Duration(*args.Delay) * time.Millisecond)
	}

	// Simulate error if requested
	if args.Error != nil && *args.Error {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: "Simulated error as requested"}},
		}, nil, nil
	}

	response := fmt.Sprintf("Echo: %s (processed at %s)", args.Message, time.Now().Format("15:04:05"))

	return &mcp.CallToolResult{
		IsError: false,
		Content: []mcp.Content{&mcp.TextContent{Text: response}},
	}, nil, nil
}

func (s *ExampleServer) handleCalculator(ctx context.Context, req *mcp.CallToolRequest, args CalculatorArgs) (*mcp.CallToolResult, interface{}, error) {
	var result float64

	switch args.Operation {
	case "add":
		result = args.A + args.B
	case "subtract":
		result = args.A - args.B
	case "multiply":
		result = args.A * args.B
	case "divide":
		if args.B == 0 {
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: "Division by zero is not allowed"}},
			}, nil, nil
		}
		result = args.A / args.B
	default:
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Unknown operation: %s", args.Operation)}},
		}, nil, nil
	}

	response := fmt.Sprintf("%.2f %s %.2f = %.2f", args.A, args.Operation, args.B, result)

	return &mcp.CallToolResult{
		IsError: false,
		Content: []mcp.Content{&mcp.TextContent{Text: response}},
	}, nil, nil
}

func (s *ExampleServer) handleDataProcessor(ctx context.Context, req *mcp.CallToolRequest, args DataProcessorArgs) (*mcp.CallToolResult, interface{}, error) {
	var response string

	switch args.Operation {
	case "count":
		response = fmt.Sprintf("Array contains %d items", len(args.Data))
	case "reverse":
		reversed := make([]string, len(args.Data))
		for i, v := range args.Data {
			reversed[len(args.Data)-1-i] = v
		}
		response = fmt.Sprintf("Reversed: %v", reversed)
	case "sort":
		// Simple bubble sort for demonstration
		sorted := make([]string, len(args.Data))
		copy(sorted, args.Data)
		for i := 0; i < len(sorted); i++ {
			for j := 0; j < len(sorted)-1-i; j++ {
				if sorted[j] > sorted[j+1] {
					sorted[j], sorted[j+1] = sorted[j+1], sorted[j]
				}
			}
		}
		response = fmt.Sprintf("Sorted: %v", sorted)
	case "uppercase":
		uppercased := make([]string, len(args.Data))
		for i, v := range args.Data {
			uppercased[i] = strings.ToUpper(v)
		}
		response = fmt.Sprintf("Uppercased: %v", uppercased)
	default:
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Unknown operation: %s", args.Operation)}},
		}, nil, nil
	}

	return &mcp.CallToolResult{
		IsError: false,
		Content: []mcp.Content{&mcp.TextContent{Text: response}},
	}, nil, nil
}

type RandomGeneratorArgs struct {
	Type  string `json:"type"`
	Count *int   `json:"count,omitempty"`
}

func (s *ExampleServer) handleRandomGenerator(ctx context.Context, req *mcp.CallToolRequest, args RandomGeneratorArgs) (*mcp.CallToolResult, interface{}, error) {
	log.Printf("Meta Data in Random Generator: %+v", req.Params.GetMeta())

	span := trace.SpanContextFromContext(ctx)
	log.Printf("Server======Trace ID: %s, Span ID: %s", span.TraceID().String(), span.SpanID().String())

	count := 1
	if args.Count != nil {
		count = *args.Count
	}

	if count <= 0 || count > 100 {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: "Count must be between 1 and 100"}},
		}, nil, nil
	}

	var results []interface{}

	for i := 0; i < count; i++ {
		switch args.Type {
		case "number":
			results = append(results, rand.Float64()*1000)
		case "string":
			// Generate random string
			const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
			length := 5 + rand.Intn(10) // 5-14 characters
			b := make([]byte, length)
			for j := range b {
				b[j] = charset[rand.Intn(len(charset))]
			}
			results = append(results, string(b))
		case "boolean":
			results = append(results, rand.Intn(2) == 1)
		default:
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Unknown type: %s", args.Type)}},
			}, nil, nil
		}
	}

	response := fmt.Sprintf("Generated %d %s value(s): %v", count, args.Type, results)

	return &mcp.CallToolResult{
		IsError: false,
		Content: []mcp.Content{&mcp.TextContent{Text: response}},
	}, nil, nil
}

// HTTPAPIArgs represents arguments for the HTTP API tool
type HTTPAPIArgs struct {
	URL     string `json:"url"`
	Method  string `json:"method"`
	Timeout *int   `json:"timeout,omitempty"` // Optional timeout in seconds
}

// handleHTTPAPICall demonstrates HTTP tracing by making external API calls
func (s *ExampleServer) handleHTTPAPICall(ctx context.Context, req *mcp.CallToolRequest, args HTTPAPIArgs) (*mcp.CallToolResult, interface{}, error) {
	// Set default timeout
	timeout := 10 * time.Second
	if args.Timeout != nil && *args.Timeout > 0 {
		timeout = time.Duration(*args.Timeout) * time.Second
	}

	// Example 1: Using WithHTTPTracing middleware (recommended)
	client := last9mcp.WithHTTPTracing(&http.Client{
		Timeout: timeout,
	})

	// Alternative examples (commented out):
	// Example 2: Using NewTracedHTTPClient
	// client := last9mcp.NewTracedHTTPClient(timeout)

	// Example 3: Using WithHTTPTracingOptions for custom span names
	// client := last9mcp.WithHTTPTracingOptions(&http.Client{Timeout: timeout},
	//     otelhttp.WithSpanNameFormatter(func(operation string, r *http.Request) string {
	//         return fmt.Sprintf("External API: %s %s", r.Method, r.URL.Host)
	//     }),
	// )

	// Create the HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, args.Method, args.URL, nil)
	if err != nil {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Failed to create request: %v", err)}},
		}, nil, nil
	}

	// Set some headers
	httpReq.Header.Set("User-Agent", "MCP-Go-SDK-Example/1.0")
	httpReq.Header.Set("Accept", "application/json")

	// Log trace info for debugging
	span := trace.SpanContextFromContext(ctx)
	log.Printf("HTTP Tool - Trace ID: %s, Span ID: %s, Making %s request to %s",
		span.TraceID().String(), span.SpanID().String(), args.Method, args.URL)

	// Make the traced HTTP request
	resp, err := client.Do(httpReq)
	if err != nil {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("HTTP request failed: %v", err)}},
		}, nil, nil
	}
	defer resp.Body.Close()

	// Read response body (limit to 1KB for demo)
	body := make([]byte, 1024)
	n, _ := resp.Body.Read(body)
	bodyStr := string(body[:n])
	if n == 1024 {
		bodyStr += "... (truncated)"
	}

	response := fmt.Sprintf(`HTTP %s %s
Status: %d %s
Content-Length: %s
Content-Type: %s

Body:
%s`, args.Method, args.URL, resp.StatusCode, resp.Status,
		resp.Header.Get("Content-Length"), resp.Header.Get("Content-Type"), bodyStr)

	return &mcp.CallToolResult{
		IsError: false,
		Content: []mcp.Content{&mcp.TextContent{Text: response}},
	}, nil, nil
}
