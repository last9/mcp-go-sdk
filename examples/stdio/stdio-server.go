package main

import (
	"context"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	mcp "github.com/last9/mcp-go-sdk/mcp"
)

type TestToolArgs struct {
	Message string `json:"message"`
	Delay   *int   `json:"delay,omitempty"`
	Error   *bool  `json:"error,omitempty"`
}

type CalculatorArgs struct {
	Operation string  `json:"operation"`
	A         float64 `json:"a"`
	B         float64 `json:"b"`
}

type DataProcessorArgs struct {
	Data      []string `json:"data"`
	Operation string   `json:"operation"`
}

type RandomGeneratorArgs struct {
	Type  string `json:"type"`
	Count *int   `json:"count,omitempty"`
}

type HTTPAPIArgs struct {
	URL     string `json:"url"`
	Method  string `json:"method"`
	Timeout *int   `json:"timeout,omitempty"`
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	server, err := mcp.NewServer("stdio-mcp-server", "1.0.0")
	if err != nil {
		log.Fatal(err)
	}
	defer server.Shutdown(context.Background())

	registerTools(server)

	if err := server.Serve(ctx, &sdkmcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}

func registerTools(server *mcp.Last9MCPServer) {
	mcp.RegisterInstrumentedTool(server, &sdkmcp.Tool{
		Name:        "test-tool",
		Description: "Echoes a message with optional delay and error simulation",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"message": {Type: "string", Description: "Message to echo"},
				"delay":   {Type: "integer", Description: "Delay in milliseconds"},
				"error":   {Type: "boolean", Description: "Trigger a simulated error"},
			},
			Required: []string{"message"},
		},
	}, handleTestTool)

	mcp.RegisterInstrumentedTool(server, &sdkmcp.Tool{
		Name:        "calculator",
		Description: "Basic arithmetic: add, subtract, multiply, divide",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"operation": {Type: "string", Enum: []any{"add", "subtract", "multiply", "divide"}},
				"a":         {Type: "number"},
				"b":         {Type: "number"},
			},
			Required: []string{"operation", "a", "b"},
		},
	}, handleCalculator)

	mcp.RegisterInstrumentedTool(server, &sdkmcp.Tool{
		Name:        "data-processor",
		Description: "Process string arrays: count, reverse, sort, uppercase",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"data":      {Type: "array", Items: &jsonschema.Schema{Type: "string"}},
				"operation": {Type: "string", Enum: []any{"count", "reverse", "sort", "uppercase"}},
			},
			Required: []string{"data", "operation"},
		},
	}, handleDataProcessor)

	mcp.RegisterInstrumentedTool(server, &sdkmcp.Tool{
		Name:        "random-generator",
		Description: "Generate random numbers, strings, or booleans",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"type":  {Type: "string", Enum: []any{"number", "string", "boolean"}},
				"count": {Type: "integer", Description: "How many values (max 100)"},
			},
			Required: []string{"type"},
		},
	}, handleRandomGenerator)

	mcp.RegisterInstrumentedTool(server, &sdkmcp.Tool{
		Name:        "http-api-call",
		Description: "Make a traced HTTP request to an external URL",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"url":     {Type: "string"},
				"method":  {Type: "string", Enum: []any{"GET", "POST", "PUT", "DELETE"}},
				"timeout": {Type: "integer", Description: "Timeout in seconds"},
			},
			Required: []string{"url", "method"},
		},
	}, handleHTTPAPICall)
}

func handleTestTool(_ context.Context, _ *sdkmcp.CallToolRequest, args TestToolArgs) (*sdkmcp.CallToolResult, any, error) {
	if args.Delay != nil && *args.Delay > 0 {
		time.Sleep(time.Duration(*args.Delay) * time.Millisecond)
	}
	if args.Error != nil && *args.Error {
		return &sdkmcp.CallToolResult{
			IsError: true,
			Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: "simulated error"}},
		}, nil, nil
	}
	return &sdkmcp.CallToolResult{
		Content: []sdkmcp.Content{&sdkmcp.TextContent{
			Text: fmt.Sprintf("Echo: %s (at %s)", args.Message, time.Now().Format("15:04:05")),
		}},
	}, nil, nil
}

func handleCalculator(_ context.Context, _ *sdkmcp.CallToolRequest, args CalculatorArgs) (*sdkmcp.CallToolResult, any, error) {
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
			return &sdkmcp.CallToolResult{
				IsError: true,
				Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: "division by zero"}},
			}, nil, nil
		}
		result = args.A / args.B
	}
	return &sdkmcp.CallToolResult{
		Content: []sdkmcp.Content{&sdkmcp.TextContent{
			Text: fmt.Sprintf("%.4g %s %.4g = %.4g", args.A, args.Operation, args.B, result),
		}},
	}, nil, nil
}

func handleDataProcessor(_ context.Context, _ *sdkmcp.CallToolRequest, args DataProcessorArgs) (*sdkmcp.CallToolResult, any, error) {
	var out string
	switch args.Operation {
	case "count":
		out = fmt.Sprintf("%d items", len(args.Data))
	case "reverse":
		cp := make([]string, len(args.Data))
		copy(cp, args.Data)
		for i, j := 0, len(cp)-1; i < j; i, j = i+1, j-1 {
			cp[i], cp[j] = cp[j], cp[i]
		}
		out = strings.Join(cp, ", ")
	case "sort":
		cp := make([]string, len(args.Data))
		copy(cp, args.Data)
		sort.Strings(cp)
		out = strings.Join(cp, ", ")
	case "uppercase":
		up := make([]string, len(args.Data))
		for i, v := range args.Data {
			up[i] = strings.ToUpper(v)
		}
		out = strings.Join(up, ", ")
	}
	return &sdkmcp.CallToolResult{
		Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: out}},
	}, nil, nil
}

func handleRandomGenerator(_ context.Context, _ *sdkmcp.CallToolRequest, args RandomGeneratorArgs) (*sdkmcp.CallToolResult, any, error) {
	count := 1
	if args.Count != nil {
		count = *args.Count
	}
	if count <= 0 || count > 100 {
		return &sdkmcp.CallToolResult{
			IsError: true,
			Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: "count must be 1–100"}},
		}, nil, nil
	}

	results := make([]string, count)
	for i := range results {
		switch args.Type {
		case "number":
			results[i] = fmt.Sprintf("%.4f", rand.Float64()*1000)
		case "string":
			const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
			b := make([]byte, 5+rand.IntN(10))
			for j := range b {
				b[j] = charset[rand.IntN(len(charset))]
			}
			results[i] = string(b)
		case "boolean":
			results[i] = fmt.Sprintf("%v", rand.IntN(2) == 1)
		}
	}
	return &sdkmcp.CallToolResult{
		Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: strings.Join(results, "\n")}},
	}, nil, nil
}

func handleHTTPAPICall(ctx context.Context, _ *sdkmcp.CallToolRequest, args HTTPAPIArgs) (*sdkmcp.CallToolResult, any, error) {
	timeout := 10 * time.Second
	if args.Timeout != nil && *args.Timeout > 0 {
		timeout = time.Duration(*args.Timeout) * time.Second
	}

	// WithHTTPTracing propagates the active span into outbound request headers,
	// so this HTTP call appears as a child span in your trace.
	client := mcp.WithHTTPTracing(&http.Client{Timeout: timeout})

	req, err := http.NewRequestWithContext(ctx, args.Method, args.URL, nil)
	if err != nil {
		return &sdkmcp.CallToolResult{
			IsError: true,
			Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: err.Error()}},
		}, nil, nil
	}
	req.Header.Set("User-Agent", "mcp-go-sdk-example/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return &sdkmcp.CallToolResult{
			IsError: true,
			Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: err.Error()}},
		}, nil, nil
	}
	defer resp.Body.Close()

	body := make([]byte, 1024)
	n, _ := resp.Body.Read(body)
	text := string(body[:n])
	if n == 1024 {
		text += "\n... (truncated)"
	}

	return &sdkmcp.CallToolResult{
		Content: []sdkmcp.Content{&sdkmcp.TextContent{
			Text: fmt.Sprintf("HTTP %d\n\n%s", resp.StatusCode, text),
		}},
	}, nil, nil
}
