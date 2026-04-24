package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	mcp "github.com/last9/mcp-go-sdk/mcp"
)

type WeatherArgs struct {
	Location string `json:"location"`
	Units    string `json:"units,omitempty"`
}

type NewsArgs struct {
	Topic string `json:"topic"`
	Limit *int   `json:"limit,omitempty"`
}

type DatabaseArgs struct {
	Query  string         `json:"query"`
	Params map[string]any `json:"params,omitempty"`
}

type HTTPTestArgs struct {
	Endpoint  string `json:"endpoint"`
	CustomURL string `json:"custom_url,omitempty"`
	Method    string `json:"method"`
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mcpServer, err := mcp.NewServer("http-mcp-server", "1.0.0")
	if err != nil {
		log.Fatal(err)
	}

	registerTools(mcpServer)

	handler := sdkmcp.NewStreamableHTTPHandler(func(_ *http.Request) *sdkmcp.Server {
		return mcpServer.Server
	}, nil)

	httpServer := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("listening on :%s", port)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	serverErr := make(chan error, 1)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	select {
	case <-sigChan:
	case <-ctx.Done():
	case err := <-serverErr:
		log.Fatal(err)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	_ = httpServer.Shutdown(shutdownCtx)
	_ = mcpServer.Shutdown(shutdownCtx)
}

func registerTools(server *mcp.Last9MCPServer) {
	mcp.RegisterInstrumentedTool(server, &sdkmcp.Tool{
		Name:        "get-weather",
		Description: "Get current weather for a location",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"location": {Type: "string"},
				"units":    {Type: "string", Enum: []any{"celsius", "fahrenheit"}},
			},
			Required: []string{"location"},
		},
	}, handleWeather)

	mcp.RegisterInstrumentedTool(server, &sdkmcp.Tool{
		Name:        "get-news",
		Description: "Fetch news headlines for a topic",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"topic": {Type: "string"},
				"limit": {Type: "integer", Description: "1–10 articles, default 5"},
			},
			Required: []string{"topic"},
		},
	}, handleNews)

	mcp.RegisterInstrumentedTool(server, &sdkmcp.Tool{
		Name:        "query-database",
		Description: "Execute a SQL query (simulated)",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"query":  {Type: "string"},
				"params": {Type: "object"},
			},
			Required: []string{"query"},
		},
	}, handleDatabase)

	mcp.RegisterInstrumentedTool(server, &sdkmcp.Tool{
		Name:        "http-client-test",
		Description: "Make a traced HTTP request to httpbin, jsonplaceholder, or a custom URL",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"endpoint":   {Type: "string", Enum: []any{"httpbin", "jsonplaceholder", "custom"}},
				"custom_url": {Type: "string"},
				"method":     {Type: "string", Enum: []any{"GET", "POST", "PUT", "DELETE"}},
			},
			Required: []string{"endpoint", "method"},
		},
	}, handleHTTPTest)
}

func handleWeather(ctx context.Context, _ *sdkmcp.CallToolRequest, args WeatherArgs) (*sdkmcp.CallToolResult, any, error) {
	// Outbound HTTP call is a child span of the tool span.
	client := mcp.WithHTTPTracing(&http.Client{Timeout: 10 * time.Second})
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://httpbin.org/json", nil)
	resp, err := client.Do(req)
	if err != nil {
		return toolError(err.Error()), nil, nil
	}
	defer resp.Body.Close()

	units := "celsius"
	if args.Units != "" {
		units = args.Units
	}
	temp := 20 + rand.IntN(15)
	if units == "fahrenheit" {
		temp = temp*9/5 + 32
	}

	result := map[string]any{
		"location":    args.Location,
		"temperature": temp,
		"units":       units,
		"condition":   []string{"sunny", "cloudy", "rainy", "snowy"}[rand.IntN(4)],
		"humidity":    50 + rand.IntN(40),
		"timestamp":   time.Now().Format(time.RFC3339),
	}
	return jsonResult(result), result, nil
}

func handleNews(ctx context.Context, _ *sdkmcp.CallToolRequest, args NewsArgs) (*sdkmcp.CallToolResult, any, error) {
	limit := 5
	if args.Limit != nil && *args.Limit >= 1 && *args.Limit <= 10 {
		limit = *args.Limit
	}

	client := mcp.WithHTTPTracing(&http.Client{Timeout: 15 * time.Second})
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://jsonplaceholder.typicode.com/posts", nil)
	resp, err := client.Do(req)
	if err != nil {
		return toolError(err.Error()), nil, nil
	}
	defer resp.Body.Close()

	articles := make([]map[string]any, limit)
	for i := range articles {
		articles[i] = map[string]any{
			"title":     fmt.Sprintf("%s — Article #%d", args.Topic, i+1),
			"summary":   fmt.Sprintf("Coverage of %s.", args.Topic),
			"published": time.Now().Add(-time.Duration(i) * time.Hour).Format(time.RFC3339),
		}
	}
	result := map[string]any{"topic": args.Topic, "articles": articles}
	return jsonResult(result), result, nil
}

func handleDatabase(_ context.Context, _ *sdkmcp.CallToolRequest, args DatabaseArgs) (*sdkmcp.CallToolResult, any, error) {
	time.Sleep(time.Duration(50+rand.IntN(200)) * time.Millisecond)

	q := strings.ToLower(args.Query)
	var result map[string]any
	switch {
	case strings.Contains(q, "select"):
		result = map[string]any{
			"type":          "SELECT",
			"rows_returned": rand.IntN(100) + 1,
			"sample_data": []map[string]any{
				{"id": 1, "name": "Alice"},
				{"id": 2, "name": "Bob"},
			},
		}
	case strings.Contains(q, "insert"):
		result = map[string]any{"type": "INSERT", "rows_affected": 1, "last_insert_id": rand.IntN(1000) + 1000}
	case strings.Contains(q, "update"):
		result = map[string]any{"type": "UPDATE", "rows_affected": rand.IntN(10) + 1}
	case strings.Contains(q, "delete"):
		result = map[string]any{"type": "DELETE", "rows_affected": rand.IntN(5) + 1}
	default:
		result = map[string]any{"type": "UNKNOWN", "message": "ok"}
	}
	return jsonResult(result), result, nil
}

func handleHTTPTest(ctx context.Context, _ *sdkmcp.CallToolRequest, args HTTPTestArgs) (*sdkmcp.CallToolResult, any, error) {
	var targetURL string
	switch args.Endpoint {
	case "httpbin":
		targetURL = "https://httpbin.org/json"
		if args.Method != "GET" {
			targetURL = "https://httpbin.org/anything"
		}
	case "jsonplaceholder":
		targetURL = "https://jsonplaceholder.typicode.com/posts/1"
	case "custom":
		if args.CustomURL == "" {
			return toolError("custom_url is required when endpoint is 'custom'"), nil, nil
		}
		targetURL = args.CustomURL
	default:
		return toolError("invalid endpoint"), nil, nil
	}

	client := mcp.WithHTTPTracing(&http.Client{Timeout: 10 * time.Second})
	req, err := http.NewRequestWithContext(ctx, args.Method, targetURL, nil)
	if err != nil {
		return toolError(err.Error()), nil, nil
	}
	req.Header.Set("User-Agent", "mcp-go-sdk-example/1.0")

	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start)
	if err != nil {
		return toolError(err.Error()), nil, nil
	}
	defer resp.Body.Close()

	body := make([]byte, 1024)
	n, _ := resp.Body.Read(body)
	bodyStr := string(body[:n])
	if n == 1024 {
		bodyStr += "\n... (truncated)"
	}

	result := map[string]any{
		"url":         targetURL,
		"method":      args.Method,
		"status":      resp.StatusCode,
		"duration_ms": duration.Milliseconds(),
		"body":        bodyStr,
	}
	return jsonResult(result), result, nil
}

func toolError(msg string) *sdkmcp.CallToolResult {
	return &sdkmcp.CallToolResult{
		IsError: true,
		Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: msg}},
	}
}

func jsonResult(v any) *sdkmcp.CallToolResult {
	b, _ := json.MarshalIndent(v, "", "  ")
	return &sdkmcp.CallToolResult{
		Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: string(b)}},
	}
}
