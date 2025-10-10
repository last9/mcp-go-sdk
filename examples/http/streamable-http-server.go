package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

	last9mcp "github.com/last9/mcp-go-sdk/mcp"
)

// HTTPMCPServer demonstrates HTTP-based MCP server
type HTTPMCPServer struct {
	wrapper    *last9mcp.Last9MCPServer
	httpServer *http.Server
	port       string
}

// WeatherArgs represents arguments for the weather tool
type WeatherArgs struct {
	Location string `json:"location"`
	Units    string `json:"units,omitempty"` // celsius, fahrenheit
}

// NewsArgs represents arguments for the news tool
type NewsArgs struct {
	Topic string `json:"topic"`
	Limit *int   `json:"limit,omitempty"`
}

// DatabaseArgs represents arguments for the database query tool
type DatabaseArgs struct {
	Query  string                 `json:"query"`
	Params map[string]interface{} `json:"params,omitempty"`
}

// parseArguments helper function to handle the any type of req.Params.Arguments
func parseArguments(arguments any, target interface{}) error {
	switch args := arguments.(type) {
	case json.RawMessage:
		return json.Unmarshal(args, target)
	case map[string]interface{}:
		jsonBytes, err := json.Marshal(args)
		if err != nil {
			return fmt.Errorf("failed to marshal map to JSON: %w", err)
		}
		return json.Unmarshal(jsonBytes, target)
	case nil:
		return fmt.Errorf("no arguments provided")
	default:
		jsonBytes, err := json.Marshal(args)
		if err != nil {
			return fmt.Errorf("failed to marshal arguments to JSON: %w", err)
		}
		return json.Unmarshal(jsonBytes, target)
	}
}

// NewHTTPMCPServer creates a new HTTP-based MCP server
func NewHTTPMCPServer(port string) (*HTTPMCPServer, error) {
	wrapper, err := last9mcp.NewServer("http-mcp-server", "1.0.0")
	if err != nil {
		return nil, fmt.Errorf("failed to create wrapper: %w", err)
	}

	server := &HTTPMCPServer{
		wrapper: wrapper,
		port:    port,
	}

	// Register HTTP-specific tools
	server.registerTools()

	return server, nil
}

// registerTools registers all available tools with the server
func (s *HTTPMCPServer) registerTools() {
	// Register weather API tool
	weatherTool := &mcp.Tool{
		Name:        "get-weather",
		Description: "Get current weather information for a location via HTTP API",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"location": {
					Type:        "string",
					Description: "The location to get weather for (city, country)",
				},
				"units": {
					Type:        "string",
					Description: "Temperature units (celsius or fahrenheit)",
					Enum:        []interface{}{"celsius", "fahrenheit"},
				},
			},
			Required: []string{"location"},
		},
	}

	last9mcp.RegisterInstrumentedTool(s.wrapper, weatherTool, s.handleWeather)

	// Register news API tool
	newsTool := &mcp.Tool{
		Name:        "get-news",
		Description: "Fetch latest news headlines for a specific topic via HTTP API",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"topic": {
					Type:        "string",
					Description: "The news topic to search for",
				},
				"limit": {
					Type:        "integer",
					Description: "Number of articles to fetch (1-10, default: 5)",
				},
			},
			Required: []string{"topic"},
		},
	}

	last9mcp.RegisterInstrumentedTool(s.wrapper, newsTool, s.handleNews)

	// Register database query tool
	dbTool := &mcp.Tool{
		Name:        "query-database",
		Description: "Execute database queries with tracing support",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"query": {
					Type:        "string",
					Description: "SQL query to execute",
				},
				"params": {
					Type:        "object",
					Description: "Query parameters as key-value pairs",
				},
			},
			Required: []string{"query"},
		},
	}

	last9mcp.RegisterInstrumentedTool(s.wrapper, dbTool, s.handleDatabase)

	// Register HTTP client testing tool
	httpTestTool := &mcp.Tool{
		Name:        "http-client-test",
		Description: "Test HTTP client with different endpoints and trace requests",
		InputSchema: &jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"endpoint": {
					Type:        "string",
					Description: "API endpoint to test (httpbin, jsonplaceholder, or custom URL)",
					Enum:        []interface{}{"httpbin", "jsonplaceholder", "custom"},
				},
				"custom_url": {
					Type:        "string",
					Description: "Custom URL to test (required if endpoint is 'custom')",
				},
				"method": {
					Type:        "string",
					Description: "HTTP method to use",
					Enum:        []interface{}{"GET", "POST", "PUT", "DELETE"},
				},
			},
			Required: []string{"endpoint", "method"},
		},
	}

	last9mcp.RegisterInstrumentedTool(s.wrapper, httpTestTool, s.handleHTTPTest)

	log.Println("🔧 Registered HTTP MCP server tools successfully")
}

// Start starts the HTTP server
func (s *HTTPMCPServer) Start(ctx context.Context, url string) error {
	// Create the streamable HTTP handler.
	handler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		return s.wrapper.Server
	}, nil)

	// Create HTTP server with timeouts
	s.httpServer = &http.Server{
		Addr:         url,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("🚀 MCP server listening on %s", url)
	log.Printf("🔧 Available tools: get-weather, get-news, query-database, http-client-test")

	// add shutdown hook
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in a goroutine
	serverErr := make(chan error, 1)
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	// Wait for context cancellation or server error
	select {
	// add signal chan
	case sig := <-signalChan:
		log.Printf("🛑 Received signal: %v, initiating graceful shutdown...", sig)

	case <-ctx.Done():
		log.Println("🛑 Context cancelled, initiating graceful shutdown...")
	case err := <-serverErr:
		log.Printf("❌ Server error: %v", err)
		return err
	}

	shutdownCtx := context.Background()
	// Attempt graceful shutdown
	if err := s.Shutdown(shutdownCtx); err != nil {
		log.Printf("❌ Graceful shutdown failed: %v", err)
	}

	return nil
}

// Shutdown gracefully shuts down the HTTP server
func (s *HTTPMCPServer) Shutdown(ctx context.Context) error {
	log.Println("🛑 Shutting down HTTP MCP server...")

	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			log.Printf("❌ Error shutting down HTTP server: %v", err)
			return err
		}
	}

	if s.wrapper != nil {
		if err := s.wrapper.Shutdown(ctx); err != nil {
			log.Printf("❌ Error shutting down MCP wrapper: %v", err)
			return err
		}
	}

	log.Println("✅ HTTP MCP server shutdown complete")
	return nil
}

// httpReadWriteCloser implements io.ReadWriteCloser for HTTP requests/responses
type httpReadWriteCloser struct {
	request  *http.Request
	response http.ResponseWriter
	body     io.ReadCloser
}

func (h *httpReadWriteCloser) Read(p []byte) (n int, err error) {
	return h.body.Read(p)
}

func (h *httpReadWriteCloser) Write(p []byte) (n int, err error) {
	return h.response.Write(p)
}

func (h *httpReadWriteCloser) Close() error {
	if h.body != nil {
		return h.body.Close()
	}
	return nil
}

// Tool handlers

func (s *HTTPMCPServer) handleWeather(ctx context.Context, req *mcp.CallToolRequest, args WeatherArgs) (*mcp.CallToolResult, interface{}, error) {
	// Simulate API call with HTTP tracing
	client := last9mcp.WithHTTPTracing(&http.Client{
		Timeout: 10 * time.Second,
	})

	// create http request with context
	httpReq, err := http.NewRequestWithContext(ctx, "GET", "https://httpbin.org/json", nil)
	if err != nil {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Failed to create request: %v", err)}},
		}, nil, nil
	}

	// Mock weather API call (using httpbin for demonstration)
	resp, err := client.Do(httpReq)
	if err != nil {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Weather API error: %v", err)}},
		}, nil, nil
	}
	defer resp.Body.Close()

	// Simulate weather data
	units := "celsius"
	if args.Units != "" {
		units = args.Units
	}

	temp := 20 + rand.Intn(15) // Random temperature between 20-35
	if units == "fahrenheit" {
		temp = temp*9/5 + 32
	}

	weather := map[string]interface{}{
		"location":    args.Location,
		"temperature": temp,
		"units":       units,
		"condition":   []string{"sunny", "cloudy", "rainy", "snowy"}[rand.Intn(4)],
		"humidity":    50 + rand.Intn(40),
		"api_status":  resp.Status,
		"timestamp":   time.Now().Format(time.RFC3339),
	}

	weatherJSON, _ := json.MarshalIndent(weather, "", "  ")

	return &mcp.CallToolResult{
		IsError: false,
		Content: []mcp.Content{&mcp.TextContent{Text: string(weatherJSON)}},
	}, weather, nil
}

func (s *HTTPMCPServer) handleNews(ctx context.Context, req *mcp.CallToolRequest, args NewsArgs) (*mcp.CallToolResult, interface{}, error) {
	limit := 5
	if args.Limit != nil && *args.Limit > 0 && *args.Limit <= 10 {
		limit = *args.Limit
	}

	// Simulate news API call with HTTP tracing
	client := last9mcp.WithHTTPTracing(&http.Client{
		Timeout: 15 * time.Second,
	})

	httpReq, err := http.NewRequestWithContext(ctx, "GET", "https://jsonplaceholder.typicode.com/posts", nil)
	if err != nil {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Failed to create request: %v", err)}},
		}, nil, nil
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("News API error: %v", err)}},
		}, nil, nil
	}
	defer resp.Body.Close()

	// Simulate news articles
	articles := make([]map[string]interface{}, limit)
	for i := 0; i < limit; i++ {
		articles[i] = map[string]interface{}{
			"title":      fmt.Sprintf("%s News Article #%d", args.Topic, i+1),
			"summary":    fmt.Sprintf("This is a sample news article about %s with some interesting content.", args.Topic),
			"source":     "Mock News API",
			"published":  time.Now().Add(-time.Duration(i) * time.Hour).Format(time.RFC3339),
			"category":   args.Topic,
			"api_status": resp.Status,
		}
	}

	result := map[string]interface{}{
		"topic":    args.Topic,
		"count":    len(articles),
		"articles": articles,
	}

	resultJSON, _ := json.MarshalIndent(result, "", "  ")

	return &mcp.CallToolResult{
		IsError: false,
		Content: []mcp.Content{&mcp.TextContent{Text: string(resultJSON)}},
	}, result, nil
}

func (s *HTTPMCPServer) handleDatabase(ctx context.Context, req *mcp.CallToolRequest, args DatabaseArgs) (*mcp.CallToolResult, interface{}, error) {
	// Simulate query execution time
	time.Sleep(time.Duration(50+rand.Intn(200)) * time.Millisecond)

	// Mock database results based on query type
	var result map[string]interface{}

	queryLower := strings.ToLower(args.Query)
	switch {
	case strings.Contains(queryLower, "select"):
		result = map[string]interface{}{
			"query_type":        "SELECT",
			"rows_returned":     rand.Intn(100) + 1,
			"execution_time_ms": 50 + rand.Intn(200),
			"sample_data": []map[string]interface{}{
				{"id": 1, "name": "John Doe", "email": "john@example.com"},
				{"id": 2, "name": "Jane Smith", "email": "jane@example.com"},
			},
			"query":  args.Query,
			"params": args.Params,
		}
	case strings.Contains(queryLower, "insert"):
		result = map[string]interface{}{
			"query_type":        "INSERT",
			"rows_affected":     1,
			"execution_time_ms": 25 + rand.Intn(100),
			"last_insert_id":    rand.Intn(1000) + 1000,
			"query":             args.Query,
			"params":            args.Params,
		}
	case strings.Contains(queryLower, "update"):
		result = map[string]interface{}{
			"query_type":        "UPDATE",
			"rows_affected":     rand.Intn(10) + 1,
			"execution_time_ms": 30 + rand.Intn(150),
			"query":             args.Query,
			"params":            args.Params,
		}
	case strings.Contains(queryLower, "delete"):
		result = map[string]interface{}{
			"query_type":        "DELETE",
			"rows_affected":     rand.Intn(5) + 1,
			"execution_time_ms": 20 + rand.Intn(80),
			"query":             args.Query,
			"params":            args.Params,
		}
	default:
		result = map[string]interface{}{
			"query_type":        "UNKNOWN",
			"message":           "Query executed successfully",
			"execution_time_ms": 10 + rand.Intn(50),
			"params":            args.Params,
		}
	}

	resultJSON, _ := json.MarshalIndent(result, "", "  ")

	return &mcp.CallToolResult{
		IsError: false,
		Content: []mcp.Content{&mcp.TextContent{Text: string(resultJSON)}},
	}, result, nil
}

// HTTPTestArgs represents arguments for the HTTP test tool
type HTTPTestArgs struct {
	Endpoint  string `json:"endpoint"`
	CustomURL string `json:"custom_url,omitempty"`
	Method    string `json:"method"`
}

func (s *HTTPMCPServer) handleHTTPTest(ctx context.Context, req *mcp.CallToolRequest, args HTTPTestArgs) (*mcp.CallToolResult, interface{}, error) {
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
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: "custom_url is required when endpoint is 'custom'"}},
			}, nil, nil
		}
		targetURL = args.CustomURL
	default:
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: "Invalid endpoint specified"}},
		}, nil, nil
	}

	// Use traced HTTP client
	client := last9mcp.WithHTTPTracing(&http.Client{
		Timeout: 10 * time.Second,
	})

	// Create request
	httpReq, err := http.NewRequestWithContext(ctx, args.Method, targetURL, nil)
	if err != nil {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Failed to create request: %v", err)}},
		}, nil, nil
	}

	// Set headers
	httpReq.Header.Set("User-Agent", "HTTP-MCP-Server/1.0")
	httpReq.Header.Set("Accept", "application/json")

	startTime := time.Now()
	resp, err := client.Do(httpReq)
	duration := time.Since(startTime)

	if err != nil {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("HTTP request failed: %v", err)}},
		}, nil, nil
	}
	defer resp.Body.Close()

	// Read limited response body
	body := make([]byte, 1024)
	n, _ := resp.Body.Read(body)
	bodyStr := string(body[:n])
	if n == 1024 {
		bodyStr += "... (truncated)"
	}

	result := map[string]interface{}{
		"endpoint":       args.Endpoint,
		"url":            targetURL,
		"method":         args.Method,
		"status_code":    resp.StatusCode,
		"status":         resp.Status,
		"duration_ms":    duration.Milliseconds(),
		"content_type":   resp.Header.Get("Content-Type"),
		"content_length": resp.Header.Get("Content-Length"),
		"response_body":  bodyStr,
		"timestamp":      time.Now().Format(time.RFC3339),
	}

	resultJSON, _ := json.MarshalIndent(result, "", "  ")

	return &mcp.CallToolResult{
		IsError: false,
		Content: []mcp.Content{&mcp.TextContent{Text: string(resultJSON)}},
	}, result, nil
}

func main() {
	// Seed random number generator
	rand.Seed(time.Now().UnixNano())

	// Get port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Create context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create and start the HTTP MCP server
	server, err := NewHTTPMCPServer(port)
	if err != nil {
		log.Fatalf("Failed to create HTTP MCP server: %v", err)
	}

	url := fmt.Sprintf("%s:%s", "localhost", port)
	if err := server.Start(ctx, url); err != nil {
		log.Printf("❌ Server error: %v", err)
		os.Exit(1)
	}
}
