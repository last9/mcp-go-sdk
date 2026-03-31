// Package main demonstrates using Last9MCPClient to call an in-process MCP
// server with full OpenTelemetry instrumentation on both sides.
//
// Every CallTool, ReadResource, and GetPrompt produces a client-side span with
// gen_ai.* and mcp.* attributes.  Run with:
//
//	OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://localhost:4318/v1/traces go run .
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	mcp "github.com/last9/mcp-go-sdk/mcp"
)

type GreetArgs struct {
	Name string `json:"name"`
}

type AddArgs struct {
	A float64 `json:"a"`
	B float64 `json:"b"`
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sigChan; cancel() }()

	// ── Server side ───────────────────────────────────────────────────────────
	// Use WithSkipProviderInit so both client and server share the same global
	// OTel providers (the client initialises them).
	server, err := mcp.NewServerWithOptions("demo-server", "1.0.0", mcp.WithSkipProviderInit())
	if err != nil {
		log.Fatal("server init:", err)
	}
	defer server.Shutdown(context.Background())

	mcp.RegisterInstrumentedTool(server, &sdkmcp.Tool{
		Name:        "greet",
		Description: "Return a greeting for a name",
	}, func(_ context.Context, _ *sdkmcp.CallToolRequest, args GreetArgs) (*sdkmcp.CallToolResult, any, error) {
		msg := fmt.Sprintf("Hello, %s!", args.Name)
		return &sdkmcp.CallToolResult{
			Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: msg}},
		}, nil, nil
	})

	mcp.RegisterInstrumentedTool(server, &sdkmcp.Tool{
		Name:        "add",
		Description: "Add two numbers",
	}, func(_ context.Context, _ *sdkmcp.CallToolRequest, args AddArgs) (*sdkmcp.CallToolResult, any, error) {
		result := fmt.Sprintf("%.4g + %.4g = %.4g", args.A, args.B, args.A+args.B)
		return &sdkmcp.CallToolResult{
			Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: result}},
		}, nil, nil
	})

	// ── In-memory transport — no network, no subprocess ───────────────────────
	// NewInMemoryTransports returns a connected pair.  The server listens on
	// serverTransport; the client dials via clientTransport.
	clientTransport, serverTransport := sdkmcp.NewInMemoryTransports()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Serve(ctx, serverTransport)
	}()

	// ── Client side ───────────────────────────────────────────────────────────
	// NewClient initialises OTel providers from environment variables and
	// registers the sending middleware that creates spans for every RPC.
	client, err := mcp.NewClient("demo-client", "1.0.0")
	if err != nil {
		log.Fatal("client init:", err)
	}
	defer client.Shutdown(context.Background())

	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		log.Fatal("connect:", err)
	}

	// Each call below produces a client span as a child of any ambient trace.
	greetResult, err := session.CallTool(ctx, &sdkmcp.CallToolParams{
		Name:      "greet",
		Arguments: map[string]any{"name": "World"},
	})
	if err != nil {
		log.Fatal("greet:", err)
	}
	if len(greetResult.Content) > 0 {
		if t, ok := greetResult.Content[0].(*sdkmcp.TextContent); ok {
			fmt.Println(t.Text)
		}
	}

	addResult, err := session.CallTool(ctx, &sdkmcp.CallToolParams{
		Name:      "add",
		Arguments: map[string]any{"a": 40, "b": 2},
	})
	if err != nil {
		log.Fatal("add:", err)
	}
	if len(addResult.Content) > 0 {
		if t, ok := addResult.Content[0].(*sdkmcp.TextContent); ok {
			fmt.Println(t.Text)
		}
	}

	cancel()
	<-serverErr
}
