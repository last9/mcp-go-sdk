# mcp-go-sdk

Wrap your MCP server or client with OpenTelemetry. Get traces, metrics, and structured logs out of the box — without touching your business logic.

```go
server, err := mcp.NewServer("my-server", "1.0.0")
client, err := mcp.NewClient("my-agent", "1.0.0")
```

Point `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` at your collector and you're done.

## Installation

```bash
go get github.com/last9/mcp-go-sdk
```

## Usage

```go
package main

import (
    "context"
    "log"

    sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
    mcp "github.com/last9/mcp-go-sdk/mcp"
)

type SearchArgs struct {
    Query string `json:"query"`
    Limit int    `json:"limit,omitempty"`
}

func main() {
    server, err := mcp.NewServer("search-server", "1.0.0")
    if err != nil {
        log.Fatal(err)
    }
    defer server.Shutdown(context.Background())

    tool := &sdkmcp.Tool{
        Name:        "search",
        Description: "Search the knowledge base",
    }

    mcp.RegisterInstrumentedTool(server, tool, func(ctx context.Context, req *sdkmcp.CallToolRequest, args SearchArgs) (*sdkmcp.CallToolResult, any, error) {
        // your logic here
        return &sdkmcp.CallToolResult{
            Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: "results..."}},
        }, nil, nil
    })

    if err := server.Serve(context.Background(), &sdkmcp.StdioTransport{}); err != nil {
        log.Fatal(err)
    }
}
```

## What you get

Every `tools/call`, `resources/read`, `prompts/get`, and `sampling/createMessage` produces:

**A span** named `mcp tools/call search` (or equivalent for the operation) with:

```
gen_ai.system            = mcp
gen_ai.operation.name    = tools/call
gen_ai.tool.name         = search
mcp.tool.name            = search
mcp.server.transport     = stdio
mcp.client.name          = claude-desktop
mcp.operation.status     = success | error
```

**Query correlation** — when Claude calls multiple tools in a single reasoning cycle, all those spans share one `mcp user_query` root span. One trace = one LLM turn. You see the whole sequence together, not scattered individual calls.

**Metrics**:

| Metric | Type | Description |
|--------|------|-------------|
| `mcp.tool.calls.total` | Counter | Tool invocations |
| `mcp.tool.call.duration.seconds` | Histogram | Tool latency |
| `mcp.tool.errors.total` | Counter | Tool failures |
| `mcp.resource.reads.total` | Counter | Resource reads |
| `mcp.resource.read.duration.seconds` | Histogram | Resource read latency |
| `mcp.prompt.gets.total` | Counter | Prompt fetches |
| `mcp.prompt.get.duration.seconds` | Histogram | Prompt fetch latency |
| `mcp.sampling.creates.total` | Counter | Sampling calls |
| `mcp.sampling.create.duration.seconds` | Histogram | Sampling latency |
| `mcp.server.request.duration.seconds` | Histogram | All operations |
| `mcp.active.sessions` | Gauge | Connected clients |

**Logs** are emitted via `log/slog` and automatically carry `trace_id` and `span_id` — every log line is correlated to the active span.

## Configuration

```bash
# Where to send traces (required)
OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://localhost:4318/v1/traces

# Where to send metrics (required)
OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=http://localhost:4318/v1/metrics

# Where to send logs (required)
OTEL_EXPORTER_OTLP_LOGS_ENDPOINT=http://localhost:4318/v1/logs

# Service identity (optional, but you want this)
OTEL_SERVICE_NAME=my-mcp-server
OTEL_SERVICE_VERSION=1.0.0
OTEL_RESOURCE_ATTRIBUTES=deployment.environment=production
```

Metrics are flushed every 10 seconds. Everything else follows standard OTel environment variable conventions.

## Options

```go
server, err := mcp.NewServerWithOptions("my-server", "1.0.0",
    // Strip PII from span attributes
    mcp.WithDisableArgCapture(),
    mcp.WithDisableResourceCapture(),
    mcp.WithDisablePromptCapture(),
    mcp.WithDisableSamplingCapture(),

    // Skip entire operation families
    mcp.WithDisableResources(),
    mcp.WithDisablePrompts(),
    mcp.WithDisableSampling(),

    // Your app already owns the OTel providers
    mcp.WithSkipProviderInit(),

    // Tune session lifetimes
    mcp.WithSessionTimeout(15 * time.Minute),
    mcp.WithQueryTimeout(5 * time.Minute),

    // Minimum log severity exported to OTel
    mcp.WithLogLevel(slog.LevelWarn),
)
```

`WithSkipProviderInit` is important if your application already calls `otel.SetTracerProvider`. Without it, the SDK registers its own global providers and you end up with two.

## Outbound HTTP tracing

If your tools make HTTP calls, propagate the trace:

```go
func handleSearch(ctx context.Context, req *sdkmcp.CallToolRequest, args SearchArgs) (*sdkmcp.CallToolResult, any, error) {
    client := mcp.WithHTTPTracing(&http.Client{Timeout: 10 * time.Second})

    httpReq, _ := http.NewRequestWithContext(ctx, "GET", "https://api.example.com/search", nil)
    resp, err := client.Do(httpReq)
    // ...
}
```

The outbound span becomes a child of the tool span. The full call chain — LLM turn → tool call → HTTP request — appears as one trace.

## Client instrumentation

If you're building an agent or orchestrator that calls MCP servers, instrument the client side the same way:

```go
client, err := mcp.NewClient("my-agent", "1.0.0")
if err != nil {
    log.Fatal(err)
}
defer client.Shutdown(context.Background())

// Connect to any MCP server — stdio, SSE, or streamable HTTP.
session, err := client.Connect(ctx, &sdkmcp.StdioTransport{}, nil)
if err != nil {
    log.Fatal(err)
}

// Every RPC through the session is automatically instrumented.
result, err := session.CallTool(ctx, &sdkmcp.CallToolParams{
    Name:      "search",
    Arguments: args,
})
```

Every `CallTool`, `ReadResource`, `GetPrompt`, and other RPC call produces a span with the same `gen_ai.*` and `mcp.*` attributes as the server side. The client span wraps the full round-trip, so you see total latency — not just server processing time.

Server name and version are populated automatically from the initialize handshake.

All the same options apply:

```go
client, err := mcp.NewClientWithOptions("my-agent", "1.0.0",
    mcp.WithDisableArgCapture(),   // strip PII from tool call spans
    mcp.WithSkipProviderInit(),    // use your app's existing OTel providers
)
```

## If your app already has OTel

Use `WithSkipProviderInit` and the SDK picks up whatever is globally registered:

```go
// Your app owns the providers
otel.SetTracerProvider(yourTracerProvider)
otel.SetMeterProvider(yourMeterProvider)

server, err := mcp.NewServerWithOptions("my-server", "1.0.0",
    mcp.WithSkipProviderInit(),
)
client, err := mcp.NewClientWithOptions("my-agent", "1.0.0",
    mcp.WithSkipProviderInit(),
)
```

## Client setup

**Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
    "mcpServers": {
        "my-server": {
            "command": "/path/to/your/binary",
            "env": {
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://localhost:4318/v1/traces",
                "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "http://localhost:4318/v1/metrics",
                "OTEL_SERVICE_NAME": "my-mcp-server"
            }
        }
    }
}
```

## Examples

- [stdio server](examples/stdio/) — calculator, data processor, random generator, outbound HTTP
- [HTTP server](examples/http/) — streamable HTTP transport with weather, news, and database tools

## License

MIT
