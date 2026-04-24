# mcp-go-sdk

MCP servers are black boxes. You ship one, an LLM starts calling it, and you have no idea what's happening inside — which tools fire, how long they take, what fails, why. That's not acceptable in production.

This library fixes it. Wrap your server or client with two lines and get full OpenTelemetry observability: traces, metrics, structured logs — all correlated, all standard.

```go
server, err := mcp.NewServer("my-server", "1.0.0")
client, err := mcp.NewClient("my-agent", "1.0.0")
```

Set `OTEL_EXPORTER_OTLP_ENDPOINT` and you're done. No configuration files, no boilerplate, no instrumentation scattered across your handlers.

## Installation

```bash
go get github.com/last9/mcp-go-sdk
```

## The thirty-second version

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
        // your logic here — untouched, unmodified
        return &sdkmcp.CallToolResult{
            Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: "results..."}},
        }, nil, nil
    })

    if err := server.Serve(context.Background(), &sdkmcp.StdioTransport{}); err != nil {
        log.Fatal(err)
    }
}
```

Your business logic stays exactly as it was. The instrumentation happens around it, not inside it.

## What you actually get

Every `tools/call`, `resources/read`, `prompts/get`, and `sampling/createMessage` produces a span named after the operation — `mcp tools/call search`, `mcp resources/read`, and so on — with attributes that follow the OpenTelemetry GenAI semantic conventions:

```
gen_ai.system            = mcp
gen_ai.operation.name    = tools/call
gen_ai.tool.name         = search
mcp.tool.name            = search
mcp.server.transport     = stdio
mcp.client.name          = claude-desktop
mcp.operation.status     = success | error
```

These aren't made-up attribute names. They're the emerging standard for AI observability, which means your traces compose with whatever else you're already shipping to your backend.

### Query correlation

When Claude calls three tools in a single reasoning turn, those are three separate RPC calls arriving at your server. Without correlation, you get three unrelated traces. That's useless.

We track the query across calls. All tools invoked during the same LLM turn share a root `mcp user_query` span. One trace = one reasoning cycle. You see the whole sequence together, in order, with relative timing. That's how you actually debug what an LLM is doing.

### Metrics

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
| `mcp.active.sessions` | Gauge | Connected clients right now |

Flushed every 10 seconds. Histogram buckets are set to sensible defaults for LLM workloads — not the generic OTel defaults that make P99 charts useless.

### Logs

Every log line emitted through `log/slog` automatically carries `trace_id` and `span_id` pulled from context. When a tool fails, you don't grep through logs trying to figure out which trace it belonged to. You click the span, open the correlated logs, and you're there.

## Environment variables

```bash
# Where to send everything (one endpoint if your collector handles all signals)
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318

# Or per-signal if you need it
OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://localhost:4318/v1/traces
OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=http://localhost:4318/v1/metrics
OTEL_EXPORTER_OTLP_LOGS_ENDPOINT=http://localhost:4318/v1/logs

# Who you are
OTEL_SERVICE_NAME=my-mcp-server
OTEL_SERVICE_VERSION=1.0.0
OTEL_RESOURCE_ATTRIBUTES=deployment.environment=production
```

Standard OTel conventions throughout. No proprietary configuration.

## Options

The defaults are good. You shouldn't need most of these. But they're here when you do.

```go
server, err := mcp.NewServerWithOptions("my-server", "1.0.0",
    // Strip arguments and URIs from spans — right call for PII-sensitive deployments
    mcp.WithDisableArgCapture(),
    mcp.WithDisableResourceCapture(),
    mcp.WithDisablePromptCapture(),
    mcp.WithDisableSamplingCapture(),

    // Skip entire operation families you don't use
    mcp.WithDisableResources(),
    mcp.WithDisablePrompts(),
    mcp.WithDisableSampling(),

    // Your app already initialized OTel — don't let us clobber it
    mcp.WithSkipProviderInit(),

    // How long before we consider a session or query dead
    mcp.WithSessionTimeout(15 * time.Minute),
    mcp.WithQueryTimeout(5 * time.Minute),

    // Minimum severity that gets exported to OTel Logs
    mcp.WithLogLevel(slog.LevelWarn),
)
```

`WithSkipProviderInit` deserves a call-out. If your application already calls `otel.SetTracerProvider`, use this option. Without it we register our own global providers and you end up with two pipelines fighting each other. With it, we pick up yours and everything goes through one place.

## Outbound HTTP

Your tools probably make HTTP calls. Those calls should be children of the tool span, not invisible gaps in your trace. Pass the context and wrap the client:

```go
func handleSearch(ctx context.Context, req *sdkmcp.CallToolRequest, args SearchArgs) (*sdkmcp.CallToolResult, any, error) {
    client := mcp.WithHTTPTracing(&http.Client{Timeout: 10 * time.Second})

    httpReq, _ := http.NewRequestWithContext(ctx, "GET", "https://api.example.com/search", nil)
    resp, err := client.Do(httpReq)
    // ...
}
```

The full call chain — LLM reasoning turn → tool call → HTTP request — appears as one connected trace. That's what you need to find real latency bottlenecks.

## Client instrumentation

Building an agent or orchestrator that calls MCP servers? Instrument the client the same way:

```go
client, err := mcp.NewClient("my-agent", "1.0.0")
if err != nil {
    log.Fatal(err)
}
defer client.Shutdown(context.Background())

session, err := client.Connect(ctx, &sdkmcp.StdioTransport{}, nil)
if err != nil {
    log.Fatal(err)
}

// Every call through the session is automatically traced
result, err := session.CallTool(ctx, &sdkmcp.CallToolParams{
    Name:      "search",
    Arguments: args,
})
```

Client spans measure total round-trip latency — not just server processing time. Server name and version are populated automatically from the MCP initialize handshake. The same options apply:

```go
client, err := mcp.NewClientWithOptions("my-agent", "1.0.0",
    mcp.WithDisableArgCapture(),
    mcp.WithSkipProviderInit(),
)
```

## If your app already has OTel

Common case for mature services. Hand off your existing providers and we use them:

```go
otel.SetTracerProvider(yourTracerProvider)
otel.SetMeterProvider(yourMeterProvider)

server, err := mcp.NewServerWithOptions("my-server", "1.0.0",
    mcp.WithSkipProviderInit(),
)
```

No duplicate pipelines. No surprise exporter registrations. Your observability stack stays under your control.

## Claude Desktop setup

Point your server binary at a collector by setting env vars in the MCP config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
    "mcpServers": {
        "my-server": {
            "command": "/path/to/your/binary",
            "env": {
                "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318",
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
