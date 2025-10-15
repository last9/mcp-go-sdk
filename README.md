# MCP Go SDK with OpenTelemetry Integration

A Go SDK for building [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers with built-in OpenTelemetry observability features. This SDK provides enhanced tracing, metrics, and session management for multi-client MCP server deployments.

## Features

- **OpenTelemetry Integration**: Built-in distributed tracing and metrics collection
- **Process-based Client Handling**: Enhanced support for client process management and lifecycle tracking
- **Parent-Child Trace Relationships**: Hierarchical trace context for stdio transport connections
- **Multi-Client Session Management**: Support for multiple concurrent clients with isolated trace contexts
- **Enhanced Middleware**: Request/response instrumentation with detailed telemetry
- **Automatic Trace Context Propagation**: Cross-tool call trace correlation with proper span management
- **Graceful Disconnect Handling**: Automatic cleanup of client sessions and traces
- **Configurable Telemetry Export**: OTLP HTTP endpoint support for traces and metrics

## Installation

```bash
go get github.com/last9/mcp-go-sdk
```

## Environment Variables

Configure OpenTelemetry and server behavior using these environment variables:

### Required Environment Variables

```bash
# OpenTelemetry OTLP Endpoints
OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://localhost:4318/v1/traces
OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=http://localhost:4318/v1/metrics

# Service identification
OTEL_SERVICE_NAME=your-mcp-server
OTEL_SERVICE_VERSION=1.0.0
```

### Optional Environment Variables

```bash
# Additional OTEL configuration
OTEL_RESOURCE_ATTRIBUTES=deployment.environment=production,service.instance.id=server-1
OTEL_EXPORTER_OTLP_HEADERS=authorization=Bearer your-token

# Sampling configuration
OTEL_TRACES_SAMPLER=always_on
# or OTEL_TRACES_SAMPLER=traceidratio
# OTEL_TRACES_SAMPLER_ARG=0.1

# Export intervals
OTEL_METRIC_EXPORT_INTERVAL=10000  # milliseconds
OTEL_BSP_EXPORT_TIMEOUT=30000      # milliseconds
```

## Quick Start

### 1. Create Your Server

```go
package main

import (
    "context"
    "log"

    "github.com/google/jsonschema-go/jsonschema"
    "github.com/modelcontextprotocol/go-sdk/mcp"
    last9mcp "github.com/last9/mcp-go-sdk/mcp"
)

func main() {
    // Create the instrumented MCP server
    server, err := last9mcp.NewServer("my-mcp-server", "1.0.0")
    if err != nil {
        log.Fatalf("Failed to create server: %v", err)
    }

    // Register your tools
    registerTools(server)

    // Start the server
    ctx := context.Background()
    transport := &mcp.StdioTransport{}

    if err := server.Serve(ctx, transport); err != nil {
        log.Fatalf("Server error: %v", err)
    }
}

func registerTools(server *last9mcp.Last9MCPServer) {
    tool := &mcp.Tool{
        Name:        "hello-world",
        Description: "A simple hello world tool",
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

    last9mcp.RegisterInstrumentedTool(server, tool, handleHelloWorld)
}

type HelloWorldArgs struct {
    Name string `json:"name"`
}

func handleHelloWorld(ctx context.Context, req *mcp.CallToolRequest, args HelloWorldArgs) (*mcp.CallToolResult, interface{}, error) {
    return &mcp.CallToolResult{
        IsError: false,
        Content: []mcp.Content{&mcp.TextContent{Text: "Hello, " + args.Name + "!"}},
    }, nil, nil
}
```

### 2. Set Environment Variables

Create a `.env` file or export these variables:

```bash
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://localhost:4318/v1/traces
export OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=http://localhost:4318/v1/metrics
export OTEL_SERVICE_NAME=my-mcp-server
export OTEL_SERVICE_VERSION=1.0.0
```

## Client Configuration

### VSCode (with Continue extension)

Add to your VSCode `settings.json`:

```json
{
    "continue.mcpServers": {
        "your-server-name": {
            "command": "/path/to/your/server/binary",
            "env": {
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://localhost:4318/v1/traces",
                "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "http://localhost:4318/v1/metrics",
                "OTEL_SERVICE_NAME": "your-mcp-server",
                "OTEL_SERVICE_VERSION": "1.0.0"
            }
        }
    }
}
```

### Claude Desktop

Add to your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
    "mcpServers": {
        "your-server-name": {
            "command": "/path/to/your/server/binary",
            "env": {
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://localhost:4318/v1/traces",
                "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "http://localhost:4318/v1/metrics",
                "OTEL_SERVICE_NAME": "your-mcp-server",
                "OTEL_SERVICE_VERSION": "1.0.0"
            }
        }
    }
}
```

## API Reference

### Server Creation

```go
func NewServer(serverName, version string) (*Last9MCPServer, error)
```

Creates a new instrumented MCP server with OpenTelemetry integration.

### Tool Registration

```go
func RegisterInstrumentedTool[In, Out any](
    server *Last9MCPServer,
    tool *mcp.Tool,
    handler mcp.ToolHandlerFor[In, Out],
) error
```

Registers a tool with automatic instrumentation and type safety.

### Server Methods

```go
func (s *Last9MCPServer) Serve(ctx context.Context, transport mcp.Transport) error
func (s *Last9MCPServer) Shutdown(ctx context.Context) error
```

## Automatic Telemetry

The server automatically handles trace lifecycle management without requiring manual telemetry tool calls. Traces are automatically ended when the client calls `tools/list`, ensuring proper trace isolation between queries.

## Observability Features

### Automatic Metrics

- `mcp_tool_calls_total`: Total number of tool calls
- `mcp_tool_call_duration_seconds`: Duration of tool calls
- `mcp_tool_errors_total`: Total number of tool errors

### Trace Attributes

Each trace includes detailed attributes:
- Client information (name, version, transport)
- Process information and lifecycle events
- Query context and correlation with parent-child relationships
- Tool parameters and results
- Error details and status codes

### Session Management

- Process-aware client session creation and cleanup
- Automatic client session creation and cleanup
- Query context isolation between clients with proper span management
- Parent-child trace context propagation for stdio transport
- Stale session cleanup (30 min timeout)
- Graceful disconnect handling with process tracking

## Development Setup

1. **Start OpenTelemetry Collector** (optional, for local development):

```bash
# Using Docker
docker run -p 4317:4317 -p 4318:4318 -p 8889:8889 \
  -v $(pwd)/otel-collector.yaml:/etc/otelcol/config.yaml \
  otel/opentelemetry-collector-contrib:latest
```

2. **Set up Jaeger** (for trace visualization):

```bash
docker run -d --name jaeger \
  -p 16686:16686 \
  -p 14250:14250 \
  jaegertracing/all-in-one:latest
```

3. **Run your server**:

```bash
go run main.go
```

## Error Handling

The SDK provides comprehensive error handling:

- Automatic error metrics collection
- Span status and error recording
- Client disconnect detection and cleanup
- Graceful degradation when telemetry endpoints are unavailable

## Best Practices

1. **Use structured arguments**: Define proper struct types for tool arguments to enable type safety and better observability.

2. **Set meaningful service names**: Use descriptive service names that identify your server's purpose.

3. **Configure appropriate sampling**: For high-traffic servers, consider using ratio-based sampling to manage telemetry volume.

4. **Monitor client sessions**: Check logs for client connect/disconnect events to understand usage patterns.

5. **Understand trace boundaries**: Traces automatically span from the first tool call until `tools/list` is called, grouping related tool calls together.

## Troubleshooting

### Common Issues

1. **Traces not appearing**: Verify OTLP endpoint configuration and network connectivity.

2. **High memory usage**: Check for stale client sessions; the SDK automatically cleans up after 30 minutes.

3. **Missing trace correlation**: Verify that `tools/list` calls are happening to trigger automatic trace completion.

### Debug Logging

The server provides detailed logs for:
- Client connections and disconnections
- Query start and end events
- Trace context propagation
- Session cleanup activities

## Examples

See the [example](./example) directory for a complete working implementation with multiple tools demonstrating various features of the SDK.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
