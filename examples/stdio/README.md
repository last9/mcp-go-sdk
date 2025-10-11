# MCP Go SDK Example

A complete example showing how to build and run an MCP server with OpenTelemetry observability, featuring process-aware client handling and parent-child trace relationships.

## Tools Available

- **test-tool**: Echo messages with optional delay/error
- **calculator**: Basic math operations
- **data-processor**: Array operations (count, reverse, sort, uppercase)
- **random-generator**: Generate random data
- **last9-telemetry**: Built-in trace management

## Quick Start

### 1. Start Observability Stack

```bash
# Start Jaeger and OpenTelemetry Collector
docker-compose up -d

# Verify services are running
docker-compose ps
```

### 2. Build and Run Server

```bash
# Load environment variables
source .env

# Build the server
go build -o stdio-server stdio-server.go

# Run the server
./stdio-server
```

### 3. Configure Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
    "mcpServers": {
        "example-server": {
            "command": "/absolute/path/to/stdio-server",
            "env": {
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://localhost:4318/v1/traces",
                "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "http://localhost:4318/v1/metrics",
                "OTEL_SERVICE_NAME": "example-mcp-server",
                "OTEL_SERVICE_VERSION": "1.0.0"
            }
        }
    }
}
```

### 4. Test and Observe

1. **Use the tools in Claude Desktop**:
   - "Calculate 25 * 4"
   - "Generate 3 random strings"
   - "Process this array: ['apple', 'banana', 'cherry'] and sort it"

2. **View traces in Jaeger**:
   - Open http://localhost:16686
   - Select service: `example-mcp-server`
   - View distributed traces of your tool calls

3. **Check server logs**:
   - See real-time session and trace information
   - Monitor client connections and disconnections

## What You'll See

### In the Server Console
```
🚀 Starting example MCP server with OpenTelemetry...
📊 OpenTelemetry traces and metrics will be exported
🔄 Created new session for client Claude_stdio_12345_1234567890
📋 Process-aware client handling initialized
🆕 [Claude] Started new query with tool: calculator (trace: parent-child hierarchy)
🏁 [Claude] Completed tool call: calculator (duration: 2ms, success: true)
🧹 Session cleanup completed with process tracking
```

### In Jaeger UI
- Distributed traces showing tool call flows with parent-child relationships
- Span details with client info, process data, and parameters
- Query correlation across multiple tool calls with proper context propagation
- Process lifecycle events and session management traces
- Error traces when tools fail with enhanced context

### Key Features Demonstrated
- Process-aware client handling with lifecycle tracking
- Parent-child trace relationships for stdio transport
- Multi-client session management with proper span isolation
- Automatic trace correlation and context propagation
- Enhanced error handling and reporting
- Session cleanup on disconnect with process tracking

## Cleanup

```bash
# Stop observability stack
docker-compose down

# Clean up volumes (optional)
docker-compose down -v
```

## Troubleshooting

- **No traces**: Check if collector is running with `docker-compose ps`
- **Connection errors**: Verify absolute paths in Claude Desktop config
- **Missing correlation**: Ensure the `last9-telemetry` tool is called at query end