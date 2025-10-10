# StreamableHTTP MCP Server Examples

This directory contains examples of MCP servers using the StreamableHTTP protocol, which enables bidirectional communication over HTTP.

## Overview

The StreamableHTTP protocol allows MCP servers to handle requests and responses over HTTP while maintaining the bidirectional nature of the MCP protocol. This is particularly useful for web-based integrations and scenarios where stdio transport is not suitable.

## Examples

### streamable-http-server.go

A complete MCP server implementation using the StreamableHTTP protocol with the following features:

- **HTTP Transport**: Uses `mcp.StreamableServerTransport` for bidirectional communication over HTTP
- **Multiple Tools**: Includes weather, news, database query, and HTTP testing tools
- **OpenTelemetry Integration**: Full tracing and metrics support via Last9 wrapper
- **CORS Support**: Configured for browser compatibility
- **Health Checks**: Built-in health and info endpoints
- **Graceful Shutdown**: Signal handling (SIGINT/SIGTERM) with 10-second timeout for proper cleanup

#### Key Components

1. **httpReadWriteCloser**: Implements `io.ReadWriteCloser` to bridge HTTP request/response with MCP transport
2. **StreamableServerTransport**: Enables bidirectional communication over HTTP
3. **HTTP Handler**: Manages incoming HTTP requests and sets up MCP connections
4. **Tool Registration**: Demonstrates various tool types with OpenTelemetry tracing

#### Available Tools

- `get-weather`: Simulated weather API calls with HTTP tracing
- `get-news`: Mock news API integration with external HTTP requests
- `query-database`: Database query simulation with execution metrics
- `http-client-test`: HTTP client testing with different endpoints

## Running the Examples

### Prerequisites

1. Go 1.24.6 or later
2. Dependencies installed via `go mod tidy`

### Starting the Server

```bash
cd examples/http
go mod tidy
go run streamable-http-server.go
```

The server will start on port 8080 by default (configurable via `PORT` environment variable).

#### Graceful Shutdown

The server supports graceful shutdown via signal handling:

```bash
# Start the server
go run streamable-http-server.go

# In another terminal, send SIGINT (Ctrl+C) or SIGTERM
# The server will:
# 1. Stop accepting new connections
# 2. Wait up to 10 seconds for active requests to complete
# 3. Clean up resources and shut down gracefully
```

### Endpoints

- `http://localhost:8080/mcp` - Main MCP endpoint for StreamableHTTP protocol
- `http://localhost:8080/health` - Health check endpoint
- `http://localhost:8080/info` - Server information and capabilities

### Testing

You can test the server using curl or any HTTP client:

```bash
# Health check
curl http://localhost:8080/health

# Server info
curl http://localhost:8080/info

# MCP communication (requires proper MCP client)
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{"method": "tools/list", "id": 1}'
```

## Protocol Details

The StreamableHTTP protocol implementation:

1. **HTTP Request Handling**: Each HTTP POST request to `/mcp` creates a new MCP session
2. **Transport Creation**: `StreamableServerTransport` wraps the HTTP request/response in an `io.ReadWriteCloser`
3. **Bidirectional Communication**: The transport enables reading from the request body and writing to the response
4. **Session Management**: Each HTTP request is treated as a complete MCP session

## OpenTelemetry Integration

The examples include comprehensive OpenTelemetry integration:

- **Automatic Tracing**: All tool calls are automatically traced
- **HTTP Request Tracing**: External HTTP calls are traced with spans
- **Custom Metrics**: Performance and usage metrics collection
- **Trace Propagation**: Proper trace context propagation across service boundaries

## Configuration

Environment variables:

- `PORT`: Server port (default: 8080)
- `OTEL_EXPORTER_OTLP_ENDPOINT`: OpenTelemetry collector endpoint
- `OTEL_SERVICE_NAME`: Service name for tracing (default: streamable-http-mcp-server)

## Architecture Notes

The StreamableHTTP protocol is ideal for:

- Web-based MCP integrations
- Browser-compatible MCP clients
- HTTP-based service architectures
- Scenarios requiring CORS support
- Integration with existing HTTP infrastructure

For stdio-based examples, see the `../stdio/` directory.