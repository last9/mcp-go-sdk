package mcp

import (
	"net/http"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// NewStreamableHTTPHandler returns an instrumented Streamable HTTP handler for
// this server. HTTP-hosted servers must use this helper instead of exposing the
// embedded Server directly so spans, metrics, logs, and client IDs carry the
// correct streamable transport attribution.
func (s *Last9MCPServer) NewStreamableHTTPHandler(opts *sdkmcp.StreamableHTTPOptions) http.Handler {
	s.serverTransport = "streamable"
	return sdkmcp.NewStreamableHTTPHandler(func(*http.Request) *sdkmcp.Server {
		return s.Server
	}, opts)
}
