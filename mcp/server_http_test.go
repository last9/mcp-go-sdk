package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestNewStreamableHTTPHandlerSetsTransport(t *testing.T) {
	s, exp := testInfra(t)
	handler := s.NewStreamableHTTPHandler(&sdkmcp.StreamableHTTPOptions{Stateless: true})

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`,
	))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("tools/list: got HTTP %d, want 200; body: %s", recorder.Code, recorder.Body.String())
	}
	if s.serverTransport != "streamable" {
		t.Fatalf("server transport: got %q, want streamable", s.serverTransport)
	}

	for _, span := range exp.GetSpans() {
		if span.Name == spanName(opToolsList) {
			requireAttr(t, span.Attributes, keyMCPServerTransport, "streamable")
			return
		}
	}
	t.Fatalf("span %q not found in %v", spanName(opToolsList), spanNames(exp.GetSpans()))
}
