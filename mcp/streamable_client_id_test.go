package mcp

import (
	"context"
	"net/http/httptest"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

type echoArgs struct {
	Text string `json:"text"`
}

// Two users running the same MCP client (same name and version) against one
// Streamable HTTP server are different sessions and must not share a client
// ID, or their tool calls end up correlated into the same query trace.
func TestStreamableHTTP_SameClientNameDifferentSessions_GetDistinctClientIDs(t *testing.T) {
	s, exp := testInfra(t)

	tool := &sdkmcp.Tool{Name: "echo", Description: "echo text"}
	if err := RegisterInstrumentedTool(s, tool, func(ctx context.Context, req *sdkmcp.CallToolRequest, args echoArgs) (*sdkmcp.CallToolResult, any, error) {
		return &sdkmcp.CallToolResult{Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: args.Text}}}, nil, nil
	}); err != nil {
		t.Fatalf("RegisterInstrumentedTool: %v", err)
	}

	srv := httptest.NewServer(s.NewStreamableHTTPHandler(nil))
	defer srv.Close()

	ctx := context.Background()
	for i := 0; i < 2; i++ {
		client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "claude-desktop", Version: "1.0"}, nil)
		cs, err := client.Connect(ctx, &sdkmcp.StreamableClientTransport{Endpoint: srv.URL}, nil)
		if err != nil {
			t.Fatalf("Connect %d: %v", i, err)
		}
		if _, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{Name: "echo", Arguments: echoArgs{Text: "hi"}}); err != nil {
			t.Fatalf("CallTool %d: %v", i, err)
		}
		_ = cs.Close()
	}

	toolIDs := map[string]bool{}
	initIDs := map[string]bool{}
	for _, sp := range exp.GetSpans() {
		v, ok := findAttr(sp.Attributes, keyMCPClientID)
		switch sp.Name {
		case toolSpanName("echo"):
			if !ok {
				t.Fatalf("tool span missing %s", keyMCPClientID)
			}
			toolIDs[v.AsString()] = true
		case spanName(opInitialize):
			initIDs[v.AsString()] = true
		}
	}
	if len(toolIDs) != 2 {
		t.Fatalf("expected 2 distinct client IDs across sessions, got %v", toolIDs)
	}
	// A session's tool calls should carry the client ID assigned at initialize.
	for id := range toolIDs {
		if !initIDs[id] {
			t.Errorf("tool call client ID %q does not match any initialize span (%v)", id, initIDs)
		}
	}
}
