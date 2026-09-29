package mcp

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// The Mcp-Session-Id header is a bearer-style routing token: anyone holding
// it can send requests on that session. It must never appear verbatim in
// exported telemetry.
func TestStreamableHTTP_SessionIDNotExportedInSpans(t *testing.T) {
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
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "claude-desktop", Version: "1.0"}, nil)
	cs, err := client.Connect(ctx, &sdkmcp.StreamableClientTransport{Endpoint: srv.URL}, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer cs.Close()
	sid := cs.ID()
	if sid == "" {
		t.Fatal("expected a Streamable HTTP session ID")
	}
	if _, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{Name: "echo", Arguments: echoArgs{Text: "hi"}}); err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	for _, sp := range exp.GetSpans() {
		for _, kv := range sp.Attributes {
			if strings.Contains(kv.Value.Emit(), sid) {
				t.Errorf("span %q attribute %s contains the raw session ID", sp.Name, kv.Key)
			}
		}
	}
}

func TestSessionClientID_IsStableAndOpaque(t *testing.T) {
	info := ClientInfo{Name: "claude-desktop", Transport: "streamable"}
	const sid = "3f2a9c1e-7b4d-4e8a-9c21-5d6f7a8b9c0d"

	id := sessionClientID(info, sid)
	if strings.Contains(id, sid) {
		t.Errorf("client ID %q contains the raw session ID", id)
	}
	if again := sessionClientID(info, sid); again != id {
		t.Errorf("client ID not stable: %q then %q", id, again)
	}
	if other := sessionClientID(info, sid+"x"); other == id {
		t.Errorf("different sessions produced the same client ID %q", id)
	}
}
