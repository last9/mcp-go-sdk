package mcp

import (
	"context"
	"sync"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestClientInfoFromRequest_MetaClientInfo(t *testing.T) {
	s, err := NewServerWithOptions("test-server", "1.0.0", WithSkipProviderInit())
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}
	s.serverTransport = "http"

	req := &sdkmcp.CallToolRequest{
		Params: &sdkmcp.CallToolParamsRaw{
			Name: "get_logs",
			Meta: sdkmcp.Meta{
				sdkmcp.MetaKeyClientInfo: map[string]any{
					"name":    "cursor",
					"version": "2.0.0",
				},
			},
		},
	}

	info := s.clientInfoFromRequest(req)
	if info.Name != "cursor" {
		t.Fatalf("client name: got %q, want cursor", info.Name)
	}
	if info.Version != "2.0.0" {
		t.Fatalf("client version: got %q, want 2.0.0", info.Version)
	}
	if info.Transport != "http" {
		t.Fatalf("transport: got %q, want http", info.Transport)
	}
}

func TestAttachClientContext_MetaClientInfo(t *testing.T) {
	s, err := NewServerWithOptions("test-server", "1.0.0", WithSkipProviderInit())
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}
	s.serverTransport = "http"

	req := &sdkmcp.CallToolRequest{
		Params: &sdkmcp.CallToolParamsRaw{
			Name: "get_logs",
			Meta: sdkmcp.Meta{
				sdkmcp.MetaKeyClientInfo: map[string]any{
					"name":    "claude",
					"version": "1.5.0",
				},
			},
		},
	}

	ctx := s.attachClientContext(context.Background(), req)
	info := clientInfoFromCtx(ctx, s)
	if info.Name != "claude" {
		t.Fatalf("client name: got %q, want claude", info.Name)
	}
	if clientIDFromCtx(ctx) == "" || clientIDFromCtx(ctx) == "unknown_client" {
		t.Fatalf("expected stable client id, got %q", clientIDFromCtx(ctx))
	}
}

func TestStableClientID_UnknownClient(t *testing.T) {
	s, err := NewServerWithOptions("test-server", "1.0.0", WithSkipProviderInit())
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}
	info := ClientInfo{Name: "unknown_client", Version: "unknown", Transport: "streamable"}
	first := s.stableClientID(info)
	second := s.stableClientID(info)
	if first == "unknown_client" || second == "unknown_client" {
		t.Fatalf("stableClientID must not use the shared unknown_client bucket: %q, %q", first, second)
	}
	if first == second {
		t.Fatalf("anonymous requests must receive isolated client IDs, both got %q", first)
	}
}

func TestStableClientID_IdentifiedClientRemainsStable(t *testing.T) {
	s, err := NewServerWithOptions("test-server", "1.0.0", WithSkipProviderInit())
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}
	info := ClientInfo{Name: "claude", Version: "1.5.0", Transport: "streamable"}
	first := s.stableClientID(info)
	second := s.stableClientID(info)
	if first != second {
		t.Fatalf("identified requests must retain stable correlation, got %q and %q", first, second)
	}
}

func TestRequestMiddleware_AnonymousStatelessClientsAreIsolated(t *testing.T) {
	s, exp := testInfra(t)
	s.serverTransport = "streamable"

	clientIDs := make(chan string, 2)
	next := func(ctx context.Context, _ string, _ sdkmcp.Request) (sdkmcp.Result, error) {
		clientIDs <- clientIDFromCtx(ctx)
		return &sdkmcp.CallToolResult{}, nil
	}
	handler := s.requestMiddleware(next)

	var wg sync.WaitGroup
	for _, toolName := range []string{"tool-a", "tool-b"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			req := &sdkmcp.CallToolRequest{Params: &sdkmcp.CallToolParamsRaw{Name: name}}
			if _, err := handler(context.Background(), opToolsCall, req); err != nil {
				t.Errorf("anonymous %s call: %v", name, err)
			}
		}(toolName)
	}
	wg.Wait()
	close(clientIDs)

	got := make([]string, 0, 2)
	for id := range clientIDs {
		got = append(got, id)
	}
	if len(got) != 2 {
		t.Fatalf("got %d client IDs, want 2", len(got))
	}
	if got[0] == "unknown_client" || got[1] == "unknown_client" {
		t.Fatalf("anonymous stateless calls must not use the shared unknown_client bucket: %q", got)
	}
	if got[0] == got[1] {
		t.Fatalf("anonymous stateless calls must be isolated, both used client ID %q", got[0])
	}

	toolTraceIDs := make(map[string]string, 2)
	for _, span := range exp.GetSpans() {
		if span.Name == toolSpanName("tool-a") || span.Name == toolSpanName("tool-b") {
			toolTraceIDs[span.Name] = span.SpanContext.TraceID().String()
		}
	}
	if len(toolTraceIDs) != 2 {
		t.Fatalf("got tool traces %v, want tool-a and tool-b", toolTraceIDs)
	}
	if toolTraceIDs[toolSpanName("tool-a")] == toolTraceIDs[toolSpanName("tool-b")] {
		t.Fatalf("anonymous stateless calls must not share a query trace: %v", toolTraceIDs)
	}
	for _, id := range got {
		if _, ok := s.sessions.getInfo(id); ok {
			t.Errorf("anonymous stateless session %q was retained after the request", id)
		}
	}
}

func TestRequestMiddleware_IdentifiedStatelessClientRetainsSession(t *testing.T) {
	s, _ := testInfra(t)
	s.serverTransport = "streamable"

	var clientID string
	next := func(ctx context.Context, _ string, _ sdkmcp.Request) (sdkmcp.Result, error) {
		clientID = clientIDFromCtx(ctx)
		return &sdkmcp.CallToolResult{}, nil
	}
	handler := s.requestMiddleware(next)
	req := &sdkmcp.CallToolRequest{
		Params: &sdkmcp.CallToolParamsRaw{
			Name: "tool-a",
			Meta: sdkmcp.Meta{
				sdkmcp.MetaKeyClientInfo: map[string]any{
					"name":    "claude",
					"version": "1.5.0",
				},
			},
		},
	}
	if _, err := handler(context.Background(), opToolsCall, req); err != nil {
		t.Fatalf("identified call: %v", err)
	}
	if clientID == "" || clientID == "unknown_client" {
		t.Fatalf("identified call received invalid client ID %q", clientID)
	}
	if _, ok := s.sessions.getInfo(clientID); !ok {
		t.Fatalf("identified session %q was removed after the request", clientID)
	}
}

func TestHandleServerDiscover_AnonymousSessionIsRemoved(t *testing.T) {
	s, _ := testInfra(t)
	s.serverTransport = "streamable"

	var clientID string
	next := func(ctx context.Context, _ string, _ sdkmcp.Request) (sdkmcp.Result, error) {
		clientID = clientIDFromCtx(ctx)
		if _, ok := s.sessions.getInfo(clientID); !ok {
			t.Errorf("anonymous discover session %q was not active during the request", clientID)
		}
		return &sdkmcp.DiscoverResult{}, nil
	}
	req := &sdkmcp.DiscoverRequest{Params: &sdkmcp.DiscoverParams{}}
	if _, err := s.handleServerDiscover(context.Background(), next, req); err != nil {
		t.Fatalf("anonymous discover: %v", err)
	}
	if clientID == "" || clientID == "unknown_client" {
		t.Fatalf("anonymous discover received shared client ID %q", clientID)
	}
	if _, ok := s.sessions.getInfo(clientID); ok {
		t.Fatalf("anonymous discover session %q was retained after the request", clientID)
	}
}
