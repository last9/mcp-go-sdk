package mcp

import (
	"context"
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
	if got := s.stableClientID(ClientInfo{Name: "unknown_client"}); got != "unknown_client" {
		t.Fatalf("stableClientID: got %q, want unknown_client", got)
	}
}
