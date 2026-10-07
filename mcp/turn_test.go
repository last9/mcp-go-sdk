package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/trace"
)

const turnTraceID = "0123456789abcdef0123456789abcdef"
const turnParentID = "0123456789abcdef"
const turnTraceparent = "00-" + turnTraceID + "-" + turnParentID + "-01"

func TestRequestTurnContext(t *testing.T) {
	for _, tt := range []struct {
		name, header string
		meta         sdkmcp.Meta
		want         string
		remote       bool
	}{
		{"header", turnTraceparent, sdkmcp.Meta{"traceparent": "00-abcdef0123456789abcdef0123456789-abcdef0123456789-01"}, turnTraceID, true},
		{"metadata", "", sdkmcp.Meta{"traceparent": turnTraceparent}, turnTraceID, true},
		{"invalid header fallback", "bad", sdkmcp.Meta{"traceparent": turnTraceparent}, turnTraceID, true},
		{"vendor", "", sdkmcp.Meta{"last9/turn-id": "turn-a"}, "turn-a", false},
		{"codex", "", sdkmcp.Meta{"x-codex-turn-metadata": map[string]any{"turn_id": "turn-b"}}, "turn-b", false},
		{"invalid trace", "00-00000000000000000000000000000000-0123456789abcdef-01", nil, "", false},
		{"malformed meta", "", sdkmcp.Meta{"traceparent": 42, "last9/turn-id": true, "x-codex-turn-metadata": "bad"}, "", false},
		{"malformed codex id", "", sdkmcp.Meta{"x-codex-turn-metadata": map[string]any{"turn_id": 42}}, "", false},
		{"absent", "", nil, "", false},
		{"long id", "", sdkmcp.Meta{"last9/turn-id": strings.Repeat("a", 257)}, "", false},
		{"control id", "", sdkmcp.Meta{"last9/turn-id": "turn\nsecret"}, "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := &sdkmcp.CallToolRequest{Params: &sdkmcp.CallToolParamsRaw{Meta: tt.meta, Name: "search"}, Extra: &sdkmcp.RequestExtra{Header: http.Header{"Traceparent": []string{tt.header}}}}
			ctx, id := requestTurnContext(context.Background(), req)
			if id != tt.want {
				t.Fatalf("turn id = %q, want %q", id, tt.want)
			}
			sc := trace.SpanContextFromContext(ctx)
			if sc.IsValid() != tt.remote || sc.IsRemote() != tt.remote {
				t.Fatalf("parent = %v", sc)
			}
			if tt.remote && sc.SpanID().String() != turnParentID {
				t.Fatalf("parent id = %s", sc.SpanID())
			}
		})
	}
}

type turnHeaderTransport struct {
	header atomic.Value
}

func (t *turnHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	copy := req.Clone(req.Context())
	copy.Header.Set("Traceparent", t.header.Load().(string))
	return http.DefaultTransport.RoundTrip(copy)
}

func TestStreamableHTTPPreservesPerCallParent(t *testing.T) {
	s, exp := testInfra(t)
	err := RegisterInstrumentedTool(s, &sdkmcp.Tool{Name: "echo", Description: "echo text"}, func(_ context.Context, _ *sdkmcp.CallToolRequest, args echoArgs) (*sdkmcp.CallToolResult, any, error) {
		return &sdkmcp.CallToolResult{Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: args.Text}}}, nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.NewStreamableHTTPHandler(nil))
	defer srv.Close()
	transport := &turnHeaderTransport{}
	transport.header.Store("")
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "test-client", Version: "1.0"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cs, err := client.Connect(ctx, &sdkmcp.StreamableClientTransport{Endpoint: srv.URL, HTTPClient: &http.Client{Transport: transport}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	for _, header := range []string{turnTraceparent, "00-" + turnTraceID + "-abcdef0123456789-01", "00-abcdef0123456789abcdef0123456789-abcdef0123456789-01"} {
		transport.header.Store(header)
		if _, err := cs.ListTools(ctx, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{Name: "echo", Arguments: echoArgs{Text: "hi"}, Meta: sdkmcp.Meta{"traceparent": turnTraceparent}}); err != nil {
			t.Fatal(err)
		}
	}
	var calls int
	for _, sp := range exp.GetSpans() {
		if sp.Name == "mcp user_query" {
			t.Fatal("synthetic query span exported")
		}
		if sp.Name != toolSpanName("echo") {
			continue
		}
		wantTrace, wantParent := turnTraceID, turnParentID
		if calls == 1 {
			wantParent = "abcdef0123456789"
		}
		if calls == 2 {
			wantTrace, wantParent = "abcdef0123456789abcdef0123456789", "abcdef0123456789"
		}
		requireAttr(t, sp.Attributes, keyMCPTurnID, wantTrace)
		if sp.SpanContext.TraceID().String() != wantTrace || sp.Parent.SpanID().String() != wantParent || !sp.Parent.IsRemote() {
			t.Fatalf("HTTP parent mismatch: %v", sp)
		}
		calls++
	}
	if calls != 3 {
		t.Fatalf("got %d calls", calls)
	}
}

func TestToolsCallsUseRequestTurnNotSession(t *testing.T) {
	s, exp := testInfra(t)
	ctx := withTestClient(context.Background(), s, "same-session", "test-client")
	call := func(name string, meta sdkmcp.Meta) {
		t.Helper()
		req := &sdkmcp.CallToolRequest{Params: &sdkmcp.CallToolParamsRaw{Meta: meta, Name: name}}
		if _, err := s.requestMiddleware(noop)(ctx, opToolsCall, req); err != nil {
			t.Error(err)
		}
	}
	call("first", sdkmcp.Meta{"traceparent": turnTraceparent})
	call("second", sdkmcp.Meta{"traceparent": "00-abcdef0123456789abcdef0123456789-abcdef0123456789-01"})
	var wg sync.WaitGroup
	for _, id := range []string{"turn-a", "turn-b"} {
		wg.Add(1)
		go func(id string) { defer wg.Done(); call(id, sdkmcp.Meta{"last9/turn-id": id}) }(id)
	}
	wg.Wait()
	call("no-key", nil)
	call("invalid", sdkmcp.Meta{"traceparent": "invalid"})
	spans := exp.GetSpans()
	if len(spans) != 6 {
		t.Fatalf("got %d spans, want six tool spans", len(spans))
	}
	rootIDs := map[trace.TraceID]bool{}
	for _, sp := range spans {
		switch sp.Name {
		case toolSpanName("first"):
			requireAttr(t, sp.Attributes, keyMCPTurnID, turnTraceID)
			if sp.SpanContext.TraceID().String() != turnTraceID || sp.Parent.SpanID().String() != turnParentID || !sp.Parent.IsRemote() {
				t.Fatalf("wrong remote parent: %v", sp)
			}
		case toolSpanName("second"):
			requireAttr(t, sp.Attributes, keyMCPTurnID, "abcdef0123456789abcdef0123456789")
			if sp.SpanContext.TraceID().String() == turnTraceID {
				t.Fatal("successive turns share trace")
			}
		default:
			if sp.Parent.IsValid() {
				t.Fatalf("invented parent for %s", sp.Name)
			}
			if rootIDs[sp.SpanContext.TraceID()] {
				t.Fatal("untraced calls share roots")
			}
			rootIDs[sp.SpanContext.TraceID()] = true
			if sp.Name == toolSpanName("turn-a") || sp.Name == toolSpanName("turn-b") {
				id := "turn-a"
				if sp.Name == toolSpanName("turn-b") {
					id = "turn-b"
				}
				requireAttr(t, sp.Attributes, keyMCPTurnID, id)
			} else if _, ok := findAttr(sp.Attributes, keyMCPTurnID); ok {
				t.Fatal("unkeyed call has turn id")
			}
		}
	}
}
