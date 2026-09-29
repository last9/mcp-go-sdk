package mcp

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// gaugeInfra builds a server whose metrics can be read back through reader.
func gaugeInfra(t *testing.T) (*Last9MCPServer, *sdkmetric.ManualReader) {
	t.Helper()

	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(tracetest.NewInMemoryExporter()))
	otel.SetTracerProvider(tp)
	reader := sdkmetric.NewManualReader()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))

	s, err := NewServerWithOptions("test-server", "1.0.0", WithSkipProviderInit())
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}
	t.Cleanup(func() {
		_ = s.Shutdown(context.Background())
		_ = tp.Shutdown(context.Background())
	})
	return s, reader
}

// activeSessions returns the current value of mcp.active.sessions summed
// across all attribute sets.
func activeSessions(t *testing.T, reader *sdkmetric.ManualReader) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "mcp.active.sessions" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("mcp.active.sessions: unexpected data type %T", m.Data)
			}
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
		}
	}
	return total
}

// waitForActiveSessions polls until the gauge reaches want or the deadline passes.
func waitForActiveSessions(t *testing.T, reader *sdkmetric.ManualReader, want int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := activeSessions(t, reader)
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("mcp.active.sessions = %d, want %d", got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// legacyInitialize performs the pre-2026-07-28 initialize handshake over conn
// and waits for the server's response. The go-sdk client always tries
// server/discover first, so the legacy path is driven by hand.
func legacyInitialize(t *testing.T, ctx context.Context, conn sdkmcp.Connection) {
	t.Helper()
	id, err := jsonrpc.MakeID(float64(1))
	if err != nil {
		t.Fatalf("MakeID: %v", err)
	}
	params, err := json.Marshal(&sdkmcp.InitializeParams{
		ProtocolVersion: "2025-06-18",
		ClientInfo:      &sdkmcp.Implementation{Name: "cursor", Version: "1.0"},
		Capabilities:    &sdkmcp.ClientCapabilities{},
	})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	if err := conn.Write(ctx, &jsonrpc.Request{ID: id, Method: opInitialize, Params: params}); err != nil {
		t.Fatalf("write initialize: %v", err)
	}
	msg, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read initialize response: %v", err)
	}
	if resp, ok := msg.(*jsonrpc.Response); !ok || resp.Error != nil {
		t.Fatalf("initialize failed: %#v", msg)
	}
}

func TestActiveSessions_DecrementsWhenServeReturns(t *testing.T) {
	s, reader := gaugeInfra(t)
	ctx := context.Background()

	clientTransport, serverTransport := sdkmcp.NewInMemoryTransports()
	served := make(chan error, 1)
	go func() { served <- s.Serve(ctx, serverTransport) }()

	conn, err := clientTransport.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	legacyInitialize(t, ctx, conn)
	waitForActiveSessions(t, reader, 1)

	_ = conn.Close()
	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after the client disconnected")
	}
	waitForActiveSessions(t, reader, 0)
}

func TestActiveSessions_DecrementsWhenStreamableClientDisconnects(t *testing.T) {
	s, reader := gaugeInfra(t)
	ctx := context.Background()

	srv := httptest.NewServer(s.NewStreamableHTTPHandler(nil))
	defer srv.Close()

	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "cursor", Version: "1.0"}, nil)
	cs, err := client.Connect(ctx, &sdkmcp.StreamableClientTransport{Endpoint: srv.URL}, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	waitForActiveSessions(t, reader, 1)

	_ = cs.Close()
	waitForActiveSessions(t, reader, 0)
}

func TestActiveSessions_DecrementsWhenIdleSessionExpires(t *testing.T) {
	s, reader := gaugeInfra(t)

	req := &sdkmcp.InitializeRequest{Params: &sdkmcp.InitializeParams{
		ClientInfo: &sdkmcp.Implementation{Name: "cursor", Version: "1.0"},
	}}
	if _, err := s.handleInitialize(context.Background(), noop, req); err != nil {
		t.Fatalf("handleInitialize: %v", err)
	}
	waitForActiveSessions(t, reader, 1)

	for _, id := range s.sessions.allClientIDs() {
		s.sessions.mu.RLock()
		sess := s.sessions.sessions[id]
		s.sessions.mu.RUnlock()
		sess.mu.Lock()
		sess.lastActivity = time.Now().Add(-2 * s.cfg.sessionTimeout)
		sess.mu.Unlock()
	}
	s.sessions.cleanupStale(context.Background())

	waitForActiveSessions(t, reader, 0)
}
