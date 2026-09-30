package mcp

import (
	"context"
	"encoding/json"
	"errors"
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

// With Streamable HTTP, Serve is never called, so Shutdown is the last chance
// to release sessions before the final metric flush.
func TestActiveSessions_ReleasedByShutdownWhileStreamableClientConnected(t *testing.T) {
	s, reader := gaugeInfra(t)
	ctx := context.Background()

	srv := httptest.NewServer(s.NewStreamableHTTPHandler(nil))
	defer srv.Close()

	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "cursor", Version: "1.0"}, nil)
	cs, err := client.Connect(ctx, &sdkmcp.StreamableClientTransport{Endpoint: srv.URL}, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer cs.Close()
	waitForActiveSessions(t, reader, 1)

	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if got := activeSessions(t, reader); got != 0 {
		t.Errorf("mcp.active.sessions after Shutdown = %d, want 0", got)
	}
}

// HTTP handlers keep running after Shutdown starts, so an initialize that
// arrives during or after the sweep must not leave a session counted.
func TestActiveSessions_InitializeAfterShutdownIsNotCounted(t *testing.T) {
	s, reader := gaugeInfra(t)
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	req := &sdkmcp.InitializeRequest{Params: &sdkmcp.InitializeParams{
		ClientInfo: &sdkmcp.Implementation{Name: "cursor", Version: "1.0"},
	}}
	if _, err := s.handleInitialize(context.Background(), noop, req); err != nil {
		t.Fatalf("handleInitialize: %v", err)
	}

	if got := activeSessions(t, reader); got != 0 {
		t.Errorf("mcp.active.sessions = %d after an initialize that arrived post-shutdown, want 0", got)
	}
	if ids := s.sessions.allClientIDs(); len(ids) != 0 {
		t.Errorf("session stored after shutdown: %v", ids)
	}
}

func TestActiveSessions_ConcurrentInitializeAndShutdownEndAtZero(t *testing.T) {
	for i := 0; i < 50; i++ {
		s, reader := gaugeInfra(t)
		req := &sdkmcp.InitializeRequest{Params: &sdkmcp.InitializeParams{
			ClientInfo: &sdkmcp.Implementation{Name: "cursor", Version: "1.0"},
		}}

		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = s.handleInitialize(context.Background(), noop, req)
		}()
		_ = s.Shutdown(context.Background())
		<-done

		if got := activeSessions(t, reader); got != 0 {
			t.Fatalf("iteration %d: mcp.active.sessions = %d after initialize raced Shutdown, want 0", i, got)
		}
	}
}

// A removal that has already taken a session out of the store, but not yet
// recorded the decrement, must finish before Shutdown flushes metrics.
func TestActiveSessions_ShutdownWaitsForInFlightRemovals(t *testing.T) {
	s, reader := gaugeInfra(t)
	s.setTransport("stdio")

	req := &sdkmcp.InitializeRequest{Params: &sdkmcp.InitializeParams{
		ClientInfo: &sdkmcp.Implementation{Name: "cursor", Version: "1.0"},
	}}
	if _, err := s.handleInitialize(context.Background(), noop, req); err != nil {
		t.Fatalf("handleInitialize: %v", err)
	}
	ids := s.sessions.allClientIDs()
	if len(ids) != 1 {
		t.Fatalf("expected one session, got %v", ids)
	}

	// Hold the removal between leaving the store and recording the decrement,
	// the window a disconnect watcher can be preempted in.
	removed := make(chan struct{})
	release := make(chan struct{})
	onRemove := s.sessions.onRemove
	s.sessions.onRemove = func(ctx context.Context, sess *clientSession) {
		close(removed)
		<-release
		onRemove(ctx, sess)
	}
	go s.handleClientDisconnect(ids[0])
	<-removed

	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		_ = s.Shutdown(context.Background())
	}()

	select {
	case <-shutdownDone:
		close(release)
		t.Fatal("Shutdown returned while a session removal was still in flight")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	<-shutdownDone

	if got := activeSessions(t, reader); got != 0 {
		t.Errorf("mcp.active.sessions = %d after Shutdown, want 0", got)
	}
}

// Streamable HTTP handlers keep serving after Shutdown. A client that
// connects then must still have its session released when it disconnects,
// even though it is never counted.
func TestSessions_ClientConnectedAfterShutdownIsReleasedOnDisconnect(t *testing.T) {
	s, _ := gaugeInfra(t)
	ctx := context.Background()

	tool := &sdkmcp.Tool{Name: "echo", Description: "echo text"}
	if err := RegisterInstrumentedTool(s, tool, func(ctx context.Context, req *sdkmcp.CallToolRequest, args struct {
		Text string `json:"text"`
	}) (*sdkmcp.CallToolResult, any, error) {
		return &sdkmcp.CallToolResult{}, nil, nil
	}); err != nil {
		t.Fatalf("RegisterInstrumentedTool: %v", err)
	}

	srv := httptest.NewServer(s.NewStreamableHTTPHandler(nil))
	defer srv.Close()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "cursor", Version: "1.0"}, nil)
	cs, err := client.Connect(ctx, &sdkmcp.StreamableClientTransport{Endpoint: srv.URL}, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if _, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "hi"}}); err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	sessionID := sessionClientID(ClientInfo{Name: "cursor", Transport: "streamable"}, cs.ID())
	if _, ok := s.sessions.getInfo(sessionID); !ok {
		t.Fatalf("expected session %q to be stored while connected, have %v", sessionID, s.sessions.allClientIDs())
	}
	_ = cs.Close()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := s.sessions.getInfo(sessionID); !ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("session %q still stored after the client disconnected", sessionID)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Shutdown must respect its context even if a session removal it is waiting
// for never finishes (for example a blocking custom meter).
func TestShutdown_HonorsContextWhileWaitingForRemovals(t *testing.T) {
	s, _ := gaugeInfra(t)
	s.setTransport("stdio")

	req := &sdkmcp.InitializeRequest{Params: &sdkmcp.InitializeParams{
		ClientInfo: &sdkmcp.Implementation{Name: "cursor", Version: "1.0"},
	}}
	if _, err := s.handleInitialize(context.Background(), noop, req); err != nil {
		t.Fatalf("handleInitialize: %v", err)
	}
	ids := s.sessions.allClientIDs()

	removed := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	onRemove := s.sessions.onRemove
	s.sessions.onRemove = func(ctx context.Context, sess *clientSession) {
		close(removed)
		<-release
		onRemove(ctx, sess)
	}
	go s.handleClientDisconnect(ids[0])
	<-removed

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- s.Shutdown(ctx) }()

	select {
	case err := <-errc:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Shutdown error = %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown ignored its context while waiting for a removal")
	}
}

// The removals Shutdown performs itself during its sweep must also be
// bounded by Shutdown's context, not only the ones already in flight.
func TestShutdown_HonorsContextDuringItsOwnSweep(t *testing.T) {
	s, _ := gaugeInfra(t)
	s.setTransport("stdio")

	req := &sdkmcp.InitializeRequest{Params: &sdkmcp.InitializeParams{
		ClientInfo: &sdkmcp.Implementation{Name: "cursor", Version: "1.0"},
	}}
	if _, err := s.handleInitialize(context.Background(), noop, req); err != nil {
		t.Fatalf("handleInitialize: %v", err)
	}

	release := make(chan struct{})
	defer close(release)
	onRemove := s.sessions.onRemove
	s.sessions.onRemove = func(ctx context.Context, sess *clientSession) {
		<-release
		onRemove(ctx, sess)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- s.Shutdown(ctx) }()

	select {
	case err := <-errc:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Shutdown error = %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown ignored its context while its own sweep was blocked")
	}
}
