package mcp

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
)

// sessionGaugeMeterProvider hands out a meter whose mcp.active.sessions
// counter reports every Add to onAdd. With WithSkipProviderInit the SDK
// records into whatever meter the application installed, so onAdd stands in
// for arbitrary application code, including code that blocks.
type sessionGaugeMeterProvider struct {
	metricnoop.MeterProvider
	onAdd func(int64)
}

func (p sessionGaugeMeterProvider) Meter(string, ...metric.MeterOption) metric.Meter {
	return sessionGaugeMeter{onAdd: p.onAdd}
}

type sessionGaugeMeter struct {
	metricnoop.Meter
	onAdd func(int64)
}

func (m sessionGaugeMeter) Int64UpDownCounter(name string, _ ...metric.Int64UpDownCounterOption) (metric.Int64UpDownCounter, error) {
	if name != "mcp.active.sessions" {
		return metricnoop.Int64UpDownCounter{}, nil
	}
	return sessionGaugeCounter{onAdd: m.onAdd}, nil
}

type sessionGaugeCounter struct {
	metricnoop.Int64UpDownCounter
	onAdd func(int64)
}

func (c sessionGaugeCounter) Add(_ context.Context, v int64, _ ...metric.AddOption) { c.onAdd(v) }

// serverWithSessionGauge builds a server that records mcp.active.sessions
// through onAdd.
func serverWithSessionGauge(t *testing.T, onAdd func(int64)) *Last9MCPServer {
	t.Helper()
	installTestProviders(t)
	otel.SetMeterProvider(sessionGaugeMeterProvider{onAdd: onAdd})
	s, err := NewServerWithOptions("test-server", "1.0.0", WithSkipProviderInit())
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}
	s.setTransport("stdio")
	return s
}

func initializeRequest() *sdkmcp.InitializeRequest {
	return &sdkmcp.InitializeRequest{Params: &sdkmcp.InitializeParams{
		ClientInfo: &sdkmcp.Implementation{Name: "cursor", Version: "1.0"},
	}}
}

// A session increment that blocks in application code must not keep
// Shutdown from honouring its context.
func TestShutdown_HonorsContextWhileASessionIncrementBlocks(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	var once sync.Once
	s := serverWithSessionGauge(t, func(v int64) {
		if v > 0 {
			once.Do(func() { close(entered) })
			<-release
		}
	})

	go func() { _, _ = s.handleInitialize(context.Background(), noop, initializeRequest()) }()
	<-entered

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
		t.Fatal("Shutdown ignored its context while a session increment was blocked")
	}
}

// Recording a session's increment outside any lock must not let its
// decrement be recorded first: exporters would briefly see a negative gauge.
func TestActiveSessions_DecrementNeverPrecedesIncrement(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var mu sync.Mutex
	var adds []int64
	var once sync.Once
	s := serverWithSessionGauge(t, func(v int64) {
		if v > 0 {
			once.Do(func() { close(entered) })
			<-release
		}
		mu.Lock()
		adds = append(adds, v)
		mu.Unlock()
	})

	initDone := make(chan struct{})
	go func() {
		defer close(initDone)
		_, _ = s.handleInitialize(context.Background(), noop, initializeRequest())
	}()
	<-entered

	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		_ = s.Shutdown(context.Background())
	}()

	// Give the sweep time to reach the session while its increment is held.
	time.Sleep(50 * time.Millisecond)
	close(release)
	<-initDone
	<-shutdownDone

	mu.Lock()
	defer mu.Unlock()
	if len(adds) != 2 || adds[0] != 1 || adds[1] != -1 {
		t.Errorf("mcp.active.sessions adds = %v, want [1 -1]", adds)
	}
}

// blockingHandler is a slog handler whose Handle blocks until release is
// closed, standing in for an application log handler that stalls.
type blockingHandler struct {
	entered chan struct{}
	release chan struct{}
	once    *sync.Once
}

func (h blockingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h blockingHandler) Handle(context.Context, slog.Record) error {
	h.once.Do(func() { close(h.entered) })
	<-h.release
	return nil
}
func (h blockingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h blockingHandler) WithGroup(string) slog.Handler      { return h }

// A log handler that blocks while the store is recording a session must not
// keep waitForRemovals from honouring its context.
func TestSessionStore_WaitForRemovalsHonorsContextWhileLoggingBlocks(t *testing.T) {
	s := newTestStore(t)
	h := blockingHandler{entered: make(chan struct{}), release: make(chan struct{}), once: &sync.Once{}}
	defer close(h.release)
	s.logger = slog.New(h)

	go s.ensure("late-client", ClientInfo{Name: "cursor"})
	<-h.entered

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- s.waitForRemovals(ctx) }()

	select {
	case <-errc:
	case <-time.After(2 * time.Second):
		t.Fatal("waitForRemovals ignored its context while a log handler held up the store")
	}
}
