package mcp

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
)

// A process that hosts both a server and a client (a proxy or gateway, say)
// must not have the second one replace the global providers the first one
// registered. Otherwise shutting down the second leaves the first, and
// anything using the globals such as WithHTTPTracing, exporting through a
// provider that has already been shut down.
func TestNewClient_DoesNotReplaceGlobalProvidersOfRunningServer(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	shutdown := func(f func(context.Context) error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = f(ctx)
	}

	s, err := NewServer("test-server", "1.0.0")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { shutdown(s.Shutdown) })

	c, err := NewClient("test-client", "1.0.0")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if otel.GetTracerProvider() != trace.TracerProvider(s.traceProvider) {
		t.Error("client replaced the server's global tracer provider")
	}
	if otel.GetMeterProvider() != metric.MeterProvider(s.metricProvider) {
		t.Error("client replaced the server's global meter provider")
	}

	// The client still exports its own telemetry under its own resource.
	_, clientSpan := c.tracer.Start(context.Background(), "client-span")
	clientSpan.End()
	ro, ok := clientSpan.(sdktrace.ReadOnlySpan)
	if !ok {
		t.Fatalf("client span is %T, want an SDK span", clientSpan)
	}
	if name, _ := ro.Resource().Set().Value(semconv.ServiceNameKey); name.AsString() != "test-client" {
		t.Errorf("client span service.name: got %q, want test-client", name.AsString())
	}

	shutdown(c.Shutdown)
	if otel.GetTracerProvider() != trace.TracerProvider(s.traceProvider) {
		t.Error("global tracer provider changed after the client shut down")
	}
	_, span := s.tracer.Start(context.Background(), "server-after-client-shutdown")
	if !span.SpanContext().IsValid() {
		t.Error("server tracer stopped producing spans after the client shut down")
	}
	span.End()
}

// If the instance that owns the globals shuts down first, the globals must
// keep exporting for the instances still running, and must be released once
// the last of them stops.
func TestGlobalProviders_OutliveOwnerWhileOtherInstancesRun(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	shutdown := func(f func(context.Context) error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = f(ctx)
	}

	s, err := NewServer("test-server", "1.0.0")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	c, err := NewClient("test-client", "1.0.0")
	if err != nil {
		shutdown(s.Shutdown)
		t.Fatalf("NewClient: %v", err)
	}

	shutdown(s.Shutdown)
	_, span := otel.Tracer("app").Start(context.Background(), "while-client-runs")
	if !span.IsRecording() {
		t.Error("global tracer stopped recording after the owner shut down while the client was still running")
	}
	span.End()

	shutdown(c.Shutdown)
	_, span = otel.Tracer("app").Start(context.Background(), "after-everything-stopped")
	if span.IsRecording() {
		t.Error("global tracer provider was never shut down after the last instance stopped")
	}
	span.End()
}

// shutdownQuietly calls f with a short deadline; the exporters point at a
// closed port, so flush errors are expected and ignored.
func shutdownQuietly(f func(context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = f(ctx)
}

func TestGlobalProviders_RepeatedOwnerShutdownKeepsThemRunning(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")

	s, err := NewServer("test-server", "1.0.0")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	c, err := NewClient("test-client", "1.0.0")
	if err != nil {
		shutdownQuietly(s.Shutdown)
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { shutdownQuietly(c.Shutdown) })

	// For example a deferred Shutdown in main plus one in a signal handler.
	shutdownQuietly(s.Shutdown)
	shutdownQuietly(s.Shutdown)

	_, span := otel.Tracer("app").Start(context.Background(), "while-client-runs")
	if !span.IsRecording() {
		t.Error("a second Shutdown of the owner stopped the globals while the client was still running")
	}
	span.End()
}

func TestGlobalProviders_RetainedOwnerReleasedWhenReplaced(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")

	a, err := NewServer("server-a", "1.0.0")
	if err != nil {
		t.Fatalf("NewServer a: %v", err)
	}
	b, err := NewClient("client-b", "1.0.0")
	if err != nil {
		shutdownQuietly(a.Shutdown)
		t.Fatalf("NewClient b: %v", err)
	}
	t.Cleanup(func() { shutdownQuietly(b.Shutdown) })

	// a's providers are retained because they are still the globals.
	shutdownQuietly(a.Shutdown)

	// The application then installs its own globals, and a new instance
	// starts and registers itself as the owner.
	installTestProviders(t)
	c, err := NewServer("server-c", "1.0.0")
	if err != nil {
		t.Fatalf("NewServer c: %v", err)
	}
	t.Cleanup(func() { shutdownQuietly(c.Shutdown) })

	// Nothing uses a's providers any more, so they must have been shut down
	// rather than leaked.
	_, span := a.traceProvider.Tracer("check").Start(context.Background(), "leak-check")
	if span.IsRecording() {
		t.Error("retained providers of the stopped owner were leaked when a new owner registered")
	}
	span.End()
}
