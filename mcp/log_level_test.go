package mcp

import (
	"context"
	"log/slog"
	"testing"
	"time"
)

func TestWithLogLevel_AppliesWithSkipProviderInit(t *testing.T) {
	installTestProviders(t)

	s, err := NewServerWithOptions("test-server", "1.0.0",
		WithSkipProviderInit(), WithLogLevel(slog.LevelError))
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })

	c, err := NewClientWithOptions("test-client", "1.0.0",
		WithSkipProviderInit(), WithLogLevel(slog.LevelError))
	if err != nil {
		t.Fatalf("NewClientWithOptions: %v", err)
	}

	ctx := context.Background()
	if s.logger.Enabled(ctx, slog.LevelWarn) {
		t.Error("server logger: warn enabled with WithLogLevel(Error)")
	}
	if c.logger.Enabled(ctx, slog.LevelWarn) {
		t.Error("client logger: warn enabled with WithLogLevel(Error)")
	}
	if !s.logger.Enabled(ctx, slog.LevelError) {
		t.Error("server logger: error disabled with WithLogLevel(Error)")
	}
}

func TestWithLogLevel_AppliesToOTelLogPipeline(t *testing.T) {
	// Point the exporters at a closed port so nothing leaves the machine and
	// shutdown fails fast.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")

	s, err := NewServerWithOptions("test-server", "1.0.0", WithLogLevel(slog.LevelError))
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})

	if s.logger.Enabled(context.Background(), slog.LevelWarn) {
		t.Error("warn enabled with WithLogLevel(Error)")
	}
}
