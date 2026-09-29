package mcp

import (
	"context"
	"log/slog"
	"strings"
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

// recordingHandler captures records it receives. minLevel mimics a host
// handler configured with its own threshold.
type recordingHandler struct {
	minLevel slog.Level
	records  *[]slog.Record
}

func (h recordingHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.minLevel }
func (h recordingHandler) Handle(_ context.Context, r slog.Record) error {
	*h.records = append(*h.records, r)
	return nil
}
func (h recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h recordingHandler) WithGroup(string) slog.Handler      { return h }

// useDefaultLogger installs h as slog's default logger for the test.
func useDefaultLogger(t *testing.T, h slog.Handler) {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })
}

func TestWithLogLevel_AppliesToStartupWarnings(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	// A malformed entry makes resource detection return a non-fatal error,
	// which the SDK reports as a warning while it starts up.
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "malformed")

	var records []slog.Record
	useDefaultLogger(t, recordingHandler{minLevel: slog.LevelDebug, records: &records})

	s, err := NewServerWithOptions("test-server", "1.0.0", WithLogLevel(slog.LevelError))
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})

	// Only the SDK's own records are governed by WithLogLevel; OpenTelemetry's
	// internal error handler also reports the malformed attribute.
	for _, r := range records {
		if strings.HasPrefix(r.Message, "mcp ") && r.Level < slog.LevelError {
			t.Errorf("got %s record %q with WithLogLevel(Error)", r.Level, r.Message)
		}
	}
}

func TestWithLogLevel_CanLowerTheHostHandlersThreshold(t *testing.T) {
	var records []slog.Record
	useDefaultLogger(t, recordingHandler{minLevel: slog.LevelInfo, records: &records})
	installTestProviders(t)

	s, err := NewServerWithOptions("test-server", "1.0.0",
		WithSkipProviderInit(), WithLogLevel(slog.LevelDebug))
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })

	if !s.logger.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("debug disabled despite WithLogLevel(Debug)")
	}
}

func TestLogLevel_Unset_RespectsHostHandlersThreshold(t *testing.T) {
	var records []slog.Record
	useDefaultLogger(t, recordingHandler{minLevel: slog.LevelWarn, records: &records})
	installTestProviders(t)

	s, err := NewServerWithOptions("test-server", "1.0.0", WithSkipProviderInit())
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })

	if s.logger.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("info enabled although the host handler only accepts warn and above")
	}
}

type suppressKey struct{}

// contextFilterHandler rejects every record whose context is marked with
// suppressKey, regardless of level, the way sampling or per-request
// filtering handlers do.
type contextFilterHandler struct{ recordingHandler }

func (h contextFilterHandler) Enabled(ctx context.Context, l slog.Level) bool {
	if ctx.Value(suppressKey{}) != nil {
		return false
	}
	return h.recordingHandler.Enabled(ctx, l)
}

func TestWithLogLevel_KeepsHostHandlersNonLevelFiltering(t *testing.T) {
	var records []slog.Record
	useDefaultLogger(t, contextFilterHandler{recordingHandler{minLevel: slog.LevelInfo, records: &records}})
	installTestProviders(t)

	s, err := NewServerWithOptions("test-server", "1.0.0",
		WithSkipProviderInit(), WithLogLevel(slog.LevelDebug))
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })

	suppressed := context.WithValue(context.Background(), suppressKey{}, true)
	if s.logger.Enabled(suppressed, slog.LevelError) {
		t.Error("record enabled although the host handler rejects its context")
	}
}
