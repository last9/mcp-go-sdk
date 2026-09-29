package mcp

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
)

// initLogging creates an OTel log provider backed by an OTLP HTTP exporter and
// returns a slog.Logger whose handler bridges into that pipeline.
//
// Trace correlation works automatically: any call to logger.InfoContext(ctx, ...)
// or logger.ErrorContext(ctx, ...) will extract the active span from ctx and
// inject trace_id, span_id, and trace_flags into the emitted log record.
func initLogging(ctx context.Context, res *resource.Resource) (*slog.Logger, *log.LoggerProvider, error) {
	exp, err := newLogExporter(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("creating log exporter: %w", err)
	}

	provider := log.NewLoggerProvider(
		log.WithResource(res),
		log.WithProcessor(log.NewBatchProcessor(exp)),
	)

	// NewHandler bridges slog records into the OTel log pipeline.
	// The instrumentation scope name identifies this library in the log data.
	handler := otelslog.NewHandler(
		"github.com/last9/mcp-go-sdk",
		otelslog.WithLoggerProvider(provider),
	)

	logger := slog.New(handler)
	return logger, provider, nil
}

// withMinLevel returns a logger that drops records below level before they
// reach logger's handler. With override, level alone decides what is enabled;
// otherwise the wrapped handler's own threshold also applies.
func withMinLevel(logger *slog.Logger, level slog.Level, override bool) *slog.Logger {
	return slog.New(levelHandler{level: level, override: override, handler: logger.Handler()})
}

// levelHandler is a slog.Handler that enforces a minimum level on the
// handler it wraps.
type levelHandler struct {
	level    slog.Level
	override bool
	handler  slog.Handler
}

func (h levelHandler) Enabled(ctx context.Context, level slog.Level) bool {
	if h.override {
		return level >= h.level
	}
	return level >= h.level && h.handler.Enabled(ctx, level)
}

func (h levelHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.handler.Handle(ctx, r)
}

func (h levelHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return levelHandler{level: h.level, override: h.override, handler: h.handler.WithAttrs(attrs)}
}

func (h levelHandler) WithGroup(name string) slog.Handler {
	return levelHandler{level: h.level, override: h.override, handler: h.handler.WithGroup(name)}
}
