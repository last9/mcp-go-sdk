package mcp

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
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
	exp, err := otlploghttp.New(ctx)
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
