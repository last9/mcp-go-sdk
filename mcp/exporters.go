package mcp

import (
	"context"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// OTLP exporter constructors. They are variables so tests can substitute
// exporters that fail or record calls.
var (
	newTraceExporter = func(ctx context.Context) (sdktrace.SpanExporter, error) {
		return otlptracehttp.New(ctx)
	}
	newMetricExporter = func(ctx context.Context) (sdkmetric.Exporter, error) {
		return otlpmetrichttp.New(ctx)
	}
	newLogExporter = func(ctx context.Context) (sdklog.Exporter, error) {
		return otlploghttp.New(ctx)
	}
)
