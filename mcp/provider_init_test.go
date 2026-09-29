package mcp

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"go.opentelemetry.io/otel"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type recordingSpanExporter struct{ shutdown atomic.Bool }

func (e *recordingSpanExporter) ExportSpans(context.Context, []sdktrace.ReadOnlySpan) error {
	return nil
}

func (e *recordingSpanExporter) Shutdown(context.Context) error {
	e.shutdown.Store(true)
	return nil
}

type recordingMetricExporter struct{ shutdown atomic.Bool }

func (e *recordingMetricExporter) Temporality(k sdkmetric.InstrumentKind) metricdata.Temporality {
	return sdkmetric.DefaultTemporalitySelector(k)
}

func (e *recordingMetricExporter) Aggregation(k sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.DefaultAggregationSelector(k)
}

func (e *recordingMetricExporter) Export(context.Context, *metricdata.ResourceMetrics) error {
	return nil
}

func (e *recordingMetricExporter) ForceFlush(context.Context) error { return nil }

func (e *recordingMetricExporter) Shutdown(context.Context) error {
	e.shutdown.Store(true)
	return nil
}

// stubExporters replaces the exporter constructors for the duration of the
// test with recording fakes. A non-nil metricErr or logErr makes that
// exporter fail to construct.
func stubExporters(t *testing.T, metricErr, logErr error) (*recordingSpanExporter, *recordingMetricExporter) {
	t.Helper()
	origTrace, origMetric, origLog := newTraceExporter, newMetricExporter, newLogExporter
	t.Cleanup(func() {
		newTraceExporter, newMetricExporter, newLogExporter = origTrace, origMetric, origLog
	})

	traceExp := &recordingSpanExporter{}
	metricExp := &recordingMetricExporter{}
	newTraceExporter = func(context.Context) (sdktrace.SpanExporter, error) { return traceExp, nil }
	newMetricExporter = func(context.Context) (sdkmetric.Exporter, error) {
		if metricErr != nil {
			return nil, metricErr
		}
		return metricExp, nil
	}
	newLogExporter = func(context.Context) (sdklog.Exporter, error) {
		if logErr != nil {
			return nil, logErr
		}
		return origLog(context.Background())
	}
	return traceExp, metricExp
}

func TestNewServer_MetricExporterFails_ReleasesTraceProvider(t *testing.T) {
	installTestProviders(t)
	globalTP := otel.GetTracerProvider()
	traceExp, _ := stubExporters(t, errors.New("metric exporter unavailable"), nil)

	if _, err := NewServer("test-server", "1.0.0"); err == nil {
		t.Fatal("expected NewServer to fail")
	}

	if !traceExp.shutdown.Load() {
		t.Error("trace provider was not shut down after setup failed")
	}
	if otel.GetTracerProvider() != globalTP {
		t.Error("failed setup replaced the global tracer provider")
	}
}

func TestNewServer_LogExporterFails_ReleasesTraceAndMetricProviders(t *testing.T) {
	installTestProviders(t)
	globalTP, globalMP := otel.GetTracerProvider(), otel.GetMeterProvider()
	traceExp, metricExp := stubExporters(t, nil, errors.New("log exporter unavailable"))

	if _, err := NewServer("test-server", "1.0.0"); err == nil {
		t.Fatal("expected NewServer to fail")
	}

	if !traceExp.shutdown.Load() {
		t.Error("trace provider was not shut down after setup failed")
	}
	if !metricExp.shutdown.Load() {
		t.Error("meter provider was not shut down after setup failed")
	}
	if otel.GetTracerProvider() != globalTP {
		t.Error("failed setup replaced the global tracer provider")
	}
	if otel.GetMeterProvider() != globalMP {
		t.Error("failed setup replaced the global meter provider")
	}
}

func TestNewClient_LogExporterFails_ReleasesTraceAndMetricProviders(t *testing.T) {
	installTestProviders(t)
	globalTP, globalMP := otel.GetTracerProvider(), otel.GetMeterProvider()
	traceExp, metricExp := stubExporters(t, nil, errors.New("log exporter unavailable"))

	if _, err := NewClient("test-client", "1.0.0"); err == nil {
		t.Fatal("expected NewClient to fail")
	}

	if !traceExp.shutdown.Load() {
		t.Error("trace provider was not shut down after setup failed")
	}
	if !metricExp.shutdown.Load() {
		t.Error("meter provider was not shut down after setup failed")
	}
	if otel.GetTracerProvider() != globalTP {
		t.Error("failed setup replaced the global tracer provider")
	}
	if otel.GetMeterProvider() != globalMP {
		t.Error("failed setup replaced the global meter provider")
	}
}
