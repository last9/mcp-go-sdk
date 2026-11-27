package mcp

import (
	"context"
	"errors"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func metricAttrs(t *testing.T, reader *sdkmetric.ManualReader, name string) []attribute.KeyValue {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect metrics: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			switch data := m.Data.(type) {
			case metricdata.Sum[int64]:
				if len(data.DataPoints) != 1 {
					t.Fatalf("metric %q: got %d data points, want 1", name, len(data.DataPoints))
				}
				return data.DataPoints[0].Attributes.ToSlice()
			}
		}
	}
	t.Fatalf("metric %q not found", name)
	return nil
}

func TestHandleToolsCall_CallerEndedOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		wantStatus string
		wantType   string
	}{
		{"cancelled", context.Canceled, "cancelled", "cancelled"},
		{"wrapped cancellation", errors.Join(errors.New("client disconnected"), context.Canceled), "cancelled", "cancelled"},
		{"deadline exceeded", context.DeadlineExceeded, "deadline_exceeded", "deadline_exceeded"},
		{"wrapped deadline", errors.Join(errors.New("request expired"), context.DeadlineExceeded), "deadline_exceeded", "deadline_exceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exp := tracetest.NewInMemoryExporter()
			tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
			otel.SetTracerProvider(tp)
			reader := sdkmetric.NewManualReader()
			mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
			otel.SetMeterProvider(mp)

			s, err := NewServerWithOptions("test-server", "1.0.0", WithSkipProviderInit())
			if err != nil {
				t.Fatalf("NewServerWithOptions: %v", err)
			}
			t.Cleanup(func() {
				_ = s.Shutdown(context.Background())
				_ = tp.Shutdown(context.Background())
				_ = mp.Shutdown(context.Background())
			})

			handler := func(context.Context, string, sdkmcp.Request) (sdkmcp.Result, error) {
				return nil, tc.err
			}
			req := &sdkmcp.CallToolRequest{Params: &sdkmcp.CallToolParamsRaw{Name: "query"}}
			_, _ = s.handleToolsCall(context.Background(), handler, req)

			spans := exp.GetSpans()
			if len(spans) != 1 {
				t.Fatalf("got %d spans, want 1", len(spans))
			}
			requireAttr(t, spans[0].Attributes, keyMCPOperationStatus, tc.wantStatus)
			requireAttr(t, spans[0].Attributes, keyMCPErrorType, tc.wantType)
			foundErrorEvent := false
			for _, event := range spans[0].Events {
				if event.Name == "error.occurred" {
					foundErrorEvent = true
					requireAttr(t, event.Attributes, keyMCPOperationStatus, tc.wantStatus)
					requireAttr(t, event.Attributes, keyMCPErrorType, tc.wantType)
				}
			}
			if !foundErrorEvent {
				t.Fatal("error.occurred event not found")
			}

			for _, metricName := range []string{"mcp.tool.calls.total", "mcp.tool.errors.total"} {
				attrs := metricAttrs(t, reader, metricName)
				requireAttr(t, attrs, keyMCPOperationStatus, tc.wantStatus)
				requireAttr(t, attrs, keyMCPErrorType, tc.wantType)
			}
		})
	}
}
