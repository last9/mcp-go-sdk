package mcp

import (
	"context"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// toolErrorResult is what a server returns when the tool ran but failed:
// a successful JSON-RPC response carrying IsError.
func toolErrorResult(_ context.Context, _ string, _ sdkmcp.Request) (sdkmcp.Result, error) {
	return &sdkmcp.CallToolResult{
		IsError: true,
		Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: "city not found"}},
	}, nil
}

func counterTotal(t *testing.T, reader *sdkmetric.ManualReader, name string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
				total += dp.Value
			}
		}
	}
	return total
}

func TestClientHandleToolCall_IsErrorResult_RecordedAsError(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	reader := sdkmetric.NewManualReader()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))

	c, err := NewClientWithOptions("test-client", "1.0.0", WithSkipProviderInit())
	if err != nil {
		t.Fatalf("NewClientWithOptions: %v", err)
	}

	req := &sdkmcp.CallToolRequest{Params: &sdkmcp.CallToolParamsRaw{Name: "weather"}}
	if _, err := c.handleClientToolCall(context.Background(), toolErrorResult, req); err != nil {
		t.Fatalf("handleClientToolCall: %v", err)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %v", spanNames(spans))
	}
	sp := spans[0]
	if sp.Status.Code != codes.Error {
		t.Errorf("span status: got %v, want Error", sp.Status.Code)
	}
	requireAttr(t, sp.Attributes, keyMCPOperationStatus, statusError)
	requireAttr(t, sp.Attributes, keyMCPErrorType, errTypeUser)
	requireAttr(t, sp.Attributes, keyMCPErrorMessage, "city not found")

	if got := counterTotal(t, reader, "mcp.tool.errors.total"); got != 1 {
		t.Errorf("mcp.tool.errors.total: got %d, want 1", got)
	}
}
