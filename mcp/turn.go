package mcp

import (
	"context"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

func requestTurnContext(ctx context.Context, req sdkmcp.Request) (context.Context, string) {
	propagator := propagation.TraceContext{}
	if extra := req.GetExtra(); extra != nil {
		extracted := propagator.Extract(context.Background(), propagation.HeaderCarrier(extra.Header))
		if sc := trace.SpanContextFromContext(extracted); sc.IsValid() {
			return trace.ContextWithRemoteSpanContext(ctx, sc), sc.TraceID().String()
		}
	}
	meta := req.GetParams().GetMeta()
	carrier := propagation.MapCarrier{}
	for _, key := range []string{"traceparent", "tracestate"} {
		if value, ok := meta[key].(string); ok {
			carrier[key] = value
		}
	}
	extracted := propagator.Extract(context.Background(), carrier)
	if sc := trace.SpanContextFromContext(extracted); sc.IsValid() {
		return trace.ContextWithRemoteSpanContext(ctx, sc), sc.TraceID().String()
	}
	if id, ok := meta["last9/turn-id"].(string); ok && validTurnID(id) {
		return ctx, id
	}
	if codex, ok := meta["x-codex-turn-metadata"].(map[string]any); ok {
		if id, ok := codex["turn_id"].(string); ok && validTurnID(id) {
			return ctx, id
		}
	}
	return ctx, ""
}

func validTurnID(id string) bool {
	if len(id) == 0 || len(id) > 256 {
		return false
	}
	for _, c := range id {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}
