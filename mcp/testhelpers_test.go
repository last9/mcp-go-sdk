package mcp

import (
	"context"
	"errors"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// noop is a MethodHandler that succeeds and returns a CallToolResult.
func noop(_ context.Context, _ string, _ sdkmcp.Request) (sdkmcp.Result, error) {
	return &sdkmcp.CallToolResult{}, nil
}

// errHandler is a MethodHandler that always returns an error.
func errHandler(_ context.Context, _ string, _ sdkmcp.Request) (sdkmcp.Result, error) {
	return nil, errors.New("downstream error")
}

// findAttr looks up an attribute by key in a span's attribute slice.
func findAttr(attrs []attribute.KeyValue, key attribute.Key) (attribute.Value, bool) {
	for _, a := range attrs {
		if a.Key == key {
			return a.Value, true
		}
	}
	return attribute.Value{}, false
}

// requireAttr fails the test if the attribute is missing or has an unexpected value.
func requireAttr(t *testing.T, attrs []attribute.KeyValue, key attribute.Key, want string) {
	t.Helper()
	val, ok := findAttr(attrs, key)
	if !ok {
		t.Errorf("missing attribute %q", key)
		return
	}
	if got := val.AsString(); got != want {
		t.Errorf("attr %q: got %q, want %q", key, got, want)
	}
}

// spanNames extracts span names for use in error messages.
func spanNames(spans tracetest.SpanStubs) []string {
	names := make([]string, len(spans))
	for i, s := range spans {
		names[i] = s.Name
	}
	return names
}
