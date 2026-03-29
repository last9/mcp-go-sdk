package mcp

import (
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// instruments holds every OTel metric instrument used by the server.
// Grouped by MCP operation family for clarity.
type instruments struct {
	// Tool call metrics — backwards-compatible names preserved.
	toolCalls    metric.Int64Counter
	toolDuration metric.Float64Histogram
	toolErrors   metric.Int64Counter

	// Resource read metrics.
	resourceReads    metric.Int64Counter
	resourceDuration metric.Float64Histogram

	// Prompt get metrics.
	promptGets      metric.Int64Counter
	promptDuration  metric.Float64Histogram

	// Sampling createMessage metrics.
	samplingCreates  metric.Int64Counter
	samplingDuration metric.Float64Histogram

	// Server-wide request duration across all operations.
	requestDuration metric.Float64Histogram

	// Active sessions gauge — rises on initialize, falls on disconnect/cleanup.
	activeSessions metric.Int64UpDownCounter
}

func initInstruments(meter metric.Meter) (*instruments, error) {
	var inst instruments
	var err error

	// Explicit histogram buckets tailored to expected latency ranges per operation.
	subSecBuckets := []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30}
	samplingBuckets := []float64{0.1, 0.5, 1, 5, 10, 30, 60, 120}

	inst.toolCalls, err = meter.Int64Counter(
		"mcp.tool.calls.total",
		metric.WithDescription("Total number of MCP tool calls"),
		metric.WithUnit("{call}"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating tool call counter: %w", err)
	}

	inst.toolDuration, err = meter.Float64Histogram(
		"mcp.tool.call.duration.seconds",
		metric.WithDescription("Duration of MCP tool calls in seconds"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(subSecBuckets...),
	)
	if err != nil {
		return nil, fmt.Errorf("creating tool duration histogram: %w", err)
	}

	inst.toolErrors, err = meter.Int64Counter(
		"mcp.tool.errors.total",
		metric.WithDescription("Total number of MCP tool call errors"),
		metric.WithUnit("{error}"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating tool error counter: %w", err)
	}

	inst.resourceReads, err = meter.Int64Counter(
		"mcp.resource.reads.total",
		metric.WithDescription("Total number of MCP resource reads"),
		metric.WithUnit("{read}"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating resource read counter: %w", err)
	}

	inst.resourceDuration, err = meter.Float64Histogram(
		"mcp.resource.read.duration.seconds",
		metric.WithDescription("Duration of MCP resource reads in seconds"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(subSecBuckets...),
	)
	if err != nil {
		return nil, fmt.Errorf("creating resource duration histogram: %w", err)
	}

	inst.promptGets, err = meter.Int64Counter(
		"mcp.prompt.gets.total",
		metric.WithDescription("Total number of MCP prompt gets"),
		metric.WithUnit("{get}"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating prompt get counter: %w", err)
	}

	inst.promptDuration, err = meter.Float64Histogram(
		"mcp.prompt.get.duration.seconds",
		metric.WithDescription("Duration of MCP prompt gets in seconds"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(subSecBuckets...),
	)
	if err != nil {
		return nil, fmt.Errorf("creating prompt duration histogram: %w", err)
	}

	inst.samplingCreates, err = meter.Int64Counter(
		"mcp.sampling.creates.total",
		metric.WithDescription("Total number of MCP sampling/createMessage calls"),
		metric.WithUnit("{call}"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating sampling create counter: %w", err)
	}

	inst.samplingDuration, err = meter.Float64Histogram(
		"mcp.sampling.create.duration.seconds",
		metric.WithDescription("Duration of MCP sampling/createMessage calls in seconds"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(samplingBuckets...),
	)
	if err != nil {
		return nil, fmt.Errorf("creating sampling duration histogram: %w", err)
	}

	inst.requestDuration, err = meter.Float64Histogram(
		"mcp.server.request.duration.seconds",
		metric.WithDescription("Duration of all MCP server operations in seconds"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(append(subSecBuckets, 60, 120)...),
	)
	if err != nil {
		return nil, fmt.Errorf("creating request duration histogram: %w", err)
	}

	inst.activeSessions, err = meter.Int64UpDownCounter(
		"mcp.active.sessions",
		metric.WithDescription("Number of currently active MCP client sessions"),
		metric.WithUnit("{session}"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating active sessions counter: %w", err)
	}

	return &inst, nil
}

// baseAttrs returns the attribute set shared by all operation metric recordings.
func baseAttrs(operation, transport, clientName string) []attribute.KeyValue {
	return []attribute.KeyValue{
		keyGenAISystem.String(genAISystem),
		keyGenAIOperationName.String(operation),
		keyMCPServerTransport.String(transport),
		keyMCPClientName.String(clientName),
	}
}

// toolAttrs extends baseAttrs with the tool name dimension.
func toolAttrs(toolName, transport, clientName string) []attribute.KeyValue {
	return append(
		baseAttrs(opToolsCall, transport, clientName),
		keyMCPToolName.String(toolName),
		keyGenAIToolName.String(toolName),
	)
}

// promptAttrs extends baseAttrs with the prompt name dimension.
// promptName is omitted when empty (e.g. when capturePromptArgs is disabled)
// to avoid creating a high-cardinality "" label in the metric series.
func promptAttrs(promptName, transport, clientName string) []attribute.KeyValue {
	attrs := baseAttrs(opPromptsGet, transport, clientName)
	if promptName != "" {
		attrs = append(attrs, keyMCPPromptName.String(promptName))
	}
	return attrs
}
