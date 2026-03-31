package mcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// Last9MCPClient wraps an upstream MCP client with comprehensive OpenTelemetry
// observability: distributed tracing, metrics, and structured log records that
// are automatically correlated to the active trace span.
//
// Use NewClient or NewClientWithOptions to construct one, then call Connect to
// open a session. All RPC calls made through the returned ClientSession are
// automatically instrumented via the sending middleware registered here.
type Last9MCPClient struct {
	Client     *sdkmcp.Client
	clientName string

	tracer trace.Tracer
	logger *slog.Logger
	inst   *instruments
	cfg    *config

	// Server identity — populated after the first Connect() from InitializeResult.
	mu            sync.RWMutex
	serverName    string
	serverVersion string
	transport     string

	// Held for Shutdown so we can flush all three OTel pipelines.
	traceProvider  *sdktrace.TracerProvider
	metricProvider *sdkmetric.MeterProvider
	logProvider    *sdklog.LoggerProvider
}

// NewClient creates an instrumented MCP client with default observability
// configuration. OTLP endpoints are read from the standard OTel environment
// variables.
func NewClient(clientName, version string) (*Last9MCPClient, error) {
	return NewClientWithOptions(clientName, version)
}

// NewClientWithOptions creates an instrumented MCP client with the given
// Option values applied on top of the defaults.
func NewClientWithOptions(clientName, version string, opts ...Option) (*Last9MCPClient, error) {
	cfg := defaultConfig()
	for _, o := range opts {
		o(cfg)
	}

	ctx := context.Background()

	var tp *sdktrace.TracerProvider
	var mp *sdkmetric.MeterProvider
	var lp *sdklog.LoggerProvider
	var logger *slog.Logger

	if !cfg.skipOTelInit {
		resReal, tpInit, mpInit, err := initOpenTelemetry(ctx, clientName, version)
		if err != nil {
			return nil, fmt.Errorf("initializing OpenTelemetry: %w", err)
		}
		tp, mp = tpInit, mpInit
		logger, lp, err = initLogging(ctx, resReal)
		if err != nil {
			return nil, fmt.Errorf("initializing logging: %w", err)
		}
	} else {
		logger = slog.Default()
	}

	tracer := otel.Tracer(clientName)
	inst, err := initInstruments(otel.Meter(clientName))
	if err != nil {
		return nil, fmt.Errorf("initializing metric instruments: %w", err)
	}

	info := &sdkmcp.Implementation{Name: clientName, Version: version}
	c := &Last9MCPClient{
		Client:     sdkmcp.NewClient(info, nil),
		clientName: clientName,
		tracer:     tracer,
		logger:     logger,
		inst:           inst,
		cfg:            cfg,
		traceProvider:  tp,
		metricProvider: mp,
		logProvider:    lp,
	}

	c.Client.AddSendingMiddleware(c.clientMiddleware)

	logger.Info("mcp client initialised",
		"client.name", clientName,
		"client.version", version,
	)
	return c, nil
}

// Connect establishes a session with an MCP server. Server identity is
// populated from the initialize handshake result and used in all subsequent
// span and metric attributes.
func (c *Last9MCPClient) Connect(ctx context.Context, transport sdkmcp.Transport, opts *sdkmcp.ClientSessionOptions) (*sdkmcp.ClientSession, error) {
	transportName := mapClientTransport(transport)

	c.mu.Lock()
	c.transport = transportName
	c.mu.Unlock()

	session, err := c.Client.Connect(ctx, transport, opts)
	if err != nil {
		c.logger.ErrorContext(ctx, "mcp client connect failed",
			"transport", transportName,
			"err", err,
		)
		return nil, err
	}

	if result := session.InitializeResult(); result != nil && result.ServerInfo != nil {
		c.mu.Lock()
		c.serverName = result.ServerInfo.Name
		c.serverVersion = result.ServerInfo.Version
		c.mu.Unlock()
	}

	c.mu.RLock()
	sName, sVer := c.serverName, c.serverVersion
	c.mu.RUnlock()

	c.logger.InfoContext(ctx, "mcp client connected",
		"client.name", c.clientName,
		"server.name", sName,
		"server.version", sVer,
		"transport", transportName,
	)
	return session, nil
}

// Shutdown flushes and closes all three OTel pipelines (traces, metrics, logs).
func (c *Last9MCPClient) Shutdown(ctx context.Context) error {
	c.logger.InfoContext(ctx, "mcp client shutting down")

	var errs []error
	if c.traceProvider != nil {
		if err := c.traceProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("trace provider: %w", err))
		}
	}
	if c.metricProvider != nil {
		if err := c.metricProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("metric provider: %w", err))
		}
	}
	if c.logProvider != nil {
		if err := c.logProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("log provider: %w", err))
		}
	}
	return errors.Join(errs...)
}

// clientMiddleware is the sending middleware registered on the underlying
// Client. It fires before every outgoing RPC, dispatching to operation-specific
// handlers that create spans and record metrics.
func (c *Last9MCPClient) clientMiddleware(next sdkmcp.MethodHandler) sdkmcp.MethodHandler {
	return func(ctx context.Context, method string, req sdkmcp.Request) (sdkmcp.Result, error) {
		switch method {
		case opToolsCall:
			return c.handleClientToolCall(ctx, next, req)
		case opResourcesRead:
			if c.cfg.instrumentResources {
				return c.handleClientResourceRead(ctx, next, req)
			}
		case opPromptsGet:
			if c.cfg.instrumentPrompts {
				return c.handleClientPromptGet(ctx, next, req)
			}
		case opSamplingCreate:
			if c.cfg.instrumentSampling {
				return c.handleClientSimpleOp(ctx, next, method, req)
			}
		}
		return c.handleClientSimpleOp(ctx, next, method, req)
	}
}

// connInfo returns the current server name and transport under the read lock.
func (c *Last9MCPClient) connInfo() (serverName, transport string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.serverName, c.transport
}

func (c *Last9MCPClient) handleClientToolCall(ctx context.Context, next sdkmcp.MethodHandler, req sdkmcp.Request) (sdkmcp.Result, error) {
	toolName := ""
	if params, ok := req.GetParams().(*sdkmcp.CallToolParamsRaw); ok {
		toolName = params.Name
	}

	serverName, transport := c.connInfo()

	attrs := []attribute.KeyValue{
		keyGenAISystem.String(genAISystem),
		keyGenAIOperationName.String(opToolsCall),
		keyGenAIToolName.String(toolName),
		keyMCPToolName.String(toolName),
		keyMCPServerName.String(serverName),
		keyMCPServerTransport.String(transport),
		keyMCPClientName.String(c.clientName),
	}

	ctx, span := c.tracer.Start(ctx, toolSpanName(toolName), trace.WithAttributes(attrs...))
	defer span.End()

	span.AddEvent("tool.invoked", trace.WithAttributes(keyMCPToolName.String(toolName)))

	start := time.Now()
	mAttrs := toolAttrs(toolName, transport, c.clientName)
	c.inst.toolCalls.Add(ctx, 1, metric.WithAttributes(mAttrs...))

	result, err := next(ctx, opToolsCall, req)
	duration := time.Since(start)

	c.inst.toolDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(mAttrs...))
	c.inst.requestDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(mAttrs[:4]...))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(
			keyMCPOperationStatus.String(statusError),
			keyMCPErrorType.String(errTypeSystem),
			keyMCPErrorMessage.String(err.Error()),
		)
		span.AddEvent("error.occurred", trace.WithAttributes(
			keyMCPErrorType.String(errTypeSystem),
			keyMCPErrorMessage.String(err.Error()),
		))
		c.inst.toolErrors.Add(ctx, 1, metric.WithAttributes(mAttrs...))
	} else {
		span.SetStatus(codes.Ok, "")
		span.SetAttributes(keyMCPOperationStatus.String(statusSuccess))
		span.AddEvent("result.received", trace.WithAttributes(
			keyMCPOperationStatus.String(statusSuccess),
		))
	}

	return result, err
}

func (c *Last9MCPClient) handleClientResourceRead(ctx context.Context, next sdkmcp.MethodHandler, req sdkmcp.Request) (sdkmcp.Result, error) {
	serverName, transport := c.connInfo()

	attrs := []attribute.KeyValue{
		keyGenAISystem.String(genAISystem),
		keyGenAIOperationName.String(opResourcesRead),
		keyMCPServerName.String(serverName),
		keyMCPServerTransport.String(transport),
		keyMCPClientName.String(c.clientName),
	}
	if c.cfg.captureResourceBody {
		if params, ok := req.GetParams().(*sdkmcp.ReadResourceParams); ok {
			attrs = append(attrs, keyMCPResourceURI.String(params.URI))
		}
	}

	ctx, span := c.tracer.Start(ctx, spanName(opResourcesRead), trace.WithAttributes(attrs...))
	defer span.End()

	start := time.Now()
	mAttrs := baseAttrs(opResourcesRead, transport, c.clientName)

	result, err := next(ctx, opResourcesRead, req)
	duration := time.Since(start)

	c.inst.resourceReads.Add(ctx, 1, metric.WithAttributes(mAttrs...))
	c.inst.resourceDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(mAttrs...))
	c.inst.requestDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(mAttrs...))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(keyMCPOperationStatus.String(statusError), keyMCPErrorType.String(errTypeSystem))
	} else {
		span.SetStatus(codes.Ok, "")
		span.SetAttributes(keyMCPOperationStatus.String(statusSuccess))
	}
	return result, err
}

func (c *Last9MCPClient) handleClientPromptGet(ctx context.Context, next sdkmcp.MethodHandler, req sdkmcp.Request) (sdkmcp.Result, error) {
	serverName, transport := c.connInfo()

	attrs := []attribute.KeyValue{
		keyGenAISystem.String(genAISystem),
		keyGenAIOperationName.String(opPromptsGet),
		keyMCPServerName.String(serverName),
		keyMCPServerTransport.String(transport),
		keyMCPClientName.String(c.clientName),
	}

	promptName := ""
	if c.cfg.capturePromptArgs {
		if params, ok := req.GetParams().(*sdkmcp.GetPromptParams); ok {
			promptName = params.Name
			attrs = append(attrs, keyMCPPromptName.String(promptName))
		}
	}

	sName := spanName(opPromptsGet)
	if promptName != "" {
		sName = promptGetSpanName(promptName)
	}

	ctx, span := c.tracer.Start(ctx, sName, trace.WithAttributes(attrs...))
	defer span.End()

	start := time.Now()
	mAttrs := promptAttrs(promptName, transport, c.clientName)

	result, err := next(ctx, opPromptsGet, req)
	duration := time.Since(start)

	c.inst.promptGets.Add(ctx, 1, metric.WithAttributes(mAttrs...))
	c.inst.promptDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(mAttrs...))
	c.inst.requestDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(mAttrs[:4]...))

	finalizeSpan(span, err)
	return result, err
}

func (c *Last9MCPClient) handleClientSimpleOp(ctx context.Context, next sdkmcp.MethodHandler, method string, req sdkmcp.Request) (sdkmcp.Result, error) {
	serverName, transport := c.connInfo()

	ctx, span := c.tracer.Start(ctx, spanName(method),
		trace.WithAttributes(
			keyGenAISystem.String(genAISystem),
			keyGenAIOperationName.String(method),
			keyMCPServerName.String(serverName),
			keyMCPServerTransport.String(transport),
			keyMCPClientName.String(c.clientName),
		),
	)
	defer span.End()

	start := time.Now()
	result, err := next(ctx, method, req)
	duration := time.Since(start)

	c.inst.requestDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(
		baseAttrs(method, transport, c.clientName)...,
	))

	finalizeSpan(span, err)
	return result, err
}

// mapClientTransport returns the transport string for the mcp.server.transport attribute.
func mapClientTransport(t sdkmcp.Transport) string {
	switch t.(type) {
	case *sdkmcp.StdioTransport:
		return "stdio"
	case *sdkmcp.StreamableClientTransport:
		return "streamable"
	case *sdkmcp.SSEClientTransport:
		return "sse"
	case *sdkmcp.CommandTransport:
		return "command"
	default:
		return "unknown"
	}
}
