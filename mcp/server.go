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
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// Last9MCPServer wraps an upstream MCP server with comprehensive OpenTelemetry
// observability: distributed tracing, metrics, and structured log records that
// are automatically correlated to the active trace span.
type Last9MCPServer struct {
	Server          *sdkmcp.Server
	serverName      string
	serverVersion   string
	serverTransport string

	tracer  trace.Tracer
	logger  *slog.Logger
	sessions *sessionStore
	inst    *instruments
	cfg     *config

	// currentClientID is the last-seen client for stdio, which is single-client.
	mu              sync.RWMutex
	currentClientID string

	// Disconnect lifecycle
	transportCtx    context.Context
	transportCancel context.CancelFunc
	disconnectChan  chan string

	// Held for Shutdown so we can flush all three OTel pipelines.
	traceProvider  *sdktrace.TracerProvider
	metricProvider *sdkmetric.MeterProvider
	logProvider    *sdklog.LoggerProvider
}

// NewServer creates an instrumented MCP server with default observability
// configuration. OTLP endpoints are read from the standard OTel environment
// variables (OTEL_EXPORTER_OTLP_TRACES_ENDPOINT, etc.).
func NewServer(serverName, version string) (*Last9MCPServer, error) {
	return NewServerWithOptions(serverName, version)
}

// NewServerWithOptions creates an instrumented MCP server with the given
// Option values applied on top of the defaults.
func NewServerWithOptions(serverName, version string, opts ...Option) (*Last9MCPServer, error) {
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
		var res *resource.Resource
		var err error
		res, tp, mp, err = initOpenTelemetry(ctx, serverName, version)
		if err != nil {
			return nil, fmt.Errorf("initializing OpenTelemetry: %w", err)
		}
		logger, lp, err = initLogging(ctx, res)
		if err != nil {
			return nil, fmt.Errorf("initializing logging: %w", err)
		}
	} else {
		logger = slog.Default()
	}

	tracer := otel.Tracer(serverName)
	inst, err := initInstruments(otel.Meter(serverName))
	if err != nil {
		return nil, fmt.Errorf("initializing metric instruments: %w", err)
	}

	info := &sdkmcp.Implementation{Name: serverName, Version: version}
	s := &Last9MCPServer{
		Server:         sdkmcp.NewServer(info, nil),
		serverName:     serverName,
		serverVersion:  version,
		tracer:         tracer,
		logger:         logger,
		sessions:       newSessionStore(cfg, logger),
		inst:           inst,
		cfg:            cfg,
		disconnectChan: make(chan string, 10),
		traceProvider:  tp,
		metricProvider: mp,
		logProvider:    lp,
	}

	s.Server.AddReceivingMiddleware(s.requestMiddleware)

	logger.InfoContext(ctx, "mcp server initialised",
		"server.name", serverName,
		"server.version", version,
	)
	return s, nil
}

// initOpenTelemetry sets up the global trace and metric providers, returning
// the shared resource plus both providers for later shutdown.
func initOpenTelemetry(ctx context.Context, serviceName, version string) (*resource.Resource, *sdktrace.TracerProvider, *sdkmetric.MeterProvider, error) {
	res, err := resource.New(ctx,
		resource.WithFromEnv(), // honour OTEL_RESOURCE_ATTRIBUTES
		resource.WithProcess(),
		resource.WithHost(),
		resource.WithTelemetrySDK(),
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(version),
			attribute.String("mcp.server.type", "golang"),
		),
	)
	if err != nil {
		// resource.New returns a partial resource on non-fatal errors; treat
		// warnings as non-fatal so the server still starts.
		slog.Warn("mcp resource creation had warnings", "err", err)
		if res == nil {
			return nil, nil, nil, fmt.Errorf("creating resource: %w", err)
		}
	}

	traceExp, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating trace exporter: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	metricExp, err := otlpmetrichttp.New(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating metric exporter: %w", err)
	}
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp,
			sdkmetric.WithInterval(10*time.Second),
		)),
	)
	otel.SetMeterProvider(mp)

	return res, tp, mp, nil
}

// Serve starts the server on the given transport and blocks until the context
// is cancelled or the transport closes.
func (s *Last9MCPServer) Serve(ctx context.Context, transport sdkmcp.Transport) error {
	s.transportCtx, s.transportCancel = context.WithCancel(ctx)
	s.serverTransport = mapServerTransport(transport)

	go s.monitorDisconnects()

	s.logger.InfoContext(s.transportCtx, "mcp server starting",
		"transport", s.serverTransport,
	)

	if err := s.Server.Run(s.transportCtx, transport); err != nil {
		s.logger.ErrorContext(s.transportCtx, "mcp server error", "err", err)
		s.handleServerShutdown()
		return err
	}
	return nil
}

func (s *Last9MCPServer) monitorDisconnects() {
	for {
		select {
		case clientID := <-s.disconnectChan:
			s.handleClientDisconnect(clientID)
		case <-s.transportCtx.Done():
			return
		}
	}
}

func (s *Last9MCPServer) handleClientDisconnect(clientID string) {
	// Retrieve client info before forceRemove so we can match the attribute set
	// used on the increment in handleInitialize (M2: gauge would otherwise drift).
	info, _ := s.sessions.getInfo(clientID)

	s.sessions.endQuery(clientID)

	s.mu.Lock()
	if s.currentClientID == clientID {
		s.currentClientID = ""
	}
	s.mu.Unlock()

	s.sessions.forceRemove(context.Background(), clientID)

	// Use context.Background() — transportCtx may already be cancelled at this
	// point, and a cancelled context silently discards OTel writes.
	s.inst.activeSessions.Add(context.Background(), -1, metric.WithAttributes(
		keyMCPServerTransport.String(s.serverTransport),
		keyMCPClientName.String(info.Name),
	))
	s.logger.InfoContext(context.Background(), "mcp client disconnected", "client.id", clientID, "client.name", info.Name)
}

func (s *Last9MCPServer) handleServerShutdown() {
	// Call handleClientDisconnect directly rather than sending through the
	// buffered channel, which can silently drop events when there are more
	// clients than the channel capacity (H3).
	for _, id := range s.sessions.allClientIDs() {
		s.handleClientDisconnect(id)
	}
}

// Shutdown flushes and closes all three OTel pipelines (traces, metrics, logs).
func (s *Last9MCPServer) Shutdown(ctx context.Context) error {
	s.logger.InfoContext(ctx, "mcp server shutting down")

	if s.transportCancel != nil {
		s.transportCancel()
	}
	if s.sessions != nil {
		s.sessions.cleanup.Stop()
		close(s.sessions.done)
	}

	s.mu.Lock()
	s.currentClientID = ""
	s.mu.Unlock()

	// Collect all provider errors so a trace flush failure does not prevent
	// metric and log pipelines from flushing (M3).
	var errs []error
	if s.traceProvider != nil {
		if err := s.traceProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("trace provider: %w", err))
		}
	}
	if s.metricProvider != nil {
		if err := s.metricProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("metric provider: %w", err))
		}
	}
	if s.logProvider != nil {
		if err := s.logProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("log provider: %w", err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	s.logger.InfoContext(ctx, "mcp server shutdown complete")
	return nil
}

// mapServerTransport returns the transport string for the mcp.server.transport attribute.
func mapServerTransport(t sdkmcp.Transport) string {
	switch t.(type) {
	case *sdkmcp.StdioTransport:
		return "stdio"
	case *sdkmcp.StreamableServerTransport:
		return "streamable"
	case *sdkmcp.SSEServerTransport:
		return "sse"
	default:
		return "unknown"
	}
}
