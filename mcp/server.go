package mcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
)

// Last9MCPServer wraps an upstream MCP server with comprehensive OpenTelemetry
// observability: distributed tracing, metrics, and structured log records that
// are automatically correlated to the active trace span.
type Last9MCPServer struct {
	Server        *sdkmcp.Server
	serverName    string
	serverVersion string

	// transportName is the mcp.server.transport attribute value. It is set by
	// Serve or NewStreamableHTTPHandler while handlers may be reading it, so
	// access it only through transport and setTransport.
	transportName atomic.Pointer[string]

	tracer   trace.Tracer
	logger   *slog.Logger
	sessions *sessionStore
	inst     *instruments
	cfg      *config

	// currentClientID is the last-seen client for stdio, which is single-client.
	mu              sync.RWMutex
	currentClientID string
	anonymousSeq    atomic.Uint64

	// shutdownCtx is cancelled by Shutdown. Serve watches it, so Shutdown stops
	// Serve whether it is called before, during, or after Serve starts.
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc

	// lifecycleMu guards closed, which Shutdown sets before its final
	// session sweep. Registration checks it under the same lock, so every
	// counted session is either registered before the sweep or not at all.
	lifecycleMu sync.Mutex
	closed      bool

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
		var err error
		tp, mp, lp, logger, err = initOpenTelemetry(ctx, serverName, version, cfg.applyLogLevel(slog.Default()))
		if err != nil {
			return nil, fmt.Errorf("initializing OpenTelemetry: %w", err)
		}
	} else {
		logger = slog.Default()
	}
	logger = cfg.applyLogLevel(logger)

	tracerProvider, meterProvider := instrumentationProviders(tp, mp)
	tracer := tracerProvider.Tracer(serverName)
	inst, err := initInstruments(meterProvider.Meter(serverName))
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
		inst:           inst,
		cfg:            cfg,
		traceProvider:  tp,
		metricProvider: mp,
		logProvider:    lp,
	}

	s.shutdownCtx, s.shutdownCancel = context.WithCancel(context.Background())
	s.sessions = newSessionStore(cfg, logger, s.sessionRemoved)
	s.Server.AddReceivingMiddleware(s.requestMiddleware)

	logger.InfoContext(ctx, "mcp server initialised",
		"server.name", serverName,
		"server.version", version,
	)
	return s, nil
}

// initOpenTelemetry builds the trace, metric, and log pipelines and returns
// their providers for later shutdown, plus a logger bridged into the log
// pipeline. Once every pipeline has been created the trace and metric providers
// are registered as the OTel globals (see registerGlobalProviders). If any step
// fails, whatever was already created is shut down and the globals are left
// untouched. setupLogger receives any warnings raised along the way, before
// the bridged logger exists.
func initOpenTelemetry(ctx context.Context, serviceName, version string, setupLogger *slog.Logger) (*sdktrace.TracerProvider, *sdkmetric.MeterProvider, *sdklog.LoggerProvider, *slog.Logger, error) {
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
		setupLogger.Warn("mcp resource creation had warnings", "err", err)
		if res == nil {
			return nil, nil, nil, nil, fmt.Errorf("creating resource: %w", err)
		}
	}

	traceExp, err := newTraceExporter(ctx)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("creating trace exporter: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
	)

	metricExp, err := newMetricExporter(ctx)
	if err != nil {
		_ = tp.Shutdown(ctx)
		return nil, nil, nil, nil, fmt.Errorf("creating metric exporter: %w", err)
	}
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp,
			sdkmetric.WithInterval(10*time.Second),
		)),
	)

	logger, lp, err := initLogging(ctx, res)
	if err != nil {
		_ = tp.Shutdown(ctx)
		_ = mp.Shutdown(ctx)
		return nil, nil, nil, nil, fmt.Errorf("initializing logging: %w", err)
	}

	registerGlobalProviders(ctx, tp, mp)
	return tp, mp, lp, logger, nil
}

// Serve starts the server on the given transport and blocks until ctx is
// cancelled, Shutdown is called, or the transport closes.
func (s *Last9MCPServer) Serve(ctx context.Context, transport sdkmcp.Transport) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(s.shutdownCtx, cancel)
	defer stop()

	s.setTransport(mapServerTransport(transport))

	s.logger.InfoContext(ctx, "mcp server starting",
		"transport", s.transport(),
	)

	// Whether Run fails or the client simply goes away, every session it
	// served is over, so release them all.
	err := s.Server.Run(ctx, transport)
	if err != nil {
		s.logger.ErrorContext(ctx, "mcp server error", "err", err)
	}
	s.handleServerShutdown()
	return err
}

// handleClientDisconnect removes a client's session. It is idempotent, so it
// is safe for the session watcher, Serve, and Shutdown to all call it.
func (s *Last9MCPServer) handleClientDisconnect(clientID string) {
	info, _ := s.sessions.getInfo(clientID)

	s.mu.Lock()
	if s.currentClientID == clientID {
		s.currentClientID = ""
	}
	s.mu.Unlock()

	if s.sessions.forceRemove(context.Background(), clientID) {
		s.logger.InfoContext(context.Background(), "mcp client disconnected", "client.id", clientID, "client.name", info.Name)
	}
}

// sessionRemoved is the session store's removal hook. It decrements
// mcp.active.sessions for sessions that were counted when they initialized.
func (s *Last9MCPServer) sessionRemoved(ctx context.Context, sess *clientSession) {
	if len(sess.activeAttrs) == 0 {
		return
	}
	// Record the decrement only after the matching increment, which the
	// registering request makes outside any lock.
	<-sess.counted
	// The caller's context may already be cancelled (for example during
	// shutdown), and the metrics SDK drops writes made with a cancelled context.
	s.inst.activeSessions.Add(context.WithoutCancel(ctx), -1, metric.WithAttributes(sess.activeAttrs...))
}

func (s *Last9MCPServer) handleServerShutdown() {
	for _, id := range s.sessions.allClientIDs() {
		s.handleClientDisconnect(id)
	}
}

// Shutdown flushes and closes all three OTel pipelines (traces, metrics, logs).
// It is safe to call more than once.
func (s *Last9MCPServer) Shutdown(ctx context.Context) error {
	s.logger.InfoContext(ctx, "mcp server shutting down")

	s.shutdownCancel()
	var waitErr error
	if s.sessions != nil {
		s.sessions.stop()
		// Release every remaining session before the providers flush, so the
		// final export does not report clients that are no longer served.
		// Serve does this on its own exit, but Streamable HTTP never calls it,
		// and its handlers can still be initializing sessions, so close
		// registration first. Once it is closed no new counted session can
		// appear, so the sweep itself needs no lock.
		s.lifecycleMu.Lock()
		s.closed = true
		s.lifecycleMu.Unlock()

		// Sweep in the background so a removal callback that blocks cannot
		// hold Shutdown past its deadline. Then wait for the sweep's removals
		// and any that raced with it to record their decrements, again only
		// as long as the caller's context allows.
		swept := make(chan struct{})
		go func() {
			defer close(swept)
			s.handleServerShutdown()
		}()
		select {
		case <-swept:
			waitErr = s.sessions.waitForRemovals(ctx)
		case <-ctx.Done():
			// The sweep is unfinished, so the final export may still count
			// sessions; report that rather than a clean shutdown.
			waitErr = ctx.Err()
		}
	}

	s.mu.Lock()
	s.currentClientID = ""
	s.mu.Unlock()

	if err := errors.Join(waitErr, shutdownProviders(ctx, s.traceProvider, s.metricProvider, s.logProvider)); err != nil {
		return err
	}

	s.logger.InfoContext(ctx, "mcp server shutdown complete")
	return nil
}

// transport returns the current mcp.server.transport attribute value.
func (s *Last9MCPServer) transport() string {
	if name := s.transportName.Load(); name != nil {
		return *name
	}
	return ""
}

// setTransport records the transport the server is being served over.
func (s *Last9MCPServer) setTransport(name string) {
	s.transportName.Store(&name)
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
