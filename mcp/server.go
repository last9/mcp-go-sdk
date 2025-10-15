package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
)

// ClientInfo contains information about the connected client
type ClientInfo struct {
	Name         string
	Version      string
	Transport    string
	Capabilities mcp.ClientCapabilities
}

// StoredTraceContext represents a stored trace context for cross-process propagation
type StoredTraceContext struct {
	SpanContext trace.SpanContext
	QueryID     string
	LastUsed    time.Time
	IsActive    bool
}

// ClientSession manages trace contexts for a specific client
type ClientSession struct {
	ClientInfo    ClientInfo
	ActiveQueries map[string]*StoredTraceContext // queryID -> context
	LastActivity  time.Time
	mu            sync.RWMutex
}

// QueryInfo contains extracted information about the user query
type QueryInfo struct {
	Content    string               // Actual query content if available
	Attributes []attribute.KeyValue // Additional attributes from arguments
}

// SessionBasedTraceStore manages trace contexts for multiple clients
type SessionBasedTraceStore struct {
	sessions map[string]*ClientSession // clientID -> session
	mu       sync.RWMutex
	cleanup  *time.Ticker
}

// Last9MCPServer with enhanced trace store
type Last9MCPServer struct {
	Server          *mcp.Server
	serverName      string
	serverTransport string
	tracer          trace.Tracer
	meter           metric.Meter
	traceStore      *SessionBasedTraceStore

	// Metrics instruments
	callCounter  metric.Int64Counter
	callDuration metric.Float64Histogram
	errorCounter metric.Int64Counter

	// Client management (simplified from HubManager)
	currentClientID string // for stdio compatibility
	mu              sync.RWMutex

	// Disconnect handling
	transportCtx    context.Context
	transportCancel context.CancelFunc
	disconnectChan  chan string
}

// NewSessionBasedTraceStore creates a new trace store with automatic cleanup
func NewSessionBasedTraceStore() *SessionBasedTraceStore {
	store := &SessionBasedTraceStore{
		sessions: make(map[string]*ClientSession),
		cleanup:  time.NewTicker(5 * time.Minute),
	}

	// Background cleanup of stale sessions
	go func() {
		for range store.cleanup.C {
			store.cleanupStaleSessions()
		}
	}()

	return store
}

// StoreQueryContext stores a new query context for a client
func (s *SessionBasedTraceStore) StoreQueryContext(clientID, queryID string, spanCtx trace.SpanContext) {
	s.mu.RLock()
	session, exists := s.sessions[clientID]
	s.mu.RUnlock()

	if !exists {
		s.mu.Lock()
		session = &ClientSession{
			ActiveQueries: make(map[string]*StoredTraceContext),
			LastActivity:  time.Now(),
		}
		s.sessions[clientID] = session
		s.mu.Unlock()
	}

	session.mu.Lock()
	session.ActiveQueries[queryID] = &StoredTraceContext{
		SpanContext: spanCtx,
		QueryID:     queryID,
		LastUsed:    time.Now(),
		IsActive:    true,
	}
	session.LastActivity = time.Now()
	session.mu.Unlock()
}

// GetQueryContext retrieves the most recent active query context for a client
func (s *SessionBasedTraceStore) GetQueryContext(clientID string) (trace.SpanContext, string, bool) {
	s.mu.RLock()
	session, exists := s.sessions[clientID]
	s.mu.RUnlock()

	if !exists {
		return trace.SpanContext{}, "", false
	}

	session.mu.RLock()
	defer session.mu.RUnlock()

	// Find the most recent active query
	var latestQuery *StoredTraceContext
	var latestQueryID string

	for queryID, query := range session.ActiveQueries {
		if query.IsActive && (latestQuery == nil || query.LastUsed.After(latestQuery.LastUsed)) {
			latestQuery = query
			latestQueryID = queryID
		}
	}

	if latestQuery != nil {
		latestQuery.LastUsed = time.Now()
		session.LastActivity = time.Now()
		return latestQuery.SpanContext, latestQueryID, true
	}

	return trace.SpanContext{}, "", false
}

// EndQuery ends all active queries for a client
func (s *SessionBasedTraceStore) EndQuery(clientID string) bool {
	s.mu.RLock()
	session, exists := s.sessions[clientID]
	s.mu.RUnlock()

	if !exists || len(session.ActiveQueries) == 0 {
		return false
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	hasActiveQueries := false
	for queryID, query := range session.ActiveQueries {
		if query.IsActive {
			query.IsActive = false
			hasActiveQueries = true
			delete(session.ActiveQueries, queryID)
		}
	}

	if hasActiveQueries {
		session.LastActivity = time.Now()
	}

	return hasActiveQueries
}

// GetClientInfo retrieves client information for a given clientID
func (s *SessionBasedTraceStore) GetClientInfo(clientID string) (ClientInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if session, exists := s.sessions[clientID]; exists {
		return session.ClientInfo, true
	}
	return ClientInfo{}, false
}

// CreateSession creates a new session for a client
func (s *SessionBasedTraceStore) CreateSession(clientID string, clientInfo ClientInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[clientID] = &ClientSession{
		ClientInfo:    clientInfo,
		ActiveQueries: make(map[string]*StoredTraceContext),
		LastActivity:  time.Now(),
	}

	log.Printf("🔄 Created new session for client %s (%s v%s)", clientID, clientInfo.Name, clientInfo.Version)
}

// forceCleanupClient immediately removes a client session
func (s *SessionBasedTraceStore) forceCleanupClient(clientID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if session, exists := s.sessions[clientID]; exists {
		session.mu.Lock()
		for queryID, query := range session.ActiveQueries {
			if query.IsActive {
				query.IsActive = false
				log.Printf("🧹 Force-ended query %s for disconnected client %s", queryID, clientID)
			}
		}
		session.ActiveQueries = make(map[string]*StoredTraceContext)
		session.mu.Unlock()

		delete(s.sessions, clientID)
		log.Printf("🧹 Force-removed session for disconnected client %s", clientID)
	}
}

// GetAllClientIDs returns all active client IDs
func (s *SessionBasedTraceStore) GetAllClientIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	clientIDs := make([]string, 0, len(s.sessions))
	for clientID := range s.sessions {
		clientIDs = append(clientIDs, clientID)
	}
	return clientIDs
}

// cleanupStaleSessions removes old inactive sessions with more aggressive timeouts
func (s *SessionBasedTraceStore) cleanupStaleSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// More aggressive cleanup tiers
	staleCutoff := now.Add(-30 * time.Minute)         // 30 min for stale sessions
	inactiveQueryCutoff := now.Add(-10 * time.Minute) // 10 min for inactive queries

	for clientID, session := range s.sessions {
		session.mu.Lock()

		// Clean up individual stale queries first
		activeQueryCount := 0
		for queryID, query := range session.ActiveQueries {
			if query.IsActive && query.LastUsed.Before(inactiveQueryCutoff) {
				log.Printf("🧹 Ending stale query %s for client %s (inactive for %v)",
					queryID, clientID, now.Sub(query.LastUsed))
				query.IsActive = false
				delete(session.ActiveQueries, queryID)
			} else if query.IsActive {
				activeQueryCount++
			}
		}

		// Remove entire session if completely stale
		if session.LastActivity.Before(staleCutoff) && activeQueryCount == 0 {
			session.mu.Unlock()
			delete(s.sessions, clientID)
			log.Printf("🧹 Removed stale session for client %s (inactive for %v)",
				clientID, now.Sub(session.LastActivity))
			continue
		}

		session.mu.Unlock()
	}
}

// parseArguments helper function (unchanged from original)
func parseArguments(arguments any, target interface{}) error {
	switch args := arguments.(type) {
	case json.RawMessage:
		return json.Unmarshal(args, target)
	case map[string]interface{}:
		jsonBytes, err := json.Marshal(args)
		if err != nil {
			return fmt.Errorf("failed to marshal map to JSON: %w", err)
		}
		return json.Unmarshal(jsonBytes, target)
	case nil:
		return fmt.Errorf("no arguments provided")
	default:
		jsonBytes, err := json.Marshal(args)
		if err != nil {
			return fmt.Errorf("failed to marshal arguments to JSON: %w", err)
		}
		return json.Unmarshal(jsonBytes, target)
	}
}

func mapServerTransport(transport mcp.Transport) string {
	switch transport.(type) {
	case *mcp.StdioTransport:
		return "stdio"
	case *mcp.StreamableServerTransport:
		return "streamable"
	case *mcp.SSEServerTransport:
		return "sse"
	default:
		return "stdio"
	}
}

// initOpenTelemetry sets up OpenTelemetry SDK (fixed error handling)
func initOpenTelemetry(serviceName, version string) error {
	ctx := context.Background()
	traceExp, err := otlptracehttp.New(ctx)
	if err != nil {
		return fmt.Errorf("creating trace exporter: %w", err)
	}

	// Fixed: proper resource creation with error handling
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(version),
			attribute.String("mcp.server.type", "golang"),
		),
	)
	if err != nil {
		return fmt.Errorf("creating resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	metricExp, err := otlpmetrichttp.New(ctx)
	if err != nil {
		return fmt.Errorf("creating metric exporter: %w", err)
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(
			metricExp, sdkmetric.WithInterval(10*time.Second))),
	)

	otel.SetMeterProvider(mp)
	return nil
}

// initMetrics initializes OpenTelemetry metrics instruments (unchanged)
func (w *Last9MCPServer) initMetrics() error {
	var err error

	w.callCounter, err = w.meter.Int64Counter(
		"mcp_tool_calls_total",
		metric.WithDescription("Total number of MCP tool calls"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return fmt.Errorf("creating call counter: %w", err)
	}

	w.callDuration, err = w.meter.Float64Histogram(
		"mcp_tool_call_duration_seconds",
		metric.WithDescription("Duration of MCP tool calls in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return fmt.Errorf("creating duration histogram: %w", err)
	}

	w.errorCounter, err = w.meter.Int64Counter(
		"mcp_tool_errors_total",
		metric.WithDescription("Total number of MCP tool call errors"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return fmt.Errorf("creating error counter: %w", err)
	}

	log.Println("📊 OpenTelemetry metrics instruments initialized")
	return nil
}

// NewServer creates a new server with enhanced trace management
func NewServer(serverName, version string) (*Last9MCPServer, error) {
	if err := initOpenTelemetry(serverName, version); err != nil {
		return nil, fmt.Errorf("failed to initialize OpenTelemetry: %w", err)
	}

	tracer := otel.Tracer("last9-mcp-server")
	meter := otel.Meter("last9-mcp-server")

	info := mcp.Implementation{
		Name:    serverName,
		Version: version,
	}

	server := &Last9MCPServer{
		Server:         mcp.NewServer(&info, nil),
		serverName:     serverName,
		tracer:         tracer,
		meter:          meter,
		traceStore:     NewSessionBasedTraceStore(),
		disconnectChan: make(chan string, 10),
	}

	// Telemetry is now handled automatically via middleware - no separate tool needed

	server.Server.AddReceivingMiddleware(server.requestStartMiddleware)

	if err := server.initMetrics(); err != nil {
		return nil, fmt.Errorf("failed to initialize metrics: %w", err)
	}

	return server, nil
}

// Enhanced middleware with proper context propagation
func (s *Last9MCPServer) requestStartMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		var clientID string
		var clientInfo ClientInfo

		if method == "initialize" {
			clientInfo = s.extractClientInfo(req)
			clientID = s.getOrGenerateClientID(clientInfo)
			s.traceStore.CreateSession(clientID, clientInfo)

			// Set as current client for stdio compatibility
			s.mu.Lock()
			s.currentClientID = clientID
			s.mu.Unlock()
		} else {
			clientID = s.getCurrentClientID(ctx, req)
			if info, exists := s.traceStore.GetClientInfo(clientID); exists {
				clientInfo = info
			} else {
				// Fallback for unknown client
				clientInfo = ClientInfo{
					Name:      "unknown_client",
					Version:   "unknown",
					Transport: "unknown",
				}
			}
		}

		// Add client info to context
		ctx = context.WithValue(ctx, "clientID", clientID)
		ctx = context.WithValue(ctx, "clientInfo", clientInfo)

		// Handle trace context with proper cross-process propagation
		ctx, span := s.handleTraceContext(ctx, method, req, clientID)
		if span != nil {
			defer span.End()
		}

		// Call the actual handler
		result, err := next(ctx, method, req)

		// Auto-telemetry: End traces when tools/list is called (indicates query completion)
		if method == "tools/list" {
			go s.scheduleAutoTelemetry(clientID, clientInfo)
		}

		return result, err
	}
}

// scheduleAutoTelemetry automatically ends traces immediately after tool completion
func (s *Last9MCPServer) scheduleAutoTelemetry(clientID string, clientInfo ClientInfo) {
	// End the current query for this specific client
	if ended := s.traceStore.EndQuery(clientID); ended {
		log.Printf("🏁 Auto-ended query for client %s", clientInfo.Name)
	}
}

// Enhanced trace context handling with proper multi-client support
func (s *Last9MCPServer) handleTraceContext(ctx context.Context, method string, req mcp.Request, clientID string) (context.Context, trace.Span) {
	if method != "tools/call" {
		// For non-tool methods, create simple spans
		return s.tracer.Start(ctx, fmt.Sprintf("mcp.%s", method))
	}

	ctr, ok := req.(*mcp.CallToolRequest)
	if !ok {
		return ctx, nil
	}

	toolName := ctr.Params.Name
	clientInfo := ctx.Value("clientInfo").(ClientInfo)

	// Extract query information from tool arguments
	queryInfo := s.extractQueryInfo(ctr)

	// Telemetry is now handled automatically via middleware

	// Check if we have an active query context
	if parentSpanCtx, queryID, exists := s.traceStore.GetQueryContext(clientID); exists {
		// Continue existing query - create child span
		ctx = trace.ContextWithSpanContext(ctx, parentSpanCtx)

		// Build attributes including query info
		attrs := []trace.SpanStartOption{
			trace.WithAttributes(
				attribute.String("tool.name", toolName),
				attribute.String("query.id", queryID),
				attribute.String("client.id", clientID),
			),
		}

		// Add query information attributes if available
		if len(queryInfo.Attributes) > 0 {
			attrs = append(attrs, trace.WithAttributes(queryInfo.Attributes...))
		}

		ctx, span := s.tracer.Start(ctx, fmt.Sprintf("mcp.tool.%s", toolName), attrs...)

		log.Printf("🔗 [%s] Continuing query %s with tool: %s", clientInfo.Name, queryID, toolName)
		return ctx, span
	} else {
		// Start new query - create root span and store context
		queryID := fmt.Sprintf("query_%s_%d", clientID, time.Now().UnixNano())

		// Build root query span attributes
		queryAttrs := []attribute.KeyValue{
			attribute.String("query.id", queryID),
			attribute.String("client.id", clientID),
			attribute.String("client.name", clientInfo.Name),
			attribute.String("query.first_tool", toolName),
		}

		// Add extracted query information
		if queryInfo.Content != "" {
			queryAttrs = append(queryAttrs, attribute.String("query.content", queryInfo.Content))
		}
		queryAttrs = append(queryAttrs, queryInfo.Attributes...)

		ctx, querySpan := s.tracer.Start(ctx, "mcp.user_query",
			trace.WithAttributes(queryAttrs...))

		// Store query context for subsequent tool calls
		s.traceStore.StoreQueryContext(clientID, queryID, querySpan.SpanContext())

		// Create first tool span as child of query
		toolAttrs := []attribute.KeyValue{
			attribute.String("tool.name", toolName),
			attribute.String("query.id", queryID),
			attribute.String("client.id", clientID),
		}
		toolAttrs = append(toolAttrs, queryInfo.Attributes...)

		ctx, toolSpan := s.tracer.Start(ctx, fmt.Sprintf("mcp.tool.%s", toolName),
			trace.WithAttributes(toolAttrs...))

		// End query span since we only need its context stored
		querySpan.End()

		log.Printf("🆕 [%s] Started new query %s with tool: %s", clientInfo.Name, queryID, toolName)
		return ctx, toolSpan
	}
}

// getCurrentClientID retrieves current client ID with fallback
func (s *Last9MCPServer) getCurrentClientID(ctx context.Context, req mcp.Request) string {
	if clientID, ok := ctx.Value("clientID").(string); ok {
		return clientID
	}

	// Fallback to current client for stdio compatibility
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.currentClientID != "" {
		return s.currentClientID
	}

	return "unknown_client_stdio"
}

// extractClientInfo extracts client information (unchanged logic)
func (s *Last9MCPServer) extractClientInfo(req mcp.Request) ClientInfo {
	clientInfo := ClientInfo{
		Name:      "unknown_client",
		Version:   "unknown",
		Transport: "stdio",
	}

	if initParams, ok := req.GetParams().(*mcp.InitializeParams); ok {
		clientInfo.Name = initParams.ClientInfo.Name
		clientInfo.Version = initParams.ClientInfo.Version

		if initParams.Capabilities != nil {
			clientInfo.Capabilities = *initParams.Capabilities
		}

		clientInfo.Transport = "stdio"
		log.Printf("📋 Extracted client info: %s v%s", clientInfo.Name, clientInfo.Version)
	}

	return clientInfo
}

// getOrGenerateClientID creates unique client ID with process info
func (s *Last9MCPServer) getOrGenerateClientID(clientInfo ClientInfo) string {
	if clientInfo.Transport == "stdio" {
		pid := os.Getpid()
		timestamp := time.Now().UnixNano()
		return fmt.Sprintf("%s_stdio_%d_%d", clientInfo.Name, pid, timestamp)
	}

	return fmt.Sprintf("%s_%s_%d", clientInfo.Name, clientInfo.Transport, time.Now().UnixNano())
}

// extractQueryInfo extracts user query information from tool call arguments
func (s *Last9MCPServer) extractQueryInfo(ctr *mcp.CallToolRequest) QueryInfo {
	queryInfo := QueryInfo{}

	if ctr.Params.Arguments == nil {
		return queryInfo
	}

	// Parse arguments to extract meaningful query information
	var args map[string]interface{}
	if err := parseArguments(ctr.Params.Arguments, &args); err != nil {
		// If parsing fails, try to get basic string representation
		if argStr := fmt.Sprintf("%v", ctr.Params.Arguments); len(argStr) > 0 && argStr != "<nil>" {
			queryInfo.Content = argStr
		}
		return queryInfo
	}

	// Extract common query-related fields
	queryFields := []string{
		"query", "request", "question", "prompt", "message", "text", "content",
		"command", "instruction", "task", "goal", "objective", "description",
	}

	var extractedContent []string
	var allArgs []string

	for key, value := range args {
		valueStr := fmt.Sprintf("%v", value)

		// Add as attribute - keep full content without truncation
		queryInfo.Attributes = append(queryInfo.Attributes,
			attribute.String(fmt.Sprintf("arg.%s", key), valueStr))

		// Check if this looks like a query field
		keyLower := fmt.Sprintf("%v", key)
		for _, field := range queryFields {
			if keyLower == field {
				extractedContent = append(extractedContent, valueStr)
				break
			}
		}

		// Collect all args for fallback
		allArgs = append(allArgs, fmt.Sprintf("%s: %v", key, value))
	}

	// Build content
	if len(extractedContent) > 0 {
		queryInfo.Content = fmt.Sprintf("%s", extractedContent[0])
	} else if len(allArgs) > 0 {
		// Use all arguments as content if no specific query fields found
		content := fmt.Sprintf("Tool: %s, Args: %s", ctr.Params.Name, allArgs[0])
		if len(allArgs) > 1 {
			content += fmt.Sprintf(" (+%d more)", len(allArgs)-1)
		}
		queryInfo.Content = content
	}

	return queryInfo
}

// RegisterInstrumentedTool registers a typed tool handler with instrumentation
func RegisterInstrumentedTool[In, Out any](server *Last9MCPServer, tool *mcp.Tool, handler mcp.ToolHandlerFor[In,
	Out],
) error {
	instrumentedHandler := instrumentHandler(server, handler)
	mcp.AddTool(server.Server, tool, instrumentedHandler)
	return nil
}

// Enhanced tool handler instrumentation
func instrumentHandler[In, Out any](server *Last9MCPServer, originalHandler mcp.ToolHandlerFor[In, Out]) func(ctx context.Context, mcpReq *mcp.CallToolRequest, args In) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, mcpReq *mcp.CallToolRequest, args In) (*mcp.CallToolResult, any, error) {
		span := trace.SpanFromContext(ctx)
		clientID := ctx.Value("clientID").(string)
		clientInfo := ctx.Value("clientInfo").(ClientInfo)

		span.SetAttributes(
			attribute.String("mcp.server.transport", server.serverTransport),
			attribute.String("client.name", clientInfo.Name),
			attribute.String("client.id", clientID),
		)

		server.addParamsToSpan(span, args)

		toolName := mcpReq.Params.Name
		startTime := time.Now()
		metricAttrs := []attribute.KeyValue{
			attribute.String("tool_name", toolName),
			attribute.String("server_transport", server.serverTransport),
			attribute.String("client_name", clientInfo.Name),
		}

		server.callCounter.Add(ctx, 1, metric.WithAttributes(metricAttrs...))

		// Call original handler
		result, out, err := originalHandler(ctx, mcpReq, args)

		// Record metrics and span status
		duration := time.Since(startTime)
		server.callDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(metricAttrs...))

		success := err == nil && (result == nil || !result.IsError)
		if success {
			span.SetStatus(codes.Ok, "Tool call completed successfully")
			span.SetAttributes(attribute.String("mcp.result.status", "success"))
		} else {
			errorAttrs := append(metricAttrs, attribute.String("error_type", "tool_error"))
			server.errorCounter.Add(ctx, 1, metric.WithAttributes(errorAttrs...))
			span.SetStatus(codes.Error, "Tool call failed")
			span.SetAttributes(attribute.String("mcp.result.status", "error"))

			if err != nil {
				span.RecordError(err)
				span.SetAttributes(attribute.String("mcp.error.message", err.Error()))
			} else if result.IsError {
				errMsg := "unknown error"
				if len(result.Content) > 0 {
					if msg, ok := result.Content[0].(*mcp.TextContent); ok {
						errMsg = msg.Text
					}
				}
				span.SetAttributes(attribute.String("mcp.error.message", errMsg))
			}
		}

		span.SetAttributes(
			attribute.Float64("mcp.duration.seconds", duration.Seconds()),
			attribute.Int64("mcp.duration.milliseconds", duration.Milliseconds()),
			attribute.Bool("mcp.success", success),
		)

		log.Printf("🏁 [%s] Completed tool call: %s (duration: %v, success: %v)",
			clientInfo.Name, toolName, duration, success)

		return result, out, err
	}
}

// Safe parameter addition to span
func (w *Last9MCPServer) addParamsToSpan(span trace.Span, params interface{}) {
	if params == nil {
		return
	}

	defer func() {
		if r := recover(); r != nil {
			span.SetAttributes(attribute.String("mcp.params.error", "failed to parse parameters"))
		}
	}()

	if args, ok := params.(map[string]interface{}); ok {
		span.SetAttributes(attribute.Int("mcp.params.count", len(args)))

		for key, value := range args {
			valueStr := fmt.Sprintf("%v", value)
			// Keep full parameter value without truncation
			span.SetAttributes(attribute.String(fmt.Sprintf("mcp.param.%s", key), valueStr))
		}
	}
}

// Serve starts the server with enhanced telemetry tool and disconnect monitoring
func (w *Last9MCPServer) Serve(ctx context.Context, transport mcp.Transport) error {
	log.Println("🚀 Starting enhanced instrumented MCP server...")

	// Create transport context for disconnect detection
	w.transportCtx, w.transportCancel = context.WithCancel(ctx)

	// Start disconnect monitor
	go w.monitorDisconnects()

	w.serverTransport = mapServerTransport(transport)

	err := w.Server.Run(w.transportCtx, transport)
	if err != nil {
		log.Printf("❌ MCP server encountered an error: %v", err)
		span := trace.SpanFromContext(ctx)
		if span != nil {
			span.SetAttributes(attribute.String("mcp.server.error", err.Error()))
		}
		// Signal all clients as disconnected
		w.handleServerShutdown()
	}
	return err
}

// monitorDisconnects monitors for client disconnects and cleans up immediately
func (w *Last9MCPServer) monitorDisconnects() {
	for {
		select {
		case clientID := <-w.disconnectChan:
			log.Printf("🔌 Client disconnected: %s", clientID)
			w.handleClientDisconnect(clientID)

		case <-w.transportCtx.Done():
			log.Println("🔌 Transport context cancelled, stopping disconnect monitoring")
			return
		}
	}
}

// handleClientDisconnect cleans up resources for a disconnected client
func (w *Last9MCPServer) handleClientDisconnect(clientID string) {
	// Immediately clean up this client's traces
	if ended := w.traceStore.EndQuery(clientID); ended {
		log.Printf("🧹 Cleaned up active queries for disconnected client %s", clientID)
	}

	// Clear currentClientID if it matches
	w.mu.Lock()
	if w.currentClientID == clientID {
		w.currentClientID = ""
	}
	w.mu.Unlock()

	// Force cleanup of this client's session
	w.traceStore.forceCleanupClient(clientID)
}

// handleServerShutdown signals all active clients as disconnected
func (w *Last9MCPServer) handleServerShutdown() {
	// Signal all active clients as disconnected
	clientIDs := w.traceStore.GetAllClientIDs()
	for _, clientID := range clientIDs {
		select {
		case w.disconnectChan <- clientID:
		default:
		}
	}
}

// Enhanced shutdown with proper cleanup
func (w *Last9MCPServer) Shutdown(ctx context.Context) error {
	log.Println("🛑 Shutting down MCP server...")

	// Stop disconnect monitoring
	if w.transportCancel != nil {
		w.transportCancel()
	}

	// Stop trace store cleanup
	if w.traceStore != nil && w.traceStore.cleanup != nil {
		w.traceStore.cleanup.Stop()
	}

	// End all active sessions and queries
	if w.traceStore != nil {
		w.traceStore.mu.Lock()
		for clientID, session := range w.traceStore.sessions {
			session.mu.Lock()
			for queryID, query := range session.ActiveQueries {
				if query.IsActive {
					query.IsActive = false
					log.Printf("🧹 Ended active query %s for client %s during shutdown", queryID, clientID)
				}
			}
			session.ActiveQueries = make(map[string]*StoredTraceContext)
			session.mu.Unlock()
		}
		w.traceStore.sessions = make(map[string]*ClientSession)
		w.traceStore.mu.Unlock()
	}

	// Clear current client
	w.mu.Lock()
	w.currentClientID = ""
	w.mu.Unlock()

	// Shutdown OpenTelemetry providers
	if tp, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
		if err := tp.Shutdown(ctx); err != nil {
			log.Printf("❌ Error shutting down trace provider: %v", err)
			return err
		}
	}

	if mp, ok := otel.GetMeterProvider().(*sdkmetric.MeterProvider); ok {
		if err := mp.Shutdown(ctx); err != nil {
			log.Printf("❌ Error shutting down meter provider: %v", err)
			return err
		}
	}

	log.Println("✅ MCP server shutdown complete")
	return nil
}

// HTTP Tracing Middleware Functions

// WithHTTPTracing wraps an HTTP client with OpenTelemetry instrumentation.
// This allows HTTP requests made from tool handlers to be automatically traced
// and appear as child spans of the tool execution.
//
// Usage in tool handlers:
//
//	client := last9mcp.WithHTTPTracing(&http.Client{Timeout: 10 * time.Second})
//	resp, err := client.Get("https://api.example.com/data")
func WithHTTPTracing(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{}
	}

	// Create a copy of the client to avoid modifying the original
	tracedClient := &http.Client{
		Transport:     otelhttp.NewTransport(client.Transport),
		CheckRedirect: client.CheckRedirect,
		Jar:           client.Jar,
		Timeout:       client.Timeout,
	}

	return tracedClient
}

// NewTracedHTTPClient creates a new HTTP client with OpenTelemetry tracing enabled.
// This is a convenience function for creating a fresh HTTP client with tracing.
//
// Usage in tool handlers:
//
//	client := last9mcp.NewTracedHTTPClient(30 * time.Second)
//	resp, err := client.Get("https://api.example.com/data")
func NewTracedHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: otelhttp.NewTransport(http.DefaultTransport),
		Timeout:   timeout,
	}
}

// WithHTTPTracingOptions wraps an HTTP client with OpenTelemetry instrumentation
// and allows customization of the tracing behavior through options.
//
// Usage in tool handlers:
//
//	  client := last9mcp.WithHTTPTracingOptions(&http.Client{},
//	      otelhttp.WithSpanNameFormatter(func(operation string, r *http.Request) string {
//	          return fmt.Sprintf("API Call: %s %s", r.Method, r.URL.Path)
//		  }),
//	  )
func WithHTTPTracingOptions(client *http.Client, opts ...otelhttp.Option) *http.Client {
	if client == nil {
		client = &http.Client{}
	}

	// Create a copy of the client to avoid modifying the original
	tracedClient := &http.Client{
		Transport:     otelhttp.NewTransport(client.Transport, opts...),
		CheckRedirect: client.CheckRedirect,
		Jar:           client.Jar,
		Timeout:       client.Timeout,
	}

	return tracedClient
}
