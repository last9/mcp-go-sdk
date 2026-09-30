package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// finalizeSpan sets the canonical span status and mcp.operation.status attribute.
// Used by every handler except tools/call, which inspects CallToolResult.IsError.
func finalizeSpan(span trace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(keyMCPOperationStatus.String(statusError))
	} else {
		span.SetStatus(codes.Ok, "")
		span.SetAttributes(keyMCPOperationStatus.String(statusSuccess))
	}
}

// requestMiddleware is the single receiving middleware registered on the MCP
// server. It dispatches each method to an operation-specific handler that
// creates the correct span, records metrics, and emits structured log records.
func (s *Last9MCPServer) requestMiddleware(next sdkmcp.MethodHandler) sdkmcp.MethodHandler {
	return func(ctx context.Context, method string, req sdkmcp.Request) (sdkmcp.Result, error) {
		// initialize is special: it sets up the client session before any
		// telemetry so subsequent operations have access to client identity.
		if method == opInitialize {
			return s.handleInitialize(ctx, next, req)
		}
		if method == opServerDiscover {
			return s.handleServerDiscover(ctx, next, req)
		}

		// Attach client identity to context for downstream handlers.
		ctx = s.attachClientContext(ctx, req)
		defer s.removeUnattributedSession(clientInfoFromCtx(ctx, s), clientIDFromCtx(ctx))

		if !s.cfg.instrumented(method) {
			return next(ctx, method, req)
		}

		switch method {
		case opToolsCall:
			return s.handleToolsCall(ctx, next, req)
		case opResourcesRead:
			return s.handleResourcesRead(ctx, next, req)
		case opPromptsGet:
			return s.handlePromptsGet(ctx, next, req)
		case opSamplingCreate:
			return s.handleSamplingCreate(ctx, next, req)
		case opToolsList:
			// tools/list signals the end of a query cycle.
			result, err := s.handleSimpleOp(ctx, next, method, req)
			clientID := clientIDFromCtx(ctx)
			if s.sessions.endQuery(clientID) {
				info, _ := s.sessions.getInfo(clientID)
				s.logger.InfoContext(ctx, "mcp query ended (tools/list)",
					"client.name", info.Name,
					"client.id", clientID,
				)
			}
			return result, err
		}

		// Fallthrough: instrument generically (ping, completion/complete, etc.)
		return s.handleSimpleOp(ctx, next, method, req)
	}
}

// handleInitialize processes the initialize handshake, creates a client session,
// and emits the session-created metric increment.
func (s *Last9MCPServer) handleInitialize(ctx context.Context, next sdkmcp.MethodHandler, req sdkmcp.Request) (sdkmcp.Result, error) {
	info := s.extractClientInfo(req)
	clientID := s.generateClientID(info)
	if sid := sessionID(req); sid != "" {
		clientID = sessionClientID(info, sid)
	}

	ctx = context.WithValue(ctx, contextKeyClientID, clientID)
	ctx = context.WithValue(ctx, contextKeyClientInfo, info)

	// currentClientID is only reliable for stdio, which has one client at a
	// time. For HTTP/SSE transports multiple clients connect concurrently and
	// the field would be overwritten by whichever initialize arrives last.
	if s.transport() == "stdio" {
		s.mu.Lock()
		s.currentClientID = clientID
		s.mu.Unlock()
	}

	// Start span before creating the session so that the session-created log
	// and the client-connected log both carry the active trace/span ID.
	ctx, span := s.tracer.Start(ctx, spanName(opInitialize),
		trace.WithAttributes(
			keyGenAISystem.String(genAISystem),
			keyGenAIOperationName.String(opInitialize),
			keyMCPServerName.String(s.serverName),
			keyMCPServerVersion.String(s.serverVersion),
			keyMCPClientName.String(info.Name),
			keyMCPClientVersion.String(info.Version),
			keyMCPClientID.String(clientID),
		),
	)
	defer span.End()

	s.registerSession(ctx, clientID, info)

	// Release the session when its connection closes. This is the only
	// disconnect signal for Streamable HTTP, where Serve is never called.
	// Watch every connection, including ones that initialize after Shutdown
	// and so are not counted: their later requests still store a session,
	// and removal is idempotent.
	if ss, ok := req.GetSession().(*sdkmcp.ServerSession); ok && ss != nil {
		go func() {
			_ = ss.Wait()
			s.handleClientDisconnect(clientID)
		}()
	}

	s.logger.InfoContext(ctx, "mcp client connected",
		"client.id", clientID,
		"client.name", info.Name,
		"client.version", info.Version,
	)

	return next(ctx, opInitialize, req)
}

// registerSession stores a newly initialized session and counts it in
// mcp.active.sessions. Shutdown closes registration before its final
// session sweep, so a session is either counted before the sweep (and
// released by it) or, once Shutdown has begun, not registered at all.
func (s *Last9MCPServer) registerSession(ctx context.Context, clientID string, info ClientInfo) {
	activeAttrs := []attribute.KeyValue{
		keyMCPServerTransport.String(s.transport()),
		keyMCPClientName.String(info.Name),
	}

	// Only the in-memory registration happens under the lock, so Shutdown
	// can always take it. Logging and the increment run application code
	// and happen after it is released; the session's decrement waits for
	// the increment, so the gauge never dips below zero.
	s.lifecycleMu.Lock()
	if s.closed {
		s.lifecycleMu.Unlock()
		return
	}
	sess := s.sessions.create(ctx, clientID, info, activeAttrs...)
	s.lifecycleMu.Unlock()

	s.logger.InfoContext(ctx, "mcp session created",
		"client.id", clientID,
		"client.name", info.Name,
		"client.version", info.Version,
	)
	s.inst.activeSessions.Add(ctx, 1, metric.WithAttributes(activeAttrs...))
	sess.markCounted()
}

// handleServerDiscover instruments the 2026-07-28 discover RPC and registers
// the client session from per-request _meta (there is no initialize handshake).
func (s *Last9MCPServer) handleServerDiscover(ctx context.Context, next sdkmcp.MethodHandler, req sdkmcp.Request) (sdkmcp.Result, error) {
	info := s.clientInfoFromRequest(req)
	clientID := s.stableClientID(info)
	s.sessions.ensure(clientID, info)
	defer s.removeUnattributedSession(info, clientID)

	ctx = context.WithValue(ctx, contextKeyClientID, clientID)
	ctx = context.WithValue(ctx, contextKeyClientInfo, info)

	ctx, span := s.tracer.Start(ctx, spanName(opServerDiscover),
		trace.WithAttributes(
			keyGenAISystem.String(genAISystem),
			keyGenAIOperationName.String(opServerDiscover),
			keyMCPServerName.String(s.serverName),
			keyMCPServerVersion.String(s.serverVersion),
			keyMCPClientName.String(info.Name),
			keyMCPClientVersion.String(info.Version),
			keyMCPClientID.String(clientID),
		),
	)
	defer span.End()

	s.logger.InfoContext(ctx, "mcp client discovered",
		"client.id", clientID,
		"client.name", info.Name,
		"client.version", info.Version,
	)

	return next(ctx, opServerDiscover, req)
}

// handleToolsCall instruments a tools/call operation with full query correlation:
// the first tool call in a session starts a root query span; subsequent calls
// become child spans of that same query, enabling trace grouping across an
// LLM reasoning cycle.
func (s *Last9MCPServer) handleToolsCall(ctx context.Context, next sdkmcp.MethodHandler, req sdkmcp.Request) (sdkmcp.Result, error) {
	ctr, ok := req.(*sdkmcp.CallToolRequest)
	if !ok {
		return s.handleSimpleOp(ctx, next, opToolsCall, req)
	}

	toolName := ctr.Params.Name
	clientID := clientIDFromCtx(ctx)
	info := clientInfoFromCtx(ctx, s)

	baseSpanAttrs := []attribute.KeyValue{
		keyGenAISystem.String(genAISystem),
		keyGenAIOperationName.String(opToolsCall),
		keyGenAIToolName.String(toolName),
		keyMCPServerName.String(s.serverName),
		keyMCPServerTransport.String(s.transport()),
		keyMCPToolName.String(toolName),
		keyMCPClientName.String(info.Name),
		keyMCPClientID.String(clientID),
	}

	if parentCtx, queryID, exists := s.sessions.latestQuery(clientID); exists {
		// Continue existing query — make this span a child of the stored query root.
		ctx = trace.ContextWithSpanContext(ctx, parentCtx)
		baseSpanAttrs = append(baseSpanAttrs, keyMCPSessionID.String(queryID))
		s.logger.InfoContext(ctx, "mcp tool call (continued query)",
			"tool.name", toolName, "query.id", queryID, "client.name", info.Name)
	} else {
		// First tool call in a new query — create a root query span, store its
		// context, then immediately end it so only the tool span is active.
		queryID := fmt.Sprintf("query_%s_%d", clientID, time.Now().UnixNano())
		var querySpan trace.Span
		ctx, querySpan = s.tracer.Start(ctx, "mcp user_query",
			trace.WithAttributes(
				keyGenAISystem.String(genAISystem),
				keyMCPSessionID.String(queryID),
				keyMCPClientName.String(info.Name),
				keyMCPClientID.String(clientID),
				keyMCPServerName.String(s.serverName),
			),
		)
		s.sessions.storeQuery(clientID, queryID, querySpan.SpanContext())
		querySpan.End()

		baseSpanAttrs = append(baseSpanAttrs, keyMCPSessionID.String(queryID))
		s.logger.InfoContext(ctx, "mcp tool call (new query)",
			"tool.name", toolName, "query.id", queryID, "client.name", info.Name)
	}

	ctx, span := s.tracer.Start(ctx, toolSpanName(toolName),
		trace.WithAttributes(baseSpanAttrs...),
	)
	defer span.End()

	span.AddEvent("tool.invoked", trace.WithAttributes(keyMCPToolName.String(toolName)))

	start := time.Now()
	mAttrs := toolAttrs(toolName, s.transport(), info.Name)
	s.inst.toolCalls.Add(ctx, 1, metric.WithAttributes(mAttrs...))

	result, err := next(ctx, opToolsCall, req)
	duration := time.Since(start)

	s.inst.toolDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(mAttrs...))
	s.inst.requestDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(mAttrs[:4]...))

	if success, errType, errMsg := classifyToolResult(result, err); success {
		span.SetStatus(codes.Ok, "")
		span.SetAttributes(keyMCPOperationStatus.String(statusSuccess))
		span.AddEvent("result.received", trace.WithAttributes(
			keyMCPOperationStatus.String(statusSuccess),
		))
	} else {
		if err != nil {
			span.RecordError(err)
		}
		span.SetStatus(codes.Error, errMsg)
		span.SetAttributes(
			keyMCPOperationStatus.String(statusError),
			keyMCPErrorType.String(errType),
			keyMCPErrorMessage.String(errMsg),
		)
		span.AddEvent("error.occurred", trace.WithAttributes(
			keyMCPErrorType.String(errType),
			keyMCPErrorMessage.String(errMsg),
		))
		s.inst.toolErrors.Add(ctx, 1, metric.WithAttributes(
			append(mAttrs, keyMCPErrorType.String(errType))...,
		))
	}

	return result, err
}

// classifyToolResult decides whether a tools/call succeeded. A call fails if
// it returned an error (a system error) or a CallToolResult with IsError set
// (a user error, meaning the tool ran and reported a failure, whatever content
// it returned). errMsg is the error text, or the first text block of an
// IsError result, or empty if it has none.
func classifyToolResult(result sdkmcp.Result, err error) (success bool, errType, errMsg string) {
	if err != nil {
		return false, errTypeSystem, err.Error()
	}
	cr, ok := result.(*sdkmcp.CallToolResult)
	if !ok || cr == nil || !cr.IsError {
		return true, "", ""
	}
	for _, c := range cr.Content {
		if txt, ok := c.(*sdkmcp.TextContent); ok {
			return false, errTypeUser, txt.Text
		}
	}
	return false, errTypeUser, ""
}

// handleResourcesRead instruments a resources/read operation.
func (s *Last9MCPServer) handleResourcesRead(ctx context.Context, next sdkmcp.MethodHandler, req sdkmcp.Request) (sdkmcp.Result, error) {
	attrs := []attribute.KeyValue{
		keyGenAISystem.String(genAISystem),
		keyGenAIOperationName.String(opResourcesRead),
		keyMCPServerName.String(s.serverName),
		keyMCPServerTransport.String(s.transport()),
	}
	info := clientInfoFromCtx(ctx, s)
	attrs = append(attrs, keyMCPClientName.String(info.Name))

	if s.cfg.captureResourceBody {
		if rr, ok := req.(*sdkmcp.ReadResourceRequest); ok {
			attrs = append(attrs, keyMCPResourceURI.String(rr.Params.URI))
		}
	}

	ctx, span := s.tracer.Start(ctx, spanName(opResourcesRead), trace.WithAttributes(attrs...))
	defer span.End()

	span.AddEvent("resource.read.started")
	start := time.Now()
	mAttrs := baseAttrs(opResourcesRead, s.transport(), info.Name)

	result, err := next(ctx, opResourcesRead, req)
	duration := time.Since(start)

	s.inst.resourceReads.Add(ctx, 1, metric.WithAttributes(mAttrs...))
	s.inst.resourceDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(mAttrs...))
	s.inst.requestDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(mAttrs...))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(keyMCPOperationStatus.String(statusError), keyMCPErrorType.String(errTypeSystem))
	} else {
		span.SetStatus(codes.Ok, "")
		span.SetAttributes(keyMCPOperationStatus.String(statusSuccess))
		span.AddEvent("resource.read.completed")
	}
	return result, err
}

// handlePromptsGet instruments a prompts/get operation.
func (s *Last9MCPServer) handlePromptsGet(ctx context.Context, next sdkmcp.MethodHandler, req sdkmcp.Request) (sdkmcp.Result, error) {
	attrs := []attribute.KeyValue{
		keyGenAISystem.String(genAISystem),
		keyGenAIOperationName.String(opPromptsGet),
		keyMCPServerName.String(s.serverName),
		keyMCPServerTransport.String(s.transport()),
	}
	info := clientInfoFromCtx(ctx, s)
	attrs = append(attrs, keyMCPClientName.String(info.Name))

	promptName := ""
	if s.cfg.capturePromptArgs {
		if pr, ok := req.(*sdkmcp.GetPromptRequest); ok {
			promptName = pr.Params.Name
			attrs = append(attrs, keyMCPPromptName.String(promptName))
		}
	}

	sName := spanName(opPromptsGet)
	if promptName != "" {
		sName = promptGetSpanName(promptName)
	}

	ctx, span := s.tracer.Start(ctx, sName, trace.WithAttributes(attrs...))
	defer span.End()

	start := time.Now()
	mAttrs := promptAttrs(promptName, s.transport(), info.Name)

	result, err := next(ctx, opPromptsGet, req)
	duration := time.Since(start)

	s.inst.promptGets.Add(ctx, 1, metric.WithAttributes(mAttrs...))
	s.inst.promptDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(mAttrs...))
	s.inst.requestDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(mAttrs[:4]...))

	finalizeSpan(span, err)
	return result, err
}

// handleSamplingCreate instruments a sampling/createMessage operation.
func (s *Last9MCPServer) handleSamplingCreate(ctx context.Context, next sdkmcp.MethodHandler, req sdkmcp.Request) (sdkmcp.Result, error) {
	attrs := []attribute.KeyValue{
		keyGenAISystem.String(genAISystem),
		keyGenAIOperationName.String(opSamplingCreate),
		keyMCPServerName.String(s.serverName),
		keyMCPServerTransport.String(s.transport()),
	}
	info := clientInfoFromCtx(ctx, s)
	attrs = append(attrs, keyMCPClientName.String(info.Name))

	if s.cfg.captureSamplingArgs {
		if cr, ok := req.(*sdkmcp.CreateMessageRequest); ok && cr.Params.ModelPreferences != nil {
			if cr.Params.ModelPreferences.Hints != nil {
				for _, h := range cr.Params.ModelPreferences.Hints {
					if h.Name != "" {
						attrs = append(attrs, keyMCPSamplingModel.String(h.Name))
						attrs = append(attrs, keyGenAIRequestModel.String(h.Name))
						break
					}
				}
			}
		}
	}

	ctx, span := s.tracer.Start(ctx, spanName(opSamplingCreate), trace.WithAttributes(attrs...))
	defer span.End()

	start := time.Now()
	mAttrs := baseAttrs(opSamplingCreate, s.transport(), info.Name)

	result, err := next(ctx, opSamplingCreate, req)
	duration := time.Since(start)

	s.inst.samplingCreates.Add(ctx, 1, metric.WithAttributes(mAttrs...))
	s.inst.samplingDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(mAttrs...))
	s.inst.requestDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(mAttrs...))

	finalizeSpan(span, err)
	return result, err
}

// handleSimpleOp handles any MCP method that doesn't need special logic:
// it creates a single span, calls next, and records request duration.
func (s *Last9MCPServer) handleSimpleOp(ctx context.Context, next sdkmcp.MethodHandler, method string, req sdkmcp.Request) (sdkmcp.Result, error) {
	info := clientInfoFromCtx(ctx, s)
	ctx, span := s.tracer.Start(ctx, spanName(method),
		trace.WithAttributes(
			keyGenAISystem.String(genAISystem),
			keyGenAIOperationName.String(method),
			keyMCPServerName.String(s.serverName),
			keyMCPServerTransport.String(s.transport()),
			keyMCPClientName.String(info.Name),
		),
	)
	defer span.End()

	start := time.Now()
	result, err := next(ctx, method, req)
	duration := time.Since(start)

	s.inst.requestDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(
		baseAttrs(method, s.transport(), info.Name)...,
	))

	finalizeSpan(span, err)
	return result, err
}

// RegisterInstrumentedTool registers a typed tool handler wrapped with per-call
// instrumentation: argument capture, span attribute enrichment, and error classification.
func RegisterInstrumentedTool[In, Out any](server *Last9MCPServer, tool *sdkmcp.Tool, handler sdkmcp.ToolHandlerFor[In, Out]) error {
	sdkmcp.AddTool(server.Server, tool, instrumentHandler(server, handler))
	return nil
}

// instrumentHandler wraps a typed tool handler to enrich the active span with
// call arguments and record result/error state after execution.
func instrumentHandler[In, Out any](s *Last9MCPServer, original sdkmcp.ToolHandlerFor[In, Out]) func(ctx context.Context, req *sdkmcp.CallToolRequest, args In) (*sdkmcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *sdkmcp.CallToolRequest, args In) (*sdkmcp.CallToolResult, any, error) {
		span := trace.SpanFromContext(ctx)

		// Generate callID before invoking the handler so the timestamp reflects
		// invocation time, not completion time, enabling accurate correlation.
		callID := fmt.Sprintf("%s_%d", req.Params.Name, time.Now().UnixNano())
		span.SetAttributes(
			keyGenAIToolCallID.String(callID),
			keyMCPToolCallID.String(callID),
		)

		if s.cfg.captureToolArgs {
			addArgsToSpan(span, args)
		}

		return original(ctx, req, args)
	}
}

// addArgsToSpan marshals typed tool arguments into span attributes.
// Uses JSON round-trip to handle arbitrary struct types uniformly.
func addArgsToSpan(span trace.Span, args any) {
	if args == nil {
		return
	}

	defer func() {
		if r := recover(); r != nil {
			span.SetAttributes(attribute.String("mcp.args.error", "failed to capture args"))
		}
	}()

	b, err := json.Marshal(args)
	if err != nil {
		return
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return
	}

	span.SetAttributes(attribute.Int("mcp.arg.count", len(m)))
	for k, v := range m {
		span.SetAttributes(attribute.String("mcp.arg."+k, fmt.Sprintf("%v", v)))
	}
}

// attachClientContext extracts client identity from the request (_meta for
// 2026-07-28, initialize params for legacy) and attaches it to the context.
func (s *Last9MCPServer) attachClientContext(ctx context.Context, req sdkmcp.Request) context.Context {
	if id, ok := ctx.Value(contextKeyClientID).(string); ok && id != "" {
		if info, ok := ctx.Value(contextKeyClientInfo).(ClientInfo); ok && info.Name != "" {
			return ctx
		}
	}

	info := s.clientInfoFromRequest(req)
	clientID := s.resolveClientID(ctx, req, info)
	s.sessions.ensure(clientID, info)

	ctx = context.WithValue(ctx, contextKeyClientID, clientID)
	ctx = context.WithValue(ctx, contextKeyClientInfo, info)
	return ctx
}

// clientInfoFromRequest reads client identity from per-request _meta
// (2026-07-28) or legacy initialize params.
func (s *Last9MCPServer) clientInfoFromRequest(req sdkmcp.Request) ClientInfo {
	info := ClientInfo{Name: "unknown_client", Version: "unknown", Transport: s.transport()}

	if peer, ok := req.(interface {
		ClientInfo() *sdkmcp.Implementation
		ClientCapabilities() *sdkmcp.ClientCapabilities
	}); ok {
		if impl := peer.ClientInfo(); impl != nil {
			if impl.Name != "" {
				info.Name = impl.Name
			}
			if impl.Version != "" {
				info.Version = impl.Version
			}
		}
		if caps := peer.ClientCapabilities(); caps != nil {
			info.Capabilities = *caps
		}
	}

	if info.Name == "unknown_client" {
		if p, ok := req.GetParams().(*sdkmcp.InitializeParams); ok && p.ClientInfo.Name != "" {
			info.Name = p.ClientInfo.Name
			info.Version = p.ClientInfo.Version
			if p.Capabilities != nil {
				info.Capabilities = *p.Capabilities
			}
		}
	}

	return info
}

// extractClientInfo parses client identity for the legacy initialize handshake.
func (s *Last9MCPServer) extractClientInfo(req sdkmcp.Request) ClientInfo {
	return s.clientInfoFromRequest(req)
}

// generateClientID produces a unique client ID for a legacy initialize handshake.
func (s *Last9MCPServer) generateClientID(info ClientInfo) string {
	pid := os.Getpid()
	return fmt.Sprintf("%s_%s_%d_%d", info.Name, info.Transport, pid, time.Now().UnixNano())
}

// sessionID returns the MCP session ID of the connection req arrived on, or ""
// when the transport does not assign one (stdio, stateless HTTP).
func sessionID(req sdkmcp.Request) string {
	if req == nil {
		return ""
	}
	if ss, ok := req.GetSession().(*sdkmcp.ServerSession); ok && ss != nil {
		return ss.ID()
	}
	return ""
}

// sessionClientID returns the client ID for a client on MCP session sid.
// Initialize and every later request on that session resolve to the same ID,
// so clients that share a name and version stay distinct.
//
// The session ID itself is never used verbatim: clients present it on every
// request, so exporting it would let anyone with access to traces or logs
// send requests on the session. A truncated SHA-256 digest keeps the ID
// stable and unique per session without revealing the token.
func sessionClientID(info ClientInfo, sid string) string {
	sum := sha256.Sum256([]byte(sid))
	return fmt.Sprintf("%s_%s_%s", info.Name, info.Transport, hex.EncodeToString(sum[:8]))
}

// stableClientID returns a deterministic ID for stateless per-request clients
// that identify themselves via _meta on every call. Anonymous requests cannot
// be correlated safely, so each gets an isolated per-request ID instead of
// sharing the unknown_client session bucket.
func (s *Last9MCPServer) stableClientID(info ClientInfo) string {
	if info.Name == "unknown_client" {
		return fmt.Sprintf("unattributed_%s_%d_%d", info.Transport, os.Getpid(), s.anonymousSeq.Add(1))
	}
	return fmt.Sprintf("%s_%s_%s", info.Name, info.Version, info.Transport)
}

// removeUnattributedSession bounds per-request state for anonymous stateless
// clients. Without a stable identity their requests cannot be correlated, and
// retaining each isolated session until the normal timeout would grow memory
// with request volume.
func (s *Last9MCPServer) removeUnattributedSession(info ClientInfo, clientID string) {
	if info.Name != "unknown_client" || s.transport() == "stdio" || clientID == "" {
		return
	}
	s.sessions.forceRemove(context.Background(), clientID)
}

// resolveClientID picks the client ID for a non-initialize request.
func (s *Last9MCPServer) resolveClientID(ctx context.Context, req sdkmcp.Request, info ClientInfo) string {
	if id, ok := ctx.Value(contextKeyClientID).(string); ok && id != "" {
		return id
	}
	if sid := sessionID(req); sid != "" {
		return sessionClientID(info, sid)
	}
	if s.transport() == "stdio" {
		s.mu.RLock()
		id := s.currentClientID
		s.mu.RUnlock()
		if id != "" {
			return id
		}
	}
	return s.stableClientID(info)
}

// getCurrentClientID returns the client ID from context or falls back to the
// last known client (required for stdio where there is one client at a time).
func (s *Last9MCPServer) getCurrentClientID(ctx context.Context) string {
	if id, ok := ctx.Value(contextKeyClientID).(string); ok && id != "" {
		return id
	}
	// currentClientID is only a reliable fallback for stdio (single client).
	// For HTTP/SSE transports the field is stale — the last initialize wins —
	// so we return "unknown_client" rather than attributing the call to the
	// wrong session (M1).
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.transport() == "stdio" && s.currentClientID != "" {
		return s.currentClientID
	}
	return "unknown_client"
}

// clientIDFromCtx is a package-level helper for reading the client ID from ctx.
func clientIDFromCtx(ctx context.Context) string {
	if id, ok := ctx.Value(contextKeyClientID).(string); ok {
		return id
	}
	return ""
}

// clientInfoFromCtx returns the ClientInfo stored in ctx, falling back to the
// session store if the context value is missing.
func clientInfoFromCtx(ctx context.Context, s *Last9MCPServer) ClientInfo {
	if info, ok := ctx.Value(contextKeyClientInfo).(ClientInfo); ok {
		return info
	}
	clientID := clientIDFromCtx(ctx)
	if info, ok := s.sessions.getInfo(clientID); ok {
		return info
	}
	return ClientInfo{Name: "unknown_client", Version: "unknown"}
}
