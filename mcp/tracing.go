package mcp

import (
	"context"
	"log/slog"
	"sync"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/trace"
)

// contextKey is an unexported type for context keys in this package.
// Using a named integer type prevents collisions with keys from other packages
// that may also store values in context.
type contextKey int

const (
	contextKeyClientID   contextKey = iota
	contextKeyClientInfo contextKey = iota
)

// ClientInfo contains information about the connected MCP client.
type ClientInfo struct {
	Name         string
	Version      string
	Transport    string
	Capabilities sdkmcp.ClientCapabilities
}

// storedQuery holds a stored trace span context for an in-flight query.
type storedQuery struct {
	spanCtx  trace.SpanContext
	queryID  string
	lastUsed time.Time
}

// clientSession tracks per-client state: identity info and active query spans.
type clientSession struct {
	info          ClientInfo
	activeQueries map[string]*storedQuery
	lastActivity  time.Time
	mu            sync.RWMutex
}

// sessionStore manages trace contexts and session metadata for all connected clients.
type sessionStore struct {
	sessions map[string]*clientSession
	mu       sync.RWMutex
	cleanup  *time.Ticker
	done     chan struct{}
	cfg      *config
	logger   *slog.Logger
}

func newSessionStore(cfg *config, logger *slog.Logger) *sessionStore {
	s := &sessionStore{
		sessions: make(map[string]*clientSession),
		cleanup:  time.NewTicker(5 * time.Minute),
		done:     make(chan struct{}),
		cfg:      cfg,
		logger:   logger,
	}
	go s.runCleanup()
	return s
}

func (s *sessionStore) runCleanup() {
	ctx := context.Background()
	for {
		select {
		case <-s.cleanup.C:
			s.cleanupStale(ctx)
		case <-s.done:
			return
		}
	}
}

func (s *sessionStore) create(ctx context.Context, clientID string, info ClientInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[clientID] = &clientSession{
		info:          info,
		activeQueries: make(map[string]*storedQuery),
		lastActivity:  time.Now(),
	}
	s.logger.InfoContext(ctx, "mcp session created",
		"client.id", clientID,
		"client.name", info.Name,
		"client.version", info.Version,
	)
}

func (s *sessionStore) getInfo(clientID string) (ClientInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sess, ok := s.sessions[clientID]; ok {
		return sess.info, true
	}
	return ClientInfo{}, false
}

func (s *sessionStore) storeQuery(clientID, queryID string, spanCtx trace.SpanContext) {
	// Single lock acquisition eliminates the TOCTOU window where two concurrent
	// callers both see !exists and both create a session, with the second write
	// silently discarding any queries stored by the first.
	s.mu.Lock()
	sess, exists := s.sessions[clientID]
	if !exists {
		sess = &clientSession{
			activeQueries: make(map[string]*storedQuery),
			lastActivity:  time.Now(),
		}
		s.sessions[clientID] = sess
	}
	s.mu.Unlock()

	sess.mu.Lock()
	sess.activeQueries[queryID] = &storedQuery{
		spanCtx:  spanCtx,
		queryID:  queryID,
		lastUsed: time.Now(),
	}
	sess.lastActivity = time.Now()
	sess.mu.Unlock()
}

// latestQuery returns the most recently used active query context for a client.
func (s *sessionStore) latestQuery(clientID string) (trace.SpanContext, string, bool) {
	s.mu.RLock()
	sess, exists := s.sessions[clientID]
	s.mu.RUnlock()
	if !exists {
		return trace.SpanContext{}, "", false
	}

	// Write lock required: we mutate lastUsed and lastActivity on the found
	// entry. A read lock would allow concurrent mutations, causing a data race.
	sess.mu.Lock()
	defer sess.mu.Unlock()

	var latest *storedQuery
	var latestID string
	for id, q := range sess.activeQueries {
		if latest == nil || q.lastUsed.After(latest.lastUsed) {
			latest = q
			latestID = id
		}
	}
	if latest != nil {
		latest.lastUsed = time.Now()
		sess.lastActivity = time.Now()
		return latest.spanCtx, latestID, true
	}
	return trace.SpanContext{}, "", false
}

// endQuery marks all active queries for a client as complete and removes them.
func (s *sessionStore) endQuery(clientID string) bool {
	s.mu.RLock()
	sess, exists := s.sessions[clientID]
	s.mu.RUnlock()
	if !exists {
		return false
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()

	ended := len(sess.activeQueries) > 0
	for id := range sess.activeQueries {
		delete(sess.activeQueries, id)
	}
	if ended {
		sess.lastActivity = time.Now()
	}
	return ended
}

// allClientIDs returns all currently tracked client IDs.
func (s *sessionStore) allClientIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.sessions))
	for id := range s.sessions {
		ids = append(ids, id)
	}
	return ids
}

// forceRemove immediately removes a client session and all its queries.
func (s *sessionStore) forceRemove(ctx context.Context, clientID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[clientID]; ok {
		sess.mu.Lock()
		sess.activeQueries = make(map[string]*storedQuery)
		sess.mu.Unlock()
		delete(s.sessions, clientID)
		s.logger.InfoContext(ctx, "mcp session removed", "client.id", clientID)
	}
}

func (s *sessionStore) cleanupStale(ctx context.Context) {
	now := time.Now()
	sessionCutoff := now.Add(-s.cfg.sessionTimeout)
	queryCutoff := now.Add(-s.cfg.queryTimeout)

	// Snapshot IDs under a short read lock, then process each session
	// individually to avoid holding the global write lock for the entire sweep.
	s.mu.RLock()
	ids := make([]string, 0, len(s.sessions))
	for id := range s.sessions {
		ids = append(ids, id)
	}
	s.mu.RUnlock()

	for _, clientID := range ids {
		s.mu.RLock()
		sess, exists := s.sessions[clientID]
		s.mu.RUnlock()
		if !exists {
			continue
		}

		sess.mu.Lock()
		activeCount := 0
		for id, q := range sess.activeQueries {
			if q.lastUsed.Before(queryCutoff) {
				delete(sess.activeQueries, id)
				s.logger.DebugContext(ctx, "mcp stale query ended", "client.id", clientID, "query.id", id)
			} else {
				activeCount++
			}
		}
		stale := sess.lastActivity.Before(sessionCutoff) && activeCount == 0
		sess.mu.Unlock()

		if stale {
			s.mu.Lock()
			// Re-check that this is still the same session pointer before deleting.
			if s.sessions[clientID] == sess {
				delete(s.sessions, clientID)
				s.logger.DebugContext(ctx, "mcp stale session removed", "client.id", clientID)
			}
			s.mu.Unlock()
		}
	}
}
