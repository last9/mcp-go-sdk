package mcp

import (
	"context"
	"log/slog"
	"sync"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/attribute"
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

	// activeAttrs holds the attributes this session was counted under in
	// mcp.active.sessions, or nil if it was never counted. Keeping them lets
	// the decrement use exactly the attribute set of the original increment.
	activeAttrs []attribute.KeyValue
}

// sessionStore manages trace contexts and session metadata for all connected clients.
type sessionStore struct {
	sessions map[string]*clientSession
	mu       sync.RWMutex
	cleanup  *time.Ticker
	done     chan struct{}
	stopOnce sync.Once
	cfg      *config
	logger   *slog.Logger

	// onRemove, if set, is called once for every session that leaves the
	// store, whether through disconnect, shutdown, or the stale-session sweep.
	// It is called without any store locks held.
	onRemove func(ctx context.Context, sess *clientSession)

	// pendingRemovals counts sessions counted in mcp.active.sessions that
	// have left the map but whose onRemove callback has not finished yet.
	// It is guarded by mu, and removalsDone is signalled when it drops to
	// zero. Uncounted sessions (stateless clients) are left out: they keep
	// arriving after Shutdown's sweep, and waiting on them could starve.
	pendingRemovals int
	removalsDone    *sync.Cond
}

func newSessionStore(cfg *config, logger *slog.Logger, onRemove func(context.Context, *clientSession)) *sessionStore {
	s := &sessionStore{
		sessions: make(map[string]*clientSession),
		cleanup:  time.NewTicker(5 * time.Minute),
		done:     make(chan struct{}),
		cfg:      cfg,
		logger:   logger,
		onRemove: onRemove,
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

// stop halts the background cleanup goroutine. It is safe to call more than once.
func (s *sessionStore) stop() {
	s.stopOnce.Do(func() {
		s.cleanup.Stop()
		close(s.done)
	})
}

// create registers a new session. activeAttrs, when given, are the attributes
// the caller used to count this session in mcp.active.sessions; they are
// handed back through onRemove when the session is removed.
func (s *sessionStore) create(ctx context.Context, clientID string, info ClientInfo, activeAttrs ...attribute.KeyValue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[clientID] = &clientSession{
		info:          info,
		activeQueries: make(map[string]*storedQuery),
		lastActivity:  time.Now(),
		activeAttrs:   activeAttrs,
	}
	s.logger.InfoContext(ctx, "mcp session created",
		"client.id", clientID,
		"client.name", info.Name,
		"client.version", info.Version,
	)
}

// ensure creates a session when missing and refreshes last-activity otherwise.
func (s *sessionStore) ensure(clientID string, info ClientInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[clientID]; ok {
		sess.mu.Lock()
		sess.info = info
		sess.lastActivity = time.Now()
		sess.mu.Unlock()
		return
	}
	s.sessions[clientID] = &clientSession{
		info:          info,
		activeQueries: make(map[string]*storedQuery),
		lastActivity:  time.Now(),
	}
	s.logger.Info("mcp session created",
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
// It reports whether a session was removed.
func (s *sessionStore) forceRemove(ctx context.Context, clientID string) bool {
	s.mu.Lock()
	sess, ok := s.sessions[clientID]
	if ok {
		sess.mu.Lock()
		sess.activeQueries = make(map[string]*storedQuery)
		sess.mu.Unlock()
		delete(s.sessions, clientID)
		s.trackRemoval(sess)
	}
	s.mu.Unlock()

	if !ok {
		return false
	}
	s.logger.InfoContext(ctx, "mcp session removed", "client.id", clientID)
	s.notifyRemoved(ctx, sess)
	return true
}

// trackRemoval records that sess has left the map and its removal callback
// is about to run. The caller must hold s.mu.
func (s *sessionStore) trackRemoval(sess *clientSession) {
	if len(sess.activeAttrs) > 0 {
		s.pendingRemovals++
	}
}

// notifyRemoved runs the onRemove callback for a session that has left the
// map. The caller must have passed it to trackRemoval while holding s.mu.
func (s *sessionStore) notifyRemoved(ctx context.Context, sess *clientSession) {
	defer func() {
		if len(sess.activeAttrs) == 0 {
			return
		}
		s.mu.Lock()
		s.pendingRemovals--
		if s.pendingRemovals == 0 {
			s.removalsDoneCond().Broadcast()
		}
		s.mu.Unlock()
	}()
	if s.onRemove != nil {
		s.onRemove(ctx, sess)
	}
}

// waitForRemovals blocks until every counted session already taken out of
// the store has finished its onRemove callback.
func (s *sessionStore) waitForRemovals() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.pendingRemovals > 0 {
		s.removalsDoneCond().Wait()
	}
}

// removalsDoneCond returns removalsDone, creating it on first use. The
// caller must hold s.mu.
func (s *sessionStore) removalsDoneCond() *sync.Cond {
	if s.removalsDone == nil {
		s.removalsDone = sync.NewCond(&s.mu)
	}
	return s.removalsDone
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
			removed := s.sessions[clientID] == sess
			if removed {
				delete(s.sessions, clientID)
				s.trackRemoval(sess)
			}
			s.mu.Unlock()

			if removed {
				s.logger.DebugContext(ctx, "mcp stale session removed", "client.id", clientID)
				s.notifyRemoved(ctx, sess)
			}
		}
	}
}
