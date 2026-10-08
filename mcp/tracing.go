package mcp

import (
	"context"
	"log/slog"
	"sync"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/attribute"
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

// clientSession tracks per-client state: identity and activity.
type clientSession struct {
	info         ClientInfo
	lastActivity time.Time
	mu           sync.RWMutex

	// activeAttrs holds the attributes this session was counted under in
	// mcp.active.sessions, or nil if it was never counted. Keeping them lets
	// the decrement use exactly the attribute set of the original increment.
	activeAttrs []attribute.KeyValue

	// counted is closed once the session's increment has been recorded, so
	// its decrement can wait for it. It is nil for uncounted sessions.
	counted chan struct{}
}

// markCounted records that the session's increment in mcp.active.sessions
// has been made. It must be called exactly once for every counted session.
func (sess *clientSession) markCounted() {
	close(sess.counted)
}

// sessionStore manages session metadata for all connected clients.
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
	// Uncounted sessions (stateless clients) are left out: they keep
	// arriving after Shutdown's sweep, and waiting on them could starve.
	//
	// It has its own mutex, pendingMu, which is never held while calling
	// out of the store, so waitForRemovals cannot be held up by a caller
	// that is stuck while holding mu. removalsDone is signalled on pendingMu
	// when the count drops to zero.
	pendingMu       sync.Mutex
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

// create registers a new session and returns it. activeAttrs, when given,
// are the attributes the caller counts this session under in
// mcp.active.sessions; they are handed back through onRemove when the
// session is removed, and the caller must call markCounted once the
// increment has been recorded. create does not log, so callers can hold
// their own locks around it without calling into the application.
func (s *sessionStore) create(ctx context.Context, clientID string, info ClientInfo, activeAttrs ...attribute.KeyValue) *clientSession {
	sess := &clientSession{
		info:         info,
		lastActivity: time.Now(),
		activeAttrs:  activeAttrs,
	}
	if len(activeAttrs) > 0 {
		sess.counted = make(chan struct{})
	}
	s.mu.Lock()
	s.sessions[clientID] = sess
	s.mu.Unlock()
	return sess
}

// ensure creates a session when missing and refreshes last-activity otherwise.
func (s *sessionStore) ensure(clientID string, info ClientInfo) {
	s.mu.Lock()
	if sess, ok := s.sessions[clientID]; ok {
		sess.mu.Lock()
		sess.info = info
		sess.lastActivity = time.Now()
		sess.mu.Unlock()
		s.mu.Unlock()
		return
	}
	s.sessions[clientID] = &clientSession{
		info:         info,
		lastActivity: time.Now(),
	}
	s.mu.Unlock()

	// Log outside the lock: the handler is application code.
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

// forceRemove immediately removes a client session.
// It reports whether a session was removed.
func (s *sessionStore) forceRemove(ctx context.Context, clientID string) bool {
	s.mu.Lock()
	sess, ok := s.sessions[clientID]
	if ok {
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
// is about to run. The caller must hold s.mu, so the count is raised before
// anyone can observe the session as gone.
func (s *sessionStore) trackRemoval(sess *clientSession) {
	if len(sess.activeAttrs) == 0 {
		return
	}
	s.pendingMu.Lock()
	s.pendingRemovals++
	s.pendingMu.Unlock()
}

// notifyRemoved runs the onRemove callback for a session that has left the
// map. The caller must have passed it to trackRemoval while holding s.mu.
func (s *sessionStore) notifyRemoved(ctx context.Context, sess *clientSession) {
	defer func() {
		if len(sess.activeAttrs) == 0 {
			return
		}
		s.pendingMu.Lock()
		s.pendingRemovals--
		if s.pendingRemovals == 0 {
			s.removalsDoneCond().Broadcast()
		}
		s.pendingMu.Unlock()
	}()
	if s.onRemove != nil {
		s.onRemove(ctx, sess)
	}
}

// waitForRemovals blocks until every counted session already taken out of
// the store has finished its onRemove callback, or until ctx is done, in
// which case it returns ctx's error.
func (s *sessionStore) waitForRemovals(ctx context.Context) error {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()

	// Wake the wait below when ctx is done. Broadcasting under pendingMu
	// ensures the wakeup cannot fall between the ctx check and Wait.
	stop := context.AfterFunc(ctx, func() {
		s.pendingMu.Lock()
		s.removalsDoneCond().Broadcast()
		s.pendingMu.Unlock()
	})
	defer stop()

	for s.pendingRemovals > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		s.removalsDoneCond().Wait()
	}
	return nil
}

// removalsDoneCond returns removalsDone, creating it on first use. The
// caller must hold s.pendingMu.
func (s *sessionStore) removalsDoneCond() *sync.Cond {
	if s.removalsDone == nil {
		s.removalsDone = sync.NewCond(&s.pendingMu)
	}
	return s.removalsDone
}

func (s *sessionStore) cleanupStale(ctx context.Context) {
	now := time.Now()
	sessionCutoff := now.Add(-s.cfg.sessionTimeout)

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
		stale := sess.lastActivity.Before(sessionCutoff)
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
