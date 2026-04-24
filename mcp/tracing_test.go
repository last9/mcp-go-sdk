package mcp

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// newTestStore builds a sessionStore without starting the cleanup goroutine,
// which prevents goroutine leaks in short-lived unit tests.
func newTestStore(t *testing.T) *sessionStore {
	t.Helper()
	cfg := defaultConfig()
	return &sessionStore{
		sessions: make(map[string]*clientSession),
		cleanup:  time.NewTicker(time.Hour), // long interval — won't fire during tests
		cfg:      cfg,
		logger:   slog.Default(),
	}
}

func TestSessionStore_CreateAndGetInfo(t *testing.T) {
	s := newTestStore(t)
	info := ClientInfo{Name: "claude", Version: "3.0", Transport: "stdio"}
	s.create(context.Background(), "c1", info)

	got, ok := s.getInfo("c1")
	if !ok {
		t.Fatal("expected session to exist")
	}
	if got.Name != info.Name {
		t.Errorf("name: got %q, want %q", got.Name, info.Name)
	}
	if got.Version != info.Version {
		t.Errorf("version: got %q, want %q", got.Version, info.Version)
	}
}

func TestSessionStore_GetInfo_Missing(t *testing.T) {
	s := newTestStore(t)
	_, ok := s.getInfo("nonexistent")
	if ok {
		t.Error("expected getInfo to return false for unknown client")
	}
}

func TestSessionStore_StoreAndRetrieveQuery(t *testing.T) {
	s := newTestStore(t)
	s.create(context.Background(), "c1", ClientInfo{Name: "test"})

	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SpanID:     trace.SpanID{1, 2, 3, 4, 5, 6, 7, 8},
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})

	s.storeQuery("c1", "q1", sc)

	got, id, ok := s.latestQuery("c1")
	if !ok {
		t.Fatal("expected latestQuery to return true")
	}
	if id != "q1" {
		t.Errorf("queryID: got %q, want %q", id, "q1")
	}
	if got.TraceID() != sc.TraceID() {
		t.Errorf("traceID mismatch: got %v, want %v", got.TraceID(), sc.TraceID())
	}
}

func TestSessionStore_LatestQuery_NoSession(t *testing.T) {
	s := newTestStore(t)
	_, _, ok := s.latestQuery("nonexistent")
	if ok {
		t.Error("expected latestQuery to return false for unknown client")
	}
}

func TestSessionStore_LatestQuery_NoQueries(t *testing.T) {
	s := newTestStore(t)
	s.create(context.Background(), "c1", ClientInfo{Name: "test"})
	_, _, ok := s.latestQuery("c1")
	if ok {
		t.Error("expected latestQuery to return false when no queries stored")
	}
}

func TestSessionStore_LatestQuery_ReturnsNewest(t *testing.T) {
	s := newTestStore(t)
	s.create(context.Background(), "c1", ClientInfo{Name: "test"})

	old := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1},
		SpanID:     trace.SpanID{1},
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
	newer := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{2},
		SpanID:     trace.SpanID{2},
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})

	// Store older first, then newer — latestQuery should return the newer one.
	s.storeQuery("c1", "q-old", old)
	time.Sleep(time.Millisecond) // ensure lastUsed differs
	s.storeQuery("c1", "q-new", newer)

	_, id, ok := s.latestQuery("c1")
	if !ok {
		t.Fatal("expected latestQuery to return true")
	}
	if id != "q-new" {
		t.Errorf("got %q, want %q", id, "q-new")
	}
}

func TestSessionStore_EndQuery_ClearsActive(t *testing.T) {
	s := newTestStore(t)
	s.create(context.Background(), "c1", ClientInfo{Name: "test"})

	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1},
		SpanID:     trace.SpanID{1},
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
	s.storeQuery("c1", "q1", sc)

	if ended := s.endQuery("c1"); !ended {
		t.Error("expected endQuery to return true")
	}

	_, _, ok := s.latestQuery("c1")
	if ok {
		t.Error("expected no active queries after endQuery")
	}
}

func TestSessionStore_EndQuery_MissingSession(t *testing.T) {
	s := newTestStore(t)
	if ended := s.endQuery("nonexistent"); ended {
		t.Error("expected endQuery to return false for unknown client")
	}
}

func TestSessionStore_ForceRemove(t *testing.T) {
	s := newTestStore(t)
	s.create(context.Background(), "c1", ClientInfo{Name: "test"})
	s.forceRemove(context.Background(), "c1")

	_, ok := s.getInfo("c1")
	if ok {
		t.Error("expected session to be gone after forceRemove")
	}
}

func TestSessionStore_ForceRemove_NoOp(t *testing.T) {
	s := newTestStore(t)
	// Should not panic on unknown client
	s.forceRemove(context.Background(), "nonexistent")
}

func TestSessionStore_AllClientIDs(t *testing.T) {
	s := newTestStore(t)
	s.create(context.Background(), "c1", ClientInfo{Name: "a"})
	s.create(context.Background(), "c2", ClientInfo{Name: "b"})

	ids := s.allClientIDs()
	if len(ids) != 2 {
		t.Errorf("got %d IDs, want 2", len(ids))
	}
	seen := map[string]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	if !seen["c1"] || !seen["c2"] {
		t.Errorf("missing IDs: %v", ids)
	}
}

func TestSessionStore_StoreQuery_AutoCreatesSession(t *testing.T) {
	s := newTestStore(t)
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1},
		SpanID:     trace.SpanID{1},
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})

	// Store query without calling create first — storeQuery must auto-create.
	s.storeQuery("auto-client", "q1", sc)

	_, _, ok := s.latestQuery("auto-client")
	if !ok {
		t.Error("expected storeQuery to auto-create the session")
	}
}

func TestSessionStore_CleanupStale_RemovesExpiredSessions(t *testing.T) {
	s := newTestStore(t)
	// Session timeout of 1ms so any session is immediately stale.
	s.cfg = &config{
		sessionTimeout: time.Millisecond,
		queryTimeout:   time.Millisecond,
	}
	s.create(context.Background(), "stale-client", ClientInfo{Name: "stale"})

	time.Sleep(5 * time.Millisecond) // ensure past timeout
	s.cleanupStale()

	_, ok := s.getInfo("stale-client")
	if ok {
		t.Error("expected stale session to be removed by cleanupStale")
	}
}

func TestSessionStore_CleanupStale_KeepsActiveSession(t *testing.T) {
	s := newTestStore(t)
	// Very short timeout, but we'll store a query to keep it active.
	s.cfg = &config{
		sessionTimeout: time.Millisecond,
		queryTimeout:   time.Hour, // query not expired
	}
	s.create(context.Background(), "active-client", ClientInfo{Name: "active"})
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1},
		SpanID:     trace.SpanID{1},
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
	s.storeQuery("active-client", "q1", sc)

	time.Sleep(5 * time.Millisecond)
	s.cleanupStale() // session lastActivity is old but has an active query

	_, ok := s.getInfo("active-client")
	if !ok {
		t.Error("expected active-query session to survive cleanup")
	}
}

func TestSessionStore_StoreQuery_ConcurrentSafe(t *testing.T) {
	s := newTestStore(t)
	s.create(context.Background(), "c1", ClientInfo{Name: "test"})

	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1},
		SpanID:     trace.SpanID{1},
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s.storeQuery("c1", string(rune('a'+i%26)), sc)
		}(i)
	}
	wg.Wait()
}

func TestSessionStore_LatestQuery_ConcurrentSafe(t *testing.T) {
	s := newTestStore(t)
	s.create(context.Background(), "c1", ClientInfo{Name: "test"})

	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1},
		SpanID:     trace.SpanID{1},
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
	s.storeQuery("c1", "q1", sc)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.latestQuery("c1")
		}()
	}
	wg.Wait()
}
