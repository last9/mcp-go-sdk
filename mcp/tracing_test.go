package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
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

func TestSessionStore_CleanupStale_RemovesExpiredSessions(t *testing.T) {
	s := newTestStore(t)
	// Session timeout of 1ms so any session is immediately stale.
	s.cfg = &config{
		sessionTimeout: time.Millisecond,
	}
	s.create(context.Background(), "stale-client", ClientInfo{Name: "stale"})

	time.Sleep(5 * time.Millisecond) // ensure past timeout
	s.cleanupStale(context.Background())

	_, ok := s.getInfo("stale-client")
	if ok {
		t.Error("expected stale session to be removed by cleanupStale")
	}
}

// Stateless requests keep creating and removing uncounted sessions while
// Shutdown waits for in-flight removals. Those removals must not block the
// wait or interfere with it.
func TestSessionStore_UncountedRemovalsWhileWaitingForRemovals(t *testing.T) {
	s := newTestStore(t)
	s.onRemove = func(context.Context, *clientSession) { time.Sleep(time.Microsecond) }

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				id := fmt.Sprintf("w%d-c%d", w, i)
				s.create(context.Background(), id, ClientInfo{Name: "anon"})
				s.forceRemove(context.Background(), id)
			}
		}(w)
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if err := s.waitForRemovals(context.Background()); err != nil {
			t.Fatalf("waitForRemovals: %v", err)
		}
	}
	close(stop)
	wg.Wait()
}

// A counted removal that starts while waitForRemovals is already blocked on
// another one must be waited for too, and the wait must end once both finish.
func TestSessionStore_WaitForRemovalsCoversRemovalsStartedDuringWait(t *testing.T) {
	s := newTestStore(t)
	counted := attribute.String("mcp.client.name", "cursor")
	s.create(context.Background(), "a", ClientInfo{Name: "a"}, counted)
	s.create(context.Background(), "b", ClientInfo{Name: "b"}, counted)

	started := make(chan string, 2)
	release := map[string]chan struct{}{"a": make(chan struct{}), "b": make(chan struct{})}
	s.onRemove = func(_ context.Context, sess *clientSession) {
		started <- sess.info.Name
		<-release[sess.info.Name]
	}

	go s.forceRemove(context.Background(), "a")
	<-started

	waited := make(chan error, 1)
	go func() { waited <- s.waitForRemovals(context.Background()) }()

	// Start the second removal while the wait is blocked on the first.
	time.Sleep(20 * time.Millisecond)
	go s.forceRemove(context.Background(), "b")
	<-started

	close(release["a"])
	select {
	case <-waited:
		t.Fatal("waitForRemovals returned while a removal was still in flight")
	case <-time.After(50 * time.Millisecond):
	}

	close(release["b"])
	select {
	case err := <-waited:
		if err != nil {
			t.Fatalf("waitForRemovals: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waitForRemovals did not return after every removal finished")
	}
}
