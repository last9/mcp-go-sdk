package mcp

import (
	"context"
	"sync"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// These tests are only meaningful under the race detector (go test -race),
// which is how CI runs the suite.

func TestServerTransport_SetWhileHandlingRequests(t *testing.T) {
	s, _ := testInfra(t)
	ctx := withTestClient(context.Background(), s, "c1", "cursor")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			s.NewStreamableHTTPHandler(nil)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_, _ = s.handleSimpleOp(ctx, noop, opToolsList, &sdkmcp.ListToolsRequest{})
		}
	}()
	wg.Wait()
}

// newUnmanagedServer returns a server whose Shutdown is left to the test.
func newUnmanagedServer(t *testing.T) *Last9MCPServer {
	t.Helper()
	s, err := NewServerWithOptions("test-server", "1.0.0", WithSkipProviderInit())
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}
	return s
}

// Shutdown may run before, during, or after Serve has started (for example
// from a signal handler). In every case Serve must return.
func TestShutdown_ConcurrentWithServe_StopsServe(t *testing.T) {
	s := newUnmanagedServer(t)

	_, serverTransport := sdkmcp.NewInMemoryTransports()
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = s.Serve(context.Background(), serverTransport)
	}()

	_ = s.Shutdown(context.Background())
	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after Shutdown")
	}
}

func TestShutdown_BeforeServe_StopsServe(t *testing.T) {
	s := newUnmanagedServer(t)
	_ = s.Shutdown(context.Background())

	_, serverTransport := sdkmcp.NewInMemoryTransports()
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = s.Serve(context.Background(), serverTransport)
	}()

	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return on a server that was already shut down")
	}
}
