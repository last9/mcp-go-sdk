package mcp

import (
	"context"
	"testing"
)

// Shutdown is commonly called from both a defer and a signal handler, so it
// must tolerate being invoked more than once.
func TestShutdown_CalledTwice_DoesNotPanic(t *testing.T) {
	s, _ := testInfra(t)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("second Shutdown panicked: %v", r)
		}
	}()

	_ = s.Shutdown(context.Background())
	_ = s.Shutdown(context.Background())
}
