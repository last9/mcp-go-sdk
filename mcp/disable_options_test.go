package mcp

import (
	"context"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

type disabledCase struct {
	name   string
	opt    Option
	method string
	req    sdkmcp.Request
}

func disabledCases() []disabledCase {
	return []disabledCase{
		{"resources/read", WithDisableResources(), opResourcesRead,
			&sdkmcp.ReadResourceRequest{Params: &sdkmcp.ReadResourceParams{URI: "file:///data.txt"}}},
		{"resources/list", WithDisableResources(), opResourcesList,
			&sdkmcp.ListResourcesRequest{Params: &sdkmcp.ListResourcesParams{}}},
		{"resources/templates/list", WithDisableResources(), "resources/templates/list",
			&sdkmcp.ListResourceTemplatesRequest{Params: &sdkmcp.ListResourceTemplatesParams{}}},
		{"prompts/get", WithDisablePrompts(), opPromptsGet,
			&sdkmcp.GetPromptRequest{Params: &sdkmcp.GetPromptParams{Name: "summarise"}}},
		{"prompts/list", WithDisablePrompts(), opPromptsList,
			&sdkmcp.ListPromptsRequest{Params: &sdkmcp.ListPromptsParams{}}},
		{"sampling/createMessage", WithDisableSampling(), opSamplingCreate,
			&sdkmcp.CreateMessageRequest{Params: &sdkmcp.CreateMessageParams{}}},
	}
}

func TestServerMiddleware_DisabledOperationsAreNotInstrumented(t *testing.T) {
	for _, tc := range disabledCases() {
		t.Run(tc.name, func(t *testing.T) {
			exp := installTestProviders(t)
			s, err := NewServerWithOptions("test-server", "1.0.0", WithSkipProviderInit(), tc.opt)
			if err != nil {
				t.Fatalf("NewServerWithOptions: %v", err)
			}
			t.Cleanup(func() { _ = s.Shutdown(context.Background()) })

			called := false
			next := func(ctx context.Context, method string, req sdkmcp.Request) (sdkmcp.Result, error) {
				called = true
				return noop(ctx, method, req)
			}
			if _, err := s.requestMiddleware(next)(context.Background(), tc.method, tc.req); err != nil {
				t.Fatalf("middleware: %v", err)
			}

			if !called {
				t.Fatal("next handler was not called")
			}
			if spans := exp.GetSpans(); len(spans) != 0 {
				t.Errorf("expected no spans for disabled %s, got %v", tc.method, spanNames(spans))
			}
		})
	}
}

func TestClientMiddleware_DisabledOperationsAreNotInstrumented(t *testing.T) {
	for _, tc := range disabledCases() {
		t.Run(tc.name, func(t *testing.T) {
			exp := installTestProviders(t)
			c, err := NewClientWithOptions("test-client", "1.0.0", WithSkipProviderInit(), tc.opt)
			if err != nil {
				t.Fatalf("NewClientWithOptions: %v", err)
			}

			called := false
			next := func(ctx context.Context, method string, req sdkmcp.Request) (sdkmcp.Result, error) {
				called = true
				return noop(ctx, method, req)
			}
			if _, err := c.clientMiddleware(next)(context.Background(), tc.method, tc.req); err != nil {
				t.Fatalf("middleware: %v", err)
			}

			if !called {
				t.Fatal("next handler was not called")
			}
			if spans := exp.GetSpans(); len(spans) != 0 {
				t.Errorf("expected no spans for disabled %s, got %v", tc.method, spanNames(spans))
			}
		})
	}
}
