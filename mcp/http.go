package mcp

import (
	"net/http"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// WithHTTPTracing wraps an HTTP client with OpenTelemetry instrumentation so
// that outbound requests made inside tool handlers appear as child spans of the
// active tool span.
//
//	client := last9mcp.WithHTTPTracing(&http.Client{Timeout: 10 * time.Second})
//	resp, err := client.Get("https://api.example.com/data")
func WithHTTPTracing(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{}
	}
	return &http.Client{
		Transport:     otelhttp.NewTransport(client.Transport),
		CheckRedirect: client.CheckRedirect,
		Jar:           client.Jar,
		Timeout:       client.Timeout,
	}
}

// NewTracedHTTPClient creates a new HTTP client with OTel tracing enabled.
//
//	client := last9mcp.NewTracedHTTPClient(30 * time.Second)
func NewTracedHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: otelhttp.NewTransport(http.DefaultTransport),
		Timeout:   timeout,
	}
}

// WithHTTPTracingOptions wraps an HTTP client with OTel instrumentation and
// allows customisation of the tracing behaviour through otelhttp.Option values.
//
//	client := last9mcp.WithHTTPTracingOptions(&http.Client{},
//	    otelhttp.WithSpanNameFormatter(func(op string, r *http.Request) string {
//	        return fmt.Sprintf("API Call: %s %s", r.Method, r.URL.Path)
//	    }),
//	)
func WithHTTPTracingOptions(client *http.Client, opts ...otelhttp.Option) *http.Client {
	if client == nil {
		client = &http.Client{}
	}
	return &http.Client{
		Transport:     otelhttp.NewTransport(client.Transport, opts...),
		CheckRedirect: client.CheckRedirect,
		Jar:           client.Jar,
		Timeout:       client.Timeout,
	}
}
