package mcp

import (
	"log/slog"
	"time"
)

// config holds server observability configuration populated by Option funcs.
type config struct {
	// Capture controls — disable these in PII-sensitive environments.
	captureToolArgs     bool
	captureResourceBody bool
	capturePromptArgs   bool
	captureSamplingArgs bool

	// Feature toggles for operation families.
	instrumentResources bool
	instrumentPrompts   bool
	instrumentSampling  bool

	// Session and query lifecycle timeouts.
	sessionTimeout time.Duration
	queryTimeout   time.Duration

	// Minimum log severity emitted to the OTel log pipeline.
	logLevel slog.Level

	// skipOTelInit prevents NewServer from calling otel.SetTracerProvider /
	// otel.SetMeterProvider. Use this when the host application already
	// configures its own OTel providers — the server will use whatever global
	// providers are already registered.
	skipOTelInit bool
}

func defaultConfig() *config {
	return &config{
		captureToolArgs:     true,
		captureResourceBody: true,
		capturePromptArgs:   true,
		captureSamplingArgs: true,
		instrumentResources: true,
		instrumentPrompts:   true,
		instrumentSampling:  true,
		sessionTimeout:      30 * time.Minute,
		queryTimeout:        10 * time.Minute,
		logLevel:            slog.LevelInfo,
	}
}

// Option configures observability behaviour for a Last9MCPServer.
type Option func(*config)

// WithDisableArgCapture disables recording tool arguments as span attributes.
// Use this in environments where tool arguments may contain PII.
func WithDisableArgCapture() Option {
	return func(c *config) { c.captureToolArgs = false }
}

// WithDisableResourceCapture disables recording resource URI/name in spans.
func WithDisableResourceCapture() Option {
	return func(c *config) { c.captureResourceBody = false }
}

// WithDisablePromptCapture disables recording prompt names and arguments in spans.
func WithDisablePromptCapture() Option {
	return func(c *config) { c.capturePromptArgs = false }
}

// WithDisableSamplingCapture disables recording sampling message content in spans.
func WithDisableSamplingCapture() Option {
	return func(c *config) { c.captureSamplingArgs = false }
}

// WithSessionTimeout sets how long an idle client session is retained before
// automatic cleanup. Default: 30 minutes.
func WithSessionTimeout(d time.Duration) Option {
	return func(c *config) { c.sessionTimeout = d }
}

// WithQueryTimeout sets how long an inactive query span context is retained.
// Default: 10 minutes.
func WithQueryTimeout(d time.Duration) Option {
	return func(c *config) { c.queryTimeout = d }
}

// WithLogLevel sets the minimum severity for log records exported to the OTel
// log pipeline. Default: slog.LevelInfo.
func WithLogLevel(level slog.Level) Option {
	return func(c *config) { c.logLevel = level }
}

// WithDisableResources disables span and metric instrumentation for all
// resources/* operations.
func WithDisableResources() Option {
	return func(c *config) { c.instrumentResources = false }
}

// WithDisablePrompts disables span and metric instrumentation for all
// prompts/* operations.
func WithDisablePrompts() Option {
	return func(c *config) { c.instrumentPrompts = false }
}

// WithDisableSampling disables span and metric instrumentation for
// sampling/createMessage operations.
func WithDisableSampling() Option {
	return func(c *config) { c.instrumentSampling = false }
}

// WithSkipProviderInit prevents NewServer from initialising and registering
// global OTel trace/metric/log providers. Use this when your application
// already configures its own OTel pipeline — the SDK will obtain tracers and
// meters from whatever providers are already globally registered.
func WithSkipProviderInit() Option {
	return func(c *config) { c.skipOTelInit = true }
}
