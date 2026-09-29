package mcp

import (
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// globalOwner is the tracer provider of the server or client whose providers
// are currently registered as the OTel globals, or nil if none is.
var globalOwner struct {
	sync.Mutex
	tp *sdktrace.TracerProvider
}

// registerGlobalProviders makes tp and mp the OTel global providers, unless
// another server or client in this process registered its providers and they
// are still the globals. The first instance to start keeps the globals until
// it shuts down.
func registerGlobalProviders(tp *sdktrace.TracerProvider, mp *sdkmetric.MeterProvider) {
	globalOwner.Lock()
	defer globalOwner.Unlock()

	if globalOwner.tp != nil && otel.GetTracerProvider() == trace.TracerProvider(globalOwner.tp) {
		return
	}
	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	globalOwner.tp = tp
}

// releaseGlobalProviders gives up ownership of the globals if tp holds it, so
// the next server or client to start can register its own providers.
func releaseGlobalProviders(tp *sdktrace.TracerProvider) {
	globalOwner.Lock()
	defer globalOwner.Unlock()
	if tp != nil && globalOwner.tp == tp {
		globalOwner.tp = nil
	}
}

// instrumentationProviders returns the providers an instance should take its
// tracer and meter from: its own when it created them, otherwise the globals
// (with WithSkipProviderInit).
func instrumentationProviders(tp *sdktrace.TracerProvider, mp *sdkmetric.MeterProvider) (trace.TracerProvider, metric.MeterProvider) {
	if tp == nil || mp == nil {
		return otel.GetTracerProvider(), otel.GetMeterProvider()
	}
	return tp, mp
}
