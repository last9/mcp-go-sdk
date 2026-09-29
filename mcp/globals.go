package mcp

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// globalOwner tracks the providers registered as the OTel globals and the
// instances that depend on them.
var globalOwner struct {
	sync.Mutex

	// tp and mp belong to the server or client whose providers are the
	// globals, or are nil if none is.
	tp *sdktrace.TracerProvider
	mp *sdkmetric.MeterProvider

	// running holds the tracer provider of every server or client that
	// created its own providers and has not shut down yet.
	running map[*sdktrace.TracerProvider]struct{}

	// ownerStopped is set when the owner shut down while other instances
	// were still running. Its providers are then kept alive, because the
	// globals still point at them, until the last instance stops.
	ownerStopped bool
}

// registerGlobalProviders records a new running instance and makes tp and mp
// the OTel global providers, unless another server or client in this process
// registered its providers and they are still the globals. The first instance
// to start keeps the globals until every instance has shut down.
func registerGlobalProviders(tp *sdktrace.TracerProvider, mp *sdkmetric.MeterProvider) {
	globalOwner.Lock()
	defer globalOwner.Unlock()

	if globalOwner.running == nil {
		globalOwner.running = make(map[*sdktrace.TracerProvider]struct{})
	}
	globalOwner.running[tp] = struct{}{}

	if globalOwner.tp != nil && otel.GetTracerProvider() == trace.TracerProvider(globalOwner.tp) {
		return
	}
	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	globalOwner.tp, globalOwner.mp, globalOwner.ownerStopped = tp, mp, false
}

// releaseGlobalProviders records that the instance owning tp is shutting down.
// keep reports that tp is still serving as the global provider for other
// running instances, so the caller must flush its providers rather than shut
// them down. orphaned holds a previous owner's providers that the last running
// instance must now shut down.
func releaseGlobalProviders(tp *sdktrace.TracerProvider) (keep bool, orphaned []interface {
	Shutdown(context.Context) error
}) {
	globalOwner.Lock()
	defer globalOwner.Unlock()

	if _, ok := globalOwner.running[tp]; !ok {
		return false, nil
	}
	delete(globalOwner.running, tp)

	if tp == globalOwner.tp {
		if len(globalOwner.running) > 0 {
			globalOwner.ownerStopped = true
			return true, nil
		}
		globalOwner.tp, globalOwner.mp = nil, nil
		return false, nil
	}
	if len(globalOwner.running) == 0 && globalOwner.ownerStopped {
		orphaned = append(orphaned, globalOwner.tp, globalOwner.mp)
		globalOwner.tp, globalOwner.mp, globalOwner.ownerStopped = nil, nil, false
	}
	return false, orphaned
}

// shutdownProviders flushes and closes an instance's trace, metric and log
// providers. Providers that are still the OTel globals for other running
// instances are flushed but kept running; the last instance to stop shuts
// them down.
func shutdownProviders(ctx context.Context, tp *sdktrace.TracerProvider, mp *sdkmetric.MeterProvider, lp *sdklog.LoggerProvider) error {
	keep, orphaned := releaseGlobalProviders(tp)

	// Collect every error so a failure in one pipeline does not stop the
	// others from flushing.
	var errs []error
	if tp != nil {
		stop := tp.Shutdown
		if keep {
			stop = tp.ForceFlush
		}
		if err := stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("trace provider: %w", err))
		}
	}
	if mp != nil {
		stop := mp.Shutdown
		if keep {
			stop = mp.ForceFlush
		}
		if err := stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("metric provider: %w", err))
		}
	}
	if lp != nil {
		if err := lp.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("log provider: %w", err))
		}
	}
	for _, p := range orphaned {
		if err := p.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("global provider: %w", err))
		}
	}
	return errors.Join(errs...)
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
