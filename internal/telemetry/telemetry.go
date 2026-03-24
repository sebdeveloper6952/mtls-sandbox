package telemetry

import (
	"context"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
)

// Init bootstraps OpenTelemetry tracing and metrics. When
// OTEL_EXPORTER_OTLP_ENDPOINT is not set the global providers remain no-ops
// and the returned shutdown function is a no-op.
func Init(ctx context.Context, version string) (shutdown func(context.Context) error, err error) {
	noop := func(context.Context) error { return nil }

	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" {
		return noop, nil
	}

	env := os.Getenv("MTLS_ENVIRONMENT")
	if env == "" {
		env = "development"
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			attribute.String("service.name", "mtls-sandbox"),
			attribute.String("service.version", version),
			attribute.String("deployment.environment.name", env),
		),
	)
	if err != nil {
		return noop, err
	}

	// Trace exporter.
	traceExp, err := otlptracehttp.New(ctx)
	if err != nil {
		return noop, err
	}
	tp := trace.NewTracerProvider(
		trace.WithBatcher(traceExp),
		trace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	// Metric exporter.
	metricExp, err := otlpmetrichttp.New(ctx)
	if err != nil {
		_ = tp.Shutdown(ctx)
		return noop, err
	}
	mp := metric.NewMeterProvider(
		metric.WithReader(metric.NewPeriodicReader(metricExp)),
		metric.WithResource(res),
	)
	otel.SetMeterProvider(mp)

	return func(ctx context.Context) error {
		tErr := tp.Shutdown(ctx)
		mErr := mp.Shutdown(ctx)
		if tErr != nil {
			return tErr
		}
		return mErr
	}, nil
}
