package telemetry

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

// Metrics holds the custom metric instruments for the service.
var Metrics struct {
	InboundRequests  metric.Int64Counter
	OutboundProbes   metric.Int64Counter
	SessionsCreated  metric.Int64Counter
	HandshakeResults metric.Int64Counter
	InboundLatency   metric.Float64Histogram
	OutboundLatency  metric.Float64Histogram
	ActiveSessions   metric.Int64UpDownCounter
}

func init() {
	m := otel.Meter("mtls-sandbox")

	Metrics.InboundRequests, _ = m.Int64Counter("mtls.inbound.requests",
		metric.WithDescription("Total inbound mTLS requests"))

	Metrics.OutboundProbes, _ = m.Int64Counter("mtls.outbound.probes",
		metric.WithDescription("Total outbound session test probes"))

	Metrics.SessionsCreated, _ = m.Int64Counter("mtls.sessions.created",
		metric.WithDescription("Total sessions created"))

	Metrics.HandshakeResults, _ = m.Int64Counter("mtls.handshake.results",
		metric.WithDescription("TLS handshake pass/fail counts"))

	Metrics.InboundLatency, _ = m.Float64Histogram("mtls.inbound.latency_ms",
		metric.WithDescription("Inbound request latency in milliseconds"))

	Metrics.OutboundLatency, _ = m.Float64Histogram("mtls.outbound.latency_ms",
		metric.WithDescription("Outbound probe latency in milliseconds"))

	Metrics.ActiveSessions, _ = m.Int64UpDownCounter("mtls.sessions.active",
		metric.WithDescription("Number of active sessions"))
}
