package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"

	"github.com/sebdeveloper6952/mtls-sandbox/internal/inspector"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/store"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/telemetry"
)

type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rr *responseRecorder) WriteHeader(code int) {
	rr.statusCode = code
	rr.ResponseWriter.WriteHeader(code)
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rec, r)

		attrs := []slog.Attr{
			slog.String("client_ip", r.RemoteAddr),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rec.statusCode),
			slog.Duration("latency", time.Since(start)),
		}

		if r.TLS != nil {
			attrs = append(attrs, slog.String("tls_version", inspector.TLSVersionName(r.TLS.Version)))
			if len(r.TLS.PeerCertificates) > 0 {
				peer := r.TLS.PeerCertificates[0]
				attrs = append(attrs,
					slog.String("cert_cn", peer.Subject.CommonName),
					slog.Any("cert_sans", peer.DNSNames),
					slog.Time("cert_expiry", peer.NotAfter),
				)
			}
		}

		s.logger.LogAttrs(r.Context(), slog.LevelInfo, "request", attrs...)
	})
}

// recordingMiddleware captures request metadata and the inspection report,
// storing each request in the request store.
func (s *Server) recordingMiddleware(next http.Handler) http.Handler {
	if s.store == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rec, r)

		latencyMS := time.Since(start).Milliseconds()

		ctx, span := otel.Tracer("mtls-sandbox").Start(r.Context(), "tls.inspect")
		report := s.inspect(r)
		handshakeOK := report != nil && report.HandshakeOK
		span.SetAttributes(
			attribute.Bool("handshake.ok", handshakeOK),
		)
		if report != nil && report.FailureReason != "" {
			span.SetAttributes(attribute.String("failure_code", report.FailureReason))
		}
		span.End()

		// Record metrics.
		telemetry.Metrics.InboundRequests.Add(ctx, 1,
			otelmetric.WithAttributes(
				attribute.Int("status", rec.statusCode),
				attribute.Bool("handshake_ok", handshakeOK),
			),
		)
		telemetry.Metrics.InboundLatency.Record(ctx, float64(latencyMS),
			otelmetric.WithAttributes(attribute.String("path", r.URL.Path)),
		)
		telemetry.Metrics.HandshakeResults.Add(ctx, 1,
			otelmetric.WithAttributes(attribute.Bool("ok", handshakeOK)),
		)

		entry := store.RequestEntry{
			Timestamp: time.Now().Format(time.RFC3339),
			Method:    r.Method,
			Path:      r.URL.Path,
			Status:    rec.statusCode,
			LatencyMS: latencyMS,
			Report:    report,
		}

		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			peer := r.TLS.PeerCertificates[0]
			entry.CertCN = peer.Subject.CommonName
			entry.CertSANs = peer.DNSNames
		}

		s.store.Append(entry)

		// Associate with a session if the client cert CN is "session-<id>".
		if s.sessionStore != nil && strings.HasPrefix(entry.CertCN, "session-") {
			sessionID := strings.TrimPrefix(entry.CertCN, "session-")
			if err := s.sessionStore.AddInboundRequest(sessionID, entry.Method, entry.Path, entry.Status, entry.LatencyMS, entry.Report); err != nil {
				s.logger.Error("failed to record inbound request for session", "session_id", sessionID, "error", err)
			}
		}
	})
}

func (s *Server) inspect(r *http.Request) *inspector.InspectionReport {
	return inspector.Inspect(inspector.InspectParams{
		TLSState:   r.TLS,
		Mode:       s.cfg.Mode,
		TrustedCA:  s.caCert,
		CARootPool: s.caPool,
	})
}

func (s *Server) modeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		report := s.inspect(r)

		switch s.cfg.Mode {
		case "strict":
			if !report.HandshakeOK {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(report)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"status":  "ok",
				"message": "mTLS handshake successful",
				"client":  clientSummaryFromReport(report),
			})

		case "lenient":
			if !report.HandshakeOK {
				w.Header().Set("X-MTLS-Warning", report.FailureReason)
			}
			json.NewEncoder(w).Encode(map[string]any{
				"status":     "ok",
				"inspection": report,
			})

		case "inspect":
			json.NewEncoder(w).Encode(report)
		}
	})
}

func (s *Server) debugHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		report := s.inspect(r)
		json.NewEncoder(w).Encode(report)
	})
}

// clientSummaryFromReport extracts a concise client summary from a successful report.
func clientSummaryFromReport(report *inspector.InspectionReport) map[string]any {
	if len(report.Presented.CertChain) == 0 {
		return nil
	}
	cert := report.Presented.CertChain[0]
	return map[string]any{
		"cn":      cert.Subject,
		"issuer":  cert.Issuer,
		"expires": cert.NotAfter,
	}
}
