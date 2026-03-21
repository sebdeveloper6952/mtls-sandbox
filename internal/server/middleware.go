package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/sebdeveloper6952/mtls-sandbox/internal/inspector"
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
