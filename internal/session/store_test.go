package session

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/sebdeveloper6952/mtls-sandbox/internal/ca"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/client"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/inspector"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	authority, err := ca.NewCA("ecdsa-p256")
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := NewStore(dbPath, authority, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCreateAndGet(t *testing.T) {
	s := newTestStore(t)

	sess, err := s.Create()
	if err != nil {
		t.Fatal(err)
	}
	if sess.ID == "" {
		t.Error("expected non-empty ID")
	}
	if len(sess.ID) != 12 {
		t.Errorf("expected 12-char ID, got %d", len(sess.ID))
	}
	if sess.CertCN != "session-"+sess.ID {
		t.Errorf("expected CN=session-%s, got %s", sess.ID, sess.CertCN)
	}
	if sess.CertPEM == "" {
		t.Error("expected client cert PEM")
	}
	if sess.KeyPEM == "" {
		t.Error("expected client key PEM on creation")
	}
	if sess.CACertPEM == "" {
		t.Error("expected CA cert PEM")
	}

	// Get should return session without key.
	got, err := s.Get(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected session, got nil")
	}
	if got.ID != sess.ID {
		t.Errorf("expected ID=%s, got %s", sess.ID, got.ID)
	}
	if got.KeyPEM != "" {
		t.Error("Get should not return private key")
	}
}

func TestGetWithKey(t *testing.T) {
	s := newTestStore(t)

	sess, err := s.Create()
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.GetWithKey(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyPEM == "" {
		t.Error("GetWithKey should return private key")
	}
}

func TestGetNotFound(t *testing.T) {
	s := newTestStore(t)

	got, err := s.Get("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Error("expected nil for nonexistent session")
	}
}

func TestUpdateCallbackURL(t *testing.T) {
	s := newTestStore(t)

	sess, err := s.Create()
	if err != nil {
		t.Fatal(err)
	}

	err = s.UpdateCallbackURL(sess.ID, "https://example.com:8443/test")
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.Get(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CallbackURL != "https://example.com:8443/test" {
		t.Errorf("expected callback URL updated, got %s", got.CallbackURL)
	}
}

func TestUpdateCallbackURL_NotFound(t *testing.T) {
	s := newTestStore(t)

	err := s.UpdateCallbackURL("nonexistent", "https://example.com")
	if err == nil {
		t.Error("expected error for nonexistent session")
	}
}

func TestAddCallAndList(t *testing.T) {
	s := newTestStore(t)

	sess, err := s.Create()
	if err != nil {
		t.Fatal(err)
	}

	probe := &client.ProbeResult{
		URL:        "https://example.com",
		StatusCode: 200,
		DurationMS: 42,
		Inspection: &inspector.InspectionReport{HandshakeOK: true},
	}
	callID, err := s.AddCall(sess.ID, "https://example.com", 200, 42, "", probe)
	if err != nil {
		t.Fatal(err)
	}
	if callID <= 0 {
		t.Error("expected positive call ID")
	}

	// Add a failed call.
	_, err = s.AddCall(sess.ID, "https://fail.example.com", 0, 100, "connection refused", nil)
	if err != nil {
		t.Fatal(err)
	}

	calls, total, err := s.ListCalls(sess.ID, 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Errorf("expected total=2, got %d", total)
	}
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(calls))
	}

	// Find each call by content (order may vary within same second).
	var hasError, hasProbe bool
	for _, c := range calls {
		if c.Error == "connection refused" {
			hasError = true
		}
		if c.ProbeResult != nil {
			hasProbe = true
		}
	}
	if !hasError {
		t.Error("expected a call with error='connection refused'")
	}
	if !hasProbe {
		t.Error("expected a call with probe result")
	}
}

func TestCleanExpired(t *testing.T) {
	authority, err := ca.NewCA("ecdsa-p256")
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "test.db")
	// Use a very short max age.
	s, err := NewStore(dbPath, authority, 1*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	_, err = s.Create()
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(10 * time.Millisecond)

	n, err := s.CleanExpired()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 1 expired session cleaned, got %d", n)
	}
}
