package session

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"embed"
	"fmt"
	"time"

	"github.com/sebdeveloper6952/mtls-sandbox/internal/ca"
	"github.com/sebdeveloper6952/mtls-sandbox/internal/client"
	migrate "github.com/rubenv/sql-migrate"
	_ "modernc.org/sqlite"
)

//go:embed migrations
var migrationsFS embed.FS

// Session represents a testing session with its issued client cert.
type Session struct {
	ID            string `json:"id"`
	CreatedAt     string `json:"created_at"`
	ExpiresAt     string `json:"expires_at"`
	CallbackURL   string `json:"callback_url"`
	CertPEM       string `json:"client_cert_pem,omitempty"`
	KeyPEM        string `json:"client_key_pem,omitempty"`
	CertCN        string `json:"cert_cn"`
	CACertPEM     string `json:"ca_cert_pem,omitempty"`
}

// CallRecord is a stored record of an outbound test call.
type CallRecord struct {
	ID          int64              `json:"id"`
	SessionID   string             `json:"session_id"`
	CreatedAt   string             `json:"created_at"`
	CallbackURL string             `json:"callback_url"`
	TestMode    string             `json:"test_mode"`
	StatusCode  int                `json:"status_code"`
	DurationMS  int64              `json:"duration_ms"`
	Error       string             `json:"error,omitempty"`
	ProbeResult *client.ProbeResult `json:"probe_result,omitempty"`
}

// TestMode controls which credentials the outbound test call uses.
type TestMode string

const (
	TestModeNormal  TestMode = "normal"   // session's own client cert (should pass)
	TestModeNoCert  TestMode = "no_cert"  // no client cert at all (should fail)
	TestModeWrongCA TestMode = "wrong_ca" // client cert from a different CA (should fail)
)

// Store manages sessions and call history in SQLite.
type Store struct {
	db      *sql.DB
	ca      *ca.CA
	wrongCA *ca.CA // separate CA for negative tests
	maxAge  time.Duration
}

// NewStore opens (or creates) a SQLite database and runs migrations.
func NewStore(dbPath string, authority *ca.CA, maxAge time.Duration) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Enable WAL mode and foreign keys.
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("setting pragma: %w", err)
		}
	}

	if err := runMigrations(db); err != nil {
		db.Close()
		return nil, err
	}

	// Generate a separate CA for "wrong CA" negative tests.
	wrongCA, err := ca.NewCA("ecdsa-p256")
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("generating wrong CA: %w", err)
	}

	return &Store{db: db, ca: authority, wrongCA: wrongCA, maxAge: maxAge}, nil
}

func runMigrations(db *sql.DB) error {
	src := &migrate.EmbedFileSystemMigrationSource{
		FileSystem: migrationsFS,
		Root:       "migrations",
	}
	_, err := migrate.Exec(db, "sqlite3", src, migrate.Up)
	if err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}
	return nil
}

// Create generates a new session with a unique ID and client cert.
func (s *Store) Create() (*Session, error) {
	id, err := generateID()
	if err != nil {
		return nil, fmt.Errorf("generating session ID: %w", err)
	}

	cn := "session-" + id
	certPEM, keyPEM, err := s.ca.IssueCert("client", cn, nil)
	if err != nil {
		return nil, fmt.Errorf("issuing client cert: %w", err)
	}

	now := time.Now().UTC()
	expiresAt := now.Add(s.maxAge)

	sess := &Session{
		ID:        id,
		CreatedAt: now.Format(time.RFC3339),
		ExpiresAt: expiresAt.Format(time.RFC3339),
		CertPEM:   string(certPEM),
		KeyPEM:    string(keyPEM),
		CertCN:    cn,
		CACertPEM: string(s.ca.CertPEM),
	}

	_, err = s.db.Exec(
		`INSERT INTO sessions (id, created_at, expires_at, cert_pem, key_pem, cert_cn) VALUES (?, ?, ?, ?, ?, ?)`,
		sess.ID, sess.CreatedAt, sess.ExpiresAt, certPEM, keyPEM, sess.CertCN,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting session: %w", err)
	}

	return sess, nil
}

// Get retrieves a session by ID. Returns nil if not found or expired.
func (s *Store) Get(id string) (*Session, error) {
	row := s.db.QueryRow(
		`SELECT id, created_at, expires_at, callback_url, cert_pem, cert_cn FROM sessions WHERE id = ? AND expires_at > ?`,
		id, time.Now().UTC().Format(time.RFC3339),
	)

	sess := &Session{}
	var certPEM string
	err := row.Scan(&sess.ID, &sess.CreatedAt, &sess.ExpiresAt, &sess.CallbackURL, &certPEM, &sess.CertCN)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying session: %w", err)
	}

	sess.CertPEM = certPEM
	sess.CACertPEM = string(s.ca.CertPEM)
	return sess, nil
}

// GetWithKey retrieves a session including its private key (for making outbound calls).
func (s *Store) GetWithKey(id string) (*Session, error) {
	row := s.db.QueryRow(
		`SELECT id, created_at, expires_at, callback_url, cert_pem, key_pem, cert_cn FROM sessions WHERE id = ? AND expires_at > ?`,
		id, time.Now().UTC().Format(time.RFC3339),
	)

	sess := &Session{}
	err := row.Scan(&sess.ID, &sess.CreatedAt, &sess.ExpiresAt, &sess.CallbackURL, &sess.CertPEM, &sess.KeyPEM, &sess.CertCN)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying session: %w", err)
	}

	sess.CACertPEM = string(s.ca.CertPEM)
	return sess, nil
}

// UpdateCallbackURL sets the callback URL for a session.
func (s *Store) UpdateCallbackURL(id, url string) error {
	result, err := s.db.Exec(
		`UPDATE sessions SET callback_url = ? WHERE id = ? AND expires_at > ?`,
		url, id, time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("updating callback URL: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("session not found or expired")
	}
	return nil
}

// AddCall records a test call result and returns the call ID.
func (s *Store) AddCall(sessionID string, callbackURL string, testMode TestMode, statusCode int, durationMS int64, callError string, probeResult *client.ProbeResult) (int64, error) {
	var probeJSON []byte
	if probeResult != nil {
		var err error
		probeJSON, err = json.Marshal(probeResult)
		if err != nil {
			return 0, fmt.Errorf("marshalling probe result: %w", err)
		}
	}

	result, err := s.db.Exec(
		`INSERT INTO call_history (session_id, created_at, callback_url, test_mode, status_code, duration_ms, error, probe_result) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sessionID, time.Now().UTC().Format(time.RFC3339), callbackURL, string(testMode), statusCode, durationMS, nullString(callError), probeJSON,
	)
	if err != nil {
		return 0, fmt.Errorf("inserting call record: %w", err)
	}

	return result.LastInsertId()
}

// ListCalls returns call history for a session with pagination.
func (s *Store) ListCalls(sessionID string, limit, offset int) ([]CallRecord, int, error) {
	var total int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM call_history WHERE session_id = ?`, sessionID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("counting calls: %w", err)
	}

	rows, err := s.db.Query(
		`SELECT id, session_id, created_at, callback_url, test_mode, status_code, duration_ms, error, probe_result FROM call_history WHERE session_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		sessionID, limit, offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("querying calls: %w", err)
	}
	defer rows.Close()

	var calls []CallRecord
	for rows.Next() {
		var c CallRecord
		var callErr sql.NullString
		var probeJSON sql.NullString
		err := rows.Scan(&c.ID, &c.SessionID, &c.CreatedAt, &c.CallbackURL, &c.TestMode, &c.StatusCode, &c.DurationMS, &callErr, &probeJSON)
		if err != nil {
			return nil, 0, fmt.Errorf("scanning call: %w", err)
		}
		c.Error = callErr.String
		if probeJSON.Valid && probeJSON.String != "" {
			var pr client.ProbeResult
			if json.Unmarshal([]byte(probeJSON.String), &pr) == nil {
				c.ProbeResult = &pr
			}
		}
		calls = append(calls, c)
	}

	return calls, total, nil
}

// CleanExpired removes expired sessions and their associated call history.
func (s *Store) CleanExpired() (int64, error) {
	result, err := s.db.Exec(
		`DELETE FROM sessions WHERE expires_at <= ?`,
		time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		return 0, fmt.Errorf("cleaning expired sessions: %w", err)
	}
	return result.RowsAffected()
}

// WrongCACert returns client cert PEM and key PEM issued by the wrong CA.
func (s *Store) WrongCACert() (certPEM, keyPEM []byte, err error) {
	return s.wrongCA.IssueCert("client", "wrong-ca-client", nil)
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

func generateID() (string, error) {
	b := make([]byte, 6) // 6 bytes = 12 hex chars
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
