package store

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sebdeveloper6952/mtls-sandbox/internal/inspector"
)

// RequestEntry represents a single recorded request.
type RequestEntry struct {
	ID        string                      `json:"id"`
	Timestamp string                      `json:"timestamp"`
	Method    string                      `json:"method"`
	Path      string                      `json:"path"`
	Status    int                         `json:"status"`
	LatencyMS int64                       `json:"latency_ms"`
	CertCN    string                      `json:"cert_cn,omitempty"`
	CertSANs  []string                    `json:"cert_sans,omitempty"`
	Report    *inspector.InspectionReport `json:"inspection"`
}

// Store is a thread-safe, fixed-capacity ring buffer of request entries.
type Store struct {
	mu       sync.RWMutex
	entries  []RequestEntry
	capacity int
	head     int // next write position
	count    int
	nextID   atomic.Uint64

	ndjsonFile *os.File
	ndjsonMu   sync.Mutex
}

// NewStore creates a Store with the given capacity. If ndjsonPath is non-empty,
// entries are also appended as NDJSON to that file.
func NewStore(capacity int, ndjsonPath string) (*Store, error) {
	s := &Store{
		entries:  make([]RequestEntry, capacity),
		capacity: capacity,
	}

	if ndjsonPath != "" {
		f, err := os.OpenFile(ndjsonPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("opening NDJSON log file: %w", err)
		}
		s.ndjsonFile = f
	}

	return s, nil
}

// Append adds an entry to the ring buffer and returns the assigned ID.
func (s *Store) Append(entry RequestEntry) string {
	id := strconv.FormatUint(s.nextID.Add(1), 10)
	entry.ID = id
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().Format(time.RFC3339)
	}

	s.mu.Lock()
	s.entries[s.head] = entry
	s.head = (s.head + 1) % s.capacity
	if s.count < s.capacity {
		s.count++
	}
	s.mu.Unlock()

	if s.ndjsonFile != nil {
		s.ndjsonMu.Lock()
		data, err := json.Marshal(entry)
		if err == nil {
			data = append(data, '\n')
			s.ndjsonFile.Write(data)
		}
		s.ndjsonMu.Unlock()
	}

	return id
}

// List returns up to limit entries in reverse chronological order (newest first),
// starting after skipping offset entries.
func (s *Store) List(limit, offset int) []RequestEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.count == 0 || offset >= s.count {
		return nil
	}

	available := s.count - offset
	if limit <= 0 || limit > available {
		limit = available
	}

	result := make([]RequestEntry, 0, limit)
	// newest entry is at (head - 1), so start at (head - 1 - offset)
	for i := 0; i < limit; i++ {
		idx := (s.head - 1 - offset - i + s.capacity*2) % s.capacity
		result = append(result, s.entries[idx])
	}

	return result
}

// Get retrieves a single entry by ID.
func (s *Store) Get(id string) (RequestEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := 0; i < s.count; i++ {
		idx := (s.head - 1 - i + s.capacity) % s.capacity
		if s.entries[idx].ID == id {
			return s.entries[idx], true
		}
	}

	return RequestEntry{}, false
}

// Count returns the number of entries currently stored.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.count
}

// Close releases any resources held by the store.
func (s *Store) Close() error {
	if s.ndjsonFile != nil {
		return s.ndjsonFile.Close()
	}
	return nil
}
