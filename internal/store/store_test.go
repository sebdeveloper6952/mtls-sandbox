package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestAppendAndGet(t *testing.T) {
	s, _ := NewStore(10, "")
	defer s.Close()

	id := s.Append(RequestEntry{Method: "GET", Path: "/test"})
	if id != "1" {
		t.Errorf("expected id 1, got %s", id)
	}

	entry, ok := s.Get(id)
	if !ok {
		t.Fatal("expected entry to be found")
	}
	if entry.Method != "GET" || entry.Path != "/test" {
		t.Errorf("unexpected entry: %+v", entry)
	}
}

func TestGetNotFound(t *testing.T) {
	s, _ := NewStore(10, "")
	defer s.Close()

	_, ok := s.Get("999")
	if ok {
		t.Error("expected entry not found")
	}
}

func TestListNewestFirst(t *testing.T) {
	s, _ := NewStore(10, "")
	defer s.Close()

	for i := 0; i < 5; i++ {
		s.Append(RequestEntry{Path: "/" + strconv.Itoa(i)})
	}

	entries := s.List(0, 0)
	if len(entries) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(entries))
	}
	// Newest first: /4, /3, /2, /1, /0
	if entries[0].Path != "/4" {
		t.Errorf("expected newest first (/4), got %s", entries[0].Path)
	}
	if entries[4].Path != "/0" {
		t.Errorf("expected oldest last (/0), got %s", entries[4].Path)
	}
}

func TestListWithLimitAndOffset(t *testing.T) {
	s, _ := NewStore(10, "")
	defer s.Close()

	for i := 0; i < 5; i++ {
		s.Append(RequestEntry{Path: "/" + strconv.Itoa(i)})
	}

	entries := s.List(2, 1)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	// Skip newest (4), get next 2: /3, /2
	if entries[0].Path != "/3" {
		t.Errorf("expected /3, got %s", entries[0].Path)
	}
	if entries[1].Path != "/2" {
		t.Errorf("expected /2, got %s", entries[1].Path)
	}
}

func TestRingBufferWrap(t *testing.T) {
	s, _ := NewStore(3, "")
	defer s.Close()

	for i := 0; i < 5; i++ {
		s.Append(RequestEntry{Path: "/" + strconv.Itoa(i)})
	}

	if s.Count() != 3 {
		t.Errorf("expected count 3, got %d", s.Count())
	}

	entries := s.List(0, 0)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	// Should have /4, /3, /2 (oldest /0 and /1 evicted)
	if entries[0].Path != "/4" {
		t.Errorf("expected /4, got %s", entries[0].Path)
	}
	if entries[2].Path != "/2" {
		t.Errorf("expected /2, got %s", entries[2].Path)
	}

	// /0 and /1 should be gone
	_, ok := s.Get("1")
	if ok {
		t.Error("expected entry 1 to be evicted")
	}
}

func TestConcurrentAppend(t *testing.T) {
	s, _ := NewStore(1000, "")
	defer s.Close()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s.Append(RequestEntry{Path: "/" + strconv.Itoa(n)})
		}(i)
	}
	wg.Wait()

	if s.Count() != 100 {
		t.Errorf("expected count 100, got %d", s.Count())
	}
}

func TestNDJSONWriter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "requests.ndjson")

	s, err := NewStore(10, path)
	if err != nil {
		t.Fatal(err)
	}

	s.Append(RequestEntry{Method: "GET", Path: "/one"})
	s.Append(RequestEntry{Method: "POST", Path: "/two"})
	s.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	var entry RequestEntry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("invalid JSON on line 1: %v", err)
	}
	if entry.Path != "/one" {
		t.Errorf("expected /one, got %s", entry.Path)
	}
}

func TestTimestampAutoSet(t *testing.T) {
	s, _ := NewStore(10, "")
	defer s.Close()

	s.Append(RequestEntry{Path: "/test"})
	entry, _ := s.Get("1")
	if entry.Timestamp == "" {
		t.Error("expected timestamp to be auto-set")
	}
}
