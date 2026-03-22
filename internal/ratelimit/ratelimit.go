package ratelimit

import (
	"sync"
	"time"
)

type window struct {
	count int
	start time.Time
}

// Limiter implements a fixed-window rate limiter keyed by an arbitrary string (e.g. session ID).
type Limiter struct {
	mu      sync.Mutex
	windows map[string]*window
	limit   int
	period  time.Duration
}

// New creates a Limiter that allows limit requests per period per key.
func New(limit int, period time.Duration) *Limiter {
	return &Limiter{
		windows: make(map[string]*window),
		limit:   limit,
		period:  period,
	}
}

// Allow returns true if the request for the given key should be allowed.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	w, ok := l.windows[key]
	if !ok || now.Sub(w.start) >= l.period {
		l.windows[key] = &window{count: 1, start: now}
		return true
	}

	if w.count >= l.limit {
		return false
	}

	w.count++
	return true
}
