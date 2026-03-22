package ratelimit

import (
	"testing"
	"time"
)

func TestLimiter_AllowsUpToLimit(t *testing.T) {
	l := New(3, time.Minute)

	for i := 0; i < 3; i++ {
		if !l.Allow("sess1") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	if l.Allow("sess1") {
		t.Error("4th request should be denied")
	}
}

func TestLimiter_DifferentKeys(t *testing.T) {
	l := New(1, time.Minute)

	if !l.Allow("a") {
		t.Error("first request to 'a' should be allowed")
	}
	if l.Allow("a") {
		t.Error("second request to 'a' should be denied")
	}
	if !l.Allow("b") {
		t.Error("first request to 'b' should be allowed")
	}
}

func TestLimiter_WindowResets(t *testing.T) {
	l := New(1, 50*time.Millisecond)

	if !l.Allow("x") {
		t.Error("first request should be allowed")
	}
	if l.Allow("x") {
		t.Error("second request should be denied")
	}

	time.Sleep(60 * time.Millisecond)

	if !l.Allow("x") {
		t.Error("request after window reset should be allowed")
	}
}
