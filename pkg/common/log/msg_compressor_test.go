package log

import (
	"testing"
	"time"
)

func TestMsgCompressorThrottleAndRecover(t *testing.T) {
	c := NewMsgCompressor(10 * time.Second)

	base := time.Date(2026, 4, 27, 10, 0, 0, 0, time.UTC)
	now := base
	c.now = func() time.Time { return now }

	msg := c.NextMessage("dial failed")
	if msg == "" {
		t.Fatalf("first message should be logged")
	}

	now = base.Add(5 * time.Second)
	msg = c.NextMessage("dial failed")
	if msg != "" {
		t.Fatalf("message should be suppressed before summary period")
	}

	now = base.Add(11 * time.Second)
	msg = c.NextMessage("dial failed")
	if msg == "" {
		t.Fatalf("summary message should be logged")
	}

	now = base.Add(12 * time.Second)
	s, ok := c.Recover()
	if !ok {
		t.Fatalf("expected recovery summary")
	}
	if s.Elapsed != 12*time.Second {
		t.Fatalf("unexpected elapsed, got %s", s.Elapsed)
	}
	if s.Suppressed != 0 {
		t.Fatalf("unexpected suppressed, got %d", s.Suppressed)
	}
}
