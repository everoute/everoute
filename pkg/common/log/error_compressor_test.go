package log

import (
	"testing"
	"time"
)

func TestErrorCompressorThrottleAndRecover(t *testing.T) {
	compressor := NewErrorCompressor(10 * time.Second)

	base := time.Date(2026, 4, 27, 10, 0, 0, 0, time.UTC)
	now := base
	compressor.now = func() time.Time { return now }

	msg := "dial failed"
	compressor.LogErrorf(msg)
	state, ok := compressor.states[msg]
	if !ok {
		t.Fatalf("missing state for msg %q", msg)
	}
	if state.since != base {
		t.Fatalf("unexpected since, got %v want %v", state.since, base)
	}
	if state.suppressed != 0 {
		t.Fatalf("unexpected suppressed, got %d want 0", state.suppressed)
	}

	now = base.Add(5 * time.Second)
	compressor.LogErrorf(msg)
	if state.suppressed != 1 {
		t.Fatalf("unexpected suppressed, got %d want 1", state.suppressed)
	}

	now = base.Add(11 * time.Second)
	compressor.LogErrorf(msg)
	if state.suppressed != 0 {
		t.Fatalf("unexpected suppressed after summary log, got %d want 0", state.suppressed)
	}
	if state.lastLogTime != now {
		t.Fatalf("unexpected lastLogTime, got %v want %v", state.lastLogTime, now)
	}

	now = base.Add(12 * time.Second)
	compressor.LogRecoveryf("dpi status: %s", "alive")
	if len(compressor.states) != 0 {
		t.Fatalf("unexpected states after recover, got %d want 0", len(compressor.states))
	}
}

func TestErrorCompressorDoNotMergeDifferentMessages(t *testing.T) {
	compressor := NewErrorCompressor(10 * time.Second)

	base := time.Date(2026, 4, 27, 10, 0, 0, 0, time.UTC)
	now := base
	compressor.now = func() time.Time { return now }

	msgA := "dial failed"
	msgB := "read failed"

	compressor.LogErrorf(msgA)
	now = base.Add(1 * time.Second)
	compressor.LogErrorf(msgB)

	stateA, ok := compressor.states[msgA]
	if !ok {
		t.Fatalf("missing state for msg %q", msgA)
	}
	stateB, ok := compressor.states[msgB]
	if !ok {
		t.Fatalf("missing state for msg %q", msgB)
	}

	now = base.Add(2 * time.Second)
	compressor.LogErrorf(msgA)
	if stateA.suppressed != 1 || stateB.suppressed != 0 {
		t.Fatalf("unexpected suppressed after msgA repeat, got a=%d b=%d", stateA.suppressed, stateB.suppressed)
	}

	now = base.Add(3 * time.Second)
	compressor.LogErrorf(msgB)
	if stateA.suppressed != 1 || stateB.suppressed != 1 {
		t.Fatalf("unexpected suppressed after msgB repeat, got a=%d b=%d", stateA.suppressed, stateB.suppressed)
	}
}

func TestErrorCompressorByKeyDoesNotMerge(t *testing.T) {
	compressor := NewErrorCompressor(10 * time.Second)

	base := time.Date(2026, 4, 27, 10, 0, 0, 0, time.UTC)
	now := base
	compressor.now = func() time.Time { return now }

	compressor.LogErrorWithKeyf("dial", "dial failed: %s", "e1")
	now = base.Add(1 * time.Second)
	compressor.LogErrorWithKeyf("dial", "dial failed: %s", "e2")
	now = base.Add(2 * time.Second)
	compressor.LogErrorWithKeyf("read", "read failed: %s", "e3")

	if len(compressor.states) != 2 {
		t.Fatalf("unexpected key count, got %d want 2", len(compressor.states))
	}
	if compressor.states["dial"].suppressed != 1 {
		t.Fatalf("unexpected dial suppressed, got %d want 1", compressor.states["dial"].suppressed)
	}
	if compressor.states["read"].suppressed != 0 {
		t.Fatalf("unexpected read suppressed, got %d want 0", compressor.states["read"].suppressed)
	}
}

func TestErrorCompressorProlongedStateUpdate(t *testing.T) {
	compressor := NewErrorCompressorWithProlonged(30*time.Second, 10*time.Minute, 10*time.Minute)

	base := time.Date(2026, 4, 27, 10, 0, 0, 0, time.UTC)
	now := base
	compressor.now = func() time.Time { return now }

	key := "dial"
	compressor.LogErrorWithKeyf(key, "dial failed: %s", "e1")
	state := compressor.states[key]
	if !state.lastProlongedLogTime.IsZero() {
		t.Fatalf("unexpected prolonged log time before threshold, got %v", state.lastProlongedLogTime)
	}

	now = base.Add(9*time.Minute + 59*time.Second)
	compressor.LogErrorWithKeyf(key, "dial failed: %s", "e2")
	if !state.lastProlongedLogTime.IsZero() {
		t.Fatalf("unexpected prolonged log time before threshold, got %v", state.lastProlongedLogTime)
	}

	now = base.Add(10 * time.Minute)
	compressor.LogErrorWithKeyf(key, "dial failed: %s", "e3")
	if state.lastProlongedLogTime != now {
		t.Fatalf("unexpected prolonged log time at threshold, got %v want %v", state.lastProlongedLogTime, now)
	}

	now = base.Add(15 * time.Minute)
	compressor.LogErrorWithKeyf(key, "dial failed: %s", "e4")
	if state.lastProlongedLogTime != base.Add(10*time.Minute) {
		t.Fatalf("unexpected prolonged log time before period, got %v", state.lastProlongedLogTime)
	}

	now = base.Add(20 * time.Minute)
	compressor.LogErrorWithKeyf(key, "dial failed: %s", "e5")
	if state.lastProlongedLogTime != now {
		t.Fatalf("unexpected prolonged log time after period, got %v want %v", state.lastProlongedLogTime, now)
	}
}
