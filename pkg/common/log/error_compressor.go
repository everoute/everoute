package log

import (
	"fmt"
	"sync"
	"time"

	"k8s.io/klog/v2"
)

type errorState struct {
	since                time.Time
	lastLogTime          time.Time
	lastProlongedLogTime time.Time
	suppressed           int
}

// ErrorCompressor compresses repetitive error logs by message key.
// The first occurrence of each message is logged immediately, then summarized periodically.
type ErrorCompressor struct {
	mu                 sync.Mutex
	now                func() time.Time
	summaryPeriod      time.Duration
	prolongedThreshold time.Duration
	prolongedLogPeriod time.Duration
	states             map[string]*errorState
}

func NewErrorCompressor(summaryPeriod time.Duration) *ErrorCompressor {
	return &ErrorCompressor{
		now:                time.Now,
		summaryPeriod:      summaryPeriod,
		prolongedThreshold: 0,
		prolongedLogPeriod: 0,
		states:             make(map[string]*errorState),
	}
}

func NewErrorCompressorWithProlonged(summaryPeriod, prolongedThreshold, prolongedLogPeriod time.Duration) *ErrorCompressor {
	return &ErrorCompressor{
		now:                time.Now,
		summaryPeriod:      summaryPeriod,
		prolongedThreshold: prolongedThreshold,
		prolongedLogPeriod: prolongedLogPeriod,
		states:             make(map[string]*errorState),
	}
}

func (l *ErrorCompressor) LogErrorf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	l.LogErrorWithKeyf(msg, "%s", msg)
}

func (l *ErrorCompressor) LogErrorWithKeyf(key, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	state, ok := l.states[key]
	if !ok {
		l.states[key] = &errorState{
			since:                now,
			lastLogTime:          now,
			lastProlongedLogTime: time.Time{},
		}
		klog.Errorf("%s", msg)
		return
	}

	if now.Sub(state.lastLogTime) >= l.summaryPeriod {
		klog.Errorf(
			"still failing for %s (suppressed %d repeated logs), latest error: %s",
			now.Sub(state.since).Round(time.Second), state.suppressed, msg,
		)
		state.lastLogTime = now
		state.suppressed = 0
		l.maybeLogProlongedLocked(key, msg, now, state)
		return
	}

	state.suppressed++

	l.maybeLogProlongedLocked(key, msg, now, state)
}

func (l *ErrorCompressor) maybeLogProlongedLocked(key, msg string, now time.Time, state *errorState) {
	if l.prolongedThreshold <= 0 || l.prolongedLogPeriod <= 0 {
		return
	}
	if now.Sub(state.since) < l.prolongedThreshold {
		return
	}
	if !state.lastProlongedLogTime.IsZero() && now.Sub(state.lastProlongedLogTime) < l.prolongedLogPeriod {
		return
	}

	klog.Errorf(
		"prolonged unhealthy for key %q: duration=%s, suppressed=%d, latest error: %s",
		key, now.Sub(state.since).Round(time.Second), state.suppressed, msg,
	)
	state.lastProlongedLogTime = now
}

// LogRecoveryf flushes compression state and emits one recovery info log.
// If there are no tracked failures, this is a no-op.
func (l *ErrorCompressor) LogRecoveryf(format string, args ...interface{}) {
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.states) == 0 {
		return
	}

	var earliest time.Time
	totalSuppressed := 0
	for _, state := range l.states {
		if earliest.IsZero() || state.since.Before(earliest) {
			earliest = state.since
		}
		totalSuppressed += state.suppressed
	}

	klog.Infof(
		"recovered after %s (error categories %d, suppressed %d repeated failure logs): %s",
		now.Sub(earliest).Round(time.Second), len(l.states), totalSuppressed, fmt.Sprintf(format, args...),
	)

	l.states = make(map[string]*errorState)
}
