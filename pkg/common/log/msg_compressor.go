package log

import (
	"fmt"
	"sync"
	"time"
)

type MsgRecoverySummary struct {
	Since      time.Time
	Elapsed    time.Duration
	Suppressed int
}

// MsgCompressor compresses repeated logs for one message stream.
// It does not log directly; caller decides how to print returned messages.
type MsgCompressor struct {
	mu            sync.Mutex
	now           func() time.Time
	summaryPeriod time.Duration
	since         time.Time
	lastLogTime   time.Time
	suppressed    int
}

func NewMsgCompressor(summaryPeriod time.Duration) *MsgCompressor {
	return &MsgCompressor{
		now:           time.Now,
		summaryPeriod: summaryPeriod,
	}
}

// NextMessage records one occurrence and returns text to print.
// Empty string means this occurrence is suppressed.
func (c *MsgCompressor) NextMessage(format string, args ...interface{}) string {
	msg := fmt.Sprintf(format, args...)
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.since.IsZero() {
		c.since = now
		c.lastLogTime = now
		return msg
	}

	elapsed := now.Sub(c.since)
	if now.Sub(c.lastLogTime) >= c.summaryPeriod {
		out := fmt.Sprintf(
			"still failing for %s (suppressed %d repeated logs), latest error: %s",
			elapsed.Round(time.Second), c.suppressed, msg,
		)
		c.lastLogTime = now
		c.suppressed = 0
		return out
	}

	c.suppressed++
	return ""
}

func (c *MsgCompressor) Recover() (MsgRecoverySummary, bool) {
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.since.IsZero() {
		return MsgRecoverySummary{}, false
	}

	s := MsgRecoverySummary{
		Since:      c.since,
		Elapsed:    now.Sub(c.since).Round(time.Second),
		Suppressed: c.suppressed,
	}
	c.since = time.Time{}
	c.lastLogTime = time.Time{}
	c.suppressed = 0
	return s, true
}
