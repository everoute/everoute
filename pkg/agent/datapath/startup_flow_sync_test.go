package datapath

import (
	"context"
	"testing"
	"time"
)

func TestStartupFlowSyncWaitWithMinDelayWaitsForBothConditions(t *testing.T) {
	sync := NewStartupFlowSync()

	result := waitStartupFlowSync(t, sync, 20*time.Millisecond)

	select {
	case err := <-result:
		t.Fatalf("wait returned before startup flow sync done: %v", err)
	case <-time.After(60 * time.Millisecond):
	}

	sync.MarkNormalPolicyDone()
	sync.MarkGlobalPolicyDone()
	sync.MarkTrafficRedirectDone()

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("wait returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("wait should return after startup flow sync done and min delay elapsed")
	}
}

func TestStartupFlowSyncWaitWithMinDelayWaitsForMinDelayWhenStartupAlreadyDone(t *testing.T) {
	sync := NewStartupFlowSync()
	sync.MarkNormalPolicyDone()
	sync.MarkGlobalPolicyDone()
	sync.MarkTrafficRedirectDone()

	result := waitStartupFlowSync(t, sync, 80*time.Millisecond)

	select {
	case err := <-result:
		t.Fatalf("wait returned before min delay elapsed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("wait returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("wait should return after min delay elapsed")
	}
}

func TestStartupFlowSyncWaitWithMinDelayReturnsOnContextCancel(t *testing.T) {
	sync := NewStartupFlowSync()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)

	go func() {
		result <- sync.WaitWithMinDelay(ctx, "", time.Hour, time.Hour)
	}()

	cancel()

	select {
	case err := <-result:
		if err == nil {
			t.Fatalf("expected context cancellation error")
		}
	case <-time.After(time.Second):
		t.Fatalf("wait should return after context cancellation")
	}
}

func TestStartupFlowSyncWaitWithMinDelayReturnsOnManualCleanup(t *testing.T) {
	sync := NewStartupFlowSync()
	result := waitStartupFlowSync(t, sync, time.Hour)

	select {
	case err := <-result:
		t.Fatalf("wait returned before manual cleanup: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	if !sync.TriggerManualCleanup() {
		t.Fatalf("expected first manual cleanup request to succeed")
	}

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("wait returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("wait should return after manual cleanup request")
	}

	status := sync.Status()
	if !status.ManualCleanupRequested {
		t.Fatalf("expected manual cleanup request to be recorded")
	}
	if sync.TriggerManualCleanup() {
		t.Fatalf("expected repeated manual cleanup request to be ignored")
	}
}

func waitStartupFlowSync(t *testing.T, sync *StartupFlowSync, minDelay time.Duration) <-chan error {
	t.Helper()

	result := make(chan error, 1)
	go func() {
		result <- sync.WaitWithMinDelay(context.Background(), "", minDelay, time.Hour)
	}()
	return result
}
