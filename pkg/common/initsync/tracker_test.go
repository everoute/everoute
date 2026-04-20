package initsync

import (
	"sync"
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"
)

func TestTrackerMarkProcessed(t *testing.T) {
	tracker := NewTracker()
	if tracker.IsDone() {
		t.Fatalf("new tracker should not be done")
	}

	isNew, current, recorded := tracker.MarkProcessed("a")
	if !recorded || !isNew {
		t.Fatalf("first mark should be recorded and new, got recorded=%v isNew=%v", recorded, isNew)
	}
	if !sets.New[string](current...).Has("a") {
		t.Fatalf("first mark should contain a, current=%v", current)
	}

	isNew, current, recorded = tracker.MarkProcessed("a")
	if !recorded || isNew {
		t.Fatalf("second mark should be recorded but not new, got recorded=%v isNew=%v", recorded, isNew)
	}
	if len(current) != 1 || current[0] != "a" {
		t.Fatalf("duplicate mark should keep single entry, current=%v", current)
	}
}

func TestTrackerCheckDone(t *testing.T) {
	tracker := NewTracker()
	tracker.MarkProcessed("a")

	ready, justDone, processed := tracker.CheckDone(sets.New[string]("a", "b"))
	if ready || justDone || processed != nil {
		t.Fatalf("tracker should not be ready before all expected processed, got ready=%v justDone=%v processed=%v", ready, justDone, processed)
	}

	tracker.MarkProcessed("b")
	ready, justDone, processed = tracker.CheckDone(sets.New[string]("a", "b"))
	if !ready || !justDone {
		t.Fatalf("tracker should be just done when expected all processed, got ready=%v justDone=%v", ready, justDone)
	}
	if !sets.New[string](processed...).Equal(sets.New[string]("a", "b")) {
		t.Fatalf("processed on done mismatch, got=%v", processed)
	}
	if !tracker.IsDone() {
		t.Fatalf("tracker should be done after CheckDone succeeds")
	}

	ready, justDone, processed = tracker.CheckDone(sets.New[string]("a", "b"))
	if !ready || justDone || processed != nil {
		t.Fatalf("done tracker should return ready=true justDone=false processed=nil, got ready=%v justDone=%v processed=%v", ready, justDone, processed)
	}
}

func TestTrackerMarkProcessedAfterDone(t *testing.T) {
	tracker := NewTracker()
	ready, justDone, processed := tracker.CheckDone(sets.New[string]())
	if !ready || !justDone || len(processed) != 0 {
		t.Fatalf("empty expected should mark tracker done, got ready=%v justDone=%v processed=%v", ready, justDone, processed)
	}

	isNew, current, recorded := tracker.MarkProcessed("a")
	if recorded || isNew || current != nil {
		t.Fatalf("mark after done should not record, got recorded=%v isNew=%v current=%v", recorded, isNew, current)
	}
}

func TestTrackerConcurrentMarkProcessed(t *testing.T) {
	tracker := NewTracker()
	names := []string{"a", "b", "c", "d", "e", "f"}

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tracker.MarkProcessed(names[idx%len(names)])
		}(i)
	}
	wg.Wait()

	ready, justDone, processed := tracker.CheckDone(sets.New[string](names...))
	if !ready || !justDone {
		t.Fatalf("tracker should be done after concurrent marks, got ready=%v justDone=%v", ready, justDone)
	}
	if !sets.New[string](processed...).Equal(sets.New[string](names...)) {
		t.Fatalf("processed on done mismatch after concurrent marks, got=%v", processed)
	}
}

