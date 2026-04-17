package initsync

import (
	"sync"
	"sync/atomic"

	"k8s.io/apimachinery/pkg/util/sets"
)

// Tracker tracks whether the initial informer objects have all been processed.
type Tracker struct {
	done      atomic.Bool
	lock      sync.Mutex
	processed sets.Set[string]
}

func NewTracker() *Tracker {
	return &Tracker{}
}

func (t *Tracker) IsDone() bool {
	return t.done.Load()
}

// MarkProcessed records one processed object name.
// Returns isNew/current/recorded where recorded is false when init is already done.
func (t *Tracker) MarkProcessed(name string) (bool, []string, bool) {
	if t.done.Load() {
		return false, nil, false
	}

	t.lock.Lock()
	defer t.lock.Unlock()
	if t.done.Load() {
		return false, nil, false
	}
	if t.processed == nil {
		t.processed = sets.New[string]()
	}
	isNew := !t.processed.Has(name)
	t.processed.Insert(name)
	return isNew, t.processed.UnsortedList(), true
}

// CheckDone returns ready/justDone/processedOnDone.
func (t *Tracker) CheckDone(expected sets.Set[string]) (bool, bool, []string) {
	if t.done.Load() {
		return true, false, nil
	}

	t.lock.Lock()
	defer t.lock.Unlock()
	if t.done.Load() {
		return true, false, nil
	}
	if t.processed == nil {
		t.processed = sets.New[string]()
	}
	if expected.Len() == 0 || t.processed.IsSuperset(expected) {
		t.done.Store(true)
		processed := t.processed.UnsortedList()
		t.processed = nil
		return true, true, processed
	}
	return false, false, nil
}
