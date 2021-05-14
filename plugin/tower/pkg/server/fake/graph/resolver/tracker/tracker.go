/*
Copyright 2021 The Lynx Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tracker

import (
	"fmt"
	"sync"

	"github.com/smartxworks/lynx/plugin/tower/pkg/server/fake/graph/model"
)

type Event struct {
	Type   model.MutationType
	Object interface{}
}

type KeyFunc func(obj interface{}) string

// Tracker keeps track of objects. It's used to mock resource server.
type Tracker struct {
	sync.RWMutex

	keyFunc KeyFunc
	items   map[string]interface{}

	watchChanSize int
	watchers      map[chan<- *Event]struct{}
}

func New(keyFunc KeyFunc, watchChanSize int) *Tracker {
	return &Tracker{
		items:         make(map[string]interface{}),
		keyFunc:       keyFunc,
		watchChanSize: watchChanSize,
		watchers:      make(map[chan<- *Event]struct{}),
	}
}

func (w *Tracker) Create(obj interface{}) error {
	w.Lock()
	defer w.Unlock()

	_, ok := w.items[w.keyFunc(obj)]
	if ok {
		return fmt.Errorf("create object %s already exist", obj)
	}

	w.notifyLocked(&Event{Type: model.MutationTypeCreated, Object: obj})
	w.items[w.keyFunc(obj)] = obj
	return nil
}

func (w *Tracker) Update(obj interface{}) error {
	w.Lock()
	defer w.Unlock()

	_, ok := w.items[w.keyFunc(obj)]
	if !ok {
		return fmt.Errorf("update object %s not found", obj)
	}

	w.notifyLocked(&Event{Type: model.MutationTypeUpdated, Object: obj})
	w.items[w.keyFunc(obj)] = obj
	return nil
}

func (w *Tracker) CreateOrUpdate(obj interface{}) {
	w.Lock()
	defer w.Unlock()

	var eventType = model.MutationTypeCreated
	_, ok := w.items[w.keyFunc(obj)]
	if ok {
		eventType = model.MutationTypeUpdated
	}

	w.notifyLocked(&Event{Type: eventType, Object: obj})
	w.items[w.keyFunc(obj)] = obj
}

func (w *Tracker) Delete(key string) error {
	w.Lock()
	defer w.Unlock()

	obj, ok := w.items[key]
	if !ok {
		return fmt.Errorf("delete object key %s not found", key)
	}

	w.notifyLocked(&Event{Type: model.MutationTypeDeleted, Object: obj})
	delete(w.items, key)
	return nil
}

func (w *Tracker) Get(key string) (interface{}, bool) {
	w.RLock()
	defer w.RUnlock()
	item, exists := w.items[key]
	return item, exists
}

func (w *Tracker) List() []interface{} {
	w.RLock()
	defer w.RUnlock()

	list := make([]interface{}, 0, len(w.items))
	for _, item := range w.items {
		list = append(list, item)
	}
	return list
}

func (w *Tracker) Watch() (eventCh <-chan *Event, stopWatch func()) {
	eventChan := make(chan *Event, w.watchChanSize)

	w.Lock()
	defer w.Unlock()

	w.watchers[eventChan] = struct{}{}
	return eventChan, w.stopWatchFunc(eventChan)
}

func (w *Tracker) Reset() {
	w.Lock()
	defer w.Unlock()

	for watcher := range w.watchers {
		close(watcher)
	}

	w.items = make(map[string]interface{})
	w.watchers = make(map[chan<- *Event]struct{})
}

func (w *Tracker) notifyLocked(event *Event) {
	for watcher := range w.watchers {
		select {
		case watcher <- event:
		default:
			panic(fmt.Errorf("channel full"))
		}
	}
}

func (w *Tracker) stopWatchFunc(eventCh chan *Event) func() {
	return func() {
		w.Lock()
		defer w.Unlock()
		delete(w.watchers, eventCh)

		select {
		case _, ok := <-eventCh:
			if ok {
				close(eventCh)
			}
		default:
			close(eventCh)
		}
	}
}
