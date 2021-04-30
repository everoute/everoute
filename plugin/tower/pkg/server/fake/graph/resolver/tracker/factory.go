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
	"reflect"
	"sync"

	"github.com/smartxworks/lynx/plugin/tower/pkg/schema"
	"github.com/smartxworks/lynx/plugin/tower/pkg/server/fake/graph/model"
)

type TrackerFactory struct {
	lock             sync.Mutex
	defaultWatchSize int
	defaultKeyFunc   KeyFunc
	trackers         map[reflect.Type]*Tracker
}

var (
	DefaultKeyFunc = func(obj interface{}) string {
		return obj.(schema.Object).GetID()
	}

	DefaultChanSize = 100
)

func NewFactory(keyFunc KeyFunc, watchSize int) *TrackerFactory {
	if keyFunc == nil {
		keyFunc = DefaultKeyFunc
	}
	if watchSize == 0 {
		watchSize = DefaultChanSize
	}

	return &TrackerFactory{
		lock:             sync.Mutex{},
		defaultWatchSize: watchSize,
		defaultKeyFunc:   keyFunc,
		trackers:         make(map[reflect.Type]*Tracker),
	}
}

func (f *TrackerFactory) VM() *Tracker {
	return f.TrackerFor(&schema.VM{}, nil, 0)
}

func (f *TrackerFactory) Label() *Tracker {
	return f.TrackerFor(&schema.Label{}, nil, 0)
}

func (f *TrackerFactory) User() *Tracker {
	var userNameFunc = func(obj interface{}) string {
		return obj.(*model.User).Name
	}
	return f.TrackerFor(&model.User{}, userNameFunc, 0)
}

func (f *TrackerFactory) ResetAll() {
	f.lock.Lock()
	defer f.lock.Unlock()

	for _, tracker := range f.trackers {
		tracker.Reset()
	}
}

func (f *TrackerFactory) TrackerFor(obj interface{}, keyFunc KeyFunc, watchSize int) *Tracker {
	f.lock.Lock()
	defer f.lock.Unlock()

	trackerType := reflect.TypeOf(obj)
	tracker, exists := f.trackers[trackerType]
	if exists {
		return tracker
	}

	if keyFunc == nil {
		keyFunc = f.defaultKeyFunc
	}

	if watchSize == 0 {
		watchSize = f.defaultWatchSize
	}

	f.trackers[trackerType] = New(keyFunc, watchSize)

	return f.trackers[trackerType]
}
