/*
Copyright 2021 The Everoute Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
t
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

	"github.com/everoute/everoute/plugin/tower/pkg/schema"
	"github.com/everoute/everoute/plugin/tower/pkg/server/fake/graph/model"
)

type Factory struct {
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

func NewFactory(keyFunc KeyFunc, watchSize int) *Factory {
	if keyFunc == nil {
		keyFunc = DefaultKeyFunc
	}
	if watchSize == 0 {
		watchSize = DefaultChanSize
	}

	return &Factory{
		lock:             sync.Mutex{},
		defaultWatchSize: watchSize,
		defaultKeyFunc:   keyFunc,
		trackers:         make(map[reflect.Type]*Tracker),
	}
}

func (f *Factory) VM() *Tracker {
	return f.TrackerFor(&schema.VM{}, nil, 0)
}

func (f *Factory) Label() *Tracker {
	return f.TrackerFor(&schema.Label{}, nil, 0)
}

func (f *Factory) SecurityPolicy() *Tracker {
	return f.TrackerFor(&schema.SecurityPolicy{}, nil, 0)
}

func (f *Factory) IsolationPolicy() *Tracker {
	return f.TrackerFor(&schema.IsolationPolicy{}, nil, 0)
}

func (f *Factory) EverouteCluster() *Tracker {
	return f.TrackerFor(&schema.EverouteCluster{}, nil, 0)
}

func (f *Factory) Host() *Tracker {
	return f.TrackerFor(&schema.Host{}, nil, 0)
}

func (f *Factory) User() *Tracker {
	var userNameFunc = func(obj interface{}) string {
		return obj.(*model.User).Name
	}
	return f.TrackerFor(&model.User{}, userNameFunc, 0)
}

func (f *Factory) SystemEndpoints() *Tracker {
	return f.TrackerFor(&schema.SystemEndpoints{}, nil, 0)
}

func (f *Factory) Task() *Tracker {
	return f.TrackerFor(&schema.Task{}, nil, 0)
}

func (f *Factory) ResetAll() {
	f.lock.Lock()
	defer f.lock.Unlock()

	for _, tracker := range f.trackers {
		tracker.Reset()
	}
}

func (f *Factory) TrackerFor(obj interface{}, keyFunc KeyFunc, watchSize int) *Tracker {
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
