/*
Copyright 2014 The Kubernetes Authors.

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

package informer

import (
	"time"

	"k8s.io/apimachinery/pkg/util/clock"
	"k8s.io/client-go/tools/cache"
)

// Reflector watches a specified resource and causes all changes to be reflected in the given store.
type Reflector interface {
	// Run repeatedly fetch all the objects and subsequent deltas.
	// Run will exit when stopCh is closed.
	Run(stopCh <-chan struct{})
	// LastSyncResourceVersion is the resource version observed when last sync with the underlying store
	// The value returned is not synchronized with access to the underlying store and is not thread-safe
	LastSyncResourceVersion() string
}

// ReflectorOptions giving options for setup new reflector.
type ReflectorOptions struct {
	// Store is the destination to sync up with the watch source.
	Store cache.Store
	// ObjectType is an example object of the type this reflector is
	// expected to handle.
	ExpectedType interface{}
	// ResyncPeriod is the period at which ShouldResync is considered
	ResyncPeriod time.Duration
	// ShouldResync is periodically used by the reflector to determine
	// whether to Resync the Queue. If ShouldResync is `nil` or
	// returns true, it means the reflector should proceed with the
	// resync.
	ShouldResync cache.ShouldResyncFunc
	// WatchListPageSize is the requested chunk size of lists.
	WatchListPageSize int64
	// Clock allows for testability
	Clock clock.Clock
}

type NewReflectorFunc func(options *ReflectorOptions) Reflector
