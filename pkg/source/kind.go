/*
Copyright 2023 The Everoute Authors.

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

package source

import (
	"context"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// Kind provides a source of events originating inside the cluster from Watches
// difference from source.Kind, add informer to factory on cache inject

func Kind(cache cache.Cache, object client.Object) source.SyncingSource {
	// should never hang on WaitForCacheSync
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// add typed informer to informers factory before controller start
	// make sure that when controllers start, all caches are synchronized
	if _, err := cache.GetInformer(ctx, object); err != nil && !errors.IsTimeout(err) {
		klog.Fatalf("Failed to add %v informer, err: %v", object, err)
	}

	return source.Kind(cache, object)
}
