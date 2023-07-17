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
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/runtime/inject"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// Kind provides a source of events originating inside the cluster from Watches
// difference from source.Kind, add informer to factory on cache inject
type Kind struct {
	Type runtime.Object
	source.Kind
}

var _ inject.Cache = &Kind{}  // implements cache inject
var _ source.Source = &Kind{} // implements watch source

func (ks *Kind) InjectCache(c cache.Cache) error {
	// inject source watch type
	ks.Kind.Type = ks.Type

	// inject source watch cache
	if err := ks.Kind.InjectCache(c); err != nil {
		return err
	}

	// should never hang on WaitForCacheSync
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// add typed informer to informers factory before controller start
	// make sure that when controllers start, all caches are synchronized
	if _, err := c.GetInformer(ctx, ks.Type); err != nil && !errors.IsTimeout(err) {
		return err
	}

	return nil
}
