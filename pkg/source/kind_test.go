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

package source_test

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	tcache "k8s.io/client-go/tools/cache"
	fcache "k8s.io/client-go/tools/cache/testing"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/everoute/everoute/pkg/source"
)

var mgr manager.Manager
var reconcileFunc reconcile.Func = func(context.Context, reconcile.Request) (reconcile.Result, error) { return reconcile.Result{}, nil }
var newCacheFunc = func(*rest.Config, cache.Options) (cache.Cache, error) { return &FakeInformers{}, nil }

func TestMain(m *testing.M) {
	RegisterTestingT(&testing.T{})

	config, err := (&envtest.Environment{}).Start()
	Expect(err).ShouldNot(HaveOccurred())

	mgr, err = manager.New(config, manager.Options{NewCache: newCacheFunc})
	Expect(err).ShouldNot(HaveOccurred())

	os.Exit(m.Run())
}

func TestKind(t *testing.T) {
	RegisterTestingT(t)

	t.Run("should add informer to factory on controller create", func(t *testing.T) {
		ctr01, err := controller.New("test01", mgr, controller.Options{Reconciler: reconcileFunc})
		Expect(err).ShouldNot(HaveOccurred())

		err = ctr01.Watch(source.Kind(mgr.GetCache(), &corev1.ConfigMap{}), &handler.EnqueueRequestForObject{})
		Expect(err).ShouldNot(HaveOccurred())

		fakeInformers, ok := mgr.GetCache().(*FakeInformers)
		Expect(ok).Should(BeTrue())
		Expect(fakeInformers.Informers).Should(HaveLen(1))

		informer, ok := fakeInformers.Informers[reflect.TypeOf(&corev1.ConfigMap{})]
		Expect(ok).Should(BeTrue())
		Expect(informer.HasSynced()).Should(BeFalse())
	})

	t.Run("should add informer to factory on controller create", func(t *testing.T) {
		ctr02, err := controller.New("test02", mgr, controller.Options{Reconciler: reconcileFunc})
		Expect(err).ShouldNot(HaveOccurred())

		err = ctr02.Watch(source.Kind(mgr.GetCache(), &corev1.Service{}), &handler.EnqueueRequestForObject{})
		Expect(err).ShouldNot(HaveOccurred())

		fakeInformers, ok := mgr.GetCache().(*FakeInformers)
		Expect(ok).Should(BeTrue())
		Expect(fakeInformers.Informers).Should(HaveLen(2))

		informer, ok := fakeInformers.Informers[reflect.TypeOf(&corev1.Service{})]
		Expect(ok).Should(BeTrue())
		Expect(informer.HasSynced()).Should(BeFalse())
	})

	t.Run("should wait all cache synced", func(t *testing.T) {
		RegisterTestingT(t)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		go mgr.Start(ctx)

		fakeInformers, ok := mgr.GetCache().(*FakeInformers)
		Expect(ok).Should(BeTrue())
		Expect(fakeInformers.WaitForCacheSync(ctx)).Should(BeTrue())

		informer, ok := fakeInformers.Informers[reflect.TypeOf(&corev1.ConfigMap{})]
		Expect(ok).Should(BeTrue())
		Expect(informer.HasSynced()).Should(BeTrue())

		informer, ok = fakeInformers.Informers[reflect.TypeOf(&corev1.ConfigMap{})]
		Expect(ok).Should(BeTrue())
		Expect(informer.HasSynced()).Should(BeTrue())
	})
}

type FakeInformers struct {
	cache.Cache
	Informers map[reflect.Type]tcache.SharedIndexInformer
}

func (c *FakeInformers) GetInformer(_ context.Context, obj client.Object) (cache.Informer, error) {
	if c.Informers == nil {
		c.Informers = map[reflect.Type]tcache.SharedIndexInformer{}
	}

	informer, ok := c.Informers[reflect.TypeOf(obj)]
	if !ok {
		informer = tcache.NewSharedIndexInformer(fcache.NewFakeControllerSource(), obj, 0, tcache.Indexers{})
		c.Informers[reflect.TypeOf(obj)] = informer
	}

	return informer, nil
}

func (c *FakeInformers) Start(ctx context.Context) error {
	for _, informer := range c.Informers {
		go informer.Run(ctx.Done())
	}
	return nil
}

func (c *FakeInformers) WaitForCacheSync(ctx context.Context) bool {
	informersHasSynced := make([]tcache.InformerSynced, 0, len(c.Informers))
	for _, informer := range c.Informers {
		informersHasSynced = append(informersHasSynced, informer.HasSynced)
	}
	return tcache.WaitForCacheSync(ctx.Done(), informersHasSynced...)
}
