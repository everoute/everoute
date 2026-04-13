/*
Copyright 2022 The Everoute Authors.

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
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"

	"github.com/everoute/everoute/plugin/tower/pkg/schema"
	"github.com/everoute/everoute/plugin/tower/pkg/server/fake"
	. "github.com/everoute/everoute/plugin/tower/pkg/utils/testing"
	"github.com/everoute/everoute/plugin/tower/third_party/forked/client-go/informer"
)

func Test_matchFieldNotExistFromMessage(t *testing.T) {
	tests := []struct {
		message      string
		expectResult []string
	}{
		{
			message:      `Cannot query field "fsaw" on type "Vm".`,
			expectResult: []string{`fsaw`, `Vm`},
		},
		{
			message:      `Cannot return null for non-nullable field EverouteClusterAgentStatus.elfClusterNumber.`,
			expectResult: nil,
		},
		{
			message:      `Cannot query field "fsaw" on type "Vm".`,
			expectResult: []string{`fsaw`, `Vm`},
		},
		{
			message:      `Cannot query field "cpu_fan_speedk" on type "Host". Did you mean "cpu_fan_speed" or "cpu_fan_speed_unit"?`,
			expectResult: []string{`cpu_fan_speedk`, `Host`},
		},
	}

	for item, tt := range tests {
		t.Run(fmt.Sprintf("case%2d", item), func(t *testing.T) {
			if got := matchFieldNotExistFromMessage(tt.message); !reflect.DeepEqual(got, tt.expectResult) {
				t.Errorf("matchFieldNotExistFromMessage() = %v, want %v", got, tt.expectResult)
			}
		})
	}
}

type VM struct {
	ID            string `json:"id"`
	FieldNotFound string `json:"field_not_found"`
}

func TestReflectorWithNotExistField(t *testing.T) {
	RegisterTestingT(t)

	server := fake.NewServer(nil)
	server.Serve()
	defer server.Stop()

	objectStore := cache.NewIndexer(func(obj interface{}) (string, error) { return obj.(*VM).ID, nil }, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	newReflector := NewReflectorBuilder(server.NewClient(), make(chan *CrcEvent))(&informer.ReflectorOptions{
		Store:        objectStore,
		ExpectedType: &VM{},
		ShouldResync: func() bool { return false },
		Clock:        &clock.RealClock{},
	})
	go newReflector.Run(ctx.Done())

	server.TrackerFactory().VM().CreateOrUpdate(NewRandomVM())
	server.TrackerFactory().VM().CreateOrUpdate(NewRandomVM())

	Eventually(func() int {
		return len(objectStore.ListKeys())
	}, 60).Should(Equal(2))
}

type UnExpectedObject struct {
	ID string `json:"id"`
}

func TestReflectorWithNotExistObject(t *testing.T) {
	RegisterTestingT(t)

	server := fake.NewServer(nil)
	server.Serve()
	defer server.Stop()

	objectFIFO := cache.NewFIFO(TowerObjectKey)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	newReflector := NewReflectorBuilder(server.NewClient(), make(chan *CrcEvent))(&informer.ReflectorOptions{
		Store:        objectFIFO,
		ExpectedType: &UnExpectedObject{},
		ShouldResync: func() bool { return false },
		Clock:        &clock.RealClock{},
	})
	go newReflector.Run(ctx.Done())

	Eventually(objectFIFO.HasSynced, 60).Should(BeTrue())
}

func TestReflectorSubscriptionEventHandlerQueueByKey(t *testing.T) {
	RegisterTestingT(t)

	server := fake.NewServer(nil)
	server.Serve()
	defer server.Stop()

	vm := &schema.VM{
		ObjectMeta: schema.ObjectMeta{ID: "vm-1"},
		Name:       "from-query",
		Status:     schema.VMStatusRunning,
	}
	server.TrackerFactory().VM().CreateOrUpdate(vm)

	objectStore := cache.NewIndexer(func(obj interface{}) (string, error) { return obj.(*schema.VM).ID, nil }, nil)
	queue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "test-subscription")
	defer queue.ShutDown()
	r := &reflector{
		client:          server.NewClient(),
		store:           objectStore,
		expectType:      gqlType{reflect.TypeOf(&schema.VM{})},
		storeEventQueue: queue,
	}
	go ReconcileWorker("test-subscription", queue, r.processStoreEvent)()

	raw, err := json.Marshal(map[string]any{
		"mutation": schema.CreateEvent,
		"node": map[string]any{
			"id":     vm.ID,
			"name":   "from-event",
			"status": schema.VMStatusStopped,
		},
	})
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}

	if err := r.eventHandler(raw); err != nil {
		t.Fatalf("handle event: %v", err)
	}

	Eventually(func() string {
		got, exists, err := objectStore.GetByKey(vm.ID)
		if err != nil || !exists {
			return ""
		}
		return got.(*schema.VM).Name
	}, 10*time.Second, 100*time.Millisecond).Should(Equal("from-query"))
}

func TestReflectorCRCEventHandlerQueueByKey(t *testing.T) {
	RegisterTestingT(t)

	server := fake.NewServer(nil)
	server.Serve()
	defer server.Stop()

	vm := &schema.VM{
		ObjectMeta: schema.ObjectMeta{ID: "vm-2"},
		Name:       "from-query",
		Status:     schema.VMStatusRunning,
	}
	server.TrackerFactory().VM().CreateOrUpdate(vm)

	objectStore := cache.NewIndexer(func(obj interface{}) (string, error) { return obj.(*schema.VM).ID, nil }, nil)
	queue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "test-crc")
	defer queue.ShutDown()
	crcEventCh := make(chan *CrcEvent, 1)
	r := &reflector{
		client:          server.NewClient(),
		store:           objectStore,
		expectType:      gqlType{reflect.TypeOf(&schema.VM{})},
		crcEvent:        crcEventCh,
		storeEventQueue: queue,
	}
	go ReconcileWorker("test-crc", queue, r.processStoreEvent)()

	stopCh := make(chan struct{})
	defer close(stopCh)
	go r.crcEventHandler(stopCh)

	crcEventCh <- &CrcEvent{
		EventType: CrcEventInsert,
		NewObj: &schema.VM{
			ObjectMeta: schema.ObjectMeta{ID: vm.ID},
			Name:       "from-event",
			Status:     schema.VMStatusStopped,
		},
	}

	Eventually(func() string {
		got, exists, err := objectStore.GetByKey(vm.ID)
		if err != nil || !exists {
			return ""
		}
		return got.(*schema.VM).Name
	}, 10*time.Second, 100*time.Millisecond).Should(Equal("from-query"))
}

func TestReflectorProcessStoreEventDeleteByKey(t *testing.T) {
	RegisterTestingT(t)

	objectStore := cache.NewIndexer(func(obj interface{}) (string, error) { return obj.(*schema.VM).ID, nil }, nil)

	obj := &schema.VM{
		ObjectMeta: schema.ObjectMeta{ID: "vm-3"},
		Name:       "stale",
		Status:     schema.VMStatusRunning,
	}
	if err := objectStore.Add(obj); err != nil {
		t.Fatalf("add stale object: %v", err)
	}

	if err := objectStore.Delete(&schema.VM{ObjectMeta: schema.ObjectMeta{ID: obj.ID}}); err != nil {
		t.Fatalf("delete by key tombstone: %v", err)
	}
	if _, exists, err := objectStore.GetByKey(obj.ID); err != nil || exists {
		t.Fatalf("expected object deleted, exists=%t err=%v", exists, err)
	}
}

func TestReflectorProcessStoreEventDeleteByKeyWhenQueryMissing(t *testing.T) {
	RegisterTestingT(t)

	server := fake.NewServer(nil)
	server.Serve()
	defer server.Stop()

	objectStore := cache.NewIndexer(func(obj interface{}) (string, error) { return obj.(*schema.VM).ID, nil }, nil)
	obj := &schema.VM{
		ObjectMeta: schema.ObjectMeta{ID: "vm-delete-by-query-miss"},
		Name:       "stale",
		Status:     schema.VMStatusRunning,
	}
	if err := objectStore.Add(obj); err != nil {
		t.Fatalf("add stale object: %v", err)
	}

	r := &reflector{
		client:     server.NewClient(),
		store:      objectStore,
		expectType: gqlType{reflect.TypeOf(&schema.VM{})},
	}

	if err := r.processStoreEvent(obj.ID); err != nil {
		t.Fatalf("processStoreEvent returned error: %v", err)
	}

	if _, exists, err := objectStore.GetByKey(obj.ID); err != nil || exists {
		t.Fatalf("expected object deleted by processStoreEvent, exists=%t err=%v", exists, err)
	}
}

type noKeySettableObject struct {
	ID string `json:"id"`
}

func (noKeySettableObject) GetQueryRequestWithID(id string, _ map[string][]string) string {
	return fmt.Sprintf(`query {vms(where:{id:"%s"}) {id}}`, id)
}

func (noKeySettableObject) UnmarshalSlice(_ json.RawMessage, _ interface{}) error {
	return nil
}

func TestReflectorProcessStoreEventReturnErrorWhenObjectNotKeySettable(t *testing.T) {
	RegisterTestingT(t)

	server := fake.NewServer(nil)
	server.Serve()
	defer server.Stop()

	key := "non-keysettable-id"
	r := &reflector{
		client:     server.NewClient(),
		store:      cache.NewIndexer(TowerObjectKey, nil),
		expectType: gqlType{reflect.TypeOf(noKeySettableObject{})},
	}

	err := r.processStoreEvent(key)
	if err == nil {
		t.Fatalf("expected error when object doesn't implement schema.KeySettable")
	}
	if !strings.Contains(err.Error(), key) {
		t.Fatalf("expected error to contain key %q, got %v", key, err)
	}
	if !strings.Contains(err.Error(), "schema.KeySettable") {
		t.Fatalf("expected error to mention schema.KeySettable, got %v", err)
	}
}
