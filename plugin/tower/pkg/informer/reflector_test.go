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
	"fmt"
	"reflect"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/clock"
	"k8s.io/client-go/tools/cache"

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

	server := fake.NewServer()
	server.Serve()
	defer server.Stop()

	objectStore := cache.NewIndexer(func(obj interface{}) (string, error) { return obj.(*VM).ID, nil }, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	newReflector := NewReflectorBuilder(server.NewClient())(&informer.ReflectorOptions{
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
