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

package endpoint

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/event"

	agentv1alpha1 "github.com/smartxworks/lynx/pkg/apis/agent/v1alpha1"
	securityv1alpha1 "github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
	"github.com/smartxworks/lynx/pkg/types"
)

const (
	numOfAgentInfos      = 100
	numOfEndpoints       = 1000
	ovsPortsPerAgentinfo = 100
)

func getAgentInfos() []*agentv1alpha1.AgentInfo {
	agentinfos := []*agentv1alpha1.AgentInfo{}

	getRandomBridge := func() agentv1alpha1.OVSBridge {
		bridge := agentv1alpha1.OVSBridge{}

		for i := 0; i < ovsPortsPerAgentinfo; i++ {
			id := fmt.Sprintf("id%d", rand.Int63n(numOfEndpoints))

			bridge.Ports = append(bridge.Ports, agentv1alpha1.OVSPort{
				Interfaces: []agentv1alpha1.OVSInterface{{
					Mac: fmt.Sprintf("mac:address"),
					IPs: []types.IPAddress{"192.168.2.2", "192.168.1.1"},
				}},
				ExternalIDs: map[string]string{id: id},
			})
		}
		return bridge
	}

	for i := 0; i < numOfAgentInfos; i++ {
		ai := agentv1alpha1.AgentInfo{}
		ai.Name = fmt.Sprintf("agentinfo%d", i)
		ai.OVSInfo.Bridges = []agentv1alpha1.OVSBridge{getRandomBridge()}
		agentinfos = append(agentinfos, &ai)
	}

	return agentinfos
}

func getEndpoints() []*securityv1alpha1.Endpoint {
	eps := []*securityv1alpha1.Endpoint{}

	for i := 0; i < numOfEndpoints; i++ {
		ep := securityv1alpha1.Endpoint{}
		eps = append(eps, &ep)
		ep.Name = fmt.Sprintf("endpoint%d", i)

		id := fmt.Sprintf("id%d", rand.Int63n(numOfEndpoints))
		ep.Spec = securityv1alpha1.EndpointReference{
			ExternalIDName:  id,
			ExternalIDValue: id,
		}
	}
	return eps
}

func TestEndpointReconcilerPerf(t *testing.T) {
	reconciler := newFakeReconciler()
	agentInfos := getAgentInfos()
	endpoints := getEndpoints()

	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	go heartBeat(10 * time.Second)

	bgTime := time.Now()
	defer func() {
		edTime := time.Now()
		fmt.Printf("Use time %s to process %d agentinfo and %d endpoints\n", edTime.Sub(bgTime), numOfAgentInfos, numOfEndpoints)
	}()

	for _, ai := range agentInfos {
		err := reconciler.Client.Create(context.Background(), ai)
		if err != nil {
			t.Fatalf("fail to create agentinfo %s, %s", ai.Name, err)
		}
		reconciler.addAgentInfo(event.CreateEvent{Meta: ai.GetObjectMeta(), Object: ai}, queue)
	}
	for _, ep := range endpoints {
		err := reconciler.Client.Create(context.Background(), ep)
		if err != nil {
			t.Fatalf("fail to create endpoint %s, %s", ep.Name, err)
		}
		reconciler.addEndpoint(event.CreateEvent{Meta: ep.GetObjectMeta(), Object: ep}, queue)
	}

	err := processQueue(reconciler, queue)
	if err != nil {
		t.Fatal(err)
	}
}

func heartBeat(duration time.Duration) {
	for {
		select {
		case <-time.Tick(duration):
			fmt.Println("heart beat, 10s has passed ...")
		}
	}
}
