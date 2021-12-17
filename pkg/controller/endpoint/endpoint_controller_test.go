/*
Copyright 2021 The Everoute Authors.

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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	agentv1alpha1 "github.com/everoute/everoute/pkg/apis/agent/v1alpha1"
	groupv1alpha1 "github.com/everoute/everoute/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/client/clientset_generated/clientset/scheme"
	"github.com/everoute/everoute/pkg/types"
)

var (
	ovsPortStatusA = securityv1alpha1.EndpointStatus{
		MacAddress: rand.String(10),
		IPs:        []types.IPAddress{types.IPAddress(rand.String(10))},
	}
	ovsPortStatusB = securityv1alpha1.EndpointStatus{
		MacAddress: rand.String(10),
		IPs:        []types.IPAddress{types.IPAddress(rand.String(10))},
	}
	fakeAgentInfoA = &agentv1alpha1.AgentInfo{
		TypeMeta: v1.TypeMeta{
			Kind:       "AgentInfo",
			APIVersion: "agent.everoute.io/v1alpha1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: "fakeAgentInfoA",
		},
		Hostname: "node01",
		OVSInfo: agentv1alpha1.OVSInfo{
			Version: "x.x.x",
			Bridges: []agentv1alpha1.OVSBridge{
				{
					Name: "bri01",
					Ports: []agentv1alpha1.OVSPort{
						{
							Name: "endpoint01",
							Interfaces: []agentv1alpha1.OVSInterface{
								{
									Name: "iface1",
									ExternalIDs: map[string]string{
										"idk1":                "idv1",
										"idk2":                "idv2",
										"idk3":                "idv3",
										endpointExternalIDKey: "ep01",
									},
									Mac: ovsPortStatusA.MacAddress,
									IPMap: map[types.IPAddress]v1.Time{
										ovsPortStatusA.IPs[0]: {},
									},
								},
							},
						},
					},
				},
			},
		},
		Conditions: []agentv1alpha1.AgentCondition{
			{
				Type:              agentv1alpha1.AgentHealthy,
				Status:            corev1.ConditionTrue,
				LastHeartbeatTime: v1.NewTime(time.Now()),
			},
		},
	}
	fakeAgentInfoB = &agentv1alpha1.AgentInfo{
		TypeMeta: v1.TypeMeta{
			Kind:       "AgentInfo",
			APIVersion: "agent.everoute.io/v1alpha1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: "fakeAgentInfoA",
		},
		Hostname: "node01",
		OVSInfo: agentv1alpha1.OVSInfo{
			Version: "x.x.x",
			Bridges: []agentv1alpha1.OVSBridge{
				{
					Name: "bri01",
					Ports: []agentv1alpha1.OVSPort{
						{
							Name: "endpoint01",
							Interfaces: []agentv1alpha1.OVSInterface{
								{
									Name: "iface1",
									ExternalIDs: map[string]string{
										"idk1":                "idv1",
										"idk2":                "idv2",
										"idk3":                "idv3",
										endpointExternalIDKey: "ep01",
									},
									Mac: ovsPortStatusB.MacAddress,
									IPMap: map[types.IPAddress]v1.Time{
										ovsPortStatusB.IPs[0]: {},
									},
								},
							},
						},
					},
				},
			},
		},
		Conditions: []agentv1alpha1.AgentCondition{
			{
				Type:              agentv1alpha1.AgentHealthy,
				Status:            corev1.ConditionTrue,
				LastHeartbeatTime: v1.NewTime(time.Now()),
			},
		},
	}
	fakeAgentInfoC = &agentv1alpha1.AgentInfo{
		TypeMeta: v1.TypeMeta{
			Kind:       "AgentInfo",
			APIVersion: "agent.everoute.io/v1alpha1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: "fakeAgentInfoC",
		},
		Hostname: "node02",
		OVSInfo: agentv1alpha1.OVSInfo{
			Version: "x.x.x",
			Bridges: []agentv1alpha1.OVSBridge{
				{
					Name: "bri01",
					Ports: []agentv1alpha1.OVSPort{
						{
							Name: "endpoint02",
							Interfaces: []agentv1alpha1.OVSInterface{
								{
									Name: "iface2",
									ExternalIDs: map[string]string{
										"idk1":                "idv1",
										"idk2":                "idv2",
										"idk3":                "idv3",
										endpointExternalIDKey: "ep01",
									},
									Mac:   ovsPortStatusA.MacAddress,
									IPMap: map[types.IPAddress]v1.Time{},
								},
							},
						},
					},
				},
			},
		},
		Conditions: []agentv1alpha1.AgentCondition{
			{
				Type:              agentv1alpha1.AgentHealthy,
				Status:            corev1.ConditionTrue,
				LastHeartbeatTime: v1.NewTime(time.Now()),
			},
		},
	}
	updatedfakeAgentInfoC = &agentv1alpha1.AgentInfo{
		TypeMeta: v1.TypeMeta{
			Kind:       "AgentInfo",
			APIVersion: "agent.everoute.io/v1alpha1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: "fakeAgentInfoC",
		},
		Hostname: "node02",
		OVSInfo: agentv1alpha1.OVSInfo{
			Version: "x.x.x",
			Bridges: []agentv1alpha1.OVSBridge{
				{
					Name: "bri01",
					Ports: []agentv1alpha1.OVSPort{
						{
							Name: "endpoint02",
							Interfaces: []agentv1alpha1.OVSInterface{
								{
									Name: "iface2",
									ExternalIDs: map[string]string{
										"idk1":                "idv1",
										"idk2":                "idv2",
										"idk3":                "idv3",
										endpointExternalIDKey: "ep01",
									},
									Mac: ovsPortStatusA.MacAddress,
									IPMap: map[types.IPAddress]v1.Time{
										ovsPortStatusA.IPs[0]: {},
									},
								},
							},
						},
					},
				},
			},
		},
		Conditions: []agentv1alpha1.AgentCondition{
			{
				Type:              agentv1alpha1.AgentHealthy,
				Status:            corev1.ConditionTrue,
				LastHeartbeatTime: v1.NewTime(time.Now()),
			},
		},
	}
	fakeEndpointA = &securityv1alpha1.Endpoint{
		TypeMeta: v1.TypeMeta{
			Kind:       "Endpoint",
			APIVersion: "security.everoute.io/v1alpha1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: "fakeEndpointA",
		},
		Spec: securityv1alpha1.EndpointSpec{
			Reference: securityv1alpha1.EndpointReference{
				ExternalIDName:  endpointExternalIDKey,
				ExternalIDValue: "ep01",
			},
			Type: securityv1alpha1.EndpointDynamic,
		},
	}
	fakeEndpointC = &securityv1alpha1.Endpoint{
		TypeMeta: v1.TypeMeta{
			Kind:       "Endpoint",
			APIVersion: "security.everoute.io/v1alpha1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: "fakeEndpointC",
		},
		Spec: securityv1alpha1.EndpointSpec{
			Reference: securityv1alpha1.EndpointReference{
				ExternalIDName:  endpointExternalIDKey,
				ExternalIDValue: "ep01",
			},
			Type: securityv1alpha1.EndpointDynamic,
		},
	}
	fakeEndpointD = &securityv1alpha1.Endpoint{
		TypeMeta: v1.TypeMeta{
			Kind:       "Endpoint",
			APIVersion: "security.everoute.io/v1alpha1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: "fakeEndpointD",
		},
		Spec: securityv1alpha1.EndpointSpec{
			Reference: securityv1alpha1.EndpointReference{
				ExternalIDName:  endpointExternalIDKey,
				ExternalIDValue: "ep04",
			},
			Type: securityv1alpha1.EndpointStatic,
		},
		Status: securityv1alpha1.EndpointStatus{
			MacAddress: rand.String(10),
			IPs:        []types.IPAddress{types.IPAddress(rand.String(10))},
		},
	}
)

// newFakeReconciler return a new EndpointReconciler with fake client, this client
// will save objects in memory.
func newFakeReconciler(initObjs ...runtime.Object) *EndpointReconciler {
	// scheme
	_ = agentv1alpha1.AddToScheme(scheme.Scheme)
	_ = securityv1alpha1.AddToScheme(scheme.Scheme)
	_ = groupv1alpha1.AddToScheme(scheme.Scheme)

	return &EndpointReconciler{
		Client: fakeclient.NewFakeClientWithScheme(scheme.Scheme, initObjs...),
		Scheme: scheme.Scheme,
		ifaceCache: cache.NewIndexer(ifaceKeyFunc, cache.Indexers{
			agentIndex:      agentIndexFunc,
			externalIDIndex: externalIDIndexFunc,
		}),
	}
}

// processQueue use reconciler r process item in workqueue q, simulate processing events.
func processQueue(r reconcile.Reconciler, q workqueue.RateLimitingInterface) error {
	qLen := q.Len()
	for i := 0; i < qLen; i++ {
		request, _ := q.Get()
		if _, err := r.Reconcile(request.(ctrl.Request)); err != nil {
			return err
		}
		q.Done(request)
	}

	return nil
}

func getFakeEndpoint(c client.Client, name string) securityv1alpha1.Endpoint {
	endpoint := securityv1alpha1.Endpoint{}
	_ = c.Get(context.Background(), k8stypes.NamespacedName{Name: name}, &endpoint)
	return endpoint
}
func getFakeAgentInfo(c client.Client, name string) agentv1alpha1.AgentInfo {
	agentinfo := agentv1alpha1.AgentInfo{}
	_ = c.Get(context.Background(), k8stypes.NamespacedName{Name: name}, &agentinfo)
	return agentinfo
}

func TestEndpointController(t *testing.T) {
	testProcessAgentinfo(t)
	testInterfaceIPUpdate(t)
}

func testProcessAgentinfo(t *testing.T) {
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	r := newFakeReconciler(fakeAgentInfoA, fakeEndpointA, fakeEndpointD)

	t.Run("agentinfo-added", func(t *testing.T) {
		// Fake: endpoint added and agentinfo added event when controller start.
		r.addEndpoint(event.CreateEvent{
			Meta:   fakeEndpointA.GetObjectMeta(),
			Object: fakeEndpointA,
		}, queue)

		r.addEndpoint(event.CreateEvent{
			Meta:   fakeEndpointD.GetObjectMeta(),
			Object: fakeEndpointD,
		}, queue)

		_ = r.Client.Update(context.Background(), fakeEndpointD)

		r.addAgentInfo(event.CreateEvent{
			Meta:   fakeAgentInfoA.GetObjectMeta(),
			Object: fakeAgentInfoA,
		}, queue)

		// process new agentinfo create request from queue
		if err := processQueue(r, queue); err != nil {
			t.Errorf("failed to process add agentinfo request")
		}

		endpointStatus := getFakeEndpoint(r.Client, fakeEndpointD.Name).Status
		if !EqualEndpointStatus(endpointStatus, fakeEndpointD.Status) {
			t.Errorf("endpoint status should not change, get %v, want %v", endpointStatus, fakeEndpointD.Status)
		}

		endpointStatus = getFakeEndpoint(r.Client, fakeEndpointA.Name).Status
		if !EqualEndpointStatus(ovsPortStatusA, endpointStatus) {
			t.Errorf("unmatch endpoint status, get %v, want %v", endpointStatus, ovsPortStatusA)
		}
		ifaces := r.ifaceCache.ListKeys()
		if len(ifaces) != 1 {
			t.Errorf("expect cache should have one iface after add agentinfo %s", fakeAgentInfoA.Name)
		}
	})

	t.Run("agentinfo-updated", func(t *testing.T) {
		// Fake: agent will update information when ovsinfo changes.
		r.updateAgentInfo(event.UpdateEvent{
			MetaOld:   fakeAgentInfoA.GetObjectMeta(),
			ObjectOld: fakeAgentInfoA,
			MetaNew:   fakeAgentInfoB.GetObjectMeta(),
			ObjectNew: fakeAgentInfoB,
		}, queue)

		// process agentinfo update request from queue
		if err := processQueue(r, queue); err != nil {
			t.Errorf("failed to process add agentinfo request")
		}

		endpointStatus := getFakeEndpoint(r.Client, fakeEndpointA.Name).Status
		if !EqualEndpointStatus(ovsPortStatusB, endpointStatus) {
			t.Errorf("unmatch endpoint status, get %v, want %v", endpointStatus, ovsPortStatusB)
		}
		ifaces := r.ifaceCache.ListKeys()
		if len(ifaces) != 1 {
			t.Errorf("expect cache should have one iface after update agentinfo %s", fakeAgentInfoA.Name)
		}
	})

	t.Run("agentinfo-deleted", func(t *testing.T) {
		// Fake: agent removed from cluster delete agentinfo.
		r.deleteAgentInfo(event.DeleteEvent{
			Meta:   fakeAgentInfoA.GetObjectMeta(),
			Object: fakeAgentInfoA,
		}, queue)

		// process agentinfo delete request from queue
		if err := processQueue(r, queue); err != nil {
			t.Errorf("failed to process add agentinfo request")
		}

		endpointStatus := getFakeEndpoint(r.Client, fakeEndpointA.Name).Status
		if !EqualEndpointStatus(securityv1alpha1.EndpointStatus{}, endpointStatus) {
			t.Errorf("unmatch endpoint status, get %v, expect empty status", endpointStatus)
		}
		ifaces := r.ifaceCache.ListKeys()
		if len(ifaces) != 0 {
			t.Errorf("expect cache should be empty after delete agentinfo %s", fakeAgentInfoA.Name)
		}
	})
}

func testInterfaceIPUpdate(t *testing.T) {
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	r := newFakeReconciler(fakeAgentInfoA, fakeAgentInfoC, fakeEndpointA, fakeEndpointC)
	t.Run("interface ipset update", func(t *testing.T) {
		// agentinfo added event when controller start.
		r.addEndpoint(event.CreateEvent{
			Meta:   fakeEndpointA.GetObjectMeta(),
			Object: fakeEndpointA,
		}, queue)
		r.addAgentInfo(event.CreateEvent{
			Meta:   fakeAgentInfoA.GetObjectMeta(),
			Object: fakeAgentInfoA,
		}, queue)

		r.addEndpoint(event.CreateEvent{
			Meta:   fakeEndpointC.GetObjectMeta(),
			Object: fakeEndpointC,
		}, queue)
		r.addAgentInfo(event.CreateEvent{
			Meta:   fakeAgentInfoC.GetObjectMeta(),
			Object: fakeAgentInfoC,
		}, queue)
		// process new agentinfo create request from queue
		if err := processQueue(r, queue); err != nil {
			t.Errorf("failed to process add agentinfo request")
		}

		r.updateAgentInfo(event.UpdateEvent{
			MetaOld:   fakeAgentInfoC.GetObjectMeta(),
			ObjectOld: fakeAgentInfoC,
			MetaNew:   updatedfakeAgentInfoC.GetObjectMeta(),
			ObjectNew: updatedfakeAgentInfoC,
		}, queue)
		// process new agentinfo create request from queue
		if err := processQueue(r, queue); err != nil {
			t.Errorf("failed to process add agentinfo request")
		}

		agentInfoA := getFakeAgentInfo(r.Client, fakeAgentInfoA.Name)
		if len(agentInfoA.OVSInfo.Bridges[0].Ports[0].Interfaces[0].IPMap) != 0 {
			t.Errorf("failed to get udpate agentinfo")
		}
	})
}
