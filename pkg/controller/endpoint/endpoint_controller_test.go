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
	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/metrics"
	"github.com/everoute/everoute/pkg/types"
	"github.com/everoute/everoute/pkg/utils"
)

const (
	endpointExternalIDKey = constants.EndpointExternalIDKey
)

var (
	ovsPortStatusA = securityv1alpha1.EndpointStatus{
		MacAddress: rand.String(10),
		IPs:        []types.IPAddress{types.IPAddress(rand.String(10))},
		Agents:     []string{"fakeAgentInfoA"},
	}
	ovsPortStatusB = securityv1alpha1.EndpointStatus{
		MacAddress: rand.String(10),
		IPs:        []types.IPAddress{types.IPAddress(rand.String(10))},
		Agents:     []string{"fakeAgentInfoA"},
	}
	ovsPortStatusC = securityv1alpha1.EndpointStatus{
		MacAddress: rand.String(10),
		IPs:        []types.IPAddress{types.IPAddress(rand.String(10))},
		Agents:     []string{"fakeAgentInfoA"},
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
									IPMap: map[types.IPAddress]*agentv1alpha1.IPInfo{
										ovsPortStatusA.IPs[0]: {
											Mac: "aa:aa:aa:aa:aa:aa",
										},
									},
								},
								{
									Name: "iface2",
									ExternalIDs: map[string]string{
										endpointExternalIDKey: "ep04",
									},
									Mac: ovsPortStatusB.MacAddress,
									IPMap: map[types.IPAddress]*agentv1alpha1.IPInfo{
										ovsPortStatusB.IPs[0]: {},
									},
								},
								{
									Name: "iface3",
									ExternalIDs: map[string]string{
										"idk1":                "idv1",
										"idk2":                "idv2",
										"idk3":                "idv3",
										endpointExternalIDKey: "ep05",
									},
									Mac: ovsPortStatusC.MacAddress,
									IPMap: map[types.IPAddress]*agentv1alpha1.IPInfo{
										ovsPortStatusC.IPs[0]: {
											Mac: "bb:bb:bb:bb:bb:bb",
										},
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
									IPMap: map[types.IPAddress]*agentv1alpha1.IPInfo{
										ovsPortStatusB.IPs[0]: {
											Mac: "",
										},
									},
								},
								{
									Name: "iface3",
									ExternalIDs: map[string]string{
										"idk1":                "idv1",
										"idk2":                "idv2",
										"idk3":                "idv3",
										endpointExternalIDKey: "ep05",
									},
									Mac: ovsPortStatusC.MacAddress,
									IPMap: map[types.IPAddress]*agentv1alpha1.IPInfo{
										ovsPortStatusC.IPs[0]: {
											Mac: "",
										},
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
									IPMap: map[types.IPAddress]*agentv1alpha1.IPInfo{},
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
									IPMap: map[types.IPAddress]*agentv1alpha1.IPInfo{
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
			Type:      securityv1alpha1.EndpointDynamic,
			StrictMac: false,
		},
	}
	fakeEndpointB = &securityv1alpha1.Endpoint{
		TypeMeta: v1.TypeMeta{
			Kind:       "Endpoint",
			APIVersion: "security.everoute.io/v1alpha1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: "fakeEndpointB",
		},
		Spec: securityv1alpha1.EndpointSpec{
			Reference: securityv1alpha1.EndpointReference{
				ExternalIDName:  endpointExternalIDKey,
				ExternalIDValue: "ep05",
			},
			Type:      securityv1alpha1.EndpointDynamic,
			StrictMac: true,
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
	fakeEndpointE = &securityv1alpha1.Endpoint{
		TypeMeta: v1.TypeMeta{
			Kind:       "Endpoint",
			APIVersion: "security.everoute.io/v1alpha1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: "fakeEndpointE",
		},
		Spec: securityv1alpha1.EndpointSpec{
			Reference: securityv1alpha1.EndpointReference{
				ExternalIDName:  endpointExternalIDKey,
				ExternalIDValue: "ep04",
			},
			Type: securityv1alpha1.EndpointStaticIP,
		},
		Status: securityv1alpha1.EndpointStatus{
			IPs: []types.IPAddress{ovsPortStatusA.IPs[0]},
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
	ep := securityv1alpha1.Endpoint{}

	return &EndpointReconciler{
		Client:         fakeclient.NewClientBuilder().WithScheme(scheme.Scheme).WithRuntimeObjects(initObjs...).WithStatusSubresource(&ep).Build(),
		Scheme:         scheme.Scheme,
		IPMigrateCount: metrics.NewIPMigrateCount(),
		ifaceCache: cache.NewIndexer(ifaceKeyFunc, cache.Indexers{
			agentIndex:      agentIndexFunc,
			externalIDIndex: externalIDIndexFunc,
			ipAddrIndex:     ipAddrIndexFunc,
		}),
	}
}

// processQueue use reconciler r process item in workqueue q, simulate processing events.
func processQueue(r reconcile.Reconciler, q workqueue.RateLimitingInterface) error {
	ctx := context.Background()
	qLen := q.Len()
	for i := 0; i < qLen; i++ {
		request, _ := q.Get()
		if _, err := r.Reconcile(ctx, request.(ctrl.Request)); err != nil {
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
	r := newFakeReconciler(fakeAgentInfoA, fakeEndpointA, fakeEndpointB, fakeEndpointD, fakeEndpointE)
	ctx := context.Background()

	t.Run("agentinfo-added", func(t *testing.T) {
		// Fake: endpoint added and agentinfo added event when controller start.
		r.addEndpoint(ctx, event.CreateEvent{
			Object: fakeEndpointA,
		}, queue)

		r.addEndpoint(ctx, event.CreateEvent{
			Object: fakeEndpointB,
		}, queue)

		r.addEndpoint(ctx, event.CreateEvent{
			Object: fakeEndpointD,
		}, queue)

		r.addEndpoint(ctx, event.CreateEvent{
			Object: fakeEndpointE,
		}, queue)

		_ = r.Client.Update(context.Background(), fakeEndpointD)
		_ = r.Client.Update(context.Background(), fakeEndpointE)

		r.addAgentInfo(ctx, event.CreateEvent{
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

		endpointStatusE := getFakeEndpoint(r.Client, fakeEndpointE.Name).Status
		if !utils.EqualIPs(endpointStatusE.IPs, fakeEndpointE.Status.IPs) {
			t.Errorf("static ip endpoint should not change ip, get %v, want %v", endpointStatusE.IPs, fakeEndpointE.Status.IPs)
		}
		if !utils.EqualStringSlice(endpointStatusE.Agents, []string{"fakeAgentInfoA"}) {
			t.Errorf("static ip endpoint should update agent, get %v, want fakeAgentInfoA", endpointStatusE)
		}

		endpointStatus = getFakeEndpoint(r.Client, fakeEndpointB.Name).Status
		newOvsPortStatusC := ovsPortStatusC.DeepCopy()
		newOvsPortStatusC.IPs = []types.IPAddress{}
		if !EqualEndpointStatus(*newOvsPortStatusC, endpointStatus) {
			t.Errorf("unmatch endpoint status, get %v, want %v", endpointStatus, ovsPortStatusC)
		}

		endpointStatus = getFakeEndpoint(r.Client, fakeEndpointA.Name).Status
		if !EqualEndpointStatus(ovsPortStatusA, endpointStatus) {
			t.Errorf("unmatch endpoint status, get %v, want %v", endpointStatus, ovsPortStatusA)
		}
		ifaces := r.ifaceCache.ListKeys()
		if len(ifaces) != 3 {
			t.Errorf("expect cache should have two iface after add agentinfo %s", fakeAgentInfoA.Name)
		}
	})

	t.Run("agentinfo-updated", func(t *testing.T) {
		_ = r.Client.Update(context.Background(), fakeEndpointE)
		endpointStatusE := getFakeEndpoint(r.Client, fakeEndpointE.Name).Status
		if !utils.EqualIPs(endpointStatusE.IPs, fakeEndpointE.Status.IPs) {
			t.Errorf("static ip endpoint should not change ip, get %v, want %v", endpointStatusE.IPs, fakeEndpointE.Status.IPs)
		}
		if !utils.EqualStringSlice(endpointStatusE.Agents, []string{"fakeAgentInfoA"}) {
			t.Errorf("static ip endpoint should update agent, get %v, want fakeAgentInfoA", endpointStatusE)
		}

		// Fake: agent will update information when ovsinfo changes.
		r.updateAgentInfo(ctx, event.UpdateEvent{
			ObjectOld: fakeAgentInfoA,

			ObjectNew: fakeAgentInfoB,
		}, queue)

		// process agentinfo update request from queue
		if err := processQueue(r, queue); err != nil {
			t.Errorf("failed to process add agentinfo request")
		}

		endpointStatusE = getFakeEndpoint(r.Client, fakeEndpointE.Name).Status
		if !utils.EqualIPs(endpointStatusE.IPs, fakeEndpointE.Status.IPs) {
			t.Errorf("static ip endpoint should not change ip, get %v, want %v", endpointStatusE.IPs, fakeEndpointE.Status.IPs)
		}
		if len(endpointStatusE.Agents) != 0 {
			t.Errorf("static ip endpoint should clean agents, get %v, want null", endpointStatusE.Agents)
		}

		endpointStatusB := getFakeEndpoint(r.Client, fakeEndpointB.Name).Status
		if !EqualEndpointStatus(ovsPortStatusC, endpointStatusB) {
			t.Errorf("unmatch endpoint status, get %v, want %v", endpointStatusB, ovsPortStatusC)
		}

		endpointStatus := getFakeEndpoint(r.Client, fakeEndpointA.Name).Status
		if !EqualEndpointStatus(ovsPortStatusB, endpointStatus) {
			t.Errorf("unmatch endpoint status, get %v, want %v", endpointStatus, ovsPortStatusB)
		}
		ifaces := r.ifaceCache.ListKeys()
		if len(ifaces) != 2 {
			t.Errorf("expect cache should have one iface after update agentinfo %s", fakeAgentInfoA.Name)
		}
	})

	t.Run("agentinfo-deleted", func(t *testing.T) {
		// Fake: agent removed from cluster delete agentinfo.
		r.deleteAgentInfo(ctx, event.DeleteEvent{
			Object: fakeAgentInfoA,
		}, queue)

		// process agentinfo delete request from queue
		if err := processQueue(r, queue); err != nil {
			t.Errorf("failed to process add agentinfo request")
		}

		_ = r.Client.Update(context.Background(), fakeEndpointE)
		endpointStatusE := getFakeEndpoint(r.Client, fakeEndpointE.Name).Status
		if !utils.EqualIPs(endpointStatusE.IPs, fakeEndpointE.Status.IPs) {
			t.Errorf("static ip endpoint should not change ip, get %v, want %v", endpointStatusE.IPs, fakeEndpointE.Status.IPs)
		}
		if len(endpointStatusE.Agents) != 0 {
			t.Errorf("static ip endpoint should clean agents, get %v, want null", endpointStatusE.Agents)
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
	ctx := context.Background()
	t.Run("interface ipset update", func(t *testing.T) {
		// agentinfo added event when controller start.
		r.addEndpoint(ctx, event.CreateEvent{
			Object: fakeEndpointA,
		}, queue)
		r.addAgentInfo(ctx, event.CreateEvent{
			Object: fakeAgentInfoA,
		}, queue)

		r.addEndpoint(ctx, event.CreateEvent{
			Object: fakeEndpointC,
		}, queue)
		r.addAgentInfo(ctx, event.CreateEvent{
			Object: fakeAgentInfoC,
		}, queue)
		// process new agentinfo create request from queue
		if err := processQueue(r, queue); err != nil {
			t.Errorf("failed to process add agentinfo request")
		}

		r.updateAgentInfo(ctx, event.UpdateEvent{
			ObjectOld: fakeAgentInfoC,
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
