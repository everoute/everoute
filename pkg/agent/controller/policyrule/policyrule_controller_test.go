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

package policyrule

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/contiv/ofnet"
	"github.com/contiv/ofnet/ovsdbDriver"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	networkpolicyv1alpha1 "github.com/smartxworks/lynx/pkg/apis/policyrule/v1alpha1"
)

var (
	SrcIpAddr1  = "10.10.10.1"
	SrcIpAddr2  = "10.10.10.2"
	DstIpAddr1  = "10.10.20.1"
	DstIpAddr2  = "10.10.20.2"
	DstIpAddr3  = "10.10.20.3"
	SrcPort1    = 80
	SrcPort2    = 8080
	DstPort1    = 443
	DstPort2    = 8443
	IpProtocol1 = "UDP"
	IpProtocol2 = "TCP"
	IpProtocol3 = "ICMP"
)

const (
	BridgeName = "vlanArpLearnBridge"
	DPName     = "vlanArpLearner"
	LocalIp    = "127.0.0.1"
	RPCPort    = 30000
	OVSPort    = 30001
)

var reconciler *PolicyRuleReconciler
var queue workqueue.RateLimitingInterface

var (
	policyRule1 = &networkpolicyv1alpha1.PolicyRule{
		TypeMeta: v1.TypeMeta{
			Kind:       "PolicyRule",
			APIVersion: "policyrule.lynx.smartx.com/v1alpha1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: "securityPolicy1-policyRule1",
		},
		Spec: networkpolicyv1alpha1.PolicyRuleSpec{
			Direction:  networkpolicyv1alpha1.RuleDirectionOut,
			RuleType:   networkpolicyv1alpha1.RuleTypeNormalRule,
			Tier:       "tier0",
			SrcIPAddr:  SrcIpAddr1,
			DstIPAddr:  DstIpAddr1,
			IPProtocol: IpProtocol1,
			SrcPort:    uint16(SrcPort1),
			DstPort:    uint16(DstPort1),
			TCPFlags:   "",
			Action:     networkpolicyv1alpha1.RuleActionAllow,
		},
		Status: networkpolicyv1alpha1.PolicyRuleStatus{},
	}
	policyRule2 = &networkpolicyv1alpha1.PolicyRule{
		TypeMeta: v1.TypeMeta{
			Kind:       "PolicyRule",
			APIVersion: "policyrule.lynx.smartx.com/v1alpha1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: "securityPolicy1-policyRule2",
		},
		Spec: networkpolicyv1alpha1.PolicyRuleSpec{
			Direction:  networkpolicyv1alpha1.RuleDirectionOut,
			RuleType:   networkpolicyv1alpha1.RuleTypeNormalRule,
			Tier:       "tier0",
			SrcIPAddr:  SrcIpAddr2,
			DstIPAddr:  DstIpAddr2,
			IPProtocol: IpProtocol2,
			SrcPort:    uint16(SrcPort2),
			DstPort:    uint16(DstPort2),
			TCPFlags:   "",
			Action:     networkpolicyv1alpha1.RuleActionAllow,
		},
		Status: networkpolicyv1alpha1.PolicyRuleStatus{},
	}
	policyRule2Updated = &networkpolicyv1alpha1.PolicyRule{
		TypeMeta: v1.TypeMeta{
			Kind:       "PolicyRule",
			APIVersion: "policyrule.lynx.smartx.com/v1alpha1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: "securityPolicy1-policyRule2Updated",
		},
		Spec: networkpolicyv1alpha1.PolicyRuleSpec{
			Direction:  networkpolicyv1alpha1.RuleDirectionOut,
			RuleType:   networkpolicyv1alpha1.RuleTypeNormalRule,
			Tier:       "tier0",
			SrcIPAddr:  SrcIpAddr2,
			DstIPAddr:  DstIpAddr3,
			IPProtocol: IpProtocol2,
			SrcPort:    uint16(SrcPort2),
			DstPort:    uint16(DstPort2),
			TCPFlags:   "",
			Action:     networkpolicyv1alpha1.RuleActionAllow,
		},
		Status: networkpolicyv1alpha1.PolicyRuleStatus{},
	}
)

func TestMain(m *testing.M) {
	var err error
	ofPortUpdateChan := make(chan map[uint32][]net.IP, 100)
	uplinks := []string{}

	ovsdbDriver := ovsdbDriver.NewOvsDriver(BridgeName)
	agent, err := ofnet.NewOfnetAgent(BridgeName, DPName, net.ParseIP(LocalIp), RPCPort, OVSPort, nil, uplinks, ofPortUpdateChan)
	if err != nil {
		fmt.Println("Init ofnetAgent failed.")
		return
	}
	err = ovsdbDriver.AddController(LocalIp, OVSPort)
	if err != nil {
		fmt.Println("Init ovs controller failed")
		return
	}

	agent.WaitForSwitchConnection()

	queue = workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	reconciler = newFakeReconciler(agent, policyRule1, policyRule2)

	exitCode := m.Run()
	os.Exit(exitCode)
}

func newFakeReconciler(agent *ofnet.OfnetAgent, initObjs ...runtime.Object) *PolicyRuleReconciler {
	// Add scheme
	scheme := runtime.NewScheme()
	_ = networkpolicyv1alpha1.AddToScheme(scheme)

	return &PolicyRuleReconciler{
		Client:              fakeclient.NewFakeClientWithScheme(scheme, initObjs...),
		Scheme:              scheme,
		Agent:               agent,
		flowKeyReferenceMap: make(map[string]sets.String),
	}
}

func processQueue(r reconcile.Reconciler, q workqueue.RateLimitingInterface) error {
	for i := 0; i < q.Len(); i++ {
		request, _ := q.Get()
		if _, err := r.Reconcile(context.Background(), request.(ctrl.Request)); err != nil {
			return err
		}
		q.Done(request)
	}

	return nil
}

func TestProcessPolicyRule(t *testing.T) {
	// AddPolicyRule event
	t.Run("PolicyRule add", func(t *testing.T) {
		queue.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Name:      policyRule1.GetName(),
			Namespace: policyRule1.GetNamespace(),
		}})

		if err := processQueue(reconciler, queue); err != nil {
			t.Errorf("failed to process add policyRule1 %v.", policyRule1)
		}

		flowKey := flowKeyFromRuleName(policyRule1.Name)
		datapathRules := reconciler.Agent.GetDatapath().GetPolicyAgent().Rules
		if _, ok := datapathRules[flowKey]; !ok {
			t.Errorf("Failed to add policyRule1 %v to datapath.", policyRule1)
		}
	})

	// UpdatePolicyRule event: delete event && add event
	t.Run("PolicyRule Del", func(t *testing.T) {
		queue.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Name:      policyRule2.GetName(),
			Namespace: policyRule2.GetNamespace(),
		}})

		if err := processQueue(reconciler, queue); err != nil {
			t.Errorf("Failed to add policyRule2 %v from datapath.", policyRule2)
		}

		flowKey := flowKeyFromRuleName(policyRule1.Name)
		datapathRules := reconciler.Agent.GetDatapath().GetPolicyAgent().Rules
		if _, ok := datapathRules[flowKey]; !ok {
			t.Errorf("Failed to add policyRule2 %v from datapath.", policyRule2)
		}

		queue.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Name:      policyRule2.GetName(),
			Namespace: policyRule2.GetNamespace(),
		}})

		ctx := context.Background()
		reconciler.Delete(ctx, policyRule2)

		if err := processQueue(reconciler, queue); err != nil {
			t.Errorf("failed to process del policyRule2 %v.", policyRule2)
		}

		datapathRules = reconciler.Agent.GetDatapath().GetPolicyAgent().Rules
		if _, ok := datapathRules["securityPolicy1-policyRule2"]; ok {
			t.Errorf("Failed to del policyRule2 %v.", policyRule2)
		}
	})
}
