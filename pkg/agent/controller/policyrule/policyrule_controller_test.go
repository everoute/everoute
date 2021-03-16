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
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/contiv/ofnet"
	"github.com/contiv/ofnet/ovsdbDriver"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/util/workqueue"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

	networkpolicyv1alpha1 "github.com/smartxworks/lynx/pkg/apis/policyrule/v1alpha1"
)

var (
	SrcIpAddr1  = "10.10.10.1"
	SrcIpAddr2  = "10.10.10.2"
	DstIpAddr1  = "10.10.20.1"
	DstIpAddr2  = "10.10.20.2"
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
			Name: "policyRule1",
		},
		Spec: networkpolicyv1alpha1.PolicyRuleSpec{
			RuleId:            "securityPolicy1-policyRule1",
			Direction:         networkpolicyv1alpha1.RuleDirectionIn,
			DefaultPolicyRule: false,
			Tier:              "tier0",
			Priority:          100,
			SrcIpAddr:         SrcIpAddr1,
			DstIpAddr:         DstIpAddr1,
			IpProtocol:        IpProtocol1,
			SrcPort:           uint16(SrcPort1),
			DstPort:           uint16(DstPort1),
			TcpFlags:          "",
			Action:            networkpolicyv1alpha1.RuleActionAllow,
		},
		Status: networkpolicyv1alpha1.PolicyRuleStatus{},
	}
	policyRule1Updated = &networkpolicyv1alpha1.PolicyRule{
		TypeMeta: v1.TypeMeta{
			Kind:       "PolicyRule",
			APIVersion: "policyrule.lynx.smartx.com/v1alpha1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: "policyRule1Updated",
		},
		Spec: networkpolicyv1alpha1.PolicyRuleSpec{
			RuleId:            "securityPolicy1-policyRule1Updated",
			Direction:         networkpolicyv1alpha1.RuleDirectionIn,
			DefaultPolicyRule: false,
			Tier:              "tier0",
			Priority:          100,
			SrcIpAddr:         SrcIpAddr1,
			DstIpAddr:         DstIpAddr2,
			IpProtocol:        IpProtocol1,
			SrcPort:           uint16(SrcPort1),
			DstPort:           uint16(DstPort1),
			TcpFlags:          "",
			Action:            networkpolicyv1alpha1.RuleActionAllow,
		},
		Status: networkpolicyv1alpha1.PolicyRuleStatus{},
	}
	policyRule2 = &networkpolicyv1alpha1.PolicyRule{
		TypeMeta: v1.TypeMeta{
			Kind:       "PolicyRule",
			APIVersion: "policyrule.lynx.smartx.com/v1alpha1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: "policyRule2",
		},
		Spec: networkpolicyv1alpha1.PolicyRuleSpec{
			RuleId:            "securityPolicy1-policyRule2",
			Direction:         networkpolicyv1alpha1.RuleDirectionIn,
			DefaultPolicyRule: true,
			Tier:              "tier1",
			Priority:          100,
			SrcIpAddr:         SrcIpAddr2,
			DstIpAddr:         DstIpAddr2,
			IpProtocol:        IpProtocol2,
			SrcPort:           uint16(SrcPort2),
			DstPort:           uint16(DstPort2),
			TcpFlags:          "",
			Action:            networkpolicyv1alpha1.RuleActionAllow,
		},
		Status: networkpolicyv1alpha1.PolicyRuleStatus{},
	}
)

func TestMain(m *testing.M) {
	var err error
	ofPortUpdateChan := make(chan map[uint32][]net.IP, 100)
	uplinks := []string{}

	ovsdbDriver := ovsdbDriver.NewOvsDriver(BridgeName)
	agent, err := ofnet.NewOfnetAgent(BridgeName, DPName, net.ParseIP(LocalIp), RPCPort, OVSPort, uplinks, ofPortUpdateChan)
	if err != nil {
		fmt.Println("Init ofnetAgent failed.")
		return
	}
	err = ovsdbDriver.AddController(LocalIp, OVSPort)
	if err != nil {
		fmt.Println("Init ovs controller failed")
		return
	}

	queue = workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	reconciler = newFakeReconciler(agent, policyRule1, policyRule1Updated)

	exitCode := m.Run()
	os.Exit(exitCode)
}

func newFakeReconciler(agent *ofnet.OfnetAgent, initObjs ...runtime.Object) *PolicyRuleReconciler {
	// Add scheme
	scheme := runtime.NewScheme()
	_ = networkpolicyv1alpha1.AddToScheme(scheme)

	return &PolicyRuleReconciler{
		Client: fakeclient.NewFakeClientWithScheme(scheme, initObjs...),
		Scheme: scheme,
		Agent:  agent,
	}
}

func TestProcessPolicyRule(t *testing.T) {
	// AddPolicyRule event
	t.Run("PolicyRule add", func(t *testing.T) {
		reconciler.addPolicyRule(event.CreateEvent{
			Meta:   policyRule1.GetObjectMeta(),
			Object: policyRule1,
		}, queue)

		datapathRules := reconciler.Agent.GetDatapath().GetPolicyAgent().Rules
		if _, ok := datapathRules["securityPolicy1-policyRule1"]; !ok {
			t.Errorf("Failed to add policyRule1 %v to datapath.", policyRule1)
		}
	})

	// UpdatePolicyRule event: delete event && add event
	t.Run("PolicyRule Del", func(t *testing.T) {
		reconciler.deletePolicyRule(event.DeleteEvent{
			Meta:   policyRule1.GetObjectMeta(),
			Object: policyRule1,
		}, queue)
		reconciler.addPolicyRule(event.CreateEvent{
			Meta:   policyRule1Updated.GetObjectMeta(),
			Object: policyRule1Updated,
		}, queue)

		datapathRules := reconciler.Agent.GetDatapath().GetPolicyAgent().Rules
		if _, ok := datapathRules["securityPolicy1-policyRule1"]; ok {
			t.Errorf("Failed to delete policyRule1 %v from datapath.", policyRule1)
		}
		rule := datapathRules["securityPolicy1-policyRule1"]
		if rule.Rule.DstIpAddr != DstIpAddr2 {
			t.Errorf("Failed to update policyRule1 %v dstIpAddr field.", policyRule1)
		}
	})
}
