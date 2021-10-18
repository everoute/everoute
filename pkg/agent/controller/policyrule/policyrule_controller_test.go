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

package policyrule

import (
	"context"
	"net"
	"os"
	"testing"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/everoute/everoute/pkg/agent/datapath"
	networkpolicyv1alpha1 "github.com/everoute/everoute/pkg/apis/policyrule/v1alpha1"
)

var (
	SrcIPAddr1  = "10.10.10.1"
	SrcIPAddr2  = "10.10.10.2"
	DstIPAddr1  = "10.10.20.1"
	DstIPAddr2  = "10.10.20.2"
	DstIPAddr3  = "10.10.20.3"
	SrcPort1    = 80
	SrcPort2    = 8080
	DstPort1    = 443
	DstPort2    = 8443
	IPProtocol1 = "UDP"
	IPProtocol2 = "TCP"
)

var reconciler *PolicyRuleReconciler
var queue workqueue.RateLimitingInterface

var (
	policyRule1 = &networkpolicyv1alpha1.PolicyRule{
		TypeMeta: v1.TypeMeta{
			Kind:       "PolicyRule",
			APIVersion: "policyrule.everoute.io/v1alpha1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: "securityPolicy1-policyRule1",
		},
		Spec: networkpolicyv1alpha1.PolicyRuleSpec{
			Direction:  networkpolicyv1alpha1.RuleDirectionOut,
			RuleType:   networkpolicyv1alpha1.RuleTypeNormalRule,
			Tier:       "tier0",
			SrcIPAddr:  SrcIPAddr1,
			DstIPAddr:  DstIPAddr1,
			IPProtocol: IPProtocol1,
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
			APIVersion: "policyrule.everoute.io/v1alpha1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: "securityPolicy1-policyRule2",
		},
		Spec: networkpolicyv1alpha1.PolicyRuleSpec{
			Direction:  networkpolicyv1alpha1.RuleDirectionOut,
			RuleType:   networkpolicyv1alpha1.RuleTypeNormalRule,
			Tier:       "tier0",
			SrcIPAddr:  SrcIPAddr2,
			DstIPAddr:  DstIPAddr2,
			IPProtocol: IPProtocol2,
			SrcPort:    uint16(SrcPort2),
			DstPort:    uint16(DstPort2),
			TCPFlags:   "",
			Action:     networkpolicyv1alpha1.RuleActionAllow,
		},
		Status: networkpolicyv1alpha1.PolicyRuleStatus{},
	}
)

var (
	datapathConfig = datapath.Config{
		ManagedVDSMap: map[string]string{
			"ovsbr1": "ovsbr1",
		},
	}
)

func TestMain(m *testing.M) {
	ofPortUpdateChan := make(chan map[string][]net.IP, 100)

	if err := datapath.ExcuteCommand(datapath.SetupBridgeChain, "ovsbr1"); err != nil {
		klog.Fatalf("Failed to setup bridgechain, error: %v", err)
	}

	stopChan := make(<-chan struct{})
	datapathManager := datapath.NewDatapathManager(&datapathConfig, ofPortUpdateChan)
	datapathManager.InitializeDatapath(stopChan)

	queue = workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	reconciler = newFakeReconciler(datapathManager, policyRule1, policyRule2)

	exitCode := m.Run()
	_ = datapath.ExcuteCommand(datapath.CleanBridgeChain, "ovsbr1")
	os.Exit(exitCode)
}

func newFakeReconciler(datapathManager *datapath.DpManager, initObjs ...runtime.Object) *PolicyRuleReconciler {
	// Add scheme
	scheme := runtime.NewScheme()
	_ = networkpolicyv1alpha1.AddToScheme(scheme)

	return &PolicyRuleReconciler{
		Client:              fakeclient.NewFakeClientWithScheme(scheme, initObjs...),
		Scheme:              scheme,
		DatapathManager:     datapathManager,
		flowKeyReferenceMap: make(map[string]sets.String),
	}
}

func processQueue(r reconcile.Reconciler, q workqueue.RateLimitingInterface) error {
	for i := 0; i < q.Len(); i++ {
		request, _ := q.Get()
		if _, err := r.Reconcile(request.(ctrl.Request)); err != nil {
			return err
		}
		q.Done(request)
	}

	return nil
}

func TestProcessPolicyRule(t *testing.T) {
	// AddPolicyRule event
	t.Run("PolicyRule add", func(t *testing.T) {
		reconciler.addPolicyRule(event.CreateEvent{
			Meta:   policyRule1.GetObjectMeta(),
			Object: policyRule1,
		}, queue)

		if err := processQueue(reconciler, queue); err != nil {
			t.Errorf("failed to process add policyRule1 %v.", policyRule1)
		}

		flowKey := flowKeyFromRuleName(policyRule1.Name)
		datapathRules := reconciler.DatapathManager.Rules
		if _, ok := datapathRules[flowKey]; !ok {
			t.Errorf("Failed to add policyRule1 %v to datapath.", policyRule1)
		}
	})

	// UpdatePolicyRule event: delete event && add event
	t.Run("PolicyRule Del", func(t *testing.T) {
		reconciler.addPolicyRule(event.CreateEvent{
			Meta:   policyRule2.GetObjectMeta(),
			Object: policyRule2,
		}, queue)

		if err := processQueue(reconciler, queue); err != nil {
			t.Errorf("Failed to add policyRule2 %v from datapath.", policyRule2)
		}

		flowKey := flowKeyFromRuleName(policyRule1.Name)
		datapathRules := reconciler.DatapathManager.Rules
		if _, ok := datapathRules[flowKey]; !ok {
			t.Errorf("Failed to add policyRule2 %v from datapath.", policyRule2)
		}

		reconciler.deletePolicyRule(event.DeleteEvent{
			Meta:   policyRule2.GetObjectMeta(),
			Object: policyRule2,
		}, queue)

		ctx := context.Background()
		if err := reconciler.Delete(ctx, policyRule2); err != nil {
			t.Errorf("failed to del policyRule2 %v.", policyRule2)
		}

		if err := processQueue(reconciler, queue); err != nil {
			t.Errorf("failed to process del policyRule2 %v.", policyRule2)
		}

		datapathRules = reconciler.DatapathManager.Rules
		if _, ok := datapathRules["securityPolicy1-policyRule2"]; ok {
			t.Errorf("Failed to del policyRule2 %v.", policyRule2)
		}
	})
}
