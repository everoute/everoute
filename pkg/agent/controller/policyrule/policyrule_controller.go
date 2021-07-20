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
	"strings"
	"sync"

	"github.com/contiv/ofnet"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	networkpolicyv1alpha1 "github.com/smartxworks/lynx/pkg/apis/policyrule/v1alpha1"
)

var (
	defaultRulePriority = 0
)

// PolicyRuleReconciler reconciles a PolicyRule object
type PolicyRuleReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Agent  *ofnet.OfnetAgent

	flowKeyReferenceMapLock sync.RWMutex
	flowKeyReferenceMap     map[string]sets.String // Map flowKey to policyRule names
}

func (r *PolicyRuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if mgr == nil {
		return fmt.Errorf("can't setup with nil manager")
	}

	r.flowKeyReferenceMap = make(map[string]sets.String)

	c, err := controller.New("policyrule-controller", mgr, controller.Options{
		Reconciler: r,
	})
	if err != nil {
		return err
	}

	c.Watch(&source.Kind{Type: &networkpolicyv1alpha1.PolicyRule{}}, &handler.Funcs{
		CreateFunc: r.addPolicyRule,
		DeleteFunc: r.deletePolicyRule,
	})

	return nil
}

// +kubebuilder:rbac:groups=networkpolicy.lynx.smartx.com,resources=policyrules,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networkpolicy.lynx.smartx.com,resources=policyrules/status,verbs=get;update;patch

func (r *PolicyRuleReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	var ctx = context.Background()
	var policyRule = networkpolicyv1alpha1.PolicyRule{}

	err := r.Get(ctx, req.NamespacedName, &policyRule)
	if client.IgnoreNotFound(err) != nil {
		klog.Errorf("unable to fetch policyRule %s: %s", req.Name, err.Error())
		return ctrl.Result{}, err
	}

	if errors.IsNotFound(err) || !policyRule.DeletionTimestamp.IsZero() {
		r.processPolicyRuleDelete(req.Name)
		return ctrl.Result{}, nil
	}

	r.processPolicyRuleAdd(&policyRule)

	return ctrl.Result{}, nil
}

func (r *PolicyRuleReconciler) addPolicyRule(e event.CreateEvent, q workqueue.RateLimitingInterface) {
	_, ok := e.Object.(*networkpolicyv1alpha1.PolicyRule)
	if !ok {
		klog.Errorf("addPolicyRule receive event %v with error object", e)
		return
	}

	if e.Meta == nil {
		klog.Errorf("AddPolicyRule received with no metadata event: %v", e)
		return
	}

	q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
		Namespace: e.Meta.GetNamespace(),
		Name:      e.Meta.GetName(),
	}})
}

func (r *PolicyRuleReconciler) deletePolicyRule(e event.DeleteEvent, q workqueue.RateLimitingInterface) {
	_, ok := e.Object.(*networkpolicyv1alpha1.PolicyRule)
	if !ok {
		klog.Errorf("addPolicyRule receive event %v with error object", e)
		return
	}

	if e.Meta == nil {
		klog.Errorf("AddPolicyRule received with no metadata event: %v", e)
		return
	}

	q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
		Namespace: e.Meta.GetNamespace(),
		Name:      e.Meta.GetName(),
	}})
}

func (r *PolicyRuleReconciler) processPolicyRuleDelete(ruleName string) {
	r.flowKeyReferenceMapLock.Lock()
	defer r.flowKeyReferenceMapLock.Unlock()

	var flowKey = flowKeyFromRuleName(ruleName)
	if r.flowKeyReferenceMap[flowKey] == nil {
		// already deleted
		return
	}

	r.flowKeyReferenceMap[flowKey].Delete(ruleName)

	if r.flowKeyReferenceMap[flowKey].Len() == 0 {
		delete(r.flowKeyReferenceMap, flowKey)

		klog.Infof("remove rule %s from datapath", flowKey)
		r.deletePolicyRuleFromDatapath(flowKey)
	}
}

func (r *PolicyRuleReconciler) processPolicyRuleAdd(policyRule *networkpolicyv1alpha1.PolicyRule) {
	r.flowKeyReferenceMapLock.Lock()
	defer r.flowKeyReferenceMapLock.Unlock()

	var flowKey = flowKeyFromRuleName(policyRule.Name)

	if r.flowKeyReferenceMap[flowKey] == nil {
		r.flowKeyReferenceMap[flowKey] = sets.NewString()

		klog.Infof("add rule %s to datapath", flowKey)
		r.addPolicyRuleToDatapath(flowKey, &policyRule.Spec)
	}

	r.flowKeyReferenceMap[flowKey].Insert(policyRule.Name)
}

func (r *PolicyRuleReconciler) deletePolicyRuleFromDatapath(flowKey string) {
	var err error
	ofnetPolicyRule := &ofnet.OfnetPolicyRule{
		RuleId: flowKey,
	}

	datapath := r.Agent.GetDatapath()
	err = datapath.GetPolicyAgent().DelRule(ofnetPolicyRule, nil)
	if err != nil {
		// Update policyRule enforce status for statistics and display. TODO
		klog.Fatalf("del ofnetPolicyRule %v failed,", ofnetPolicyRule)
	}
}

func (r *PolicyRuleReconciler) addPolicyRuleToDatapath(ruleId string, rule *networkpolicyv1alpha1.PolicyRuleSpec) {
	// Process PolicyRule: convert it to ofnetPolicyRule, filter illegal PolicyRule; install ofnetPolicyRule flow
	var err error
	ofnetPolicyRule := toOfnetPolicyRule(ruleId, rule)
	ruleDirection := getRuleDirection(rule.Direction)
	ruleTier := getRuleTier(rule.Tier)

	datapath := r.Agent.GetDatapath()
	err = datapath.GetPolicyAgent().AddRuleToTier(ofnetPolicyRule, ruleDirection, ruleTier)
	if err != nil {
		// Update policyRule enforce status for statistics and display. TODO
		klog.Fatalf("add ofnetPolicyRule %v failed,", ofnetPolicyRule)
	}
}

func toOfnetPolicyRule(ruleId string, rule *networkpolicyv1alpha1.PolicyRuleSpec) *ofnet.OfnetPolicyRule {
	ipProtoNo := protocolToInt(rule.IpProtocol)
	ruleAction := getRuleAction(rule.Action)

	var rulePriority int
	if rule.DefaultPolicyRule {
		rulePriority = defaultRulePriority
	} else {
		rulePriority = int(rule.Priority)
	}

	ofnetPolicyRule := &ofnet.OfnetPolicyRule{
		RuleId:     ruleId,
		Priority:   rulePriority,
		SrcIpAddr:  rule.SrcIpAddr,
		DstIpAddr:  rule.DstIpAddr,
		IpProtocol: ipProtoNo,
		SrcPort:    rule.SrcPort,
		DstPort:    rule.DstPort,
		TcpFlags:   rule.TcpFlags,
		Action:     ruleAction,
	}

	return ofnetPolicyRule
}

func protocolToInt(ipProtocol string) uint8 {
	var protoNo uint8
	switch ipProtocol {
	case "ICMP":
		protoNo = 1
	case "TCP":
		protoNo = 6
	case "UDP":
		protoNo = 17
	case "":
		protoNo = 0
	default:
		klog.Fatalf("unsupport ipProtocol %s in policyRule", ipProtocol)
	}
	return protoNo
}

func getRuleAction(ruleAction networkpolicyv1alpha1.RuleAction) string {
	var action string
	switch ruleAction {
	case networkpolicyv1alpha1.RuleActionAllow:
		action = "allow"
	case networkpolicyv1alpha1.RuleActionDrop:
		action = "deny"
	default:
		klog.Fatalf("unsupport ruleAction %s in policyrule.", ruleAction)
		return action
	}
	return action
}

func getRuleDirection(ruleDir networkpolicyv1alpha1.RuleDirection) uint8 {
	var direction uint8
	switch ruleDir {
	case networkpolicyv1alpha1.RuleDirectionOut:
		direction = 0
	case networkpolicyv1alpha1.RuleDirectionIn:
		direction = 1
	default:
		klog.Fatalf("unsupport ruleDirection %s in policyRule.", ruleDir)
	}
	return direction
}

func getRuleTier(ruleTier string) uint8 {
	var tier uint8
	switch ruleTier {
	case "tier0":
		tier = 0
	case "tier1":
		tier = 1
	case "tier2":
		tier = 2
	default:
		klog.Fatalf("unsupport ruleTier %s in policyRule.", ruleTier)
	}
	return tier
}

func flowKeyFromRuleName(ruleName string) string {
	// rule name format like: policyname-rulename-namehash-flowkey
	keys := strings.Split(ruleName, "-")
	return keys[len(keys)-1]
}
