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

	"github.com/contiv/ofnet"
	errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
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
}

func (r *PolicyRuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if mgr == nil {
		return fmt.Errorf("can't setup with nil manager")
	}

	c, err := controller.New("policyrule-controller", mgr, controller.Options{
		Reconciler: r,
	})
	if err != nil {
		return err
	}

	c.Watch(&source.Kind{Type: &networkpolicyv1alpha1.PolicyRuleList{}}, &handler.Funcs{
		CreateFunc: r.addPolicyRule,
		DeleteFunc: r.deletePolicyRule,
	})

	return nil
}

// +kubebuilder:rbac:groups=networkpolicy.lynx.smartx.com,resources=policyrules,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networkpolicy.lynx.smartx.com,resources=policyrules/status,verbs=get;update;patch

func (r *PolicyRuleReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	klog.Infof("PolicyRuleReconiler received policyRule %s operation.", req.NamespacedName)

	policyRule := networkpolicyv1alpha1.PolicyRule{}
	err := r.Get(ctx, req.NamespacedName, &policyRule)
	if err != nil {
		klog.Errorf("unable to fetch policyRule %s: %s", req.Name, err.Error())
		if errors.IsNotFound(err) {
			r.deletePolicyRuleFromDatapath(req.Name)

			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, err
	}

	if policyRule.ObjectMeta.DeletionTimestamp != nil {
		r.deletePolicyRuleFromDatapath(req.Name)
		return ctrl.Result{}, nil
	}

	r.addPolicyRuleToDatapath(&policyRule)

	return ctrl.Result{}, nil
}

func (r *PolicyRuleReconciler) addPolicyRule(e event.CreateEvent, q workqueue.RateLimitingInterface) {
	_, ok := e.Object.(*networkpolicyv1alpha1.PolicyRule)
	if !ok {
		klog.Errorf("addPolicyRule receive event %v with error object", e)
		return
	}

	if e.Meta == nil {
		klog.Errorf("AddPolicRule received with no metadata event: %v", e)
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
		klog.Errorf("AddPolicRule received with no metadata event: %v", e)
		return
	}

	q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
		Namespace: e.Meta.GetNamespace(),
		Name:      e.Meta.GetName(),
	}})
}

func (r *PolicyRuleReconciler) deletePolicyRuleFromDatapath(ruleId string) {
	var err error
	ofnetPolicyRule := &ofnet.OfnetPolicyRule{
		RuleId: ruleId,
	}

	datapath := r.Agent.GetDatapath()
	err = datapath.GetPolicyAgent().DelRule(ofnetPolicyRule, nil)
	if err != nil {
		// Update policyRule enforce status for statistics and display. TODO
		klog.Errorf("del ofnetPolicyRule %v failed,", ofnetPolicyRule)
	}
}

func (r *PolicyRuleReconciler) addPolicyRuleToDatapath(policyRule *networkpolicyv1alpha1.PolicyRule) {
	var err error

	// Process PolicyRule: convert it to ofnetPolicyRule, filter illegal PolicyRule; install ofnetPolicyRule flow
	ofnetPolicyRule, err := toOfnetPolicyRule(policyRule)
	if err != nil {
		klog.Errorf("Error when convert networkpolicyv1alpha1 %v policyRule to ofnetpolicyrule,", err)
	}
	rule := policyRule.Spec

	ruleDirection, err := getRuleDirection(rule.Direction)
	if err != nil {
		klog.Errorf("unsupport ruleDirection %s in policyRule", rule.Direction)
	}
	ruleTier, err := getRuleTier(rule.Tier)
	if err != nil {
		klog.Errorf("unsupport ruleTier %s in policyRule.", rule.Tier)
	}

	datapath := r.Agent.GetDatapath()
	err = datapath.GetPolicyAgent().AddRuleToTier(ofnetPolicyRule, ruleDirection, ruleTier)
	if err != nil {
		// Update policyRule enforce status for statistics and display. TODO
		klog.Errorf("add ofnetPolicyRule %v failed,", ofnetPolicyRule)
	}
}

func toOfnetPolicyRule(policyRule *networkpolicyv1alpha1.PolicyRule) (*ofnet.OfnetPolicyRule, error) {
	// Process PolicyRule: convert it to ofnetPolicyRule, filter illegal PolicyRule; install ofnetPolicyRule flow
	rule := policyRule.Spec
	ipProtoNo, err := protocolToInt(rule.IpProtocol)
	if err != nil {
		klog.Errorf("unsupport ipProtocol %s in PolicyRule", rule.IpProtocol)
		// Mark policyRule as failed
		return nil, err
	}

	var rulePriority int
	if rule.DefaultPolicyRule {
		rulePriority = defaultRulePriority
	} else {
		rulePriority = int(rule.Priority)
	}

	ruleAction, err := getRuleAction(rule.Action)
	if err != nil {
		klog.Errorf("unsupport ruleAction %s in PolicyRule", rule.Action)
		return nil, err
	}

	ofnetPolicyRule := &ofnet.OfnetPolicyRule{
		RuleId:     rule.RuleId,
		Priority:   rulePriority,
		SrcIpAddr:  rule.SrcIpAddr,
		DstIpAddr:  rule.DstIpAddr,
		IpProtocol: ipProtoNo,
		SrcPort:    rule.SrcPort,
		DstPort:    rule.DstPort,
		TcpFlags:   rule.TcpFlags,
		Action:     ruleAction,
	}

	return ofnetPolicyRule, nil
}

func protocolToInt(ipProtocol string) (uint8, error) {
	var protoNo uint8
	switch ipProtocol {
	case "ICMP":
		protoNo = 1
	case "TCP":
		protoNo = 6
	case "UDP":
		protoNo = 17
	default:
		err := fmt.Errorf("unsupport ipProtocol %s in policyRule", ipProtocol)
		return protoNo, err
	}
	return protoNo, nil
}

func getRuleAction(ruleAction networkpolicyv1alpha1.RuleAction) (string, error) {
	var action string
	switch ruleAction {
	case networkpolicyv1alpha1.RuleActionAllow:
		action = "allow"
	case networkpolicyv1alpha1.RuleActionDrop:
		action = "deny"
	default:
		err := fmt.Errorf("unsupport ruleAction %s in policyrule.", ruleAction)
		return action, err
	}
	return action, nil
}

func getRuleDirection(ruleDir networkpolicyv1alpha1.RuleDirection) (uint8, error) {
	var direction uint8
	switch ruleDir {
	case networkpolicyv1alpha1.RuleDirectionOut:
		direction = 0
	case networkpolicyv1alpha1.RuleDirectionIn:
		direction = 1
	default:
		err := fmt.Errorf("unsupport ruleDirection %s in policyRule.", ruleDir)
		return direction, err
	}
	return direction, nil
}

func getRuleTier(ruleTier string) (uint8, error) {
	var tier uint8
	switch ruleTier {
	case "tier0":
		tier = 0
	case "tier1":
		tier = 1
	case "tier2":
		tier = 2
	default:
		err := fmt.Errorf("unsupport ruleTier %s in policyRule.", ruleTier)
		return tier, err
	}
	return tier, nil
}
