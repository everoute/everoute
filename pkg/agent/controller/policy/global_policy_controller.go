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

package policy

import (
	"context"
	"fmt"

	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/everoute/everoute/pkg/agent/controller/policy/cache"
	rulev1alpha1 "github.com/everoute/everoute/pkg/apis/policyrule/v1alpha1"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/utils"
)

// ReconcileGlobalPolicy handle GlobalPolicy. At most one GlobalPolicy at the same time,
// so we full sync PolicyRules every reconcile.
func (r *Reconciler) ReconcileGlobalPolicy(_ ctrl.Request) (ctrl.Result, error) {
	var newPolicyRule, oldPolicyRule rulev1alpha1.PolicyRuleList

	oldPolicyRuleList := r.globalRuleCache.List()
	for _, rule := range oldPolicyRuleList {
		oldPolicyRule.Items = append(oldPolicyRule.Items, rule.(rulev1alpha1.PolicyRule))
	}

	newPolicyRule, err := r.calculateExpectGlobalPolicyRules()
	if err != nil {
		klog.Errorf("unable calculate global PolicyRules: %s", err)
		return ctrl.Result{}, err
	}
	if err := r.updateGlobalPolicyCache(oldPolicyRule, newPolicyRule); err != nil {
		klog.Errorf("unable update global PolicyRules cache: %s", err)
		return ctrl.Result{}, err
	}

	r.syncPolicyRulesUntilSuccess(oldPolicyRule, newPolicyRule)
	return ctrl.Result{}, nil
}

func (r *Reconciler) updateGlobalPolicyCache(oldRule, newRule rulev1alpha1.PolicyRuleList) error {
	for _, rule := range oldRule.Items {
		if err := r.globalRuleCache.Delete(rule); err != nil {
			return err
		}
	}

	for _, rule := range newRule.Items {
		if err := r.globalRuleCache.Add(rule); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reconciler) calculateExpectGlobalPolicyRules() (rulev1alpha1.PolicyRuleList, error) {
	policyList := securityv1alpha1.GlobalPolicyList{}
	err := r.List(context.Background(), &policyList)
	if err != nil {
		return rulev1alpha1.PolicyRuleList{}, err
	}

	switch len(policyList.Items) {
	case 1:
		ruleList, err := getGlobalPolicyRules(&policyList.Items[0])
		return ruleList, err
	case 0:
		return rulev1alpha1.PolicyRuleList{}, nil
	default:
		return rulev1alpha1.PolicyRuleList{}, fmt.Errorf("unexpect multiple global policy found")
	}
}

func getGlobalPolicyRules(policy *securityv1alpha1.GlobalPolicy) (rulev1alpha1.PolicyRuleList, error) {
	var policyRuleList rulev1alpha1.PolicyRuleList

	// global default rule
	policyRuleList.Items = append(policyRuleList.Items,
		newGlobalPolicyRulePair("", rulev1alpha1.RuleTypeGlobalDefaultRule, rulev1alpha1.RuleAction(policy.Spec.DefaultAction))...,
	)

	// global white list rule
	for item := range policy.Spec.Whitelist {
		ipNets, err := utils.ParseIPBlock(&policy.Spec.Whitelist[item])
		if err != nil {
			return rulev1alpha1.PolicyRuleList{}, err
		}
		for _, ipNet := range ipNets {
			policyRuleList.Items = append(policyRuleList.Items,
				newGlobalPolicyRulePair(ipNet.String(), rulev1alpha1.RuleTypeNormalRule, rulev1alpha1.RuleActionAllow)...,
			)
		}
	}

	return policyRuleList, nil
}

func newGlobalPolicyRulePair(ipCIDR string, ruleType rulev1alpha1.RuleType, ruleAction rulev1alpha1.RuleAction) []rulev1alpha1.PolicyRule {
	var defaultLabels = map[string]string{constants.IsGlobalPolicyRuleLabel: ""}
	var ingressRule, egressRule rulev1alpha1.PolicyRule

	ingressRule.Spec = rulev1alpha1.PolicyRuleSpec{
		Direction: rulev1alpha1.RuleDirectionIn,
		RuleType:  ruleType,
		Tier:      constants.Tier2,
		DstIPAddr: ipCIDR,
		Action:    ruleAction,
	}
	ingressRule.Name = fmt.Sprintf("global-%s", cache.GenerateFlowKey(&ingressRule.Spec))
	ingressRule.Labels = defaultLabels

	egressRule.Spec = rulev1alpha1.PolicyRuleSpec{
		Direction: rulev1alpha1.RuleDirectionOut,
		RuleType:  ruleType,
		Tier:      constants.Tier2,
		SrcIPAddr: ipCIDR,
		Action:    ruleAction,
	}
	egressRule.Name = fmt.Sprintf("global-%s", cache.GenerateFlowKey(&egressRule.Spec))
	egressRule.Labels = defaultLabels

	return []rulev1alpha1.PolicyRule{ingressRule, egressRule}
}
