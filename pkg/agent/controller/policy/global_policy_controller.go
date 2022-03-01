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
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
)

const (
	DefaultGlobalPolicyName = "everoute-global-policy"
)

// ReconcileGlobalPolicy handle GlobalPolicy. At most one GlobalPolicy at the same time,
// so we full sync PolicyRules every reconcile.
func (r *Reconciler) ReconcileGlobalPolicy(_ ctrl.Request) (ctrl.Result, error) {
	var newPolicyRule, oldPolicyRule []cache.PolicyRule

	oldPolicyRuleList := r.globalRuleCache.List()
	for _, rule := range oldPolicyRuleList {
		oldPolicyRule = append(oldPolicyRule, rule.(cache.PolicyRule))
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

func (r *Reconciler) updateGlobalPolicyCache(oldRule, newRule []cache.PolicyRule) error {
	for _, rule := range oldRule {
		if err := r.globalRuleCache.Delete(rule); err != nil {
			return err
		}
	}

	for _, rule := range newRule {
		if err := r.globalRuleCache.Add(rule); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reconciler) calculateExpectGlobalPolicyRules() ([]cache.PolicyRule, error) {
	policyList := securityv1alpha1.GlobalPolicyList{}
	err := r.List(context.Background(), &policyList)
	if err != nil {
		return []cache.PolicyRule{}, err
	}

	switch len(policyList.Items) {
	case 1:
		ruleList := newGlobalPolicyRulePair("", cache.RuleTypeGlobalDefaultRule,
			cache.RuleAction(policyList.Items[0].Spec.DefaultAction))
		return ruleList, nil
	case 0:
		return []cache.PolicyRule{}, nil
	default:
		return []cache.PolicyRule{}, fmt.Errorf("unexpect multiple global policy found")
	}
}

func newGlobalPolicyRulePair(ipCIDR string, ruleType cache.RuleType, ruleAction cache.RuleAction) []cache.PolicyRule {
	var ingressRule, egressRule cache.PolicyRule

	ingressRule = cache.PolicyRule{
		Direction: cache.RuleDirectionIn,
		RuleType:  ruleType,
		Tier:      constants.Tier2,
		DstIPAddr: ipCIDR,
		Action:    ruleAction,
	}
	ingressRule.Name = fmt.Sprintf("/%s/%s/global.ingress/-%s", DefaultGlobalPolicyName, cache.GlobalPolicy, cache.GenerateFlowKey(ingressRule))

	egressRule = cache.PolicyRule{
		Direction: cache.RuleDirectionOut,
		RuleType:  ruleType,
		Tier:      constants.Tier2,
		SrcIPAddr: ipCIDR,
		Action:    ruleAction,
	}
	egressRule.Name = fmt.Sprintf("/%s/%s/global.egress/-%s", DefaultGlobalPolicyName, cache.GlobalPolicy, cache.GenerateFlowKey(egressRule))

	return []cache.PolicyRule{ingressRule, egressRule}
}
