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
	"time"

	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/everoute/everoute/pkg/agent/controller/policy/cache"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	ertypes "github.com/everoute/everoute/pkg/types"
)

const (
	DefaultGlobalPolicyName = "everoute-global-policy"
)

// ReconcileGlobalPolicy handle GlobalPolicy. At most one GlobalPolicy at the same time,
// so we full sync PolicyRules every reconcile.
func (r *Reconciler) ReconcileGlobalPolicy(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)
	log.V(4).Info("Reconcile start")
	defer log.V(4).Info("Reconcile end")
	var newPolicyRule, oldPolicyRule []cache.PolicyRule

	if !r.isReadyToProcessGlobalRule(ctx) {
		log.V(4).Info("Doesn't ready to process global rule, keep waiting")
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}

	oldPolicyRuleList := r.globalRuleCache.List()
	for _, rule := range oldPolicyRuleList {
		oldPolicyRule = append(oldPolicyRule, rule.(cache.PolicyRule))
	}

	policy, newPolicyRule, err := r.calculateExpectGlobalPolicyRules()
	if err != nil {
		log.Error(err, "unable calculate global PolicyRules")
		return ctrl.Result{}, err
	}
	if err := r.updateGlobalPolicyCache(oldPolicyRule, newPolicyRule); err != nil {
		log.Error(err, "unable update global PolicyRules cache")
		return ctrl.Result{}, err
	}

	if policy != nil {
		ctx = context.WithValue(ctx, ertypes.CtxKeyObject, policy.Spec)
	}
	_ = r.syncPolicyRulesUntilSuccess(ctx, []string{}, oldPolicyRule, newPolicyRule)
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

func (r *Reconciler) calculateExpectGlobalPolicyRules() (*securityv1alpha1.GlobalPolicy, []cache.PolicyRule, error) {
	policyList := securityv1alpha1.GlobalPolicyList{}
	err := r.List(context.Background(), &policyList)
	if err != nil {
		return nil, []cache.PolicyRule{}, err
	}

	switch len(policyList.Items) {
	case 1:
		ruleList := newGlobalPolicyRulePair(policyList.Items[0])
		return &policyList.Items[0], ruleList, nil
	case 0:
		return nil, []cache.PolicyRule{}, nil
	default:
		return nil, []cache.PolicyRule{}, fmt.Errorf("unexpect multiple global policy found")
	}
}

func newGlobalPolicyRulePair(policy securityv1alpha1.GlobalPolicy) []cache.PolicyRule {
	var ingressRule, egressRule cache.PolicyRule

	ingressRule = cache.PolicyRule{
		Policy:          "/" + DefaultGlobalPolicyName,
		Direction:       cache.RuleDirectionIn,
		RuleType:        cache.RuleTypeGlobalDefaultRule,
		Tier:            constants.Tier2,
		DstIPAddr:       "",
		Action:          cache.RuleAction(policy.Spec.DefaultAction),
		EnforcementMode: string(policy.Spec.GlobalPolicyEnforcementMode),
	}
	ingressRule.Name = fmt.Sprintf("/%s/%s/global.ingress/-%s", DefaultGlobalPolicyName, cache.GlobalPolicy, cache.GenerateFlowKey(ingressRule))

	egressRule = cache.PolicyRule{
		Policy:          "/" + DefaultGlobalPolicyName,
		Direction:       cache.RuleDirectionOut,
		RuleType:        cache.RuleTypeGlobalDefaultRule,
		Tier:            constants.Tier2,
		SrcIPAddr:       "",
		Action:          cache.RuleAction(policy.Spec.DefaultAction),
		EnforcementMode: string(policy.Spec.GlobalPolicyEnforcementMode),
	}
	egressRule.Name = fmt.Sprintf("/%s/%s/global.egress/-%s", DefaultGlobalPolicyName, cache.GlobalPolicy, cache.GenerateFlowKey(egressRule))

	return []cache.PolicyRule{ingressRule, egressRule}
}
