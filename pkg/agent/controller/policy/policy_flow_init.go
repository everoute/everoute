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
	"sync/atomic"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	policycache "github.com/everoute/everoute/pkg/agent/controller/policy/cache"
	groupv1alpha1 "github.com/everoute/everoute/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
)

const policyFlowInitRetryInterval = time.Second

type PolicyFlowInit struct {
	done atomic.Bool
}

func (r *Reconciler) EnsurePolicyFlowInitialized(ctx context.Context) error {
	if r.IsPolicyFlowInitDone() {
		return nil
	}

	r.reconcilerLock.Lock()
	defer r.reconcilerLock.Unlock()
	if r.IsPolicyFlowInitDone() {
		return nil
	}

	for {
		err := r.TryCompletePolicyFlowInit(ctx)
		if err == nil {
			return nil
		}
		klog.Errorf("unable to complete policy flow initialization, will retry: %s", err.Error())

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(policyFlowInitRetryInterval):
		}
	}
}

func (r *Reconciler) TryCompletePolicyFlowInit(ctx context.Context) error {
	if r.IsPolicyFlowInitDone() {
		return nil
	}

	policyRules, completeRules, globalRules, policyIDs, err := r.BuildInitialPolicyFlowSnapshot(ctx)
	if err != nil {
		return err
	}

	ruleCache, err := NewCompleteRuleCacheFromRules(completeRules)
	if err != nil {
		return err
	}
	globalRuleCache, err := NewGlobalRuleCacheFromRules(globalRules)
	if err != nil {
		return err
	}
	r.ruleCache = ruleCache
	r.globalRuleCache = globalRuleCache

	if len(policyRules) > 0 {
		if err := r.compareAndApplyPolicyRulesChanges(ctx, policyIDs, nil, policyRules); err != nil {
			return err
		}
	}
	r.EnsurePolicyFlowInit().done.Store(true)
	klog.Infof("agent policy controller flow initialization completed, rules=%d", len(policyRules))
	return nil
}

func (r *Reconciler) BuildInitialPolicyFlowSnapshot(ctx context.Context) ([]policycache.PolicyRule, []*policycache.CompleteRule, []policycache.PolicyRule, []string, error) {
	var securityPolicyList securityv1alpha1.SecurityPolicyList
	if err := r.List(ctx, &securityPolicyList); err != nil {
		return nil, nil, nil, nil, err
	}
	var globalPolicyList securityv1alpha1.GlobalPolicyList
	if err := r.List(ctx, &globalPolicyList); err != nil {
		return nil, nil, nil, nil, err
	}
	var groupMembersList groupv1alpha1.GroupMembersList
	if err := r.List(ctx, &groupMembersList); err != nil {
		return nil, nil, nil, nil, err
	}

	r.groupCache = NewGroupCacheFromGroupMembers(groupMembersList.Items)

	var (
		policyRules   []policycache.PolicyRule
		completeRules []*policycache.CompleteRule
		policyIDs     []string
	)
	policyIDSet := sets.New[string]()
	for i := range securityPolicyList.Items {
		policy := &securityPolicyList.Items[i]
		rules, err := r.completePolicy(ctx, policy)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		completeRules = append(completeRules, rules...)
		for _, rule := range rules {
			policyRules = append(policyRules, rule.ListRules(ctx, r.groupCache)...)
		}
		policyIDSet.Insert(policy.Namespace + "/" + policy.Name)
	}
	policyIDs = policyIDSet.UnsortedList()

	globalRules, err := GlobalPolicyRulesFromList(globalPolicyList.Items)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	policyRules = append(policyRules, globalRules...)
	return policyRules, completeRules, globalRules, policyIDs, nil
}

func NewGroupCacheFromGroupMembers(groupMembers []groupv1alpha1.GroupMembers) *policycache.GroupCache {
	groupCache := policycache.NewGroupCache()
	for i := range groupMembers {
		groupCache.UpdateGroupMembership(&groupMembers[i])
	}
	return groupCache
}

func NewCompleteRuleCacheFromRules(completeRules []*policycache.CompleteRule) (cache.Indexer, error) {
	ruleCache := policycache.NewCompleteRuleCache()
	for _, rule := range completeRules {
		if err := ruleCache.Add(rule); err != nil {
			return nil, err
		}
	}
	return ruleCache, nil
}

func NewGlobalRuleCacheFromRules(policyRules []policycache.PolicyRule) (cache.Indexer, error) {
	globalRuleCache := policycache.NewGlobalRuleCache()
	for _, rule := range policyRules {
		if err := globalRuleCache.Add(rule); err != nil {
			return nil, err
		}
	}
	return globalRuleCache, nil
}

func (r *Reconciler) EnsurePolicyFlowInit() *PolicyFlowInit {
	if r.policyFlowInit == nil {
		r.policyFlowInit = &PolicyFlowInit{}
	}
	return r.policyFlowInit
}

func (r *Reconciler) IsPolicyFlowInitDone() bool {
	return r.EnsurePolicyFlowInit().done.Load()
}
