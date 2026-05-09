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

	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	policycache "github.com/everoute/everoute/pkg/agent/controller/policy/cache"
	"github.com/everoute/everoute/pkg/agent/datapath"
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

	var securityPolicyList securityv1alpha1.SecurityPolicyList
	if err := r.List(ctx, &securityPolicyList); err != nil {
		return err
	}
	var globalPolicyList securityv1alpha1.GlobalPolicyList
	if err := r.List(ctx, &globalPolicyList); err != nil {
		return err
	}
	var groupMembersList groupv1alpha1.GroupMembersList
	if err := r.List(ctx, &groupMembersList); err != nil {
		return err
	}

	r.groupCache = NewGroupCacheFromGroupMembers(groupMembersList.Items)
	ruleCache, globalRuleCache, ruleCount, err := r.applyInitialPolicyRulesInOneBundle(ctx, securityPolicyList.Items, globalPolicyList.Items)
	if err != nil {
		return err
	}
	r.ruleCache = ruleCache
	r.globalRuleCache = globalRuleCache

	r.EnsurePolicyFlowInit().done.Store(true)
	klog.Infof("agent policy controller flow initialization completed, rules=%d", ruleCount)
	return nil
}

func (r *Reconciler) applyInitialPolicyRulesInOneBundle(
	ctx context.Context,
	securityPolicies []securityv1alpha1.SecurityPolicy,
	globalPolicies []securityv1alpha1.GlobalPolicy,
) (cache.Indexer, cache.Indexer, int, error) {
	ruleCache := policycache.NewCompleteRuleCache()
	globalRuleCache := policycache.NewGlobalRuleCache()
	var (
		bundleID     datapath.PolicyRuleBundleID
		bundleOpened bool
		ruleCount    int
		policyIDs    []string
	)

	abortBundle := func() {
		if bundleOpened {
			_ = r.DatapathManager.AbortEveroutePolicyRuleBundle(bundleID)
		}
	}
	ensureBundle := func() (datapath.PolicyRuleBundleID, error) {
		if bundleOpened {
			return bundleID, nil
		}
		id, err := r.DatapathManager.BeginEveroutePolicyRuleBundle(ctx)
		if err != nil {
			return 0, err
		}
		bundleID = id
		bundleOpened = true
		return bundleID, nil
	}

	for i := range securityPolicies {
		policy := &securityPolicies[i]
		policyIDs = append(policyIDs, policy.Namespace+"/"+policy.Name)
		completeRules, err := r.completePolicy(ctx, policy)
		if err != nil {
			abortBundle()
			return nil, nil, 0, err
		}
		policyRules, err := r.addCompleteRulesToInitialBundle(ctx, ensureBundle, completeRules)
		if err != nil {
			abortBundle()
			return nil, nil, 0, err
		}
		for _, completeRule := range completeRules {
			if err := ruleCache.Add(completeRule); err != nil {
				abortBundle()
				return nil, nil, 0, err
			}
		}
		ruleCount += policyRules
	}

	globalRules, err := GlobalPolicyRulesFromList(globalPolicies)
	if err != nil {
		abortBundle()
		return nil, nil, 0, err
	}
	if len(globalRules) > 0 {
		currentBundleID, err := ensureBundle()
		if err != nil {
			return nil, nil, 0, err
		}
		for i := range globalRules {
			if err := r.processPolicyRuleAddInBundle(ctx, currentBundleID, &globalRules[i]); err != nil {
				abortBundle()
				return nil, nil, 0, err
			}
			if err := globalRuleCache.Add(globalRules[i]); err != nil {
				abortBundle()
				return nil, nil, 0, err
			}
			ruleCount++
		}
	}

	if bundleOpened {
		if err := r.DatapathManager.CommitEveroutePolicyRuleBundle(ctx, bundleID); err != nil {
			return nil, nil, 0, err
		}
		r.DatapathManager.PolicyRuleMetricsUpdate(policyIDs, false)
	}
	return ruleCache, globalRuleCache, ruleCount, nil
}

func (r *Reconciler) addCompleteRulesToInitialBundle(
	ctx context.Context,
	ensureBundle func() (datapath.PolicyRuleBundleID, error),
	completeRules []*policycache.CompleteRule,
) (int, error) {
	var ruleCount int
	for _, completeRule := range completeRules {
		policyRules := completeRule.ListRules(ctx, r.groupCache)
		for i := range policyRules {
			bundleID, err := ensureBundle()
			if err != nil {
				return 0, err
			}
			if err := r.processPolicyRuleAddInBundle(ctx, bundleID, &policyRules[i]); err != nil {
				return 0, err
			}
			ruleCount++
		}
	}
	return ruleCount, nil
}

func NewGroupCacheFromGroupMembers(groupMembers []groupv1alpha1.GroupMembers) *policycache.GroupCache {
	groupCache := policycache.NewGroupCache()
	for i := range groupMembers {
		groupCache.UpdateGroupMembership(&groupMembers[i])
	}
	return groupCache
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
