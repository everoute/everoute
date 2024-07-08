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
	"strings"
	"sync"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	policycache "github.com/everoute/everoute/pkg/agent/controller/policy/cache"
	"github.com/everoute/everoute/pkg/agent/datapath"
	groupv1alpha1 "github.com/everoute/everoute/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	ctrlpolicy "github.com/everoute/everoute/pkg/controller/policy"
	"github.com/everoute/everoute/pkg/source"
	"github.com/everoute/everoute/pkg/utils"
	"github.com/everoute/everoute/plugin/tower/pkg/informer"
)

type Reconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// reconcilerLock prevent the problem of policyRule updated by policy controller
	// and patch controller at the same time.
	reconcilerLock sync.RWMutex

	// ruleCache saved completeRules create by policy.
	ruleCache cache.Indexer

	// globalRuleCache saved rules create by global policy.
	globalRuleCache cache.Indexer

	// groupCache saved patches and groupmembers in cache. We can't make sure reconcile
	// before GroupPatch deleted, so save patches in cache.
	groupCache *policycache.GroupCache

	DatapathManager *datapath.DpManager
}

func (r *Reconciler) ReconcilePolicy(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var policy securityv1alpha1.SecurityPolicy

	r.reconcilerLock.Lock()
	defer r.reconcilerLock.Unlock()

	klog.Infof("Reconcile securitypolicy %s", req.NamespacedName)

	err := r.Get(ctx, req.NamespacedName, &policy)
	if client.IgnoreNotFound(err) != nil {
		klog.Errorf("unable to fetch policy %s: %s", req.Name, err.Error())
		return ctrl.Result{}, err
	}

	if apierrors.IsNotFound(err) {
		r.DatapathManager.AgentMetric.UpdatePolicyName(req.NamespacedName.String(), nil)
		err := r.cleanPolicyDependents(req.NamespacedName)
		if err != nil {
			klog.Errorf("failed to delete policy %s dependents: %s", req.Name, err.Error())
			return ctrl.Result{}, err
		}
		klog.Infof("succeed remove policy %s all rules", req.Name)
		return ctrl.Result{}, nil
	}
	r.DatapathManager.AgentMetric.UpdatePolicyName(req.NamespacedName.String(), &policy)

	return r.processPolicyUpdate(&policy)
}

func (r *Reconciler) ReconcileGroupMembers(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.reconcilerLock.Lock()
	defer r.reconcilerLock.Unlock()

	klog.Infof("Receive groupmembers %s reconcile", req.NamespacedName)

	gm := groupv1alpha1.GroupMembers{}
	if err := r.Get(ctx, req.NamespacedName, &gm); err != nil {
		if apierrors.IsNotFound(err) {
			// delete from cache
			rules, _ := r.ruleCache.ByIndex(policycache.GroupIndex, req.Name)
			if len(rules) > 0 {
				ruleNames := []string{}
				for i := range rules {
					ruleNames = append(ruleNames, rules[i].(*policycache.CompleteRule).RuleID)
				}
				klog.V(2).Infof("Group %s referenced by complete rules %v, can't be deleted", req.Name, ruleNames)
				return ctrl.Result{RequeueAfter: time.Second}, nil
			}
			r.groupCache.DelGroupMembership(req.Name)
			klog.Infof("Success delete groupmembers %s", req.Name)
			return ctrl.Result{}, nil
		}
		klog.Errorf("Failed to get groupmembers %s: %v", req.Name, err)
		return ctrl.Result{}, err
	}

	err := r.ruleUpdateByGroup(&gm)
	r.groupCache.UpdateGroupMembership(&gm)
	if err == nil {
		klog.Infof("Success update groupmembers %s", req.Name)
		return ctrl.Result{}, nil
	}
	return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 30}, nil
}

// GetCompleteRuleLister return cache.CompleteRule lister, used for debug or testing
func (r *Reconciler) GetCompleteRuleLister() informer.Lister {
	return r.ruleCache
}

// GetGlobalRuleLister return globalRule lister, used for debug or testing
func (r *Reconciler) GetGlobalRuleLister() informer.Lister {
	return r.globalRuleCache
}

func (r *Reconciler) GetGroupCache() *policycache.GroupCache {
	return r.groupCache
}

func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	if mgr == nil {
		return fmt.Errorf("can't setup with nil manager")
	}

	var err error
	var policyController, patchController, globalPolicyController controller.Controller

	// ignore not empty ruleCache for future cache inject
	if r.ruleCache == nil {
		r.ruleCache = policycache.NewCompleteRuleCache()
	}
	// ignore not empty globalRuleCache for future cache inject
	if r.globalRuleCache == nil {
		r.globalRuleCache = policycache.NewGlobalRuleCache()
	}
	// ignore not empty groupCache for future cache inject
	if r.groupCache == nil {
		r.groupCache = policycache.NewGroupCache()
	}

	if policyController, err = controller.New("policy-controller", mgr, controller.Options{
		MaxConcurrentReconciles: constants.DefaultMaxConcurrentReconciles,
		Reconciler:              reconcile.Func(r.ReconcilePolicy),
	}); err != nil {
		return err
	}

	if err = policyController.Watch(source.Kind(mgr.GetCache(), &securityv1alpha1.SecurityPolicy{}), &handler.EnqueueRequestForObject{}); err != nil {
		return err
	}

	if patchController, err = controller.New("groupPatch-controller", mgr, controller.Options{
		MaxConcurrentReconciles: constants.DefaultMaxConcurrentReconciles,
		Reconciler:              reconcile.Func(r.ReconcileGroupMembers),
	}); err != nil {
		return err
	}

	if err = patchController.Watch(source.Kind(mgr.GetCache(), &groupv1alpha1.GroupMembers{}), &handler.EnqueueRequestForObject{}); err != nil {
		return err
	}

	if globalPolicyController, err = controller.New("global-policy-controller", mgr, controller.Options{
		// Serial handle GlobalPolicy event
		MaxConcurrentReconciles: 1,
		Reconciler:              reconcile.Func(r.ReconcileGlobalPolicy),
	}); err != nil {
		return err
	}

	return globalPolicyController.Watch(source.Kind(mgr.GetCache(), &securityv1alpha1.GlobalPolicy{}), &handler.EnqueueRequestForObject{})
}

func (r *Reconciler) ruleUpdateByGroup(gm *groupv1alpha1.GroupMembers) error {
	rules, _ := r.ruleCache.ByIndex(policycache.GroupIndex, gm.GetName())
	if len(rules) == 0 {
		return nil
	}
	var oldRuleList, newRuleList []policycache.PolicyRule
	var relatedPolicies []string
	for i := range rules {
		rule := rules[i].(*policycache.CompleteRule)

		relatedPolicies = append(relatedPolicies,
			fmt.Sprintf("%s/%s", strings.Split(rule.RuleID, "/")[0], strings.Split(rule.RuleID, "/")[1]))

		oldRuleList = append(oldRuleList, rule.ListRules(r.groupCache)...)
		srcIPs := r.getRuleIPBlocksForUpdateGroupMembers(rule.SrcIPs, rule.SrcGroups, gm)
		dstIPs := r.getRuleIPBlocksForUpdateGroupMembers(rule.DstIPs, rule.DstGroups, gm)
		newRuleList = append(newRuleList, rule.GenerateRuleList(srcIPs, dstIPs, rule.Ports)...)
	}

	return r.syncPolicyRulesUntilSuccess(relatedPolicies, oldRuleList, newRuleList)
}

//nolint:all
func (r *Reconciler) getRuleIPBlocksForUpdateGroupMembers(staticIPs sets.Set[string], groups sets.Set[string], newGroup *groupv1alpha1.GroupMembers) map[string]*policycache.IPBlockItem {
	res, err := policycache.AssembleStaticIPAndGroup(staticIPs, groups.Clone().Delete(newGroup.GetName()), r.groupCache)
	if err != nil {
		klog.Fatalf("Failed to assemble ipblocks, err: %v", err)
	}
	if !groups.Has(newGroup.GetName()) {
		return res
	}

	res = policycache.AppendIPBlocks(res, policycache.GroupMembersToIPBlocks(newGroup.GroupMembers))
	return res
}

func (r *Reconciler) cleanPolicyDependents(policy k8stypes.NamespacedName) error {
	var oldRuleList []policycache.PolicyRule

	// retrieve policy completeRules from cache
	completeRules, _ := r.ruleCache.ByIndex(policycache.PolicyIndex, policy.Namespace+"/"+policy.Name)
	for _, completeRule := range completeRules {
		oldRuleList = append(oldRuleList, completeRule.(*policycache.CompleteRule).ListRules(r.groupCache)...)
		// start a force full synchronization of policyrule
		// remove policy completeRules from cache
		_ = r.ruleCache.Delete(completeRule)
	}

	return r.syncPolicyRulesUntilSuccess([]string{policy.String()}, oldRuleList, nil)
}

func (r *Reconciler) processPolicyUpdate(policy *securityv1alpha1.SecurityPolicy) (ctrl.Result, error) {
	var oldRuleList []policycache.PolicyRule

	completeRules, _ := r.ruleCache.ByIndex(policycache.PolicyIndex, policy.Namespace+"/"+policy.Name)
	for _, completeRule := range completeRules {
		oldRuleList = append(oldRuleList, completeRule.(*policycache.CompleteRule).ListRules(r.groupCache)...)
	}

	newRuleList, err := r.calculateExpectedPolicyRules(policy)
	if IsGroupMembersNotFoundErr(err) {
		// wait until groupmembers created
		klog.V(2).Infof("Failed to calculate expect complete rule for policy %s, %s", policy.GetName(), err)
		return ctrl.Result{RequeueAfter: time.Nanosecond}, nil
	}
	if err != nil {
		klog.Errorf("failed fetch new policy %s rules: %s", policy.Name, err)
		return ctrl.Result{}, err
	}

	// start a force full synchronization of policyrule
	if err := r.syncPolicyRulesUntilSuccess([]string{fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)}, oldRuleList, newRuleList); err != nil {
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 30}, nil
	}

	return ctrl.Result{}, nil
}

func (r *Reconciler) calculateExpectedPolicyRules(policy *securityv1alpha1.SecurityPolicy) ([]policycache.PolicyRule, error) {
	var policyRuleList []policycache.PolicyRule

	completeRules, err := r.completePolicy(policy)
	if err != nil {
		return policyRuleList, fmt.Errorf("flatten policy %s: %s", policy.Name, err)
	}

	// todo: replace delete and add completeRules with update
	oldCompleteRules, _ := r.ruleCache.ByIndex(policycache.PolicyIndex, policy.Namespace+"/"+policy.Name)
	for _, oldCompleteRule := range oldCompleteRules {
		_ = r.ruleCache.Delete(oldCompleteRule)
	}

	for _, completeRule := range completeRules {
		_ = r.ruleCache.Add(completeRule)
		policyRuleList = append(policyRuleList, completeRule.ListRules(r.groupCache)...)
	}

	return policyRuleList, nil
}

// classifyEgressPorts classify egress ports by port type.
func classifyEgressPorts(ports []securityv1alpha1.SecurityPolicyPort) ([]securityv1alpha1.SecurityPolicyPort, []securityv1alpha1.SecurityPolicyPort) {
	var numberPorts, namedPorts []securityv1alpha1.SecurityPolicyPort
	for _, p := range ports {
		if p.Type == securityv1alpha1.PortTypeName {
			namedPorts = append(namedPorts, p)
		} else {
			numberPorts = append(numberPorts, p)
		}
	}
	return numberPorts, namedPorts
}

//nolint:dupl,funlen // todo: remove dupl codes
func (r *Reconciler) completePolicy(policy *securityv1alpha1.SecurityPolicy) ([]*policycache.CompleteRule, error) {
	var completeRules []*policycache.CompleteRule
	var ingressEnabled, egressEnabled = policy.IsEnable()
	ruleAction := policycache.RuleActionAllow
	if policy.Spec.IsBlocklist {
		ruleAction = policycache.RuleActionDrop
	}

	appliedToPeer := make([]securityv1alpha1.SecurityPolicyPeer, 0, len(policy.Spec.AppliedTo))
	for _, appliedTo := range policy.Spec.AppliedTo {
		appliedToPeer = append(appliedToPeer, ctrlpolicy.AppliedAsSecurityPeer(policy.GetNamespace(), appliedTo))
	}
	appliedGroups, appliedIPs, err := r.getPeersGroupsAndIPs(policy.GetNamespace(), appliedToPeer)
	if err != nil {
		return nil, err
	}

	// if apply to is nil or empty, add all ips
	if len(policy.Spec.AppliedTo) == 0 {
		appliedIPs = sets.New[string]("")
	}

	if ingressEnabled {
		for _, rule := range policy.Spec.IngressRules {
			ingressRuleTmpl := &policycache.CompleteRule{
				RuleID:          fmt.Sprintf("%s/%s/%s/%s.%s", policy.Namespace, policy.Name, policycache.NormalPolicy, "ingress", rule.Name),
				Tier:            policy.Spec.Tier,
				Priority:        policy.Spec.Priority,
				EnforcementMode: policy.Spec.SecurityPolicyEnforcementMode.String(),
				Action:          ruleAction,
				Direction:       policycache.RuleDirectionIn,
				SymmetricMode:   policy.Spec.SymmetricMode,
				DstGroups:       appliedGroups.Clone(),
				DstIPs:          appliedIPs.Clone(),
			}

			ingressRuleTmpl.Ports, err = FlattenPorts(rule.Ports)
			if err != nil {
				return nil, err
			}

			if len(rule.From) == 0 {
				ingressRule := ingressRuleTmpl.Clone()
				// If "rule.From" is empty or missing, this rule matches all sources
				ingressRule.SrcIPs = sets.New[string]("")
				completeRules = append(completeRules, ingressRule)
			} else {
				ingressRules, err := r.getCompleteRulesByParseSymmetricMode(ingressRuleTmpl, policy, networkingv1.PolicyTypeIngress, rule.From)
				if err != nil {
					return nil, err
				}
				completeRules = append(completeRules, ingressRules...)
			}
		}

		if policy.Spec.DefaultRule == securityv1alpha1.DefaultRuleDrop {
			defaultIngressRule := &policycache.CompleteRule{
				RuleID:            fmt.Sprintf("%s/%s/%s/%s.%s", policy.Namespace, policy.Name, policycache.NormalPolicy, "default", "ingress"),
				Tier:              policy.Spec.Tier,
				Priority:          policy.Spec.Priority,
				EnforcementMode:   policy.Spec.SecurityPolicyEnforcementMode.String(),
				Action:            policycache.RuleActionDrop,
				Direction:         policycache.RuleDirectionIn,
				SymmetricMode:     false, // never generate symmetric rule for default rule
				DefaultPolicyRule: true,
				DstGroups:         appliedGroups.Clone(),
				DstIPs:            appliedIPs.Clone(),
				SrcIPs:            sets.New[string](""),       // matches all source IP
				Ports:             []policycache.RulePort{{}}, // has a port matches all ports
			}
			completeRules = append(completeRules, defaultIngressRule)
		}
	}

	if egressEnabled {
		for _, rule := range policy.Spec.EgressRules {
			egressRuleTmpl := &policycache.CompleteRule{
				RuleID:          fmt.Sprintf("%s/%s/%s/%s.%s", policy.Namespace, policy.Name, policycache.NormalPolicy, "egress", rule.Name),
				Tier:            policy.Spec.Tier,
				Priority:        policy.Spec.Priority,
				EnforcementMode: policy.Spec.SecurityPolicyEnforcementMode.String(),
				Action:          ruleAction,
				Direction:       policycache.RuleDirectionOut,
				SymmetricMode:   policy.Spec.SymmetricMode,
				SrcGroups:       appliedGroups.Clone(),
				SrcIPs:          appliedIPs.Clone(),
			}

			if len(rule.To) > 0 {
				egressRule := egressRuleTmpl.Clone()
				// use policy namespace as egress endpoint namespace
				egressRule.Ports, err = FlattenPorts(rule.Ports)
				if err != nil {
					return nil, err
				}
				egressRules, err := r.getCompleteRulesByParseSymmetricMode(egressRule, policy, networkingv1.PolicyTypeEgress, rule.To)
				if err != nil {
					return nil, err
				}
				completeRules = append(completeRules, egressRules...)
			} else {
				numberPorts, namedPorts := classifyEgressPorts(rule.Ports)

				// For numberPorts, assembly a completeRule
				// or if rule.Ports is empty, assembly a completeRule match all ports
				if len(numberPorts) > 0 || len(rule.Ports) == 0 {
					egressRuleCur := egressRuleTmpl.Clone()
					// If "rule.To" is empty or missing, this rule matches all destinations
					egressRuleCur.DstIPs = sets.New[string]("")
					egressRuleCur.Ports, err = FlattenPorts(numberPorts)
					if err != nil {
						return nil, err
					}
					completeRules = append(completeRules, egressRuleCur)
				}

				// For namedPorts, assembly a completeRule
				if len(namedPorts) > 0 {
					egressRuleCur := egressRuleTmpl.Clone()
					egressRuleCur.RuleID = fmt.Sprintf("%s.%s", egressRuleTmpl.RuleID, "namedport")
					// If "rule.To" is empty or missing, this rule matches all endpoints with named port
					egressRuleCur.DstGroups, err = r.getAllEpWithNamedPortGroup()
					if err != nil {
						return nil, err
					}
					egressRuleCur.Ports, err = FlattenPorts(namedPorts)
					if err != nil {
						return nil, err
					}
					completeRules = append(completeRules, egressRuleCur)
				}
			}
		}

		if policy.Spec.DefaultRule == securityv1alpha1.DefaultRuleDrop {
			defaultEgressRule := &policycache.CompleteRule{
				RuleID:            fmt.Sprintf("%s/%s/%s/%s.%s", policy.Namespace, policy.Name, policycache.NormalPolicy, "default", "egress"),
				Tier:              policy.Spec.Tier,
				Priority:          policy.Spec.Priority,
				EnforcementMode:   policy.Spec.SecurityPolicyEnforcementMode.String(),
				Action:            policycache.RuleActionDrop,
				Direction:         policycache.RuleDirectionOut,
				SymmetricMode:     false, // never generate symmetric rule for default rule
				DefaultPolicyRule: true,
				SrcGroups:         appliedGroups.Clone(),
				SrcIPs:            appliedIPs.Clone(),
				DstIPs:            sets.New[string](""),       // matches all destination IP
				Ports:             []policycache.RulePort{{}}, // has a port matches all ports
			}
			completeRules = append(completeRules, defaultEgressRule)
		}
	}

	return completeRules, nil
}

func (r *Reconciler) getCompleteRulesByParseSymmetricMode(ruleTmpl *policycache.CompleteRule, policy *securityv1alpha1.SecurityPolicy,
	policyType networkingv1.PolicyType, peers []securityv1alpha1.SecurityPolicyPeer) ([]*policycache.CompleteRule, error) {
	var rules []*policycache.CompleteRule
	if len(peers) == 0 {
		return rules, nil
	}

	if !policy.Spec.SymmetricMode {
		groups, ips, err := r.getPeersGroupsAndIPs(policy.Namespace, peers)
		if err != nil {
			return nil, err
		}
		rule := ruleTmpl.Clone()
		if policyType == networkingv1.PolicyTypeIngress {
			rule.SrcGroups = groups
			rule.SrcIPs = ips
		} else {
			rule.DstGroups = groups
			rule.DstIPs = ips
		}
		rules = append(rules, rule)
		return rules, nil
	}

	for i, symmetricMode := range []bool{true, false} {
		groups, ipBlocks, err := r.getPeersGroupsAndIPs(policy.Namespace, peers, symmetricMode)
		if err != nil {
			return nil, err
		}
		if len(groups) == 0 && len(ipBlocks) == 0 {
			continue
		}
		rule := ruleTmpl.Clone()
		rule.RuleID = fmt.Sprintf("%s.%d", rule.RuleID, i)
		rule.SymmetricMode = symmetricMode
		if policyType == networkingv1.PolicyTypeIngress {
			rule.SrcGroups = groups
			rule.SrcIPs = ipBlocks
		} else {
			rule.DstGroups = groups
			rule.DstIPs = ipBlocks
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// getPeersGroupsAndIPBlocks get ipBlocks from groups, return unique ipBlock list
func (r *Reconciler) getPeersGroupsAndIPs(namespace string,
	peers []securityv1alpha1.SecurityPolicyPeer, matchSymmetric ...bool) (sets.Set[string], sets.Set[string], error) {
	var groups = sets.New[string]()
	var ips = sets.New[string]()

	var ignoreSymmetricMode, matchDisableSymmetric bool
	if len(matchSymmetric) == 0 {
		ignoreSymmetricMode = true
	} else {
		matchDisableSymmetric = !matchSymmetric[0]
	}

	for _, peer := range peers {
		if !ignoreSymmetricMode && peer.DisableSymmetric != matchDisableSymmetric {
			// symmetricMode doesn't match, skip peer
			continue
		}
		switch {
		case peer.IPBlock != nil:
			ipNets, err := utils.ParseIPBlock(peer.IPBlock)
			if err != nil {
				klog.Infof("unable parse IPBlock %+v: %s", peer.IPBlock, err)
				return nil, nil, err
			}
			for i := range ipNets {
				ips.Insert(ipNets[i].String())
			}
		case peer.Endpoint != nil || peer.EndpointSelector != nil || peer.NamespaceSelector != nil:
			group := ctrlpolicy.PeerAsEndpointGroup(namespace, peer).GetName()
			_, exist := r.groupCache.ListGroupIPBlocks(group)
			if !exist {
				return nil, nil, NewGroupMembersNotFoundErr(group)
			}
			groups.Insert(group)
		default:
			klog.Errorf("Empty SecurityPolicyPeer, check your SecurityPolicy definition!")
		}
	}

	return groups, ips, nil
}

func (r *Reconciler) getAllEpWithNamedPortGroup() (sets.Set[string], error) {
	group := ctrlpolicy.GetAllEpWithNamedPortGroup().GetName()
	_, exist := r.groupCache.ListGroupIPBlocks(group)
	if !exist {
		return nil, NewGroupMembersNotFoundErr(group)
	}

	return sets.New[string](group), nil
}

func (r *Reconciler) syncPolicyRulesUntilSuccess(policyID []string, oldRuleList, newRuleList []policycache.PolicyRule) error {
	var err = r.compareAndApplyPolicyRulesChanges(policyID, oldRuleList, newRuleList)
	var rateLimiter = workqueue.NewItemExponentialFailureRateLimiter(time.Microsecond, time.Second)
	var timeout = time.Minute * 5
	var deadline = time.Now().Add(timeout)

	for err != nil && !apierrors.IsForbidden(err) {
		if time.Now().After(deadline) {
			klog.Errorf("unable sync %+v and %+v in %s", oldRuleList, newRuleList, timeout)
			return nil
		}
		duration := rateLimiter.When("next-sync")
		klog.Errorf("failed to sync policyRules, next sync after %s: %s", duration, err)
		time.Sleep(duration)

		err = r.compareAndApplyPolicyRulesChanges(policyID, oldRuleList, newRuleList)
	}
	return err
}

func (r *Reconciler) compareAndApplyPolicyRulesChanges(policyName []string, oldRuleList, newRuleList []policycache.PolicyRule) error {
	var (
		errList    []error
		newRuleMap = toRuleMap(newRuleList)
		oldRuleMap = toRuleMap(oldRuleList)
		allRuleSet = sets.StringKeySet(newRuleMap).Union(sets.StringKeySet(oldRuleMap))

		addRuleList = []*policycache.PolicyRule{}
		delRuleList = []*policycache.PolicyRule{}
	)

	for ruleName := range allRuleSet {
		oldRule, oldExist := oldRuleMap[ruleName]
		newRule, newExist := newRuleMap[ruleName]

		if newExist {
			if oldExist && ruleIsSame(oldRule, newRule) {
				continue
			}
			addRuleList = append(addRuleList, newRule)
			if newRule.ContainsTCP() && newRule.IsBlock() {
				reverseRule := newRule.ReverseForTCP()
				if reverseRule == nil {
					klog.Errorf("The reverse rule of created rule %v is nil", *newRule)
					continue
				}
				addRuleList = append(addRuleList, reverseRule)
			}
		} else if oldExist {
			delRuleList = append(delRuleList, oldRule)
			if oldRule.ContainsTCP() && oldRule.IsBlock() {
				reverseRule := oldRule.ReverseForTCP()
				if reverseRule == nil {
					klog.Errorf("The reverse rule of deleted rule %v is nil", *oldRule)
					continue
				}
				delRuleList = append(delRuleList, reverseRule)
			}
		}
	}

	if r.DatapathManager.PolicyRuleLimit(policyName, addRuleList, delRuleList) {
		r.DatapathManager.PolicyRuleMetricsUpdate(policyName, true)
		return apierrors.NewForbidden(schema.GroupResource{}, "", nil)
	}

	for _, item := range addRuleList {
		klog.Infof("create policyRule: %v", item)
		errList = append(errList,
			r.processPolicyRuleAdd(item),
		)
	}

	for _, item := range delRuleList {
		klog.Infof("remove policyRule: %v", item)
		errList = append(errList,
			r.processPolicyRuleDelete(item.Name),
		)
	}

	r.DatapathManager.PolicyRuleMetricsUpdate(policyName, false)

	return errors.NewAggregate(errList)
}

func (r *Reconciler) processPolicyRuleDelete(ruleName string) error {
	return r.DatapathManager.RemoveEveroutePolicyRule(datapath.FlowKeyFromRuleName(ruleName), ruleName)
}

func (r *Reconciler) processPolicyRuleAdd(policyRule *policycache.PolicyRule) error {
	klog.Infof("add rule %s to datapath", policyRule.Name)
	return r.addPolicyRuleToDatapath(datapath.FlowKeyFromRuleName(policyRule.Name), policyRule)
}

func (r *Reconciler) addPolicyRuleToDatapath(ruleID string, rule *policycache.PolicyRule) error {
	// Process PolicyRule: convert it to everoutePolicyRule, filter illegal PolicyRule; install everoutePolicyRule flow
	everoutePolicyRule := toEveroutePolicyRule(ruleID, rule)
	ruleDirection := getRuleDirection(rule.Direction)
	ruleTier := getRuleTier(rule.Tier)

	return r.DatapathManager.AddEveroutePolicyRule(everoutePolicyRule, rule.Name, ruleDirection, ruleTier, rule.EnforcementMode)
}

// func (r *Reconciler) getSecurityPolicyByCompleteRule(ruleID string) *securityv1alpha1.SecurityPolicy {
// 	sp := securityv1alpha1.SecurityPolicy{}
// 	if err := r.Get(context.Background(), k8stypes.NamespacedName{
// 		Namespace: strings.Split(ruleID, "/")[0],
// 		Name:      strings.Split(ruleID, "/")[1],
// 	}, &sp); err != nil {
// 		return nil
// 	}
// 	return &sp
// }
