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
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	policycache "github.com/everoute/everoute/pkg/agent/controller/policy/cache"
	"github.com/everoute/everoute/pkg/agent/datapath"
	groupv1alpha1 "github.com/everoute/everoute/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	ctrlpolicy "github.com/everoute/everoute/pkg/controller/policy"
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

	flowKeyReferenceMapLock sync.RWMutex
	flowKeyReferenceMap     map[string]sets.String // Map flowKey to policyRule names
}

func (r *Reconciler) ReconcilePolicy(req ctrl.Request) (ctrl.Result, error) {
	var policy securityv1alpha1.SecurityPolicy
	var ctx = context.Background()

	r.reconcilerLock.Lock()
	defer r.reconcilerLock.Unlock()

	err := r.Get(ctx, req.NamespacedName, &policy)
	if client.IgnoreNotFound(err) != nil {
		klog.Errorf("unable to fetch policy %s: %s", req.Name, err.Error())
		return ctrl.Result{}, err
	}

	if apierrors.IsNotFound(err) {
		err := r.cleanPolicyDependents(req.NamespacedName)
		if err != nil {
			klog.Errorf("failed to delete policy %s dependents: %s", req.Name, err.Error())
			return ctrl.Result{}, err
		}
		klog.Infof("succeed remove policy %s all rules", req.Name)
		return ctrl.Result{}, nil
	}

	return r.processPolicyUpdate(&policy)
}

func (r *Reconciler) ReconcilePatch(req ctrl.Request) (ctrl.Result, error) {
	var groupName = req.Name
	var requeue bool

	patch := r.groupCache.NextPatch(groupName)
	if patch == nil {
		return ctrl.Result{}, nil
	}

	r.reconcilerLock.Lock()
	defer r.reconcilerLock.Unlock()

	completeRules, _ := r.ruleCache.ByIndex(policycache.GroupIndex, patch.GroupName)

	for _, completeRule := range completeRules {
		var rule = completeRule.(*policycache.CompleteRule)

		newPolicyRuleList, oldPolicyRuleList := rule.GetPatchPolicyRules(patch)
		r.syncPolicyRulesUntilSuccess(oldPolicyRuleList, newPolicyRuleList)

		rule.ApplyPatch(patch)
	}

	r.groupCache.ApplyPatch(patch)

	if r.groupCache.PatchLen(groupName) != 0 {
		requeue = true
	}

	return ctrl.Result{Requeue: requeue}, nil
}

// GetCompleteRuleLister return cache.CompleteRule lister, used for debug or testing
func (r *Reconciler) GetCompleteRuleLister() informer.Lister {
	return r.ruleCache
}

// GetGlobalRuleLister return globalRule lister, used for debug or testing
func (r *Reconciler) GetGlobalRuleLister() informer.Lister {
	return r.globalRuleCache
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
	r.flowKeyReferenceMap = make(map[string]sets.String)

	if policyController, err = controller.New("policy-controller", mgr, controller.Options{
		MaxConcurrentReconciles: constants.DefaultMaxConcurrentReconciles,
		Reconciler:              reconcile.Func(r.ReconcilePolicy),
	}); err != nil {
		return err
	}

	if err = policyController.Watch(&source.Kind{Type: &securityv1alpha1.SecurityPolicy{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return err
	}

	if patchController, err = controller.New("groupPatch-controller", mgr, controller.Options{
		MaxConcurrentReconciles: constants.DefaultMaxConcurrentReconciles,
		Reconciler:              reconcile.Func(r.ReconcilePatch),
	}); err != nil {
		return err
	}

	if err = patchController.Watch(&source.Kind{Type: &groupv1alpha1.GroupMembersPatch{}}, &handler.Funcs{
		CreateFunc: r.addPatch,
	}); err != nil {
		return err
	}

	if err = patchController.Watch(&source.Kind{Type: &groupv1alpha1.GroupMembers{}}, &handler.Funcs{
		CreateFunc: func(e event.CreateEvent, q workqueue.RateLimitingInterface) {
			r.groupCache.AddGroupMembership(e.Object.(*groupv1alpha1.GroupMembers))
			// add into queue to process the group patches.
			q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
				Namespace: e.Meta.GetNamespace(),
				Name:      e.Meta.GetName(),
			}})
		},
		DeleteFunc: func(e event.DeleteEvent, q workqueue.RateLimitingInterface) {
			r.groupCache.DelGroupMembership(e.Meta.GetName())
		},
	}); err != nil {
		return err
	}

	if globalPolicyController, err = controller.New("global-policy-controller", mgr, controller.Options{
		// Serial handle GlobalPolicy event
		MaxConcurrentReconciles: 1,
		Reconciler:              reconcile.Func(r.ReconcileGlobalPolicy),
	}); err != nil {
		return err
	}

	if err = globalPolicyController.Watch(&source.Kind{Type: &securityv1alpha1.GlobalPolicy{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return err
	}

	return nil
}

func (r *Reconciler) addPatch(e event.CreateEvent, q workqueue.RateLimitingInterface) {
	if e.Object == nil {
		klog.Errorf("receive create event with no object %v", e)
		return
	}

	patch := e.Object.(*groupv1alpha1.GroupMembersPatch)
	r.groupCache.AddPatch(patch)

	q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
		Name:      patch.AppliedToGroupMembers.Name,
		Namespace: metav1.NamespaceNone,
	}})
}

func (r *Reconciler) cleanPolicyDependents(policy k8stypes.NamespacedName) error {
	// retrieve policy completeRules from cache
	completeRules, _ := r.ruleCache.ByIndex(policycache.PolicyIndex, policy.Name+"/"+policy.Namespace)
	for _, completeRule := range completeRules {
		// remove policy in datapath
		for _, rule := range completeRule.(*policycache.CompleteRule).ListRules() {
			r.processPolicyRuleDelete(rule.Name)
		}
		// remove policy completeRules from cache
		_ = r.ruleCache.Delete(completeRule)
	}

	return nil
}

func (r *Reconciler) processPolicyUpdate(policy *securityv1alpha1.SecurityPolicy) (ctrl.Result, error) {
	var oldRuleList []policycache.PolicyRule

	completeRules, _ := r.ruleCache.ByIndex(policycache.PolicyIndex, policy.Name+"/"+policy.Namespace)
	for _, completeRule := range completeRules {
		oldRuleList = append(oldRuleList, completeRule.(*policycache.CompleteRule).ListRules()...)
	}

	newRuleList, err := r.calculateExpectedPolicyRules(policy)
	if isGroupNotFound(err) {
		// wait until groupmembers created
		return ctrl.Result{Requeue: true}, nil
	}
	if err != nil {
		klog.Errorf("failed fetch new policy %s rules: %s", policy.Name, err)
		return ctrl.Result{}, err
	}

	// start a force full synchronization of policyrule
	r.syncPolicyRulesUntilSuccess(oldRuleList, newRuleList)

	return ctrl.Result{}, nil
}

func (r *Reconciler) calculateExpectedPolicyRules(policy *securityv1alpha1.SecurityPolicy) ([]policycache.PolicyRule, error) {
	var policyRuleList []policycache.PolicyRule

	completeRules, err := r.completePolicy(policy)
	if err != nil {
		return policyRuleList, fmt.Errorf("flatten policy %s: %s", policy.Name, err)
	}

	// todo: replace delete and add completeRules with update
	oldCompleteRules, _ := r.ruleCache.ByIndex(policycache.PolicyIndex, policy.Name+"/"+policy.Namespace)
	for _, oldCompleteRule := range oldCompleteRules {
		_ = r.ruleCache.Delete(oldCompleteRule)
	}

	for _, completeRule := range completeRules {
		_ = r.ruleCache.Add(completeRule)
		policyRuleList = append(policyRuleList, completeRule.ListRules()...)
	}

	return policyRuleList, nil
}

//nolint:dupl,funlen // todo: remove dupl codes
func (r *Reconciler) completePolicy(policy *securityv1alpha1.SecurityPolicy) ([]*policycache.CompleteRule, error) {
	var completeRules []*policycache.CompleteRule
	var ingressEnabled, egressEnabled = policy.IsEnable()

	appliedToPeer := make([]securityv1alpha1.SecurityPolicyPeer, 0, len(policy.Spec.AppliedTo))
	for _, appliedTo := range policy.Spec.AppliedTo {
		appliedToPeer = append(appliedToPeer, ctrlpolicy.AppliedAsSecurityPeer(policy.GetNamespace(), appliedTo))
	}
	appliedGroups, appliedIPBlocks, err := r.getPeersGroupsAndIPBlocks(policy.GetNamespace(), appliedToPeer)
	if err != nil {
		return nil, err
	}

	// if apply to is nil or empty, all all ips
	if len(policy.Spec.AppliedTo) == 0 {
		appliedIPBlocks = map[string]int{"": 1}
	}

	if ingressEnabled {
		for _, rule := range policy.Spec.IngressRules {
			ingressRule := &policycache.CompleteRule{
				RuleID:        fmt.Sprintf("%s/%s/%s.%s", policy.Name, policy.Namespace, "ingress", rule.Name),
				Tier:          policy.Spec.Tier,
				Action:        policycache.RuleActionAllow,
				Direction:     policycache.RuleDirectionIn,
				SymmetricMode: policy.Spec.SymmetricMode,
				DstGroups:     policycache.DeepCopyMap(appliedGroups).(map[string]int32),
				DstIPBlocks:   policycache.DeepCopyMap(appliedIPBlocks).(map[string]int),
			}

			if len(rule.From) == 0 {
				// If "rule.From" is empty or missing, this rule matches all sources
				ingressRule.SrcIPBlocks = map[string]int{"": 1}
			} else {
				// use policy namespace as ingress endpoint namespace
				ingressRule.SrcGroups, ingressRule.SrcIPBlocks, err = r.getPeersGroupsAndIPBlocks(policy.Namespace, rule.From)
				if err != nil {
					return nil, err
				}
			}

			if len(rule.Ports) == 0 {
				// empty Ports matches all ports
				ingressRule.Ports = []policycache.RulePort{{}}
			} else {
				ingressRule.Ports, err = FlattenPorts(rule.Ports)
				if err != nil {
					return nil, err
				}
			}

			completeRules = append(completeRules, ingressRule)
		}

		if !policy.Spec.DisableDefaultRule {
			defaultIngressRule := &policycache.CompleteRule{
				RuleID:            fmt.Sprintf("%s/%s/%s.%s", policy.Name, policy.Namespace, "default", "ingress"),
				Tier:              policy.Spec.Tier,
				Action:            policycache.RuleActionDrop,
				Direction:         policycache.RuleDirectionIn,
				SymmetricMode:     false, // never generate symmetric rule for default rule
				DefaultPolicyRule: true,
				DstGroups:         policycache.DeepCopyMap(appliedGroups).(map[string]int32),
				DstIPBlocks:       policycache.DeepCopyMap(appliedIPBlocks).(map[string]int),
				SrcIPBlocks:       map[string]int{"": 1},      // matches all source IP
				Ports:             []policycache.RulePort{{}}, // has a port matches all ports
			}
			completeRules = append(completeRules, defaultIngressRule)
		}
	}

	if egressEnabled {
		for _, rule := range policy.Spec.EgressRules {
			egressRule := &policycache.CompleteRule{
				RuleID:        fmt.Sprintf("%s/%s/%s.%s", policy.Name, policy.Namespace, "egress", rule.Name),
				Tier:          policy.Spec.Tier,
				Action:        policycache.RuleActionAllow,
				Direction:     policycache.RuleDirectionOut,
				SymmetricMode: policy.Spec.SymmetricMode,
				SrcGroups:     policycache.DeepCopyMap(appliedGroups).(map[string]int32),
				SrcIPBlocks:   policycache.DeepCopyMap(appliedIPBlocks).(map[string]int),
			}

			if len(rule.To) == 0 {
				// If "rule.To" is empty or missing, this rule matches all destinations
				egressRule.DstIPBlocks = map[string]int{"": 1}
			} else {
				// use policy namespace as egress endpoint namespace
				egressRule.DstGroups, egressRule.DstIPBlocks, err = r.getPeersGroupsAndIPBlocks(policy.Namespace, rule.To)
				if err != nil {
					return nil, err
				}
			}

			if len(rule.Ports) == 0 {
				// Empty ports matches all ports
				egressRule.Ports = []policycache.RulePort{{}}
			} else {
				egressRule.Ports, err = FlattenPorts(rule.Ports)
				if err != nil {
					return nil, err
				}
			}

			completeRules = append(completeRules, egressRule)
		}

		if !policy.Spec.DisableDefaultRule {
			defaultEgressRule := &policycache.CompleteRule{
				RuleID:            fmt.Sprintf("%s/%s/%s.%s", policy.Name, policy.Namespace, "default", "egress"),
				Tier:              policy.Spec.Tier,
				Action:            policycache.RuleActionDrop,
				Direction:         policycache.RuleDirectionOut,
				SymmetricMode:     false, // never generate symmetric rule for default rule
				DefaultPolicyRule: true,
				SrcGroups:         policycache.DeepCopyMap(appliedGroups).(map[string]int32),
				SrcIPBlocks:       policycache.DeepCopyMap(appliedIPBlocks).(map[string]int),
				DstIPBlocks:       map[string]int{"": 1},      // matches all destination IP
				Ports:             []policycache.RulePort{{}}, // has a port matches all ports
			}
			completeRules = append(completeRules, defaultEgressRule)
		}
	}

	return completeRules, nil
}

// getPeersGroupsAndIPBlocks get ipBlocks from groups, return unique ipBlock list
func (r *Reconciler) getPeersGroupsAndIPBlocks(namespace string, peers []securityv1alpha1.SecurityPolicyPeer) (map[string]int32, map[string]int, error) {
	var groups = make(map[string]int32)
	var ipBlocks = make(map[string]int)

	for _, peer := range peers {
		switch {
		case peer.IPBlock != nil:
			ipNets, err := utils.ParseIPBlock(peer.IPBlock)
			if err != nil {
				klog.Infof("unable parse IPBlock %+v: %s", peer.IPBlock, err)
				return nil, nil, err
			}
			for _, ipNet := range ipNets {
				ipBlocks[ipNet.String()]++
			}
		case peer.Endpoint != nil || peer.EndpointSelector != nil || peer.NamespaceSelector != nil:
			group := ctrlpolicy.PeerAsEndpointGroup(namespace, peer).GetName()
			revision, ipAddrs, exist := r.groupCache.ListGroupIPBlocks(group)
			if !exist {
				return nil, nil, groupNotFound(fmt.Errorf("group %s members not found", group))
			}
			groups[group] = revision

			for _, ipBlock := range ipAddrs {
				ipBlocks[ipBlock]++
			}
		default:
			klog.Errorf("Empty SecurityPolicyPeer, check your SecurityPolicy definition!")
		}
	}

	return groups, ipBlocks, nil
}

func (r *Reconciler) syncPolicyRulesUntilSuccess(oldRuleList, newRuleList []policycache.PolicyRule) {
	r.compareAndApplyPolicyRulesChanges(oldRuleList, newRuleList)
}

func (r *Reconciler) compareAndApplyPolicyRulesChanges(oldRuleList, newRuleList []policycache.PolicyRule) {
	newRuleMap := toRuleMap(newRuleList)
	oldRuleMap := toRuleMap(oldRuleList)
	allRuleSet := sets.StringKeySet(newRuleMap).Union(sets.StringKeySet(oldRuleMap))

	for ruleName := range allRuleSet {
		oldRule, oldExist := oldRuleMap[ruleName]
		newRule, newExist := newRuleMap[ruleName]

		if oldExist && newExist && oldRule.Name == newRule.Name {
			continue
		}

		if oldExist {
			klog.Infof("remove policyRule: %v", oldRule)
			r.processPolicyRuleDelete(oldRule.Name)
		}

		if newExist {
			klog.Infof("create policyRule: %v", newRule)
			r.processPolicyRuleAdd(newRule)
		}
	}
}

func (r *Reconciler) processPolicyRuleDelete(ruleName string) {
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

func (r *Reconciler) processPolicyRuleAdd(policyRule *policycache.PolicyRule) {
	r.flowKeyReferenceMapLock.Lock()
	defer r.flowKeyReferenceMapLock.Unlock()

	var flowKey = flowKeyFromRuleName(policyRule.Name)

	if r.flowKeyReferenceMap[flowKey] == nil {
		r.flowKeyReferenceMap[flowKey] = sets.NewString()
	}
	klog.Infof("add rule %s to datapath", flowKey)
	r.addPolicyRuleToDatapath(flowKey, policyRule)

	r.flowKeyReferenceMap[flowKey].Insert(policyRule.Name)
}

func (r *Reconciler) deletePolicyRuleFromDatapath(flowKey string) {
	var err error
	ERPolicyRule := &datapath.EveroutePolicyRule{
		RuleID: flowKey,
	}

	err = r.DatapathManager.RemoveEveroutePolicyRule(ERPolicyRule)
	if err != nil {
		// Update policyRule enforce status for statistics and display. TODO
		klog.Fatalf("del EveroutePolicyRule %v failed,", ERPolicyRule)
	}
}

func (r *Reconciler) addPolicyRuleToDatapath(ruleID string, rule *policycache.PolicyRule) {
	// Process PolicyRule: convert it to everoutePolicyRule, filter illegal PolicyRule; install everoutePolicyRule flow
	var err error
	everoutePolicyRule := toEveroutePolicyRule(ruleID, rule)
	ruleDirection := getRuleDirection(rule.Direction)
	ruleTier := getRuleTier(rule.Tier)

	err = r.DatapathManager.AddEveroutePolicyRule(everoutePolicyRule, ruleDirection, ruleTier)
	if err != nil {
		// Update policyRule enforce status for statistics and display. TODO
		klog.Fatalf("add everoutePolicyRule %v failed,", everoutePolicyRule)
	}
}
