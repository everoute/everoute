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
	"reflect"
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
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	policycache "github.com/everoute/everoute/pkg/agent/controller/policy/cache"
	"github.com/everoute/everoute/pkg/agent/datapath"
	groupv1alpha1 "github.com/everoute/everoute/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	msconst "github.com/everoute/everoute/pkg/constants/ms"
	ctrlpolicy "github.com/everoute/everoute/pkg/controller/policy"
	"github.com/everoute/everoute/pkg/source"
	ertypes "github.com/everoute/everoute/pkg/types"
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
	ManagedVDSes    sets.Set[string]

	sysProcessedPolicyLock sync.RWMutex
	sysProcessedPolicy     sets.Set[k8stypes.NamespacedName]

	ReadyToProcessGlobalRule     bool
	globalRuleFirstProcessedTime *time.Time

	memoryGuard       *MemoryGuard
	ruleEstimateGuard *RuleEstimateGuard
}

func (r *Reconciler) ReconcilePolicy(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var policy securityv1alpha1.SecurityPolicy

	r.reconcilerLock.Lock()
	defer r.reconcilerLock.Unlock()

	log := ctrl.LoggerFrom(ctx)
	log.V(4).Info("Reconcile start")
	defer log.V(4).Info("Reconcile end")

	err := r.Get(ctx, req.NamespacedName, &policy)
	if client.IgnoreNotFound(err) != nil {
		log.Error(err, "Unable to fetch policy")
		return ctrl.Result{}, err
	}

	if apierrors.IsNotFound(err) {
		r.DatapathManager.AgentMetric.UpdatePolicyName(req.NamespacedName.String(), nil)
		r.resetGuard(newAdmissionRequest(policyGuardResourcePolicy, req.Namespace, req.Name, policyGuardOperationDelete))
		err := r.cleanPolicyDependents(ctx, req.NamespacedName)
		if err != nil {
			log.Error(err, "failed to delete policy")
			return ctrl.Result{}, err
		}
		log.Info("succeed remove policy all rules")
		return ctrl.Result{}, nil
	}
	r.DatapathManager.AgentMetric.UpdatePolicyName(req.NamespacedName.String(), &policy)

	ctx = context.WithValue(ctx, ertypes.CtxKeyObject, policy.Spec)
	newCompleteRules, err := r.completePolicy(ctx, &policy)
	if IsGroupMembersNotFoundErr(err) {
		log.V(2).Info("Failed to calculate expect complete rule for policy", "err", err)
		return ctrl.Result{RequeueAfter: time.Nanosecond}, nil
	}
	if err != nil {
		log.Error(err, "failed fetch new policy complete rules")
		return ctrl.Result{}, err
	}
	if res := r.admitPolicyUpdate(ctx, &policy, newCompleteRules); res.Err != nil {
		return ctrl.Result{}, res.Err
	} else if !res.Allowed {
		return ctrl.Result{RequeueAfter: res.RequeueAfter}, nil
	}
	return r.processPolicyUpdate(ctx, &policy, newCompleteRules)
}

func (r *Reconciler) ReconcileGroupMembers(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.reconcilerLock.Lock()
	defer r.reconcilerLock.Unlock()

	log := ctrl.LoggerFrom(ctx)
	log.V(4).Info("Reconcile start")
	defer log.V(4).Info("Reconcile end")

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
				log.V(2).Info("Group referenced by complete rules, can't be deleted", "ruleNames", ruleNames)
				return ctrl.Result{RequeueAfter: time.Second}, nil
			}
			r.groupCache.DelGroupMembership(req.Name)
			r.resetGuard(newAdmissionRequest(policyGuardResourceGroupMembers, req.Namespace, req.Name, policyGuardOperationDelete))
			log.Info("Success delete groupmembers")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get groupmembers")
		return ctrl.Result{}, err
	}

	ctx = context.WithValue(ctx, ertypes.CtxKeyObject, gm.GroupMembers)
	if res := r.admitGroupUpdate(ctx, &gm); res.Err != nil {
		return ctrl.Result{}, res.Err
	} else if !res.Allowed {
		return ctrl.Result{RequeueAfter: res.RequeueAfter}, nil
	}
	err := r.ruleUpdateByGroup(ctx, &gm)
	r.groupCache.UpdateGroupMembership(&gm)
	if err == nil {
		return ctrl.Result{}, nil
	}
	log.Error(err, "rule update by group failed, requeue after 30s")
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

// GetRuleEstimateLimit returns the current policy rule estimate limit.
func (r *Reconciler) GetRuleEstimateLimit() uint64 {
	if r == nil {
		return DefaultPolicyRuleEstimateLimit
	}
	return r.ruleEstimateGuard.ruleEstimateLimitValue()
}

// SetRuleEstimateLimit updates the policy rule estimate limit and returns previous and current values.
func (r *Reconciler) SetRuleEstimateLimit(limit uint64) (uint64, uint64) {
	if r == nil {
		return 0, 0
	}
	prev, current := r.ruleEstimateGuard.setRuleEstimateLimit(limit)
	klog.Infof("Set policy rule estimate limit, prev: %d, current: %d", prev, current)
	return prev, current
}

// SetMemoryThreshold updates the policy memory guard threshold and returns previous and current values.
func (r *Reconciler) SetMemoryThreshold(threshold uint64) (uint64, uint64) {
	if r == nil {
		return 0, 0
	}
	prev, current := r.memoryGuard.setMemoryThreshold(threshold)
	klog.Infof("Set policy memory guard threshold, prev: %d, current: %d", prev, current)
	return prev, current
}

// SetGuardEnabled enables or disables a policy admission guard at runtime.
func (r *Reconciler) SetGuardEnabled(guardType string, enabled bool) (bool, bool, error) {
	if r == nil {
		return false, false, fmt.Errorf("policy guard is not available")
	}
	normalizedGuardType, err := normalizeGuardType(guardType)
	if err != nil {
		return false, false, err
	}
	switch normalizedGuardType {
	case policyGuardTypeMemory:
		prev, current := r.memoryGuard.setEnabled(enabled)
		klog.Infof("Set policy memory guard enabled, prev: %t, current: %t", prev, current)
		return prev, current, nil
	case policyGuardTypeRule:
		prev, current := r.ruleEstimateGuard.setEnabled(enabled)
		klog.Infof("Set policy rule estimate guard enabled, prev: %t, current: %t", prev, current)
		return prev, current, nil
	default:
		return false, false, fmt.Errorf("unsupported policy guard type %q", guardType)
	}
}

// GetGuardStatus returns current policy admission guard runtime state.
func (r *Reconciler) GetGuardStatus() GuardStatus {
	if r == nil {
		return GuardStatus{}
	}
	status := GuardStatus{}
	if r.memoryGuard != nil {
		status.MemoryEnabled = r.memoryGuard.enabledValue()
		status.MemoryBreakerOpen = r.memoryGuard.isOpen()
		status.MemoryThreshold = r.memoryGuard.memoryThresholdSnapshot()
	}
	if r.ruleEstimateGuard != nil {
		status.RuleEnabled = r.ruleEstimateGuard.enabledValue()
		status.RuleEstimateLimit = r.ruleEstimateGuard.ruleEstimateLimitValue()
	}
	return status
}

func (r *Reconciler) SetupWithManager(
	mgr ctrl.Manager,
	ruleEstimateLimit, staticMemoryThreshold uint64,
	disableMemoryGuard, disableRuleGuard bool) error {
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
	if r.ManagedVDSes == nil {
		r.ManagedVDSes = sets.New[string]()
	}
	if r.memoryGuard == nil {
		r.memoryGuard = newMemoryGuard(
			r.DatapathManager.AgentMetric,
			staticMemoryThreshold)
	}
	if disableMemoryGuard {
		r.memoryGuard.setEnabled(false)
	}
	if err := mgr.Add(r.memoryGuard); err != nil {
		return err
	}
	if r.ruleEstimateGuard == nil {
		r.ruleEstimateGuard = newRuleEstimateGuard(
			r.DatapathManager.AgentMetric,
			ruleEstimateLimit)
	}
	if disableRuleGuard {
		r.ruleEstimateGuard.setEnabled(false)
	}

	r.sysProcessedPolicy = make(sets.Set[k8stypes.NamespacedName])

	if policyController, err = controller.New("policy-controller", mgr, controller.Options{
		MaxConcurrentReconciles: constants.DefaultMaxConcurrentReconciles,
		Reconciler:              reconcile.Func(r.ReconcilePolicy),
	}); err != nil {
		return err
	}

	if err = policyController.Watch(source.Kind(mgr.GetCache(), &securityv1alpha1.SecurityPolicy{}), &handler.EnqueueRequestForObject{}, predicate.Funcs{
		UpdateFunc: func(ue event.UpdateEvent) bool {
			oldP := ue.ObjectOld.(*securityv1alpha1.SecurityPolicy)
			newP := ue.ObjectNew.(*securityv1alpha1.SecurityPolicy)
			return !reflect.DeepEqual(oldP.Spec, newP.Spec)
		},
	}); err != nil {
		return err
	}

	if patchController, err = controller.New("groupMembers-controller", mgr, controller.Options{
		MaxConcurrentReconciles: constants.DefaultMaxConcurrentReconciles,
		Reconciler:              reconcile.Func(r.ReconcileGroupMembers),
	}); err != nil {
		return err
	}

	if err = patchController.Watch(source.Kind(mgr.GetCache(), &groupv1alpha1.GroupMembers{}), &handler.EnqueueRequestForObject{}, predicate.Funcs{
		UpdateFunc: func(ue event.UpdateEvent) bool {
			oldG := ue.ObjectOld.(*groupv1alpha1.GroupMembers)
			newG := ue.ObjectNew.(*groupv1alpha1.GroupMembers)
			return !reflect.DeepEqual(oldG.GroupMembers, newG.GroupMembers)
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

	return globalPolicyController.Watch(source.Kind(mgr.GetCache(), &securityv1alpha1.GlobalPolicy{}), &handler.EnqueueRequestForObject{})
}

func (r *Reconciler) ruleUpdateByGroup(ctx context.Context, gm *groupv1alpha1.GroupMembers) error {
	rules, _ := r.ruleCache.ByIndex(policycache.GroupIndex, gm.GetName())
	if len(rules) == 0 {
		return nil
	}
	for i := range rules {
		var oldRuleList, newRuleList []policycache.PolicyRule
		rule := rules[i].(*policycache.CompleteRule)

		oldRuleList = append(oldRuleList, rule.ListRules(ctx, r.groupCache, r.ManagedVDSes)...)
		srcIPs, err := policycache.AssembleIPBlocksForGroupUpdate(ctx, rule.SrcIPs, rule.SrcGroups, r.groupCache, gm)
		if err != nil {
			return err
		}
		dstIPs, err := policycache.AssembleIPBlocksForGroupUpdate(ctx, rule.DstIPs, rule.DstGroups, r.groupCache, gm)
		if err != nil {
			return err
		}
		newRuleList = append(newRuleList, rule.GenerateRuleList(ctx, srcIPs, dstIPs, rule.Ports, r.ManagedVDSes)...)
		newRuleList = append(newRuleList, rule.GenerateFullIsolationRule(nil, gm)...)
		if err := r.syncPolicyRulesUntilSuccess(ctx, []string{rule.Policy}, oldRuleList, newRuleList); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reconciler) resetGuard(req admissionRequest) {
	r.memoryGuard.resetRejectedObject(req)
	r.ruleEstimateGuard.resetRejectedObject(req)
}

func (r *Reconciler) admitPolicyUpdate(ctx context.Context, policy *securityv1alpha1.SecurityPolicy,
	newCompleteRules []*policycache.CompleteRule) admissionResult {
	oldRuleItems, _ := r.ruleCache.ByIndex(policycache.PolicyIndex, policy.Namespace+"/"+policy.Name)
	oldCompleteRules := completeRuleInterfacesToRules(oldRuleItems)
	operation := policyGuardOperationUpdate
	if len(oldCompleteRules) == 0 {
		operation = policyGuardOperationAdd
	}

	req := newAdmissionRequest(policyGuardResourcePolicy, policy.Namespace, policy.Name, operation)
	if isPureCompleteRuleDelete(oldCompleteRules, newCompleteRules) {
		r.resetGuard(req)
		return admissionResult{Allowed: true}
	}

	if res := r.memoryGuard.admit(ctx, req); !res.Allowed {
		return res
	}

	estimate, err := estimateCompleteRules(ctx, newCompleteRules, r.groupCache, r.ManagedVDSes)
	if err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "Failed to estimate policy rules", "resource", req.Resource, "namespace", req.Namespace,
			"name", req.Name, "operation", req.Operation)
		return admissionResult{Err: err}
	}
	req.Estimate = estimate
	return r.ruleEstimateGuard.admit(ctx, req)
}

func (r *Reconciler) admitGroupUpdate(ctx context.Context, gm *groupv1alpha1.GroupMembers) admissionResult {
	rules, _ := r.ruleCache.ByIndex(policycache.GroupIndex, gm.GetName())
	if len(rules) == 0 {
		r.resetGuard(newAdmissionRequest(policyGuardResourceGroupMembers, gm.Namespace, gm.Name, policyGuardOperationUpdate))
		return admissionResult{Allowed: true}
	}

	_, groupExists := r.groupCache.GetGroupMembership(gm.Name)
	operation := policyGuardOperationUpdate
	if !groupExists {
		operation = policyGuardOperationAdd
	}

	req := newAdmissionRequest(policyGuardResourceGroupMembers, gm.Namespace, gm.Name, operation)
	if groupMembersPureShrink(r.groupCache, gm) {
		r.resetGuard(req)
		return admissionResult{Allowed: true}
	}

	if res := r.memoryGuard.admit(ctx, req); !res.Allowed {
		return res
	}

	var newEstimate uint64
	for _, item := range rules {
		rule := item.(*policycache.CompleteRule)
		srcIPs, err := policycache.AssembleIPBlocksForGroupUpdate(ctx, rule.SrcIPs, rule.SrcGroups, r.groupCache, gm)
		if err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "Failed to estimate policy rules", "resource", req.Resource, "namespace", req.Namespace,
				"name", req.Name, "operation", req.Operation)
			return admissionResult{Err: err}
		}
		dstIPs, err := policycache.AssembleIPBlocksForGroupUpdate(ctx, rule.DstIPs, rule.DstGroups, r.groupCache, gm)
		if err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "Failed to estimate policy rules", "resource", req.Resource, "namespace", req.Namespace,
				"name", req.Name, "operation", req.Operation)
			return admissionResult{Err: err}
		}
		newEstimate += rule.EstimateRuleCountWithIPBlocks(srcIPs, dstIPs, nil, gm, r.ManagedVDSes)
	}

	req.Estimate = newEstimate
	return r.ruleEstimateGuard.admit(ctx, req)
}

func (r *Reconciler) cleanPolicyDependents(ctx context.Context, policy k8stypes.NamespacedName) error {
	var oldRuleList []policycache.PolicyRule

	// retrieve policy completeRules from cache
	completeRules, _ := r.ruleCache.ByIndex(policycache.PolicyIndex, policy.Namespace+"/"+policy.Name)
	for _, completeRule := range completeRules {
		oldRuleList = append(oldRuleList, completeRule.(*policycache.CompleteRule).ListRules(ctx, r.groupCache, r.ManagedVDSes)...)
		// start a force full synchronization of policyrule
		// remove policy completeRules from cache
		_ = r.ruleCache.Delete(completeRule)
	}

	return r.syncPolicyRulesUntilSuccess(ctx, []string{policy.String()}, oldRuleList, nil)
}

func (r *Reconciler) processPolicyUpdate(ctx context.Context, policy *securityv1alpha1.SecurityPolicy,
	newCompleteRules []*policycache.CompleteRule) (ctrl.Result, error) {
	var oldRuleList, newRuleList []policycache.PolicyRule

	oldCompleteRules, _ := r.ruleCache.ByIndex(policycache.PolicyIndex, policy.Namespace+"/"+policy.Name)
	oldRuleByID := make(map[string]*policycache.CompleteRule, len(oldCompleteRules))
	newRuleByID := make(map[string]*policycache.CompleteRule, len(newCompleteRules))

	for _, completeRule := range oldCompleteRules {
		rule := completeRule.(*policycache.CompleteRule)
		oldRuleByID[rule.RuleID] = rule
	}
	for _, rule := range newCompleteRules {
		newRuleByID[rule.RuleID] = rule
	}

	for ruleID, oldRule := range oldRuleByID {
		newRule, exists := newRuleByID[ruleID]
		if !exists || completeRuleChanged(oldRule, newRule) {
			oldRuleList = append(oldRuleList, oldRule.ListRules(ctx, r.groupCache, r.ManagedVDSes)...)
		}
	}
	for ruleID, newRule := range newRuleByID {
		oldRule, exists := oldRuleByID[ruleID]
		if !exists || completeRuleChanged(oldRule, newRule) {
			newRuleList = append(newRuleList, newRule.ListRules(ctx, r.groupCache, r.ManagedVDSes)...)
		}
	}

	// start a force full synchronization of policyrule
	if err := r.syncPolicyRulesUntilSuccess(ctx, []string{fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)}, oldRuleList, newRuleList); err != nil {
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 30}, nil
	}

	r.updateCompleteRuleCache(oldCompleteRules, newCompleteRules)
	r.addProcessedSysPolicy(k8stypes.NamespacedName{Namespace: policy.Namespace, Name: policy.Name})
	return ctrl.Result{}, nil
}

func (r *Reconciler) updateCompleteRuleCache(oldCompleteRules []interface{}, newCompleteRules []*policycache.CompleteRule) {
	for _, oldCompleteRule := range oldCompleteRules {
		_ = r.ruleCache.Delete(oldCompleteRule)
	}
	for _, completeRule := range newCompleteRules {
		_ = r.ruleCache.Add(completeRule)
	}
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

//nolint:funlen
func (r *Reconciler) completePolicy(ctx context.Context, policy *securityv1alpha1.SecurityPolicy) ([]*policycache.CompleteRule, error) {
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
	appliedGroups, appliedIPs, err := r.getPeersGroupsAndIPs(ctx, policy.GetNamespace(), appliedToPeer)
	if err != nil {
		return nil, err
	}

	// if apply to is nil or empty, add all ips
	if len(policy.Spec.AppliedTo) == 0 {
		appliedIPs = sets.New("")
	}

	policyID := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)
	if ingressEnabled {
		for _, rule := range policy.Spec.IngressRules {
			ingressRuleTmpl := &policycache.CompleteRule{
				RuleID:          fmt.Sprintf("%s/%s/%s/%s.%s", policy.Namespace, policy.Name, policycache.NormalPolicy, "ingress", rule.Name),
				Policy:          policyID,
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
				ingressRules, err := r.getCompleteRulesByParseSymmetricMode(ctx, ingressRuleTmpl, policy, networkingv1.PolicyTypeIngress, rule.From)
				if err != nil {
					return nil, err
				}
				completeRules = append(completeRules, ingressRules...)
			}
		}

		if policy.Spec.DefaultRule == securityv1alpha1.DefaultRuleDrop {
			defaultIngressRule := &policycache.CompleteRule{
				RuleID:            fmt.Sprintf("%s/%s/%s/%s.%s", policy.Namespace, policy.Name, policycache.NormalPolicy, "default", "ingress"),
				Policy:            policyID,
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
			// check full isolation policy
			if policy.Spec.Tier == constants.Tier0 && egressEnabled &&
				len(policy.Spec.IngressRules) == 0 && len(policy.Spec.EgressRules) == 0 {
				defaultIngressRule.FullIsolationPolicy = true
			}
			completeRules = append(completeRules, defaultIngressRule)
		}
	}

	if egressEnabled {
		for _, rule := range policy.Spec.EgressRules {
			egressRuleTmpl := &policycache.CompleteRule{
				RuleID:          fmt.Sprintf("%s/%s/%s/%s.%s", policy.Namespace, policy.Name, policycache.NormalPolicy, "egress", rule.Name),
				Policy:          policyID,
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
				egressRules, err := r.getCompleteRulesByParseSymmetricMode(ctx, egressRule, policy, networkingv1.PolicyTypeEgress, rule.To)
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
					egressRuleCur.DstGroups, err = r.getAllEpWithNamedPortGroup(ctx)
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
				Policy:            policyID,
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
			// check full isolation policy
			if policy.Spec.Tier == constants.Tier0 && ingressEnabled &&
				len(policy.Spec.IngressRules) == 0 && len(policy.Spec.EgressRules) == 0 {
				defaultEgressRule.FullIsolationPolicy = true
			}
			completeRules = append(completeRules, defaultEgressRule)
		}
	}

	return completeRules, nil
}

func (r *Reconciler) getCompleteRulesByParseSymmetricMode(ctx context.Context, ruleTmpl *policycache.CompleteRule, policy *securityv1alpha1.SecurityPolicy,
	policyType networkingv1.PolicyType, peers []securityv1alpha1.SecurityPolicyPeer) ([]*policycache.CompleteRule, error) {
	var rules []*policycache.CompleteRule
	if len(peers) == 0 {
		return rules, nil
	}

	if !policy.Spec.SymmetricMode {
		groups, ips, err := r.getPeersGroupsAndIPs(ctx, policy.Namespace, peers)
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
		groups, ipBlocks, err := r.getPeersGroupsAndIPs(ctx, policy.Namespace, peers, symmetricMode)
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
func (r *Reconciler) getPeersGroupsAndIPs(ctx context.Context, namespace string,
	peers []securityv1alpha1.SecurityPolicyPeer, matchSymmetric ...bool) (sets.Set[string], sets.Set[string], error) {
	log := ctrl.LoggerFrom(ctx)
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
				log.Error(err, "unable parse IPBlock", "ipBlock", peer.IPBlock)
				return nil, nil, err
			}
			for i := range ipNets {
				ips.Insert(ipNets[i].String())
			}
		case peer.Endpoint != nil || peer.EndpointSelector != nil || peer.NamespaceSelector != nil:
			group := ctrlpolicy.PeerAsEndpointGroup(namespace, peer).GetName()
			_, exist := r.groupCache.ListGroupIPBlocks(ctx, group)
			if !exist {
				return nil, nil, NewGroupMembersNotFoundErr(group)
			}
			groups.Insert(group)
		default:
			log.Error(utils.ErrInternal, "Empty SecurityPolicyPeer, check your SecurityPolicy definition!")
		}
	}

	return groups, ips, nil
}

func (r *Reconciler) getAllEpWithNamedPortGroup(ctx context.Context) (sets.Set[string], error) {
	group := ctrlpolicy.GetAllEpWithNamedPortGroup().GetName()
	_, exist := r.groupCache.ListGroupIPBlocks(ctx, group)
	if !exist {
		return nil, NewGroupMembersNotFoundErr(group)
	}

	return sets.New[string](group), nil
}

func (r *Reconciler) syncPolicyRulesUntilSuccess(ctx context.Context, policyID []string, oldRuleList, newRuleList []policycache.PolicyRule) error {
	log := ctrl.LoggerFrom(ctx)
	var err = r.compareAndApplyPolicyRulesChanges(ctx, policyID, oldRuleList, newRuleList)
	var rateLimiter = workqueue.NewItemExponentialFailureRateLimiter(time.Microsecond, time.Second)
	var timeout = time.Minute * 5
	var deadline = time.Now().Add(timeout)

	for err != nil && !apierrors.IsForbidden(err) {
		if time.Now().After(deadline) {
			log.Error(utils.ErrInternal, "Sync securitypolicy failed and timeout to retry", "oldRule", oldRuleList, "newRule", newRuleList, "timeout", timeout)
			return nil
		}
		duration := rateLimiter.When("next-sync")
		log.Error(err, "Failed to sync policyRules, wait next sync", "waitTime", duration)
		time.Sleep(duration)

		err = r.compareAndApplyPolicyRulesChanges(ctx, policyID, oldRuleList, newRuleList)
	}
	return err
}

func (r *Reconciler) compareAndApplyPolicyRulesChanges(ctx context.Context, policyName []string, oldRuleList, newRuleList []policycache.PolicyRule) error {
	log := ctrl.LoggerFrom(ctx)
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
		} else if oldExist {
			delRuleList = append(delRuleList, oldRule)
		}
	}

	if r.DatapathManager.PolicyRuleLimit(policyName, addRuleList, delRuleList) {
		r.DatapathManager.PolicyRuleMetricsUpdate(policyName, true)
		return apierrors.NewForbidden(schema.GroupResource{}, "", nil)
	}

	if len(addRuleList) == 0 && len(delRuleList) == 0 {
		return nil
	}

	log.Info("policy rule changed for object", "objectSpec", ctx.Value(ertypes.CtxKeyObject))
	for _, item := range addRuleList {
		errList = append(errList,
			r.processPolicyRuleAdd(ctx, item),
		)
	}

	for _, item := range delRuleList {
		errList = append(errList,
			r.processPolicyRuleDelete(ctx, item),
		)
	}

	r.DatapathManager.PolicyRuleMetricsUpdate(policyName, false)

	return errors.NewAggregate(errList)
}

func (r *Reconciler) processPolicyRuleDelete(ctx context.Context, policyRule *policycache.PolicyRule) error {
	ruleBase := datapath.RuleBaseInfo{
		Ref: datapath.PolicyRuleRef{
			Policy: policyRule.Policy,
			Rule:   policyRule.Name,
		},
	}
	return r.DatapathManager.RemoveEveroutePolicyRule(ctx, datapath.FlowKeyFromRuleName(policyRule.Name), ruleBase)
}

func (r *Reconciler) processPolicyRuleAdd(ctx context.Context, policyRule *policycache.PolicyRule) error {
	return r.addPolicyRuleToDatapath(ctx, datapath.FlowKeyFromRuleName(policyRule.Name), policyRule)
}

func (r *Reconciler) addPolicyRuleToDatapath(ctx context.Context, ruleID string, rule *policycache.PolicyRule) error {
	// Process PolicyRule: convert it to everoutePolicyRule, filter illegal PolicyRule; install everoutePolicyRule flow
	everoutePolicyRule := toEveroutePolicyRule(ruleID, rule)
	ruleDirection := getRuleDirection(rule.Direction)
	ruleTier := getRuleTier(rule.Tier)
	ruleBase := datapath.RuleBaseInfo{
		Ref: datapath.PolicyRuleRef{
			Policy: rule.Policy,
			Rule:   rule.Name,
		},
		Direction: ruleDirection,
		Tier:      ruleTier,
		Mode:      rule.EnforcementMode,
	}

	return r.DatapathManager.AddEveroutePolicyRule(ctx, everoutePolicyRule, ruleBase)
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

func (r *Reconciler) isReadyToProcessGlobalRule(ctx context.Context) bool {
	log := ctrl.LoggerFrom(ctx)
	if r.ReadyToProcessGlobalRule {
		return true
	}
	if r.globalRuleFirstProcessedTime == nil {
		curT := time.Now()
		r.globalRuleFirstProcessedTime = &curT
		log.Info("At least wait sometime when first process global rule", "waitTime", msconst.GlobalRuleFirstDelayTime)
		time.Sleep(msconst.GlobalRuleFirstDelayTime)
	} else if time.Now().After(r.globalRuleFirstProcessedTime.Add(msconst.GlobalRuleDelayTimeout)) {
		r.ReadyToProcessGlobalRule = true
		log.Info("It has waited enough time, begin to process global rule", "timeout", msconst.GlobalRuleDelayTimeout)
		return true
	}

	r.sysProcessedPolicyLock.RLock()
	defer r.sysProcessedPolicyLock.RUnlock()
	if !r.sysProcessedPolicy.Has(msconst.SysEPPolicy) {
		return false
	}
	if !r.sysProcessedPolicy.Has(msconst.ERvmPolicy) {
		return false
	}
	if !r.sysProcessedPolicy.Has(msconst.LBPolicy) {
		return false
	}
	r.ReadyToProcessGlobalRule = true
	return true
}

func (r *Reconciler) addProcessedSysPolicy(p k8stypes.NamespacedName) {
	r.sysProcessedPolicyLock.Lock()
	defer r.sysProcessedPolicyLock.Unlock()

	if p == msconst.SysEPPolicy || p == msconst.ERvmPolicy || p == msconst.LBPolicy {
		r.sysProcessedPolicy.Insert(p)
	}
}
