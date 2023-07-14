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
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/errors"
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
}

func (r *Reconciler) ReconcilePolicy(req ctrl.Request) (ctrl.Result, error) {
	var policy securityv1alpha1.SecurityPolicy
	var ctx = context.Background()

	r.reconcilerLock.Lock()
	defer r.reconcilerLock.Unlock()
	klog.Infof("Reconcile policy: %v", req)

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

	patch := r.groupCache.NextPatch(groupName)
	if patch == nil {
		return ctrl.Result{}, nil
	}

	r.reconcilerLock.Lock()
	defer r.reconcilerLock.Unlock()
	klog.Infof("Reconcile patch: %v", *patch)

	completeRules, _ := r.ruleCache.ByIndex(policycache.GroupIndex, patch.GroupName)

	for _, completeRule := range completeRules {
		var rule = completeRule.(*policycache.CompleteRule)
		klog.Infof("Complete rule when reconcile patch: %v", *rule)

		newPolicyRuleList, oldPolicyRuleList := rule.GetPatchPolicyRules(patch)
		r.syncPolicyRulesUntilSuccess(oldPolicyRuleList, newPolicyRuleList)

		rule.ApplyPatch(patch)
		klog.Infof("Complete rule after apply patch: %v", *rule)
	}

	r.groupCache.ApplyPatch(patch)

	if r.groupCache.PatchLen(groupName) != 0 {
		return ctrl.Result{RequeueAfter: time.Nanosecond}, nil
	}

	return ctrl.Result{}, nil
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
	var oldRuleList []policycache.PolicyRule

	// retrieve policy completeRules from cache
	completeRules, _ := r.ruleCache.ByIndex(policycache.PolicyIndex, policy.Namespace+"/"+policy.Name)
	for _, completeRule := range completeRules {
		oldRuleList = append(oldRuleList, completeRule.(*policycache.CompleteRule).ListRules()...)
		// start a force full synchronization of policyrule
		// remove policy completeRules from cache
		_ = r.ruleCache.Delete(completeRule)
	}
	r.syncPolicyRulesUntilSuccess(oldRuleList, nil)

	return nil
}

func (r *Reconciler) processPolicyUpdate(policy *securityv1alpha1.SecurityPolicy) (ctrl.Result, error) {
	var oldRuleList []policycache.PolicyRule
	klog.Infof("Process policy add or update, policy: %v", *policy)

	completeRules, _ := r.ruleCache.ByIndex(policycache.PolicyIndex, policy.Namespace+"/"+policy.Name)
	for _, completeRule := range completeRules {
		klog.Infof("complete rule: %v", completeRule)
		oldRuleList = append(oldRuleList, completeRule.(*policycache.CompleteRule).ListRules()...)
	}

	newRuleList, err := r.calculateExpectedPolicyRules(policy)
	if isGroupNotFound(err) {
		// wait until groupmembers created
		return ctrl.Result{RequeueAfter: time.Nanosecond}, nil
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
	oldCompleteRules, _ := r.ruleCache.ByIndex(policycache.PolicyIndex, policy.Namespace+"/"+policy.Name)
	for _, oldCompleteRule := range oldCompleteRules {
		_ = r.ruleCache.Delete(oldCompleteRule)
	}

	for _, completeRule := range completeRules {
		_ = r.ruleCache.Add(completeRule)
		policyRuleList = append(policyRuleList, completeRule.ListRules()...)
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

	appliedToPeer := make([]securityv1alpha1.SecurityPolicyPeer, 0, len(policy.Spec.AppliedTo))
	for _, appliedTo := range policy.Spec.AppliedTo {
		appliedToPeer = append(appliedToPeer, ctrlpolicy.AppliedAsSecurityPeer(policy.GetNamespace(), appliedTo))
	}
	appliedGroups, appliedIPBlocks, err := r.getPeersGroupsAndIPBlocks(policy.GetNamespace(), appliedToPeer)
	if err != nil {
		return nil, err
	}

	// if apply to is nil or empty, add all ips
	if len(policy.Spec.AppliedTo) == 0 {
		appliedIPBlocks = map[string]*policycache.IPBlockItem{"": nil}
	}

	if ingressEnabled {
		for _, rule := range policy.Spec.IngressRules {
			ingressRuleTmpl := &policycache.CompleteRule{
				RuleID:          fmt.Sprintf("%s/%s/%s/%s.%s", policy.Namespace, policy.Name, policycache.NormalPolicy, "ingress", rule.Name),
				Tier:            policy.Spec.Tier,
				EnforcementMode: policy.Spec.SecurityPolicyEnforcementMode.String(),
				Action:          policycache.RuleActionAllow,
				Direction:       policycache.RuleDirectionIn,
				SymmetricMode:   policy.Spec.SymmetricMode,
				DstGroups:       policycache.DeepCopyMap(appliedGroups).(map[string]int32),
				DstIPBlocks:     policycache.DeepCopyMap(appliedIPBlocks).(map[string]*policycache.IPBlockItem),
			}

			ingressRuleTmpl.Ports, err = FlattenPorts(rule.Ports)
			if err != nil {
				return nil, err
			}

			if len(rule.From) == 0 {
				ingressRule := ingressRuleTmpl.Clone()
				// If "rule.From" is empty or missing, this rule matches all sources
				ingressRule.SrcIPBlocks = map[string]*policycache.IPBlockItem{"": nil}
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
				EnforcementMode:   policy.Spec.SecurityPolicyEnforcementMode.String(),
				Action:            policycache.RuleActionDrop,
				Direction:         policycache.RuleDirectionIn,
				SymmetricMode:     false, // never generate symmetric rule for default rule
				DefaultPolicyRule: true,
				DstGroups:         policycache.DeepCopyMap(appliedGroups).(map[string]int32),
				DstIPBlocks:       policycache.DeepCopyMap(appliedIPBlocks).(map[string]*policycache.IPBlockItem),
				SrcIPBlocks:       map[string]*policycache.IPBlockItem{"": nil}, // matches all source IP
				Ports:             []policycache.RulePort{{}},                   // has a port matches all ports
			}
			completeRules = append(completeRules, defaultIngressRule)
		}
	}

	if egressEnabled {
		for _, rule := range policy.Spec.EgressRules {
			egressRuleTmpl := &policycache.CompleteRule{
				RuleID:          fmt.Sprintf("%s/%s/%s/%s.%s", policy.Namespace, policy.Name, policycache.NormalPolicy, "egress", rule.Name),
				Tier:            policy.Spec.Tier,
				EnforcementMode: policy.Spec.SecurityPolicyEnforcementMode.String(),
				Action:          policycache.RuleActionAllow,
				Direction:       policycache.RuleDirectionOut,
				SymmetricMode:   policy.Spec.SymmetricMode,
				SrcGroups:       policycache.DeepCopyMap(appliedGroups).(map[string]int32),
				SrcIPBlocks:     policycache.DeepCopyMap(appliedIPBlocks).(map[string]*policycache.IPBlockItem),
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
					egressRuleCur.DstIPBlocks = map[string]*policycache.IPBlockItem{"": nil}
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
					egressRuleCur.DstGroups, egressRuleCur.DstIPBlocks, err = r.getAllEpWithNamedPortGroupAndIPBlocks()
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
				EnforcementMode:   policy.Spec.SecurityPolicyEnforcementMode.String(),
				Action:            policycache.RuleActionDrop,
				Direction:         policycache.RuleDirectionOut,
				SymmetricMode:     false, // never generate symmetric rule for default rule
				DefaultPolicyRule: true,
				SrcGroups:         policycache.DeepCopyMap(appliedGroups).(map[string]int32),
				SrcIPBlocks:       policycache.DeepCopyMap(appliedIPBlocks).(map[string]*policycache.IPBlockItem),
				DstIPBlocks:       map[string]*policycache.IPBlockItem{"": nil}, // matches all destination IP
				Ports:             []policycache.RulePort{{}},                   // has a port matches all ports
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
		groups, ipBlocks, err := r.getPeersGroupsAndIPBlocks(policy.Namespace, peers)
		if err != nil {
			return nil, err
		}
		rule := ruleTmpl.Clone()
		if policyType == networkingv1.PolicyTypeIngress {
			rule.SrcGroups = groups
			rule.SrcIPBlocks = ipBlocks
		} else {
			rule.DstGroups = groups
			rule.DstIPBlocks = ipBlocks
		}
		rules = append(rules, rule)
		return rules, nil
	}

	for i, symmetricMode := range []bool{true, false} {
		groups, ipBlocks, err := r.getPeersGroupsAndIPBlocks(policy.Namespace, peers, symmetricMode)
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
			rule.SrcIPBlocks = ipBlocks
		} else {
			rule.DstGroups = groups
			rule.DstIPBlocks = ipBlocks
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// getPeersGroupsAndIPBlocks get ipBlocks from groups, return unique ipBlock list
func (r *Reconciler) getPeersGroupsAndIPBlocks(namespace string,
	peers []securityv1alpha1.SecurityPolicyPeer, matchSymmetric ...bool) (map[string]int32, map[string]*policycache.IPBlockItem, error) {
	var groups = make(map[string]int32)
	var ipBlocks = make(map[string]*policycache.IPBlockItem)

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
			for _, ipNet := range ipNets {
				if _, exist := ipBlocks[ipNet.String()]; !exist {
					ipBlocks[ipNet.String()] = policycache.NewIPBlockItem()
				}
				ipBlocks[ipNet.String()].StaticCount++
			}
		case peer.Endpoint != nil || peer.EndpointSelector != nil || peer.NamespaceSelector != nil:
			group := ctrlpolicy.PeerAsEndpointGroup(namespace, peer).GetName()
			revision, ipAddrs, exist := r.groupCache.ListGroupIPBlocks(group)
			if !exist {
				return nil, nil, groupNotFound(fmt.Errorf("group %s members not found", group))
			}
			groups[group] = revision

			for ip, ipBlock := range ipAddrs {
				if _, exist = ipBlocks[ip]; !exist {
					ipBlocks[ip] = policycache.NewIPBlockItem()
				}
				ipBlocks[ip].AgentRef.Insert(ipBlock.AgentRef.List()...)
				ipBlocks[ip].Ports = policycache.AppendIPBlockPorts(ipBlocks[ip].Ports, ipBlock.Ports)
			}
		default:
			klog.Errorf("Empty SecurityPolicyPeer, check your SecurityPolicy definition!")
		}
	}

	return groups, ipBlocks, nil
}

func (r *Reconciler) getAllEpWithNamedPortGroupAndIPBlocks() (map[string]int32, map[string]*policycache.IPBlockItem, error) {
	var groups = make(map[string]int32)
	var ipBlocks = make(map[string]*policycache.IPBlockItem)

	group := ctrlpolicy.GetAllEpWithNamedPortGroup().GetName()
	revision, ipAddrs, exist := r.groupCache.ListGroupIPBlocks(group)
	if !exist {
		return nil, nil, groupNotFound(fmt.Errorf("group %s members not found", group))
	}
	groups[group] = revision

	for ip, ipBlock := range ipAddrs {
		if _, exist = ipBlocks[ip]; !exist {
			ipBlocks[ip] = policycache.NewIPBlockItem()
		}
		ipBlocks[ip].AgentRef.Insert(ipBlock.AgentRef.List()...)
		ipBlocks[ip].Ports = policycache.AppendIPBlockPorts(ipBlocks[ip].Ports, ipBlock.Ports)
	}

	return groups, ipBlocks, nil
}

func (r *Reconciler) syncPolicyRulesUntilSuccess(oldRuleList, newRuleList []policycache.PolicyRule) {
	var err = r.compareAndApplyPolicyRulesChanges(oldRuleList, newRuleList)
	var rateLimiter = workqueue.NewItemExponentialFailureRateLimiter(time.Microsecond, time.Second)
	var timeout = time.Minute * 5
	var deadline = time.Now().Add(timeout)

	for err != nil {
		if time.Now().After(deadline) {
			klog.Errorf("unable sync %+v and %+v in %s", oldRuleList, newRuleList, timeout)
			return
		}
		duration := rateLimiter.When("next-sync")
		klog.Errorf("failed to sync policyRules, next sync after %s: %s", duration, err)
		time.Sleep(duration)

		err = r.compareAndApplyPolicyRulesChanges(oldRuleList, newRuleList)
	}
}

func (r *Reconciler) compareAndApplyPolicyRulesChanges(oldRuleList, newRuleList []policycache.PolicyRule) error {
	var (
		errList    []error
		newRuleMap = toRuleMap(newRuleList)
		oldRuleMap = toRuleMap(oldRuleList)
		allRuleSet = sets.StringKeySet(newRuleMap).Union(sets.StringKeySet(oldRuleMap))
	)

	for ruleName := range allRuleSet {
		oldRule, oldExist := oldRuleMap[ruleName]
		newRule, newExist := newRuleMap[ruleName]

		if newExist {
			if oldExist && ruleIsSame(oldRule, newRule) {
				continue
			}
			klog.Infof("create policyRule: %v", newRule)
			errList = append(errList,
				r.processPolicyRuleAdd(newRule),
			)

		} else if oldExist {
			klog.Infof("remove policyRule: %v", oldRule)
			errList = append(errList,
				r.processPolicyRuleDelete(oldRule.Name),
			)
		}
	}

	return errors.NewAggregate(errList)
}

func (r *Reconciler) processPolicyRuleDelete(ruleName string) error {
	return r.DatapathManager.RemoveEveroutePolicyRule(flowKeyFromRuleName(ruleName), ruleName)
}

func (r *Reconciler) processPolicyRuleAdd(policyRule *policycache.PolicyRule) error {

	klog.Infof("add rule %s to datapath", policyRule.Name)
	if err := r.addPolicyRuleToDatapath(flowKeyFromRuleName(policyRule.Name), policyRule); err != nil {
		return err
	}

	return nil
}

func (r *Reconciler) addPolicyRuleToDatapath(ruleID string, rule *policycache.PolicyRule) error {
	// Process PolicyRule: convert it to everoutePolicyRule, filter illegal PolicyRule; install everoutePolicyRule flow
	everoutePolicyRule := toEveroutePolicyRule(ruleID, rule)
	ruleDirection := getRuleDirection(rule.Direction)
	ruleTier := getRuleTier(rule.Tier)

	return r.DatapathManager.AddEveroutePolicyRule(everoutePolicyRule, rule.Name, ruleDirection, ruleTier, rule.EnforcementMode)
}
