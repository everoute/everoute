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

package policy

import (
	"context"
	"fmt"
	"sync"
	"time"

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

	groupv1alpha1 "github.com/smartxworks/lynx/pkg/apis/group/v1alpha1"
	policyv1alpha1 "github.com/smartxworks/lynx/pkg/apis/policyrule/v1alpha1"
	securityv1alpha1 "github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
	lynxctrl "github.com/smartxworks/lynx/pkg/controller"
	policycache "github.com/smartxworks/lynx/pkg/controller/policy/cache"
)

type PolicyReconciler struct {
	client.Client
	ReadClient client.Reader
	Scheme     *runtime.Scheme

	// reconcilerLock prevent the problem of policyRule updated by policy controller
	// and patch controller at the same time.
	reconcilerLock sync.RWMutex

	// ruleCache saved completeRules create by policy.
	ruleCache cache.Indexer

	// groupCache saved patches and groupmembers in cache. We can't make sure reconcile
	// before GroupPatch deleted, so save patches in cache.
	groupCache *policycache.GroupCache
}

func (r *PolicyReconciler) ReconcilePolicy(req ctrl.Request) (ctrl.Result, error) {
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
		err := r.cleanPolicyDependents(ctx, req.Name)
		if err != nil {
			klog.Errorf("failed to delete policy %s dependents: %s", req.Name, err.Error())
			return ctrl.Result{}, err
		}
		klog.Infof("succeed remove policy %s all rules", req.Name)
		return ctrl.Result{}, nil
	}

	if r.isNewPolicy(&policy) {
		klog.Infof("process security policy %s create request", policy.Name)
		return r.processPolicyCreate(ctx, &policy)
	}

	if r.isDeletingPolicy(&policy) {
		klog.Infof("process security policy %s delete request", policy.Name)
		return r.processPolicyDelete(ctx, &policy)
	}

	return r.processPolicyUpdate(ctx, &policy)
}

func (r *PolicyReconciler) ReconcilePatch(req ctrl.Request) (ctrl.Result, error) {
	var ctx = context.Background()
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
		r.syncPolicyRulesUntilSuccess(ctx, oldPolicyRuleList, newPolicyRuleList)

		rule.ApplyPatch(patch)
	}

	r.groupCache.ApplyPatch(patch)

	if r.groupCache.PatchLen(groupName) != 0 {
		requeue = true
	}

	return ctrl.Result{Requeue: requeue}, nil
}

func (r *PolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if mgr == nil {
		return fmt.Errorf("can't setup with nil manager")
	}

	var err error
	var policyController, patchController controller.Controller

	// ignore not empty ruleCache for future cache inject
	if r.ruleCache == nil {
		r.ruleCache = policycache.NewCompleteRuleCache()
	}

	// ignore not empty groupCache for future cache inject
	if r.groupCache == nil {
		r.groupCache = policycache.NewGroupCache()
	}

	policyController, err = controller.New("policy-controller", mgr, controller.Options{
		MaxConcurrentReconciles: lynxctrl.DefaultMaxConcurrentReconciles,
		Reconciler:              reconcile.Func(r.ReconcilePolicy),
	})
	if err != nil {
		return err
	}

	err = policyController.Watch(&source.Kind{Type: &securityv1alpha1.SecurityPolicy{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	patchController, err = controller.New("GroupPatch-controller", mgr, controller.Options{
		MaxConcurrentReconciles: lynxctrl.DefaultMaxConcurrentReconciles,
		Reconciler:              reconcile.Func(r.ReconcilePatch),
	})
	if err != nil {
		return err
	}

	err = patchController.Watch(&source.Kind{Type: &groupv1alpha1.GroupMembersPatch{}}, &handler.Funcs{
		CreateFunc: r.addPatch,
	})
	if err != nil {
		return err
	}

	err = patchController.Watch(&source.Kind{Type: &groupv1alpha1.GroupMembers{}}, &handler.Funcs{
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
	})
	if err != nil {
		return err
	}

	return nil
}

func (r *PolicyReconciler) addPatch(e event.CreateEvent, q workqueue.RateLimitingInterface) {
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

func (r *PolicyReconciler) isNewPolicy(policy *securityv1alpha1.SecurityPolicy) bool {
	return policy.ObjectMeta.DeletionTimestamp == nil &&
		len(policy.ObjectMeta.Finalizers) == 0
}

func (r *PolicyReconciler) isDeletingPolicy(policy *securityv1alpha1.SecurityPolicy) bool {
	return policy.ObjectMeta.DeletionTimestamp != nil
}

func (r *PolicyReconciler) processPolicyCreate(ctx context.Context, policy *securityv1alpha1.SecurityPolicy) (ctrl.Result, error) {
	klog.V(2).Infof("add finalizers for securityPolicy %s", policy.Name)

	policy.ObjectMeta.Finalizers = []string{lynxctrl.DependentsCleanFinalizer}

	err := r.Update(ctx, policy)
	if err != nil {
		klog.Errorf("failed to add finalizers for policy %s: %s", policy.Name, err.Error())
		return ctrl.Result{}, err
	}

	// Requeue for process policy update request.
	return ctrl.Result{Requeue: true}, nil
}

func (r *PolicyReconciler) processPolicyDelete(ctx context.Context, policy *securityv1alpha1.SecurityPolicy) (ctrl.Result, error) {
	klog.V(2).Infof("clean policy %s dependents rules", policy.Name)

	err := r.cleanPolicyDependents(ctx, policy.Name)
	if err != nil {
		klog.Errorf("failed to delete policy %s dependents: %s", policy.Name, err.Error())
		return ctrl.Result{}, err
	}
	klog.Infof("succeed remove policy %s all rules", policy.Name)

	policy.ObjectMeta.Finalizers = []string{}
	err = r.Update(ctx, policy)
	if err != nil {
		klog.Errorf("failed to remove policy %s finalizers: %s", policy.Name, err.Error())
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *PolicyReconciler) cleanPolicyDependents(ctx context.Context, policyName string) error {
	// remove policy completeRules from cache
	completeRules, _ := r.ruleCache.ByIndex(policycache.PolicyIndex, policyName)
	for _, completeRule := range completeRules {
		r.ruleCache.Delete(completeRule)
	}

	// remove depents rules from apiserver
	err := r.DeleteAllOf(ctx, &policyv1alpha1.PolicyRule{}, client.MatchingLabels{lynxctrl.OwnerPolicyLabel: policyName})
	if err != nil {
		klog.Errorf("failed to delete policy %s dependents: %s", policyName, err.Error())
		return err
	}

	return nil
}

func (r *PolicyReconciler) processPolicyUpdate(ctx context.Context, policy *securityv1alpha1.SecurityPolicy) (ctrl.Result, error) {
	var newRuleList = policyv1alpha1.PolicyRuleList{}
	var oldRuleList = policyv1alpha1.PolicyRuleList{}
	var err error

	newRuleList, err = r.calculateExpectedPolicyRules(policy)
	if isGroupNotFound(err) {
		// wait until groupmembers created
		return ctrl.Result{Requeue: true}, nil
	}
	if err != nil {
		klog.Errorf("failed fetch new policy %s rules: %s", policy.Name, err)
		return ctrl.Result{}, err
	}

	// todo: replace with fetch from cache PolicyRules
	err = r.ReadClient.List(ctx, &oldRuleList, client.MatchingLabels{lynxctrl.OwnerPolicyLabel: policy.Name})
	if err != nil {
		klog.Errorf("failed fetch old policy %s rules: %s", policy.Name, err)
		return ctrl.Result{}, err
	}

	// start a force full synchronization of policyrule
	r.syncPolicyRulesUntilSuccess(ctx, oldRuleList, newRuleList)

	return ctrl.Result{}, nil
}

func (r *PolicyReconciler) calculateExpectedPolicyRules(policy *securityv1alpha1.SecurityPolicy) (policyv1alpha1.PolicyRuleList, error) {
	var policyRuleList = policyv1alpha1.PolicyRuleList{}

	completeRules, err := r.completePolicy(policy)
	if err != nil {
		return policyRuleList, fmt.Errorf("flatten policy %s: %s", policy.Name, err)
	}

	// todo: replace delete and add completeRules with update
	oldCompleteRules, _ := r.ruleCache.ByIndex(policycache.PolicyIndex, policy.Name)
	for _, oldCompleteRule := range oldCompleteRules {
		r.ruleCache.Delete(oldCompleteRule)
	}

	for _, completeRule := range completeRules {
		r.ruleCache.Add(completeRule)
		policyRuleList.Items = append(policyRuleList.Items, completeRule.ListRules().Items...)
	}

	return policyRuleList, nil
}

func (r *PolicyReconciler) completePolicy(policy *securityv1alpha1.SecurityPolicy) ([]*policycache.CompleteRule, error) {
	var completeRules []*policycache.CompleteRule

	appliedToPeer := securityv1alpha1.SecurityPolicyPeer{
		IPBlocks:       nil,
		EndpointGroups: policy.Spec.AppliedToEndpointGroups,
	}
	appliedGroups, appliedIPBlocks, err := r.getPeerGroupsAndIPBlocks(&appliedToPeer)
	if err != nil {
		return nil, err
	}

	for _, rule := range policy.Spec.IngressRules {
		ingressRule := &policycache.CompleteRule{
			RuleID:      fmt.Sprintf("%s/%s.%s", policy.Name, "ingress", rule.Name),
			Priority:    policy.Spec.Priority,
			Tier:        policy.Spec.Tier,
			Action:      policyv1alpha1.RuleActionAllow,
			Direction:   policyv1alpha1.RuleDirectionIn,
			DstGroups:   policycache.DeepCopyMap(appliedGroups).(map[string]int32),
			DstIPBlocks: policycache.DeepCopyMap(appliedIPBlocks).(map[string]int),
		}

		if len(rule.From.IPBlocks)+len(rule.From.EndpointGroups) == 0 {
			// empty From matches all sources
			ingressRule.SrcIPBlocks = map[string]int{"": 1}
		} else {
			ingressRule.SrcGroups, ingressRule.SrcIPBlocks, err = r.getPeerGroupsAndIPBlocks(&rule.From)
			if err != nil {
				return nil, err
			}
		}

		if len(rule.Ports) == 0 {
			// empty Ports matches all ports
			ingressRule.Ports = []policycache.RulePort{{}}
		} else {
			ingressRule.Ports, err = flattenPorts(rule.Ports)
			if err != nil {
				return nil, err
			}
		}

		completeRules = append(completeRules, ingressRule)
	}

	for _, rule := range policy.Spec.EgressRules {
		egressRule := &policycache.CompleteRule{
			RuleID:      fmt.Sprintf("%s/%s.%s", policy.Name, "egress", rule.Name),
			Priority:    policy.Spec.Priority,
			Tier:        policy.Spec.Tier,
			Action:      policyv1alpha1.RuleActionAllow,
			Direction:   policyv1alpha1.RuleDirectionOut,
			SrcGroups:   policycache.DeepCopyMap(appliedGroups).(map[string]int32),
			SrcIPBlocks: policycache.DeepCopyMap(appliedIPBlocks).(map[string]int),
		}

		if len(rule.To.IPBlocks)+len(rule.To.EndpointGroups) == 0 {
			// empty From matches all sources
			egressRule.DstIPBlocks = map[string]int{"": 1}
		} else {
			egressRule.DstGroups, egressRule.DstIPBlocks, err = r.getPeerGroupsAndIPBlocks(&rule.To)
			if err != nil {
				return nil, err
			}
		}

		if len(rule.Ports) == 0 {
			// Empty ports matches all ports
			egressRule.Ports = []policycache.RulePort{{}}
		} else {
			egressRule.Ports, err = flattenPorts(rule.Ports)
			if err != nil {
				return nil, err
			}
		}

		completeRules = append(completeRules, egressRule)
	}

	defaultIngressRule := &policycache.CompleteRule{
		RuleID:            fmt.Sprintf("%s/%s.%s", policy.Name, "default", "ingress"),
		Priority:          policy.Spec.Priority,
		Tier:              policy.Spec.Tier,
		Action:            policyv1alpha1.RuleActionDrop,
		Direction:         policyv1alpha1.RuleDirectionIn,
		DefaultPolicyRule: true,
		DstGroups:         policycache.DeepCopyMap(appliedGroups).(map[string]int32),
		DstIPBlocks:       policycache.DeepCopyMap(appliedIPBlocks).(map[string]int),
		SrcIPBlocks:       map[string]int{"": 1},      // matches all source IP
		Ports:             []policycache.RulePort{{}}, // has a port matches all ports
	}

	defaultEgressRule := &policycache.CompleteRule{
		RuleID:            fmt.Sprintf("%s/%s.%s", policy.Name, "default", "egress"),
		Priority:          policy.Spec.Priority,
		Tier:              policy.Spec.Tier,
		Action:            policyv1alpha1.RuleActionDrop,
		Direction:         policyv1alpha1.RuleDirectionOut,
		DefaultPolicyRule: true,
		SrcGroups:         policycache.DeepCopyMap(appliedGroups).(map[string]int32),
		SrcIPBlocks:       policycache.DeepCopyMap(appliedIPBlocks).(map[string]int),
		DstIPBlocks:       map[string]int{"": 1},      // matches all destination IP
		Ports:             []policycache.RulePort{{}}, // has a port matches all ports
	}

	completeRules = append(completeRules, defaultEgressRule, defaultIngressRule)
	return completeRules, nil
}

// getPeerGroupsAndIPBlocks get ipBlocks from groups, return unique ipBlock list
func (r *PolicyReconciler) getPeerGroupsAndIPBlocks(peer *securityv1alpha1.SecurityPolicyPeer) (map[string]int32, map[string]int, error) {
	var groups = make(map[string]int32)
	var ipBlocks = make(map[string]int)

	for group := range sets.NewString(peer.EndpointGroups...) {
		revision, ipAddrs, exist := r.groupCache.ListGroupIPBlocks(group)
		if !exist {
			return nil, nil, groupNotFound(fmt.Errorf("group %s members not found", group))
		}
		groups[group] = revision

		for _, ipBlock := range ipAddrs {
			ipBlocks[ipBlock]++
		}
	}

	for _, ipBlock := range peer.IPBlocks {
		ipBlocks[fmt.Sprintf("%s/%d", ipBlock.IP, ipBlock.PrefixLength)]++
	}

	return groups, ipBlocks, nil
}

func (r *PolicyReconciler) syncPolicyRulesUntilSuccess(ctx context.Context, oldRuleList, newRuleList policyv1alpha1.PolicyRuleList) {
	var err = r.compareAndApplyPolicyRulesChanges(ctx, oldRuleList, newRuleList)
	var rateLimiter = workqueue.NewItemExponentialFailureRateLimiter(time.Microsecond, time.Second)

	for err != nil {
		duration := rateLimiter.When("next-sync")
		klog.Errorf("failed to sync policyRules, next sync after %s: %s", duration, err)
		time.Sleep(duration)

		err = r.compareAndApplyPolicyRulesChanges(ctx, oldRuleList, newRuleList)
	}
}

func (r *PolicyReconciler) compareAndApplyPolicyRulesChanges(ctx context.Context, oldRuleList, newRuleList policyv1alpha1.PolicyRuleList) error {
	var errList []error

	newRuleMap := toRuleMap(newRuleList.Items)
	oldRuleMap := toRuleMap(oldRuleList.Items)
	allRuleSet := sets.StringKeySet(newRuleMap).Union(sets.StringKeySet(oldRuleMap))

	for ruleName := range allRuleSet {
		oldRule, oldExist := oldRuleMap[ruleName]
		newRule, newExist := newRuleMap[ruleName]

		if ruleIsSame(newRule, oldRule) {
			continue
		}

		if oldExist {
			klog.Infof("remove policyRule: %v", oldRule.Spec)
			if err := r.Delete(ctx, oldRule.DeepCopy()); !apierrors.IsNotFound(err) {
				errList = append(errList, err)
			}
		}

		if newExist {
			klog.Infof("create policyRule: %v", newRule.Spec)
			if err := r.Create(ctx, newRule.DeepCopy()); !apierrors.IsAlreadyExists(err) {
				errList = append(errList, err)
			}
		}
	}

	return errors.NewAggregate(errList)
}

func ruleIsSame(r1, r2 *policyv1alpha1.PolicyRule) bool {
	return r1 != nil && r2 != nil &&
		r1.Name == r2.Name && r1.Spec == r2.Spec
}

func flattenPorts(ports []securityv1alpha1.SecurityPolicyPort) ([]policycache.RulePort, error) {
	var rulePortList []policycache.RulePort
	var rulePortMap = make(map[policycache.RulePort]struct{})

	for _, port := range ports {
		if port.Protocol == securityv1alpha1.ProtocolICMP {
			// ignore portrange when Protocol is ICMP
			portItem := policycache.RulePort{
				Protocol: port.Protocol,
			}
			rulePortMap[portItem] = struct{}{}
			continue
		}

		begin, end, err := policycache.UnmarshalPortRange(port.PortRange)
		if err != nil {
			return nil, fmt.Errorf("portrange %s unavailable: %s", port.PortRange, err)
		}

		for portNumber := begin; portNumber <= end; portNumber++ {
			portItem := policycache.RulePort{
				DstPort:  portNumber,
				Protocol: port.Protocol,
			}
			rulePortMap[portItem] = struct{}{}
		}
	}

	// use map remove duplicate port
	for port := range rulePortMap {
		rulePortList = append(rulePortList, port)
	}

	return rulePortList, nil
}

func toRuleMap(ruleList []policyv1alpha1.PolicyRule) map[string]*policyv1alpha1.PolicyRule {
	var ruleMap = make(map[string]*policyv1alpha1.PolicyRule, len(ruleList))
	for item, rule := range ruleList {
		ruleMap[rule.Name] = &ruleList[item]
	}
	return ruleMap
}

type (
	// groupNotFound means policy needed group not found, needed retry.
	groupNotFound error
)

func isGroupNotFound(err error) bool {
	_, isType := err.(groupNotFound)
	return isType
}
