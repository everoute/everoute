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
	"strings"
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
	"github.com/smartxworks/lynx/pkg/constants"
	policycache "github.com/smartxworks/lynx/pkg/controller/policy/cache"
	"github.com/smartxworks/lynx/pkg/utils"
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

func (r *PolicyReconciler) ReconcileEndpoint(req ctrl.Request) (ctrl.Result, error) {
	var endpoint securityv1alpha1.Endpoint
	var ctx = context.Background()
	var err error

	r.reconcilerLock.Lock()
	defer r.reconcilerLock.Unlock()

	err = r.Get(ctx, req.NamespacedName, &endpoint)
	if client.IgnoreNotFound(err) != nil {
		klog.Errorf("unable to fetch endpoint %s: %s", req.Name, err.Error())
		return ctrl.Result{}, err
	}

	endpointReferencePolicy, err := r.endpointReferencePolicy(ctx, endpoint)
	if err != nil {
		return ctrl.Result{}, err
	}

	for i := 0; i < len(endpointReferencePolicy); i++ {
		_, err = r.processPolicyUpdate(ctx, &endpointReferencePolicy[i])
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *PolicyReconciler) endpointReferencePolicy(ctx context.Context,
	endpoint securityv1alpha1.Endpoint) ([]securityv1alpha1.SecurityPolicy, error) {
	var policyList securityv1alpha1.SecurityPolicyList
	var referencePolicyList []securityv1alpha1.SecurityPolicy

	err := r.List(ctx, &policyList)
	if client.IgnoreNotFound(err) != nil {
		klog.Errorf("failed fetch policyList, error: %s", err)
		return referencePolicyList, err
	}

	for _, policy := range policyList.Items {
		policyReferenceEndpoints := getPolicyReferenceEndpoints(policy)
		for _, ep := range policyReferenceEndpoints {
			// endpoint in security policy has the same namespace with the security policy
			if ep == endpoint.Name && policy.Namespace == endpoint.Namespace {
				referencePolicyList = append(referencePolicyList, policy)
				break
			}
		}
	}

	return referencePolicyList, err
}

func getPolicyReferenceEndpoints(policy securityv1alpha1.SecurityPolicy) []string {
	var referencedEndpoints []string

	referencedEndpoints = append(referencedEndpoints, policy.Spec.AppliedTo.Endpoints...)

	for _, rule := range policy.Spec.IngressRules {
		referencedEndpoints = append(referencedEndpoints, rule.From.Endpoints...)
	}
	for _, rule := range policy.Spec.EgressRules {
		referencedEndpoints = append(referencedEndpoints, rule.To.Endpoints...)
	}

	return referencedEndpoints
}

func (r *PolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if mgr == nil {
		return fmt.Errorf("can't setup with nil manager")
	}

	var err error
	var policyController, patchController, endpointController controller.Controller

	// ignore not empty ruleCache for future cache inject
	if r.ruleCache == nil {
		r.ruleCache = policycache.NewCompleteRuleCache()
	}

	// ignore not empty groupCache for future cache inject
	if r.groupCache == nil {
		r.groupCache = policycache.NewGroupCache()
	}

	policyController, err = controller.New("policy-controller", mgr, controller.Options{
		MaxConcurrentReconciles: constants.DefaultMaxConcurrentReconciles,
		Reconciler:              reconcile.Func(r.ReconcilePolicy),
	})
	if err != nil {
		return err
	}

	err = policyController.Watch(&source.Kind{Type: &securityv1alpha1.SecurityPolicy{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	patchController, err = controller.New("groupPatch-controller", mgr, controller.Options{
		MaxConcurrentReconciles: constants.DefaultMaxConcurrentReconciles,
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

	endpointController, err = controller.New("endpoint-controller", mgr, controller.Options{
		MaxConcurrentReconciles: constants.DefaultMaxConcurrentReconciles,
		Reconciler:              reconcile.Func(r.ReconcileEndpoint),
	})
	if err != nil {
		return err
	}

	err = endpointController.Watch(&source.Kind{Type: &securityv1alpha1.Endpoint{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	globalPolicyController, err := controller.New("global-policy-controller", mgr, controller.Options{
		// Serial handle GlobalPolicy event
		MaxConcurrentReconciles: 1,
		Reconciler:              reconcile.Func(r.ReconcileGlobalPolicy),
	})
	if err != nil {
		return err
	}

	err = globalPolicyController.Watch(&source.Kind{Type: &securityv1alpha1.GlobalPolicy{}}, &handler.EnqueueRequestForObject{})
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

	policy.ObjectMeta.Finalizers = []string{constants.DependentsCleanFinalizer}

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
	err := r.DeleteAllOf(ctx, &policyv1alpha1.PolicyRule{}, client.MatchingLabels{constants.OwnerPolicyLabelKey: policyName})
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
	err = r.ReadClient.List(ctx, &oldRuleList, client.MatchingLabels{constants.OwnerPolicyLabelKey: policy.Name})
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

//nolint:dupl // todo: remove dupl codes
func (r *PolicyReconciler) completePolicy(policy *securityv1alpha1.SecurityPolicy) ([]*policycache.CompleteRule, error) {
	var completeRules []*policycache.CompleteRule
	var ingressEnabled, egressEnabled = policy.IsEnable()

	appliedToPeer := securityv1alpha1.SecurityPolicyPeer{
		IPBlocks:       nil,
		EndpointGroups: policy.Spec.AppliedTo.EndpointGroups,
		Endpoints:      policy.Spec.AppliedTo.Endpoints,
	}
	// use policy namespace as applied to endpoint namespace
	appliedGroups, appliedIPBlocks, err := r.getPeerGroupsAndIPBlocks(policy.Namespace, &appliedToPeer)
	if err != nil {
		return nil, err
	}

	if ingressEnabled {
		for _, rule := range policy.Spec.IngressRules {
			ingressRule := &policycache.CompleteRule{
				RuleID:        fmt.Sprintf("%s/%s.%s", policy.Name, "ingress", rule.Name),
				Tier:          policy.Spec.Tier,
				Action:        policyv1alpha1.RuleActionAllow,
				Direction:     policyv1alpha1.RuleDirectionIn,
				SymmetricMode: policy.Spec.SymmetricMode,
				DstGroups:     policycache.DeepCopyMap(appliedGroups).(map[string]int32),
				DstIPBlocks:   policycache.DeepCopyMap(appliedIPBlocks).(map[string]int),
			}

			if len(rule.From.IPBlocks)+len(rule.From.EndpointGroups) == 0 {
				// empty From matches all sources
				ingressRule.SrcIPBlocks = map[string]int{"": 1}
			} else {
				// use policy namespace as ingress endpoint namespace
				ingressRule.SrcGroups, ingressRule.SrcIPBlocks, err = r.getPeerGroupsAndIPBlocks(policy.Namespace, &rule.From)
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

		defaultIngressRule := &policycache.CompleteRule{
			RuleID:            fmt.Sprintf("%s/%s.%s", policy.Name, "default", "ingress"),
			Tier:              policy.Spec.Tier,
			Action:            policyv1alpha1.RuleActionDrop,
			Direction:         policyv1alpha1.RuleDirectionIn,
			SymmetricMode:     false, // never generate symmetric rule for default rule
			DefaultPolicyRule: true,
			DstGroups:         policycache.DeepCopyMap(appliedGroups).(map[string]int32),
			DstIPBlocks:       policycache.DeepCopyMap(appliedIPBlocks).(map[string]int),
			SrcIPBlocks:       map[string]int{"": 1},      // matches all source IP
			Ports:             []policycache.RulePort{{}}, // has a port matches all ports
		}

		completeRules = append(completeRules, defaultIngressRule)
	}

	if egressEnabled {
		for _, rule := range policy.Spec.EgressRules {
			egressRule := &policycache.CompleteRule{
				RuleID:        fmt.Sprintf("%s/%s.%s", policy.Name, "egress", rule.Name),
				Tier:          policy.Spec.Tier,
				Action:        policyv1alpha1.RuleActionAllow,
				Direction:     policyv1alpha1.RuleDirectionOut,
				SymmetricMode: policy.Spec.SymmetricMode,
				SrcGroups:     policycache.DeepCopyMap(appliedGroups).(map[string]int32),
				SrcIPBlocks:   policycache.DeepCopyMap(appliedIPBlocks).(map[string]int),
			}

			if len(rule.To.IPBlocks)+len(rule.To.EndpointGroups) == 0 {
				// empty From matches all sources
				egressRule.DstIPBlocks = map[string]int{"": 1}
			} else {
				// use policy namespace as egress endpoint namespace
				egressRule.DstGroups, egressRule.DstIPBlocks, err = r.getPeerGroupsAndIPBlocks(policy.Namespace, &rule.To)
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

		defaultEgressRule := &policycache.CompleteRule{
			RuleID:            fmt.Sprintf("%s/%s.%s", policy.Name, "default", "egress"),
			Tier:              policy.Spec.Tier,
			Action:            policyv1alpha1.RuleActionDrop,
			Direction:         policyv1alpha1.RuleDirectionOut,
			SymmetricMode:     false, // never generate symmetric rule for default rule
			DefaultPolicyRule: true,
			SrcGroups:         policycache.DeepCopyMap(appliedGroups).(map[string]int32),
			SrcIPBlocks:       policycache.DeepCopyMap(appliedIPBlocks).(map[string]int),
			DstIPBlocks:       map[string]int{"": 1},      // matches all destination IP
			Ports:             []policycache.RulePort{{}}, // has a port matches all ports
		}

		completeRules = append(completeRules, defaultEgressRule)
	}

	return completeRules, nil
}

// getPeerGroupsAndIPBlocks get ipBlocks from groups, return unique ipBlock list
func (r *PolicyReconciler) getPeerGroupsAndIPBlocks(namespace string, peer *securityv1alpha1.SecurityPolicyPeer) (map[string]int32, map[string]int, error) {
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

	for index := range peer.IPBlocks {
		ipNets, err := utils.ParseIPBlock(&peer.IPBlocks[index])
		if err != nil {
			klog.Infof("unable parse IPBlocks %+v: %s", peer.IPBlocks, err)
			return nil, nil, err
		}
		for _, ipNet := range ipNets {
			ipBlocks[ipNet.String()]++
		}
	}

	for _, ep := range peer.Endpoints {
		var endpoint securityv1alpha1.Endpoint
		ctx := context.Background()
		err := r.Get(ctx, k8stypes.NamespacedName{Name: ep, Namespace: namespace}, &endpoint)
		if client.IgnoreNotFound(err) != nil {
			klog.Errorf("Failed to get endpoint: %v, error: %v", ep, err)
			return nil, nil, err
		}

		for _, ip := range endpoint.Status.IPs {
			ipBlocks[policycache.GetIPCidr(ip)]++
		}
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

func posToMask(pos int) uint16 {
	var ret uint16 = 0xffff
	for i := 16; i > pos; i-- {
		ret <<= 1
	}

	return ret
}

func calPortRangeMask(begin uint16, end uint16, protocol securityv1alpha1.Protocol) []policycache.RulePort {
	var rulePortList []policycache.RulePort

	if begin == 0 && end == 0 {
		return append(rulePortList, policycache.RulePort{
			Protocol: protocol,
			DstPort:  0,
		})
	}

	var pos int
	for begin <= end && begin != 0 {
		// find "1" pos from right
		var temp = begin
		pos = 16
		for {
			if temp%2 == 1 {
				break
			}
			temp >>= 1
			pos--
		}
		// check from pos to end
		for i := pos; i <= 16; i++ {
			if end >= begin+(1<<(16-i))-1 {
				rulePortList = append(rulePortList, policycache.RulePort{
					Protocol:    protocol,
					DstPort:     begin,
					DstPortMask: posToMask(i),
				})
				begin += 1 << (16 - i)
				break
			}
		}
	}
	return rulePortList
}

func processFlattenPorts(portMap [65536]bool, protocol securityv1alpha1.Protocol) []policycache.RulePort {
	var rulePortList []policycache.RulePort
	// generate port with mask
	begin := -1
	end := -1
	for index, port := range portMap {
		// mark begin pos
		if port && begin == -1 {
			begin = index
		}
		// mask end pos at the last element
		if port && begin != -1 && index == len(portMap)-1 {
			end = index
		}
		// mask end pos at the end of each port range
		if !port && begin != -1 {
			end = index - 1
		}
		// calculate rule
		if begin != -1 && end != -1 {
			rulePortList = append(rulePortList, calPortRangeMask(uint16(begin), uint16(end), protocol)...)
			begin = -1
			end = -1
		}
	}
	return rulePortList
}

func FlattenPorts(ports []securityv1alpha1.SecurityPolicyPort) ([]policycache.RulePort, error) {
	var rulePortList []policycache.RulePort
	var portMapTCP [65536]bool
	var portMapUDP [65536]bool
	var hasICMP = false

	for _, port := range ports {
		if port.Protocol == securityv1alpha1.ProtocolICMP {
			// ignore port when Protocol is ICMP
			hasICMP = true
			continue
		}

		// Split port range to multiple port range, e.g. "22,80-82" to ["22","80-82"]
		portRange := strings.Split(port.PortRange, ",")

		for _, subPortRange := range portRange {
			begin, end, err := policycache.UnmarshalPortRange(subPortRange)
			if err != nil {
				return nil, fmt.Errorf("portrange %s unavailable: %s", subPortRange, err)
			}

			if port.Protocol == securityv1alpha1.ProtocolTCP {
				// If defined portNumber as type uint16 here, an infinite loop will occur when end is
				// 65535 (uint16 value will never bigger than 65535, for condition would always true).
				// So we defined portNumber as type int here.
				for portNumber := int(begin); portNumber <= int(end); portNumber++ {
					portMapTCP[portNumber] = true
				}
			}

			if port.Protocol == securityv1alpha1.ProtocolUDP {
				for portNumber := int(begin); portNumber <= int(end); portNumber++ {
					portMapUDP[portNumber] = true
				}
			}
		}
	}
	rulePortList = append(rulePortList, processFlattenPorts(portMapTCP, securityv1alpha1.ProtocolTCP)...)
	rulePortList = append(rulePortList, processFlattenPorts(portMapUDP, securityv1alpha1.ProtocolUDP)...)
	// add ICMP Rule to rulePortList
	if hasICMP {
		rulePortList = append(rulePortList, policycache.RulePort{
			Protocol: securityv1alpha1.ProtocolICMP,
		})
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
