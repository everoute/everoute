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

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	groupv1alpha1 "github.com/smartxworks/lynx/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
	"github.com/smartxworks/lynx/pkg/constants"
	"github.com/smartxworks/lynx/pkg/controller/policy/cache"
)

// GroupGenerateReconcile generate EndpointGroups by SecurityPolicy selector.
func (r *PolicyReconciler) GroupGenerateReconcile(req ctrl.Request) (ctrl.Result, error) {
	policyList := securityv1alpha1.SecurityPolicyList{}
	var endpointGroupExist bool

	err := r.List(context.Background(), &policyList, client.MatchingFields{
		constants.SecurityPolicyByEndpointGroupIndex: req.Name,
	})
	if err != nil {
		klog.Errorf("list of SecurityPolicies reference EndpointGroup %s: %s", req.Name, err)
		return ctrl.Result{}, err
	}

	err = r.Get(context.Background(), req.NamespacedName, &groupv1alpha1.EndpointGroup{})
	if err != nil && !errors.IsNotFound(err) {
		klog.Errorf("get EndpointGroup %s: %s", req.Name, err)
		return ctrl.Result{}, err
	}
	endpointGroupExist = err == nil

	switch len(policyList.Items) {
	case 0:
		if endpointGroupExist {
			// not SecurityPolicies reference the EndpointGroup, try to delete the EndpointGroup
			err = r.Delete(context.Background(), &groupv1alpha1.EndpointGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      req.Name,
					Namespace: req.Namespace,
				},
			})
			if err != nil && !errors.IsNotFound(err) {
				klog.Errorf("unable delete EndpointGroup %s: %s", req.Name, err)
				return ctrl.Result{}, err
			}
			klog.Errorf("successful delete EndpointGroup %s", req.Name)
			return ctrl.Result{}, nil
		}
	default:
		if !endpointGroupExist {
			endpointGroup := r.getEndpointGroupFromSecurityPolicy(&policyList.Items[0], req.Name)
			// make sure the EndpointGroup has been created
			err = r.Create(context.Background(), endpointGroup)
			if err != nil && !errors.IsAlreadyExists(err) {
				klog.Errorf("unable create EndpointGroup %+v: %s", req.Name, err)
				return ctrl.Result{}, err
			}
			klog.Errorf("successful create EndpointGroup %+v", endpointGroup)
			return ctrl.Result{}, nil
		}
	}

	return ctrl.Result{}, nil
}

func (r *PolicyReconciler) addSecurityPolicy(e event.CreateEvent, q workqueue.RateLimitingInterface) {
	policy := e.Object.(*securityv1alpha1.SecurityPolicy)

	for _, group := range EndpointGroupIndexSecurityPolicyFunc(policy) {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Namespace: metav1.NamespaceNone,
			Name:      group,
		}})
	}
}

func (r *PolicyReconciler) updateSecurityPolicy(e event.UpdateEvent, q workqueue.RateLimitingInterface) {
	policyNew := e.ObjectNew.(*securityv1alpha1.SecurityPolicy)
	policyOld := e.ObjectOld.(*securityv1alpha1.SecurityPolicy)

	referenceGroups := append(EndpointGroupIndexSecurityPolicyFunc(policyNew), EndpointGroupIndexSecurityPolicyFunc(policyOld)...)
	for _, group := range referenceGroups {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Namespace: metav1.NamespaceNone,
			Name:      group,
		}})
	}
}

func (r *PolicyReconciler) deleteSecurityPolicy(e event.DeleteEvent, q workqueue.RateLimitingInterface) {
	policy := e.Object.(*securityv1alpha1.SecurityPolicy)

	for _, group := range EndpointGroupIndexSecurityPolicyFunc(policy) {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Namespace: metav1.NamespaceNone,
			Name:      group,
		}})
	}
}

func (r *PolicyReconciler) getEndpointGroupFromSecurityPolicy(policy *securityv1alpha1.SecurityPolicy, groupName string) *groupv1alpha1.EndpointGroup {
	for _, appliedTo := range policy.Spec.AppliedTo {
		group := appliedAsEndpointGroup(policy.GetNamespace(), appliedTo)
		if group != nil && group.GetName() == groupName {
			return group
		}
	}

	for _, rule := range append(policy.Spec.IngressRules, policy.Spec.EgressRules...) {
		for _, peer := range append(rule.From, rule.To...) {
			group := peerAsEndpointGroup(policy.GetNamespace(), peer)
			if group != nil && group.GetName() == groupName {
				return group
			}
		}
	}

	return nil
}

// EndpointGroupIndexSecurityPolicyFunc return the SecurityPolicy reference EndpointGroup names
func EndpointGroupIndexSecurityPolicyFunc(o runtime.Object) []string {
	policy := o.(*securityv1alpha1.SecurityPolicy)
	groupSet := sets.NewString()

	for _, appliedTo := range policy.Spec.AppliedTo {
		group := appliedAsEndpointGroup(policy.GetNamespace(), appliedTo)
		if group != nil {
			groupSet.Insert(group.GetName())
		}
	}

	for _, rule := range append(policy.Spec.IngressRules, policy.Spec.EgressRules...) {
		for _, peer := range append(rule.From, rule.To...) {
			group := peerAsEndpointGroup(policy.GetNamespace(), peer)
			if group != nil {
				groupSet.Insert(group.GetName())
			}
		}
	}

	return groupSet.List()
}

func peerAsEndpointGroup(namespace string, peer securityv1alpha1.SecurityPolicyPeer) *groupv1alpha1.EndpointGroup {
	if peer.EndpointSelector == nil && peer.NamespaceSelector == nil {
		return nil
	}

	group := new(groupv1alpha1.EndpointGroup)

	if peer.NamespaceSelector != nil {
		// If NamespaceSelector is also set, then the Rule would select the endpoints
		// matching EndpointSelector in the Namespaces selected by NamespaceSelector.
		group.Spec = groupv1alpha1.EndpointGroupSpec{
			EndpointSelector:  peer.EndpointSelector,
			NamespaceSelector: peer.NamespaceSelector,
		}
	} else {
		// Otherwise, it selects the Endpoints matching EndpointSelector in the policy's own Namespace.
		group.Spec = groupv1alpha1.EndpointGroupSpec{
			EndpointSelector: peer.EndpointSelector,
			Namespace:        &namespace,
		}
	}

	group.Name = GenerateGroupName(&group.Spec)

	return group
}

func appliedAsEndpointGroup(namespace string, applied securityv1alpha1.ApplyToPeer) *groupv1alpha1.EndpointGroup {
	securityPolicyPeer := appliedAsSecurityPeer(namespace, applied)
	return peerAsEndpointGroup(namespace, securityPolicyPeer)
}

func appliedAsSecurityPeer(namespace string, applied securityv1alpha1.ApplyToPeer) securityv1alpha1.SecurityPolicyPeer {
	securityPolicyPeer := securityv1alpha1.SecurityPolicyPeer{
		EndpointSelector: applied.EndpointSelector,
	}

	if applied.Endpoint != nil {
		securityPolicyPeer.Endpoint = &securityv1alpha1.NamespacedName{
			Name:      *applied.Endpoint,
			Namespace: namespace,
		}
	}

	return securityPolicyPeer
}

// GenerateGroupName use spec hash as EndpointGroup name
func GenerateGroupName(spec *groupv1alpha1.EndpointGroupSpec) string {
	hashName := cache.HashName(32, spec)
	return fmt.Sprintf("sys-%s", hashName)
}
