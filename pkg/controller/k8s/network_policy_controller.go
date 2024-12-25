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

package k8s

import (
	"context"
	"fmt"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/labels"
)

// NetworkPolicyReconciler watch network policy and sync to security policy
type NetworkPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile receive endpoint from work queue, synchronize the endpoint status
func (r *NetworkPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.Infof("NetworkPolicyReconciler received NetworkPolicy %s reconcile", req.NamespacedName)

	networkPolicy := networkingv1.NetworkPolicy{}
	securityPolicyName := "np-" + req.Name

	// delete securityPolicy if networkPolicy is not found
	if err := r.Get(ctx, req.NamespacedName, &networkPolicy); err != nil && errors.IsNotFound(err) {
		klog.Infof("Delete securityPolicy %s", securityPolicyName)
		securityPolicy := v1alpha1.SecurityPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      securityPolicyName,
				Namespace: req.Namespace,
			},
		}
		if err = r.Delete(ctx, &securityPolicy); err != nil && !errors.IsNotFound(err) {
			klog.Errorf("Delete securityPolicy %s failed, err: %s", securityPolicyName, err)
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	securityPolicy := &v1alpha1.SecurityPolicy{}
	securityPolicyReq := types.NamespacedName{
		Namespace: req.Namespace,
		Name:      securityPolicyName,
	}
	err := r.Get(ctx, securityPolicyReq, securityPolicy)
	// generate new securityPolicy
	newSecurityPolicy := getSecurityPolicy(&networkPolicy)
	if errors.IsNotFound(err) {
		// submit creation
		if err := r.Create(ctx, newSecurityPolicy); err != nil {
			klog.Errorf("create securityPolicy %s, err: %s", newSecurityPolicy.Name, err)
			return ctrl.Result{}, err
		}
	}
	if err == nil {
		// submit update
		securityPolicy.Spec = *(newSecurityPolicy.Spec.DeepCopy())
		if err := r.Update(ctx, securityPolicy); err != nil {
			klog.Errorf("update securityPolicy %s, err: %s", securityPolicy.Name, err)
			return ctrl.Result{}, err
		}
	}
	if err != nil && !errors.IsNotFound(err) {
		klog.Errorf("Get securityPolicy error, err: %s", err)
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager create and add networkPolicy Controller to the manager.
func (r *NetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if mgr == nil {
		return fmt.Errorf("can't setup with nil manager")
	}

	c, err := controller.New("networkPolicy-controller", mgr, controller.Options{
		MaxConcurrentReconciles: constants.DefaultMaxConcurrentReconciles,
		Reconciler:              r,
	})
	if err != nil {
		return err
	}

	if err = c.Watch(source.Kind(mgr.GetCache(), &networkingv1.NetworkPolicy{}), &handler.EnqueueRequestForObject{}); err != nil {
		return err
	}

	return c.Watch(source.Kind(mgr.GetCache(), &v1alpha1.SecurityPolicy{}), &handler.Funcs{
		CreateFunc: r.addSecurityPolicy,
	})
}

func (r *NetworkPolicyReconciler) addSecurityPolicy(_ context.Context, e event.CreateEvent, q workqueue.RateLimitingInterface) {
	if e.Object == nil {
		klog.Errorf("receive create event with no object %v", e)
		return
	}

	// only handle addSecurityPolicy with "np-" prefix
	if strings.HasPrefix(e.Object.GetName(), "np-") {
		q.Add(ctrl.Request{NamespacedName: types.NamespacedName{
			Namespace: e.Object.GetNamespace(),
			Name:      strings.TrimPrefix(e.Object.GetName(), "np-"),
		}})
	}
}

// getSecurityPolicy convert NetworkPolicy into SecurityPolicy
func getSecurityPolicy(networkPolicy *networkingv1.NetworkPolicy) *v1alpha1.SecurityPolicy {
	securityPolicy := &v1alpha1.SecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "np-" + networkPolicy.Name,
			Namespace: networkPolicy.Namespace,
		},
		Spec: v1alpha1.SecurityPolicySpec{
			Tier:          constants.Tier2,
			SymmetricMode: false,
			AppliedTo: []v1alpha1.ApplyToPeer{{
				EndpointSelector: labels.FromLabelSelector(networkPolicy.Spec.PodSelector.DeepCopy()),
			}},
			PolicyTypes: append([]networkingv1.PolicyType{}, networkPolicy.Spec.PolicyTypes...),
		},
	}

	// process IngressRules
	if len(networkPolicy.Spec.Ingress) != 0 {
		securityPolicy.Spec.IngressRules = []v1alpha1.Rule{}
		for index, rule := range networkPolicy.Spec.Ingress {
			newRule := v1alpha1.Rule{
				Name:  "ingress" + fmt.Sprintf("%d", index),
				Ports: getSecurityPolicyPort(rule.Ports),
				From:  getSecurityPolicyPeer(rule.From),
			}
			securityPolicy.Spec.IngressRules = append(securityPolicy.Spec.IngressRules, newRule)
		}
	}

	// process EgressRules
	if len(networkPolicy.Spec.Egress) != 0 {
		securityPolicy.Spec.EgressRules = []v1alpha1.Rule{}
		for index, rule := range networkPolicy.Spec.Egress {
			newRule := v1alpha1.Rule{
				Name:  "egress" + fmt.Sprintf("%d", index),
				Ports: getSecurityPolicyPort(rule.Ports),
				To:    getSecurityPolicyPeer(rule.To),
			}
			securityPolicy.Spec.EgressRules = append(securityPolicy.Spec.EgressRules, newRule)
		}
	}

	return securityPolicy
}

func getSecurityPolicyPort(networkPolicyPort []networkingv1.NetworkPolicyPort) []v1alpha1.SecurityPolicyPort {
	if len(networkPolicyPort) == 0 {
		return nil
	}

	var securityPolicyPort []v1alpha1.SecurityPolicyPort
	for _, port := range networkPolicyPort {
		newPort := v1alpha1.SecurityPolicyPort{
			Protocol:  v1alpha1.Protocol(*port.Protocol),
			Type:      v1alpha1.PortTypeNumber,
			PortRange: "",
		}

		if port.Port != nil {
			newPort.PortRange = port.Port.String()
			if port.Port.Type == intstr.String {
				newPort.Type = v1alpha1.PortTypeName
			}
		}

		// handle port range for Kubernetes v1.22+
		/*
			if port.EndPort != nil {
				newPort.PortRange += fmt.Sprintf("-%d", *port.EndPort)
			}
		*/
		securityPolicyPort = append(securityPolicyPort, newPort)
	}

	return securityPolicyPort
}

func getSecurityPolicyPeer(networkPolicyPeer []networkingv1.NetworkPolicyPeer) []v1alpha1.SecurityPolicyPeer {
	if len(networkPolicyPeer) == 0 {
		return nil
	}

	var securityPolicyPeer []v1alpha1.SecurityPolicyPeer
	for _, peer := range networkPolicyPeer {
		netPeer := v1alpha1.SecurityPolicyPeer{
			IPBlock:           peer.IPBlock.DeepCopy(),
			EndpointSelector:  labels.FromLabelSelector(peer.PodSelector.DeepCopy()),
			NamespaceSelector: peer.NamespaceSelector.DeepCopy(),
		}
		securityPolicyPeer = append(securityPolicyPeer, netPeer)
	}

	return securityPolicyPeer
}
