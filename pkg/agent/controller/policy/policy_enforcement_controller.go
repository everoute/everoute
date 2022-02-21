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

	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
)

func (r *Reconciler) ReconcilePolicyEnforcementMode(request ctrl.Request) (ctrl.Result, error) {
	var policyMode securityv1alpha1.PolicyEnforcementMode
	var ctx = context.Background()

	r.reconcilerLock.Lock()
	defer r.reconcilerLock.Unlock()

	err := r.Get(ctx, request.NamespacedName, &policyMode)
	if client.IgnoreNotFound(err) != nil {
		klog.Errorf("unable to fetch policy %s: %s", request.Name, err.Error())
		return ctrl.Result{}, err
	}

	if err := r.UpdatePolicyEnforcementMode(policyMode); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *Reconciler) UpdatePolicyEnforcementMode(newMode securityv1alpha1.PolicyEnforcementMode) error {
	if err := r.DatapathManager.UpdateEveroutePolicyEnforcementMode(newMode.Name); err != nil {
		return err
	}

	return nil
}
