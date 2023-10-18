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

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	groupv1alpha1 "github.com/everoute/everoute/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
)

type Reconciler struct {
	client.Client
	ReadClient client.Reader
	Scheme     *runtime.Scheme

	// reconcilerLock prevent the problem of policyRule updated by policy controller
	// and patch controller at the same time.
	reconcilerLock sync.RWMutex
}

func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	if mgr == nil {
		return fmt.Errorf("can't setup with nil manager")
	}

	var err error
	var groupGenerator controller.Controller

	groupGenerator, err = controller.New("group-generator", mgr, controller.Options{
		MaxConcurrentReconciles: constants.DefaultMaxConcurrentReconciles,
		Reconciler:              reconcile.Func(r.GroupGenerateReconcile),
	})
	if err != nil {
		return err
	}

	err = groupGenerator.Watch(source.Kind(mgr.GetCache(), &securityv1alpha1.SecurityPolicy{}), &handler.Funcs{
		CreateFunc: r.addSecurityPolicy,
		UpdateFunc: r.updateSecurityPolicy,
		DeleteFunc: r.deleteSecurityPolicy,
	})
	if err != nil {
		return err
	}

	err = groupGenerator.Watch(source.Kind(mgr.GetCache(), &groupv1alpha1.EndpointGroup{}), &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	err = mgr.GetFieldIndexer().IndexField(context.Background(), &securityv1alpha1.SecurityPolicy{},
		constants.SecurityPolicyByEndpointGroupIndex,
		EndpointGroupIndexSecurityPolicyFunc,
	)
	if err != nil {
		return err
	}

	return nil
}
