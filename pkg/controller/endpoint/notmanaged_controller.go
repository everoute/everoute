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

package endpoint

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	k8slabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	msconst "github.com/everoute/everoute/pkg/constants/ms"
	ersource "github.com/everoute/everoute/pkg/source"
)

type NotManagedReconciler struct {
	client.Client

	ConfigMapNamespace string
	ConfigMapName      string
	EndpointQueue      chan event.GenericEvent

	configMapCacheLock sync.Mutex
	configMapPrepared  bool
	managedVDSes       sets.Set[string]
}

func (r *NotManagedReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if mgr == nil {
		return fmt.Errorf("can't setup with nil manager")
	}
	if r.ConfigMapNamespace == "" {
		return fmt.Errorf("can't setup with empty ConfigMapNamespace")
	}
	if r.ConfigMapName == "" {
		return fmt.Errorf("can't setup with empty ConfigMapName")
	}
	if r.EndpointQueue == nil {
		r.EndpointQueue = make(chan event.GenericEvent, 1024)
	}
	if r.managedVDSes == nil {
		r.managedVDSes = sets.New[string]()
	}

	c, err := controller.New("endpoint-notmanaged-controller", mgr, controller.Options{
		MaxConcurrentReconciles: constants.DefaultMaxConcurrentReconciles,
		Reconciler:              r,
	})
	if err != nil {
		return err
	}

	if err = c.Watch(ersource.Kind(mgr.GetCache(), &securityv1alpha1.Endpoint{}), &handler.EnqueueRequestForObject{}, endpointVDSIDChangedPredicate()); err != nil {
		return err
	}

	if err = c.Watch(&source.Channel{Source: r.EndpointQueue}, &handler.EnqueueRequestForObject{}); err != nil {
		return err
	}

	configMapController, err := controller.New("endpoint-notmanaged-configmap-controller", mgr, controller.Options{
		MaxConcurrentReconciles: constants.DefaultMaxConcurrentReconciles,
		Reconciler:              reconcile.Func(r.ReconcileConfigMap),
	})
	if err != nil {
		return err
	}

	if err = configMapController.Watch(&ersource.WithSyncCache{
		Name:       "endpoint-notmanaged-configmap",
		Source:     ersource.Kind(mgr.GetCache(), &corev1.ConfigMap{}),
		SyncCaches: []ersource.SyncCache{mgr.GetCache()},
	}, &handler.EnqueueRequestForObject{}, r.configMapPredicate()); err != nil {
		return err
	}
	klog.Infof("Setup endpoint notManaged controller with association ConfigMap %s/%s", r.ConfigMapNamespace, r.ConfigMapName)
	return nil
}

func endpointVDSIDChangedPredicate() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldEndpoint, oldOK := e.ObjectOld.(*securityv1alpha1.Endpoint)
			newEndpoint, newOK := e.ObjectNew.(*securityv1alpha1.Endpoint)
			if !(oldOK && newOK) {
				return false
			}
			return oldEndpoint.Spec.VDSID != newEndpoint.Spec.VDSID
		},
		DeleteFunc: func(event.DeleteEvent) bool {
			return false
		},
		GenericFunc: func(event.GenericEvent) bool {
			return true
		},
	}
}

func (r *NotManagedReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.V(6).Infof("Reconciling endpoint notManaged status for %s/%s", req.Namespace, req.Name)
	endpoint := securityv1alpha1.Endpoint{}
	if err := r.Get(ctx, req.NamespacedName, &endpoint); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	prepared, managedVDSes, err := r.currentAssociation(ctx)
	if err != nil {
		klog.Errorf("Failed to load association ConfigMap for endpoint %s/%s: %s", endpoint.Namespace, endpoint.Name, err)
		return ctrl.Result{}, err
	}
	if !prepared {
		klog.V(4).Infof("Skip endpoint %s/%s notManaged reconciliation because association ConfigMap isn't prepared", endpoint.Namespace, endpoint.Name)
		return ctrl.Result{}, nil
	}

	if err := r.reconcileEndpoint(ctx, &endpoint, managedVDSes); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *NotManagedReconciler) ReconcileConfigMap(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.V(6).Infof("Reconciling endpoint notManaged association ConfigMap %s/%s", req.Namespace, req.Name)
	if req.Namespace != r.ConfigMapNamespace || req.Name != r.ConfigMapName {
		klog.V(6).Infof("Skip unexpected association ConfigMap request %s/%s", req.Namespace, req.Name)
		return ctrl.Result{}, nil
	}

	configMap := corev1.ConfigMap{}
	if err := r.Get(ctx, req.NamespacedName, &configMap); err != nil {
		if apierrors.IsNotFound(err) {
			r.updateConfigMapCache(false, sets.New[string]())
			klog.V(4).Infof("Association ConfigMap %s/%s was deleted, mark notManaged association as not prepared", req.Namespace, req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	prepared, managedVDSes, err := managedVDSesFromConfigMap(&configMap)
	if err != nil {
		r.updateConfigMapCache(false, sets.New[string]())
		klog.Errorf("parse association ConfigMap %s/%s: %s", configMap.Namespace, configMap.Name, err)
		return ctrl.Result{}, nil
	}
	if !prepared {
		r.updateConfigMapCache(false, sets.New[string]())
		klog.V(4).Infof("Association ConfigMap %s/%s isn't prepared, skip endpoint enqueue", configMap.Namespace, configMap.Name)
		return ctrl.Result{}, nil
	}

	oldPrepared, changedVDSes := r.updateConfigMapCache(true, managedVDSes)
	if !oldPrepared {
		klog.Infof("Association ConfigMap %s/%s prepared, enqueue all endpoints for notManaged reconciliation", configMap.Namespace, configMap.Name)
		r.enqueueAllEndpoints(ctx)
		return ctrl.Result{}, nil
	}
	if changedVDSes.Len() == 0 {
		klog.V(4).Infof("Association ConfigMap %s/%s has no managed VDS change, skip endpoint enqueue", configMap.Namespace, configMap.Name)
		return ctrl.Result{}, nil
	}

	klog.Infof("Association ConfigMap %s/%s changed managed VDSes %v, enqueue related endpoints for notManaged reconciliation",
		configMap.Namespace, configMap.Name, changedVDSes.UnsortedList())
	r.enqueueEndpointsByVDSes(ctx, changedVDSes)
	return ctrl.Result{}, nil
}

func (r *NotManagedReconciler) reconcileEndpoint(ctx context.Context, endpoint *securityv1alpha1.Endpoint, managedVDSes sets.Set[string]) error {
	expectNotManaged := endpoint.Spec.VDSID != "" && !managedVDSes.Has(endpoint.Spec.VDSID)
	if endpoint.Status.NotManaged == expectNotManaged {
		return nil
	}

	endpoint.Status.NotManaged = expectNotManaged
	if err := r.Status().Update(ctx, endpoint); err != nil {
		return fmt.Errorf("update endpoint %s/%s notManaged status: %w", endpoint.Namespace, endpoint.Name, err)
	}
	klog.Infof("Updated endpoint %s/%s notManaged status to %v", endpoint.Namespace, endpoint.Name, expectNotManaged)
	return nil
}

func (r *NotManagedReconciler) currentAssociation(ctx context.Context) (bool, sets.Set[string], error) {
	configMap := corev1.ConfigMap{}
	err := r.Get(ctx, k8stypes.NamespacedName{
		Namespace: r.ConfigMapNamespace,
		Name:      r.ConfigMapName,
	}, &configMap)
	if apierrors.IsNotFound(err) {
		return false, sets.New[string](), nil
	}
	if err != nil {
		return false, nil, err
	}
	return managedVDSesFromConfigMap(&configMap)
}

func (r *NotManagedReconciler) configMapPredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			configMap, ok := e.Object.(*corev1.ConfigMap)
			if !ok || !r.isAssociationConfigMap(configMap) {
				return false
			}

			newPrepared, _, err := managedVDSesFromConfigMap(configMap)
			if err != nil {
				klog.Errorf("parse association ConfigMap %s/%s: %s", configMap.Namespace, configMap.Name, err)
				return true
			}
			klog.V(6).Infof("Association ConfigMap %s/%s create predicate prepared=%v", configMap.Namespace, configMap.Name, newPrepared)
			return newPrepared
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldConfigMap, oldOK := e.ObjectOld.(*corev1.ConfigMap)
			newConfigMap, newOK := e.ObjectNew.(*corev1.ConfigMap)
			if !(oldOK && newOK) || !r.isAssociationConfigMap(newConfigMap) {
				return false
			}

			oldPrepared, oldManagedVDSes, err := managedVDSesFromConfigMap(oldConfigMap)
			if err != nil {
				klog.V(4).Infof("parse old association ConfigMap %s/%s: %s", oldConfigMap.Namespace, oldConfigMap.Name, err)
				oldPrepared = false
				oldManagedVDSes = sets.New[string]()
			}
			newPrepared, newManagedVDSes, err := managedVDSesFromConfigMap(newConfigMap)
			if err != nil {
				klog.Errorf("parse association ConfigMap %s/%s: %s", newConfigMap.Namespace, newConfigMap.Name, err)
				return true
			}
			if oldPrepared != newPrepared {
				klog.V(4).Infof("Association ConfigMap %s/%s update predicate accepted because prepared state changed from %v to %v",
					newConfigMap.Namespace, newConfigMap.Name, oldPrepared, newPrepared)
				return true
			}
			if !newPrepared {
				klog.V(6).Infof("Association ConfigMap %s/%s update predicate skipped because new object isn't prepared", newConfigMap.Namespace, newConfigMap.Name)
				return false
			}
			changedVDSes := oldManagedVDSes.Difference(newManagedVDSes).Union(newManagedVDSes.Difference(oldManagedVDSes))
			klog.V(4).Infof("Association ConfigMap %s/%s update predicate changed VDSes %v", newConfigMap.Namespace, newConfigMap.Name, changedVDSes.UnsortedList())
			return changedVDSes.Len() > 0
		},
		// Reconcile association ConfigMap delete events to clear the local prepared cache.
		DeleteFunc: r.predicateConfigMapDelete,
		GenericFunc: func(event.GenericEvent) bool {
			return false
		},
	}
}

func (r *NotManagedReconciler) predicateConfigMapDelete(e event.DeleteEvent) bool {
	configMap, ok := e.Object.(*corev1.ConfigMap)
	if !ok {
		return false
	}
	return r.isAssociationConfigMap(configMap)
}

func (r *NotManagedReconciler) isAssociationConfigMap(configMap *corev1.ConfigMap) bool {
	return configMap.Namespace == r.ConfigMapNamespace && configMap.Name == r.ConfigMapName
}

func (r *NotManagedReconciler) updateConfigMapCache(prepared bool, managedVDSes sets.Set[string]) (oldPrepared bool, changedVDSes sets.Set[string]) {
	r.configMapCacheLock.Lock()
	defer r.configMapCacheLock.Unlock()

	oldPrepared = r.configMapPrepared
	oldManagedVDSes := r.managedVDSes
	r.configMapPrepared = prepared
	r.managedVDSes = sets.New(managedVDSes.UnsortedList()...)
	if oldManagedVDSes == nil {
		oldManagedVDSes = sets.New[string]()
	}
	changedVDSes = oldManagedVDSes.Difference(managedVDSes).Union(managedVDSes.Difference(oldManagedVDSes))
	return oldPrepared, changedVDSes
}

func (r *NotManagedReconciler) enqueueAllEndpoints(ctx context.Context) {
	endpoints := securityv1alpha1.EndpointList{}
	if err := r.List(ctx, &endpoints); err != nil {
		klog.Errorf("list endpoints for notManaged reconciliation: %s", err)
		return
	}
	klog.V(4).Infof("Enqueue %d endpoints for notManaged reconciliation", len(endpoints.Items))
	for i := range endpoints.Items {
		r.enqueueEndpoint(ctx, &endpoints.Items[i])
	}
}

func (r *NotManagedReconciler) enqueueEndpointsByVDSes(ctx context.Context, vdsIDs sets.Set[string]) {
	requirement, err := k8slabels.NewRequirement(msconst.EndpointLabelKeyVDSID, selection.In, vdsIDs.UnsortedList())
	if err != nil {
		klog.Errorf("build endpoint vds label selector: %s", err)
		r.enqueueAllEndpoints(ctx)
		return
	}

	endpoints := securityv1alpha1.EndpointList{}
	if err := r.List(ctx, &endpoints, client.MatchingLabelsSelector{Selector: k8slabels.NewSelector().Add(*requirement)}); err != nil {
		klog.Errorf("list endpoints by vds labels %v: %s", vdsIDs.UnsortedList(), err)
		r.enqueueAllEndpoints(ctx)
		return
	}
	klog.V(4).Infof("Enqueue %d endpoints in changed VDSes %v for notManaged reconciliation", len(endpoints.Items), vdsIDs.UnsortedList())
	for i := range endpoints.Items {
		r.enqueueEndpoint(ctx, &endpoints.Items[i])
	}
}

func (r *NotManagedReconciler) enqueueEndpoint(ctx context.Context, endpoint *securityv1alpha1.Endpoint) {
	select {
	case r.EndpointQueue <- ersource.NewResourceEvent(endpoint.Name, endpoint.Namespace):
		klog.V(4).Infof("Enqueued endpoint %s/%s for notManaged reconciliation", endpoint.Namespace, endpoint.Name)
	case <-ctx.Done():
		klog.V(4).Infof("Skip enqueue endpoint %s/%s because context is done", endpoint.Namespace, endpoint.Name)
	}
}

func managedVDSesFromConfigMap(configMap *corev1.ConfigMap) (bool, sets.Set[string], error) {
	annotations := configMap.GetAnnotations()
	if annotations[msconst.AssociationSyncCompletedAnnotation] != "true" ||
		annotations[msconst.AssociationFormatVersionAnnotation] != msconst.AssociationFormatVersionV2 {
		return false, sets.New[string](), nil
	}

	managedVDSes := sets.New[string]()
	for clusterID, rawVDSIDs := range configMap.Data {
		var vdsIDs []string
		if err := json.Unmarshal([]byte(rawVDSIDs), &vdsIDs); err != nil {
			return false, nil, fmt.Errorf("unmarshal vdses for cluster %s: %w", clusterID, err)
		}
		for _, vdsID := range vdsIDs {
			if vdsID != "" {
				managedVDSes.Insert(vdsID)
			}
		}
	}
	return true, managedVDSes, nil
}
