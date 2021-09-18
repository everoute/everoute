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

package k8s

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
	"github.com/smartxworks/lynx/pkg/constants"
	"github.com/smartxworks/lynx/pkg/utils"
)

// PodReconciler watch pod and sync to endpoint
type PodReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile receive endpoint from work queue, synchronize the endpoint status
func (r *PodReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	klog.Infof("PodReconciler received pod %s reconcile", req.NamespacedName)

	pod := corev1.Pod{}
	endpointName := "pod-" + req.Name

	// delete endpoint if pod is not found
	if err := r.Get(ctx, req.NamespacedName, &pod); err != nil && errors.IsNotFound(err) {
		klog.Infof("Delete endpoint %s", endpointName)
		endpoint := v1alpha1.Endpoint{
			ObjectMeta: metav1.ObjectMeta{
				Name:      endpointName,
				Namespace: req.Namespace,
			},
		}
		if err = r.Delete(ctx, &endpoint); err != nil && !errors.IsNotFound(err) {
			klog.Errorf("Delete Endpoint %s failed, err: %s", endpointName, err)
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// skip host network
	if pod.Spec.HostNetwork {
		return ctrl.Result{}, nil
	}

	endpoint := v1alpha1.Endpoint{}
	endpointReq := types.NamespacedName{
		Namespace: req.Namespace,
		Name:      endpointName,
	}
	err := r.Get(ctx, endpointReq, &endpoint)
	switch errors.ReasonForError(err) {
	case metav1.StatusReasonNotFound:
		// add new pod
		endpoint.Name = endpointName
		endpoint.Namespace = req.Namespace
		endpoint.Spec.VID = 0
		endpoint.Spec.Reference.ExternalIDName = "pod-uuid"
		endpoint.Spec.Reference.ExternalIDValue = utils.EncodeNamespacedName(types.NamespacedName{
			Name:      endpointName,
			Namespace: req.Namespace,
		})
		endpoint.ObjectMeta.Labels = map[string]string{}
		for key, value := range pod.ObjectMeta.Labels {
			endpoint.ObjectMeta.Labels[key] = value
		}
		// submit creation
		if err := r.Create(ctx, &endpoint); err != nil {
			klog.Errorf("create endpoint %s err: %s", endpointName, err)
			return ctrl.Result{}, err
		}
	case metav1.StatusReasonUnknown: // no error
		// update pod
		endpoint.ObjectMeta.Labels = map[string]string{} // clear old labels
		for key, value := range pod.ObjectMeta.Labels {
			endpoint.ObjectMeta.Labels[key] = value
		}
		// submit update
		if err := r.Update(ctx, &endpoint); err != nil {
			klog.Errorf("update endpoint %s err: %s", endpointName, err)
			return ctrl.Result{}, err
		}
	default: // other errors
		klog.Errorf("Get endpoint error, err: %s", err)
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager create and add Endpoint Controller to the manager.
func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if mgr == nil {
		return fmt.Errorf("can't setup with nil manager")
	}

	c, err := controller.New("pod-controller", mgr, controller.Options{
		MaxConcurrentReconciles: constants.DefaultMaxConcurrentReconciles,
		Reconciler:              r,
	})
	if err != nil {
		return err
	}

	if err = c.Watch(&source.Kind{Type: &corev1.Pod{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return err
	}

	if err = c.Watch(&source.Kind{Type: &v1alpha1.Endpoint{}}, &handler.Funcs{
		CreateFunc: r.addEndpoint,
	}); err != nil {
		return err
	}

	return nil
}

func (r *PodReconciler) addEndpoint(e event.CreateEvent, q workqueue.RateLimitingInterface) {
	if e.Object == nil {
		klog.Errorf("receive create event with no object %v", e)
		return
	}

	// only handle endpoint with "pod-" prefix
	if strings.HasPrefix(e.Meta.GetName(), "pod-") {
		q.Add(ctrl.Request{NamespacedName: types.NamespacedName{
			Namespace: e.Meta.GetNamespace(),
			Name:      strings.TrimPrefix(e.Meta.GetName(), "pod-"),
		}})
	}
}
