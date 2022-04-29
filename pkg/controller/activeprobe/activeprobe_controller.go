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

package activeprobe

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	activeprobev1alph1 "github.com/everoute/everoute/pkg/apis/activeprobe/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
)

type ActiveprobeReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	syncQueue workqueue.RateLimitingInterface
}

// SetupWithManager create and add Endpoint Controller to the manager.
func (r *ActiveprobeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if mgr == nil {
		return fmt.Errorf("can't setup with nil manager")
	}

	c, err := controller.New("activeprobe-controller", mgr, controller.Options{
		MaxConcurrentReconciles: constants.DefaultMaxConcurrentReconciles,
		Reconciler:              r,
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &activeprobev1alph1.ActiveProbe{}}, &handler.Funcs{
		CreateFunc: r.AddActiveProbe,
		UpdateFunc: r.UpdateActiveProbe,
		DeleteFunc: r.RemoveActiveProbe,
	})
	if err != nil {
		return err
	}

	return nil
}

func (r *ActiveprobeReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	return ctrl.Result{}, nil
}

func (a *ActiveprobeReconciler) Run(stopChan <-chan struct{}) {
	defer a.syncQueue.ShutDown()

	go wait.Until(a.SyncActiveProbeWorker, 0, stopChan)
	<-stopChan
}

func (a *ActiveprobeReconciler) SyncActiveProbeWorker() {
	item, shutdown := a.syncQueue.Get()
	if shutdown {
		return
	}
	defer a.syncQueue.Done(item)
	// 1. lookup endpoint name from  endpoint agent

	objKey, ok := item.(k8stypes.NamespacedName)
	if !ok {
		a.syncQueue.Forget(item)
		klog.Errorf("Activeprobe %v was not found in workqueue", objKey)
		return
	}

	// TODO should support timeout and max retry
	if err := a.syncActiveProbe(objKey); err == nil {
		klog.Errorf("sync activeprobe  %v", objKey)
		a.syncQueue.Forget(item)
	} else {
		klog.Errorf("Failed to sync activeprobe %v, error: %v", objKey, err)
	}
}

func (a *ActiveprobeReconciler) syncActiveProbe(objKey k8stypes.NamespacedName) error {
	var err error
	ctx := context.Background()
	ap := activeprobev1alph1.ActiveProbe{}
	if err := a.Get(ctx, objKey, &ap); err != nil {
		klog.Errorf("unable to fetch activeprobe %s: %s", objKey, err.Error())
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return client.IgnoreNotFound(err)
	}

	switch ap.Status.State {
	case activeprobev1alph1.ActiveProbeRunning:
		err = a.runActiveProbe(ap)
	default:
	}

	return err
}

func (r *ActiveprobeReconciler) runActiveProbe(ap activeprobev1alph1.ActiveProbe) error {

	return nil
}

func (r *ActiveprobeReconciler) AddActiveProbe(e event.CreateEvent, q workqueue.RateLimitingInterface) {
	r.syncQueue.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
		Name:      e.Meta.GetName(),
		Namespace: e.Meta.GetNamespace(),
	}})
}

func (r *ActiveprobeReconciler) RemoveActiveProbe(e event.DeleteEvent, q workqueue.RateLimitingInterface) {
	r.syncQueue.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
		Name:      e.Meta.GetName(),
		Namespace: e.Meta.GetNamespace(),
	}})

}

func (r *ActiveprobeReconciler) UpdateActiveProbe(e event.UpdateEvent, q workqueue.RateLimitingInterface) {
	// should sync all object
	r.syncQueue.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
		Name:      e.MetaNew.GetName(),
		Namespace: e.MetaNew.GetNamespace(),
	}})

}
