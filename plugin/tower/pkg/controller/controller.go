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

package controller

import (
	"context"
	"fmt"
	"reflect"
	"time"

	kubeerror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	"github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
	"github.com/smartxworks/lynx/pkg/client/clientset_generated/clientset"
	crd "github.com/smartxworks/lynx/pkg/client/informers_generated/externalversions"
	"github.com/smartxworks/lynx/plugin/tower/pkg/informer"
	"github.com/smartxworks/lynx/plugin/tower/pkg/schema"
)

type Controller struct {
	// name of this controller
	name string
	// managePlaneID mark the endpoint source to be processed by the controller
	managePlaneID string

	crdClient clientset.Interface

	vmInformer       cache.SharedIndexInformer
	vmLister         informer.Lister
	vmInformerSynced cache.InformerSynced

	labelInformer       cache.SharedIndexInformer
	labelLister         informer.Lister
	labelInformerSynced cache.InformerSynced

	endpointInformer       cache.SharedIndexInformer
	endpointLister         informer.Lister
	endpointInformerSynced cache.InformerSynced

	endpointQueue workqueue.RateLimitingInterface
}

const (
	vnicIndex = "vnicIndex"
	vmIndex   = "vmIndex"

	externalIDName = "iface-id"
)

// New creates a new instance of controller.
func New(towerFactory informer.SharedInformerFactory, crdFactory crd.SharedInformerFactory, crdClient clientset.Interface, resyncPeriod time.Duration) *Controller {
	vmInformer := towerFactory.VM()
	labelInformer := towerFactory.Label()
	endpointInforer := crdFactory.Security().V1alpha1().Endpoints().Informer()

	c := &Controller{
		name:                   "EndpointController",
		managePlaneID:          "lynx.plugin.tower",
		crdClient:              crdClient,
		vmInformer:             vmInformer,
		vmLister:               vmInformer.GetIndexer(),
		vmInformerSynced:       vmInformer.HasSynced,
		labelInformer:          labelInformer,
		labelLister:            labelInformer.GetIndexer(),
		labelInformerSynced:    labelInformer.HasSynced,
		endpointInformer:       endpointInforer,
		endpointLister:         endpointInforer.GetIndexer(),
		endpointInformerSynced: endpointInforer.HasSynced,
		endpointQueue:          workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
	}

	// ignore error, error only when informer has already started
	_ = vmInformer.AddIndexers(cache.Indexers{
		vnicIndex: c.vnicIndexFunc,
	})

	_ = labelInformer.AddIndexers(cache.Indexers{
		vmIndex: c.vmIndexFunc,
	})

	vmInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addVM,
			UpdateFunc: c.updateVM,
			DeleteFunc: c.deleteVM,
		},
		resyncPeriod,
	)

	labelInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addLabel,
			UpdateFunc: c.updateLabel,
			DeleteFunc: c.deleteLabel,
		},
		resyncPeriod,
	)

	// Why we handle endpoint events ?
	// 1. When controller restart, vm delete event may lost. The handler would enqueue all endpoints for synchronization.
	// 2. If endpoints unexpectedly modified by other applications, the controller would found and resync them.
	endpointInforer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addEndpoint,
			UpdateFunc: c.updateEndpoint,
			DeleteFunc: c.deleteEndpoint,
		},
		resyncPeriod,
	)

	return c
}

// Run begins processing items, and will continue until a value is sent down stopCh or it is closed.
func (c *Controller) Run(workers uint, stopCh <-chan struct{}) {
	defer runtime.HandleCrash()
	defer c.endpointQueue.ShutDown()

	if !cache.WaitForNamedCacheSync(c.name, stopCh, c.vmInformerSynced, c.labelInformerSynced, c.endpointInformerSynced) {
		return
	}

	for i := uint(0); i < workers; i++ {
		go wait.Until(c.syncEndpointWorker, time.Second, stopCh)
	}

	<-stopCh
}

func (c *Controller) vmIndexFunc(obj interface{}) ([]string, error) {
	var vms []string
	for _, vm := range obj.(*schema.Label).VMs {
		vms = append(vms, vm.ID)
	}
	return vms, nil
}

func (c *Controller) vnicIndexFunc(obj interface{}) ([]string, error) {
	var vnics []string
	for _, vnic := range obj.(*schema.VM).VMNics {
		vnics = append(vnics, vnic.GetID())
	}
	return vnics, nil
}

func (c *Controller) addVM(new interface{}) {
	newVM := new.(*schema.VM)

	if newVM.Status == schema.VMStatusDeleted {
		// ignore vm that already deleted
		return
	}
	c.enqueueVMNics(newVM)
}

func (c *Controller) updateVM(old interface{}, new interface{}) {
	oldVM := old.(*schema.VM)
	newVM := new.(*schema.VM)

	if newVM.Status == schema.VMStatusDeleted {
		// ignore vm that status has been updated to deleted
		return
	}
	if reflect.DeepEqual(oldVM.VMNics, newVM.VMNics) {
		// todo: compare vmnics by order
		return
	}

	c.enqueueVMNics(oldVM)
	c.enqueueVMNics(newVM)
}

func (c *Controller) deleteVM(old interface{}) {
	unknown, ok := old.(cache.DeletedFinalStateUnknown)
	if ok {
		old = unknown.Obj
	}
	c.enqueueVMNics(old.(*schema.VM))
}

func (c *Controller) addLabel(new interface{}) {
	label := new.(*schema.Label)
	c.enqueueVMNicsByVMReference(label.VMs...)
}

func (c *Controller) updateLabel(old interface{}, new interface{}) {
	oldLabel := old.(*schema.Label)
	newLabel := new.(*schema.Label)

	c.enqueueVMNicsByVMReference(oldLabel.VMs...)
	c.enqueueVMNicsByVMReference(newLabel.VMs...)
}

func (c *Controller) deleteLabel(old interface{}) {
	if d, ok := old.(cache.DeletedFinalStateUnknown); ok {
		old = d.Obj
	}
	label := old.(*schema.Label)
	c.enqueueVMNicsByVMReference(label.VMs...)
}

func (c *Controller) enqueueVMNicsByVMReference(references ...schema.ObjectReference) {
	for _, reference := range references {
		vm, exists, _ := c.vmLister.GetByKey(reference.ID)
		if exists {
			c.enqueueVMNics(vm.(*schema.VM))
		}
	}
}

func (c *Controller) enqueueVMNics(vm *schema.VM) {
	for _, vnic := range vm.VMNics {
		c.endpointQueue.Add(vnic.ID)
	}
}

func (c *Controller) addEndpoint(new interface{}) {
	obj := new.(*v1alpha1.Endpoint)

	if obj.Spec.ManagePlaneID == c.managePlaneID {
		c.endpointQueue.Add(obj.Name)
	}
}

func (c *Controller) updateEndpoint(old interface{}, new interface{}) {
	oldEp := old.(*v1alpha1.Endpoint)
	newEp := new.(*v1alpha1.Endpoint)

	if oldEp.Spec.ManagePlaneID == c.managePlaneID || newEp.Spec.ManagePlaneID == c.managePlaneID {
		c.endpointQueue.Add(newEp.Name)
	}
}

func (c *Controller) deleteEndpoint(old interface{}) {
	if d, ok := old.(cache.DeletedFinalStateUnknown); ok {
		old = d.Obj
	}
	obj := old.(*v1alpha1.Endpoint)

	if obj.Spec.ManagePlaneID == c.managePlaneID {
		c.endpointQueue.Add(obj.Name)
	}
}

func (c *Controller) syncEndpointWorker() {
	for {
		key, quit := c.endpointQueue.Get()
		if quit {
			return
		}

		err := c.syncEndpoint(key.(string))
		if err != nil {
			c.endpointQueue.Done(key)
			c.endpointQueue.AddRateLimited(key)
			klog.Errorf("got error while sync endpoint %s: %s", key.(string), err)
			continue
		}

		// stop the rate limiter from tracking the key
		c.endpointQueue.Done(key)
		c.endpointQueue.Forget(key)
	}
}

func (c *Controller) syncEndpoint(key string) error {
	vms, err := c.vmLister.ByIndex(vnicIndex, key)
	if err != nil {
		return err
	}

	switch len(vms) {
	case 0:
		// delete this endpoint
		return c.processEndpointDelete(key)
	case 1:
		// create or update endpoint
		return c.processEndpointUpdate(vms[0].(*schema.VM), key)
	default:
		return fmt.Errorf("got multiple vms %+v for vnic %s", vms, key)
	}
}

func (c *Controller) processEndpointDelete(key string) error {
	_, exists, err := c.endpointLister.GetByKey(key)
	if err == nil && !exists {
		// object has been delete already
		return nil
	}

	err = c.crdClient.SecurityV1alpha1().Endpoints().Delete(context.Background(), key, metav1.DeleteOptions{})
	if err == nil || kubeerror.IsNotFound(err) {
		klog.Infof("endpoint %s has been delete by %s", key, c.name)
		return nil
	}
	return err
}

func (c *Controller) processEndpointUpdate(vm *schema.VM, vnicKey string) error {
	vnic, exists := fetchVnic(vm, vnicKey)
	if !exists {
		return fmt.Errorf("unable find vnic %s in vm %+v", vnicKey, vm)
	}
	if vnic.InterfaceID == "" {
		klog.V(4).Infof("ignore vnic %s on vm %s(%s) with empty interfaceID", vnic.ID, vm.Name, vm.ID)
		return nil
	}

	// use vm labels as vm's vnic labels
	vmLabels, err := c.getVMLabels(vm.ID)
	if err != nil {
		return fmt.Errorf("list labels for vm %s: %s", vm.ID, err)
	}

	obj, exists, err := c.endpointLister.GetByKey(vnicKey)
	if err != nil {
		return fmt.Errorf("get endpoint receive error: %s", err)
	}

	if !exists {
		ep := &v1alpha1.Endpoint{}
		c.setEndpoint(ep, vnic, vmLabels)

		klog.Infof("will add endpoint from vm %s vnic %s: %+v", vm.ID, vnicKey, ep)
		_, err = c.crdClient.SecurityV1alpha1().Endpoints().Create(context.Background(), ep, metav1.CreateOptions{})
		return err
	}

	ep := obj.(*v1alpha1.Endpoint).DeepCopy()
	if c.setEndpoint(ep, vnic, vmLabels) {
		klog.Infof("will update endpoint from vm %s vnic %s: %+v", vm.ID, vnicKey, ep)

		_, err = c.crdClient.SecurityV1alpha1().Endpoints().Update(context.Background(), ep, metav1.UpdateOptions{})
		return err
	}

	return nil
}

func (c *Controller) getVMLabels(vmID string) (map[string]string, error) {
	labels, err := c.labelLister.ByIndex(vmIndex, vmID)
	if err != nil {
		return nil, fmt.Errorf("list labels for vm %s: %s", vmID, err)
	}

	labelsMap := make(map[string]string, len(labels))
	for _, label := range labels {
		if !validKubernetesLabel(label.(*schema.Label)) {
			klog.Infof("ignore vm %s valid kubernetes labels %+v", vmID, label)
			continue
		}
		labelsMap[label.(*schema.Label).Key] = label.(*schema.Label).Value
	}

	if len(labelsMap) == 0 {
		// If labels length is zero, would return nil instead of an empty map.
		// Consistent with the empty labels returned by the apiserver.
		return nil, nil
	}

	return labelsMap, nil
}

// set endpoint return false if endpoint not changes
func (c *Controller) setEndpoint(ep *v1alpha1.Endpoint, vnic *schema.VMNic, labels map[string]string) bool {
	var epCopy = ep.DeepCopy()

	ep.Name = vnic.ID
	ep.Labels = labels
	ep.Spec.ManagePlaneID = c.managePlaneID
	ep.Spec.VID = uint32(vnic.Vlan.VlanID)
	ep.Spec.Reference.ExternalIDName = externalIDName
	ep.Spec.Reference.ExternalIDValue = vnic.InterfaceID

	return !reflect.DeepEqual(ep, epCopy)
}

func fetchVnic(vm *schema.VM, vnicKey string) (*schema.VMNic, bool) {
	for _, vnic := range vm.VMNics {
		if vnicKey == vnic.ID {
			return &vnic, true
		}
	}
	return nil, false
}

func validKubernetesLabel(label *schema.Label) bool {
	validKey := len(validation.IsQualifiedName(label.Key)) == 0
	validValue := len(validation.IsValidLabelValue(label.Value)) == 0
	return validKey && validValue
}
