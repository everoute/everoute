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
	"fmt"
	"reflect"
	"strings"
	"time"

	kubeerror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/client/clientset_generated/clientset"
	crd "github.com/everoute/everoute/pkg/client/informers_generated/externalversions"
	"github.com/everoute/everoute/pkg/types"
	"github.com/everoute/everoute/plugin/tower/pkg/informer"
	"github.com/everoute/everoute/plugin/tower/pkg/schema"
)

type Controller struct {
	// name of this controller
	name string
	// namespace which endpoint and security policy should create in
	namespace string

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

	systemEndpointInformer       cache.SharedIndexInformer
	systemEndpointLister         informer.Lister
	systemEndpointInformerSynced cache.InformerSynced

	everouteClusterInformer       cache.SharedIndexInformer
	everouteClusterLister         informer.Lister
	everouteClusterInformerSynced cache.InformerSynced

	// endpointQueue contains endpoint to process. The element in queue
	// is endpoint name. And we use vnic ID as endpoint name.
	endpointQueue workqueue.RateLimitingInterface

	staticEndpointQueue workqueue.RateLimitingInterface
}

const (
	vnicIndex = "vnicIndex"
	vmIndex   = "vmIndex"

	ExternalIDName         = "iface-id"
	DefaultExternalIDValue = "default-externalID-value"

	DynamicEndpointPrefix    = "tower.ep.dynamic"
	StaticEndpointPrefix     = "tower.ep.static"
	VMEndpointPrefix         = DynamicEndpointPrefix + ".vm-"
	ControllerEndpointPrefix = StaticEndpointPrefix + ".ctrl-"
	SystemEndpointPrefix     = StaticEndpointPrefix + ".sys-"
)

// New creates a new instance of controller.
func New(
	towerFactory informer.SharedInformerFactory,
	crdFactory crd.SharedInformerFactory,
	crdClient clientset.Interface,
	resyncPeriod time.Duration,
	namespace string,
) *Controller {
	vmInformer := towerFactory.VM()
	labelInformer := towerFactory.Label()
	endpointInforer := crdFactory.Security().V1alpha1().Endpoints().Informer()
	systemEndpointInformer := towerFactory.SystemEndpoints()
	erClusterInformer := towerFactory.EverouteCluster()

	c := &Controller{
		name:                   "EndpointController",
		namespace:              namespace,
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

		systemEndpointInformer:        systemEndpointInformer,
		systemEndpointLister:          systemEndpointInformer.GetIndexer(),
		systemEndpointInformerSynced:  systemEndpointInformer.HasSynced,
		everouteClusterInformer:       erClusterInformer,
		everouteClusterLister:         erClusterInformer.GetIndexer(),
		everouteClusterInformerSynced: erClusterInformer.HasSynced,
		staticEndpointQueue:           workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
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
	// 1. When controller restart, vm delete event may lose. The handler would enqueue all endpoints for synchronization.
	// 2. If endpoints unexpectedly modified by other applications, the controller would find and resync them.
	endpointInforer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addEndpoint,
			UpdateFunc: c.updateEndpoint,
			DeleteFunc: c.deleteEndpoint,
		},
		resyncPeriod,
	)

	systemEndpointInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addSystemEndpoints,
			UpdateFunc: c.updateSystemEndpoints,
			DeleteFunc: c.deleteSystemEndpoints,
		},
		resyncPeriod,
	)

	erClusterInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addEverouteCluster,
			UpdateFunc: c.updateEverouteCluster,
			DeleteFunc: c.deleteEverouteCluster,
		},
		resyncPeriod,
	)

	return c
}

// Run begins processing items, and will continue until a value is sent down stopCh or it is closed.
func (c *Controller) Run(workers uint, stopCh <-chan struct{}) {
	defer runtime.HandleCrash()
	defer c.endpointQueue.ShutDown()
	defer c.staticEndpointQueue.ShutDown()

	if !cache.WaitForNamedCacheSync(c.name, stopCh,
		c.vmInformerSynced,
		c.labelInformerSynced,
		c.endpointInformerSynced,
		c.systemEndpointInformerSynced,
		c.everouteClusterInformerSynced) {
		return
	}

	for i := uint(0); i < workers; i++ {
		go wait.Until(informer.ReconcileWorker(c.name, c.endpointQueue, c.syncEndpoint), time.Second, stopCh)
		go wait.Until(informer.ReconcileWorker(c.name, c.staticEndpointQueue, c.syncStaticEndpoint), time.Second, stopCh)
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
	if strings.HasPrefix(obj.GetName(), StaticEndpointPrefix) {
		c.staticEndpointQueue.Add(obj.GetName())
	} else {
		c.endpointQueue.Add(obj.GetName())
	}
}

func (c *Controller) updateEndpoint(old interface{}, new interface{}) {
	obj := new.(*v1alpha1.Endpoint)
	if strings.HasPrefix(obj.GetName(), StaticEndpointPrefix) {
		c.staticEndpointQueue.Add(obj.GetName())
	} else {
		c.endpointQueue.Add(obj.GetName())
	}
}

func (c *Controller) deleteEndpoint(old interface{}) {
	if d, ok := old.(cache.DeletedFinalStateUnknown); ok {
		old = d.Obj
	}
	obj := old.(*v1alpha1.Endpoint)
	if strings.HasPrefix(obj.GetName(), StaticEndpointPrefix) {
		c.staticEndpointQueue.Add(obj.GetName())
	} else {
		c.endpointQueue.Add(obj.GetName())
	}
}

func (c *Controller) addEverouteCluster(new interface{}) {
	cluster := new.(*schema.EverouteCluster)
	for _, controller := range cluster.ControllerInstances {
		if validation.IsValidIP(controller.IPAddr) == nil {
			c.staticEndpointQueue.Add(GetCtrlEndpointName(cluster.ID, controller))
		} else {
			klog.Infof("invalid controller ip address %s in enveroute cluster %s", controller.IPAddr, cluster.ID)
		}
	}
}

func (c *Controller) deleteEverouteCluster(old interface{}) {
	if d, ok := old.(cache.DeletedFinalStateUnknown); ok {
		old = d.Obj
	}
	cluster := old.(*schema.EverouteCluster)
	for _, ctrl := range cluster.ControllerInstances {
		if ctrl.IPAddr != "" {
			c.staticEndpointQueue.Add(GetCtrlEndpointName(cluster.ID, ctrl))
		}
	}
}

func (c *Controller) updateEverouteCluster(old, new interface{}) {
	oldEverouteCluster := old.(*schema.EverouteCluster)
	newEverouteCluster := new.(*schema.EverouteCluster)

	if reflect.DeepEqual(oldEverouteCluster.ControllerInstances, newEverouteCluster.ControllerInstances) {
		return
	}

	for _, ctrl := range oldEverouteCluster.ControllerInstances {
		c.staticEndpointQueue.Add(GetCtrlEndpointName(oldEverouteCluster.ID, ctrl))
	}
	for _, ctrl := range newEverouteCluster.ControllerInstances {
		if validation.IsValidIP(ctrl.IPAddr) == nil {
			c.staticEndpointQueue.Add(GetCtrlEndpointName(newEverouteCluster.ID, ctrl))
		} else {
			klog.Infof("invalid controller ip address %s in enveroute cluster %s", ctrl.IPAddr, newEverouteCluster.ID)
		}
	}
}

func (c *Controller) addSystemEndpoints(new interface{}) {
	for _, ip := range new.(*schema.SystemEndpoints).IPPortEndpoints {
		if validation.IsValidIP(ip.IP) == nil {
			c.staticEndpointQueue.Add(GetSystemEndpointName(ip.Key))
		} else {
			klog.Infof("invalid ip address %+v in system endpoint", ip)
		}
	}
}

func (c *Controller) deleteSystemEndpoints(old interface{}) {
	if d, ok := old.(cache.DeletedFinalStateUnknown); ok {
		old = d.Obj
	}
	for _, ip := range old.(*schema.SystemEndpoints).IPPortEndpoints {
		c.staticEndpointQueue.Add(GetSystemEndpointName(ip.Key))
	}
}

func (c *Controller) updateSystemEndpoints(old, new interface{}) {
	oldSystemEndpoints := old.(*schema.SystemEndpoints)
	newSystemEndpoints := new.(*schema.SystemEndpoints)

	if reflect.DeepEqual(oldSystemEndpoints.IPPortEndpoints, newSystemEndpoints.IPPortEndpoints) {
		return
	}

	for _, ip := range oldSystemEndpoints.IPPortEndpoints {
		c.staticEndpointQueue.Add(GetSystemEndpointName(ip.Key))
	}
	for _, ip := range newSystemEndpoints.IPPortEndpoints {
		if validation.IsValidIP(ip.IP) == nil {
			c.staticEndpointQueue.Add(GetSystemEndpointName(ip.Key))
		} else {
			klog.Infof("invalid ip address %+v in system endpoint", ip)
		}
	}
}

func (c *Controller) getStaticEndpoint(key string) *v1alpha1.Endpoint {
	ipAddr := c.getStaticIP(key)
	if ipAddr == "" {
		return nil
	}
	return &v1alpha1.Endpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      key,
			Namespace: c.namespace,
		},
		Spec: v1alpha1.EndpointSpec{
			VID: 0,
			Reference: v1alpha1.EndpointReference{
				ExternalIDName:  ExternalIDName,
				ExternalIDValue: DefaultExternalIDValue,
			},
			Type: v1alpha1.EndpointStatic,
		},
		Status: v1alpha1.EndpointStatus{
			IPs: []types.IPAddress{
				types.IPAddress(ipAddr),
			},
		},
	}
}

func (c *Controller) syncStaticEndpoint(key string) error {
	ip := c.getStaticIP(key)
	if ip == "" {
		err := c.processEndpointDelete(key)
		if err != nil {
			return err
		}
	}
	return c.processStaticEndpointUpdate(key)
}

// syncEndpoint process create/update/delete event for endpoint
// handle endpoint from vNic or system endpoint
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
		// create or update endpoint from vNic
		return c.processEndpointUpdate(vms[0].(*schema.VM), key)
	default:
		return fmt.Errorf("got multiple vms %+v for vnic %s", vms, key)
	}
}

func (c *Controller) processEndpointDelete(key string) error {
	_, exists, err := c.endpointLister.GetByKey(fmt.Sprintf("%s/%s", c.namespace, key))
	if err == nil && !exists {
		// object has been delete already
		return nil
	}

	err = c.crdClient.SecurityV1alpha1().Endpoints(c.namespace).Delete(context.Background(), key, metav1.DeleteOptions{})
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

	obj, exists, err := c.endpointLister.GetByKey(fmt.Sprintf("%s/%s", c.namespace, vnicKey))
	if err != nil {
		return fmt.Errorf("get endpoint receive error: %s", err)
	}

	if !exists {
		ep := &v1alpha1.Endpoint{}
		c.setEndpoint(ep, vnic, vmLabels)

		klog.Infof("will add endpoint from vm %s vnic %s: %+v", vm.ID, vnicKey, ep)
		_, err = c.crdClient.SecurityV1alpha1().Endpoints(c.namespace).Create(context.Background(), ep, metav1.CreateOptions{})
		return err
	}

	ep := obj.(*v1alpha1.Endpoint).DeepCopy()
	if c.setEndpoint(ep, vnic, vmLabels) {
		klog.Infof("will update endpoint from vm %s vnic %s: %+v", vm.ID, vnicKey, ep)

		_, err = c.crdClient.SecurityV1alpha1().Endpoints(c.namespace).Update(context.Background(), ep, metav1.UpdateOptions{})
		return err
	}

	return nil
}

func (c *Controller) processStaticEndpointUpdate(key string) error {
	endpoint := c.getStaticEndpoint(key)
	if endpoint == nil {
		return c.processEndpointDelete(key)
	}

	obj, exists, err := c.endpointLister.GetByKey(fmt.Sprintf("%s/%s", c.namespace, key))
	if err != nil {
		return fmt.Errorf("get endpoint receive error: %s", err)
	}

	if !exists {
		klog.Infof("will add endpoint from static ip: %+v", endpoint)
		_, err = c.crdClient.SecurityV1alpha1().Endpoints(c.namespace).Create(context.Background(), endpoint, metav1.CreateOptions{})
		if err != nil {
			if kubeerror.IsAlreadyExists(err) {
				return nil
			}
			return fmt.Errorf("create endpoint receive error: %s", err)
		}
		// trigger endpoint update
		c.staticEndpointQueue.Add(key)
		return nil
	}

	ep := obj.(*v1alpha1.Endpoint).DeepCopy()
	if !reflect.DeepEqual(ep.Status, endpoint.Status) {
		klog.Infof("will update endpoint from %+v to %+v", ep, endpoint)
		ep.Status = endpoint.Status
		_, err = c.crdClient.SecurityV1alpha1().Endpoints(c.namespace).Update(context.Background(), ep, metav1.UpdateOptions{})
		return err
	}

	return nil
}

func (c *Controller) getStaticIP(key string) string {
	if strings.HasPrefix(key, ControllerEndpointPrefix) {
		clusterList := c.everouteClusterLister.List()
		if len(clusterList) == 0 {
			return ""
		}
		cluster := clusterList[0].(*schema.EverouteCluster)
		for _, ctrl := range cluster.ControllerInstances {
			if GetCtrlEndpointName(cluster.ID, ctrl) == key {
				return ctrl.IPAddr
			}
		}
	} else if strings.HasPrefix(key, SystemEndpointPrefix) {
		endpoints := c.systemEndpointLister.List()
		if len(endpoints) == 0 {
			return ""
		}
		for _, ipPortEndpoint := range endpoints[0].(*schema.SystemEndpoints).IPPortEndpoints {
			if GetSystemEndpointName(ipPortEndpoint.Key) == key {
				return ipPortEndpoint.IP
			}
		}
	}

	return ""
}

func (c *Controller) getVMLabels(vmID string) (map[string]string, error) {
	labels, err := c.labelLister.ByIndex(vmIndex, vmID)
	if err != nil {
		return nil, fmt.Errorf("list labels for vm %s: %s", vmID, err)
	}

	labelsMap := make(map[string]string, len(labels))
	for _, label := range labels {
		if !ValidKubernetesLabel(label.(*schema.Label)) {
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

func GetCtrlEndpointName(cluster string, ctrl schema.EverouteControllerInstance) string {
	return ControllerEndpointPrefix + cluster + "-" + ctrl.IPAddr
}

func GetSystemEndpointName(key string) string {
	return SystemEndpointPrefix + key
}

// set endpoint return false if endpoint not changes
func (c *Controller) setEndpoint(ep *v1alpha1.Endpoint, vnic *schema.VMNic, labels map[string]string) bool {
	var epCopy = ep.DeepCopy()

	ep.Name = vnic.ID
	ep.Labels = labels
	ep.Namespace = c.namespace
	ep.Spec.VID = uint32(vnic.Vlan.VlanID)
	ep.Spec.Reference.ExternalIDName = ExternalIDName
	ep.Spec.Reference.ExternalIDValue = vnic.InterfaceID
	ep.Spec.Type = v1alpha1.EndpointDynamic

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

// ValidKubernetesLabel check if is a valid kubernetes label
func ValidKubernetesLabel(label *schema.Label) bool {
	validKey := len(validation.IsQualifiedName(label.Key)) == 0
	validValue := len(validation.IsValidLabelValue(label.Value)) == 0
	return validKey && validValue
}
