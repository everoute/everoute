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

package global

import (
	"context"
	"fmt"
	"reflect"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/client/clientset_generated/clientset"
	crd "github.com/everoute/everoute/pkg/client/informers_generated/externalversions"
	"github.com/everoute/everoute/plugin/tower/pkg/informer"
	"github.com/everoute/everoute/plugin/tower/pkg/schema"
)

const (
	elfClusterIndex         = "elfClusterIndex"
	DefaultGlobalPolicyName = "everoute-global-policy"
)

// Controller create global policy for the everoute cluster
type Controller struct {
	// name of this controller
	name              string
	everouteClusterID string
	crdClient         clientset.Interface

	everouteClusterInformer       cache.SharedIndexInformer
	everouteClusterLister         informer.Lister
	everouteClusterInformerSynced cache.InformerSynced

	hostInformer       cache.SharedIndexInformer
	hostLister         informer.Lister
	hostInformerSynced cache.InformerSynced

	globalPolicyInformer       cache.SharedIndexInformer
	globalPolicyLister         informer.Lister
	globalPolicyInformerSynced cache.InformerSynced

	systemEndpointInformer       cache.SharedIndexInformer
	systemEndpointLister         informer.Lister
	systemEndpointInformerSynced cache.InformerSynced

	reconcileQueue workqueue.RateLimitingInterface
}

// New creates a new instance of controller.
func New(
	towerFactory informer.SharedInformerFactory,
	crdFactory crd.SharedInformerFactory,
	crdClient clientset.Interface,
	resyncPeriod time.Duration,
	everouteClusterID string,
) *Controller {
	globalPolicyInformer := crdFactory.Security().V1alpha1().GlobalPolicies().Informer()
	hostInformer := towerFactory.Host()
	erClusterInformer := towerFactory.EverouteCluster()
	systemEndpointInformer := towerFactory.SystemEndpoints()

	c := &Controller{
		name:                          "GlobalPolicyController",
		everouteClusterID:             everouteClusterID,
		crdClient:                     crdClient,
		everouteClusterInformer:       erClusterInformer,
		everouteClusterLister:         erClusterInformer.GetIndexer(),
		everouteClusterInformerSynced: erClusterInformer.HasSynced,
		hostInformer:                  hostInformer,
		hostLister:                    hostInformer.GetIndexer(),
		hostInformerSynced:            hostInformer.HasSynced,
		globalPolicyInformer:          globalPolicyInformer,
		globalPolicyLister:            globalPolicyInformer.GetIndexer(),
		globalPolicyInformerSynced:    globalPolicyInformer.HasSynced,
		systemEndpointInformer:        systemEndpointInformer,
		systemEndpointLister:          systemEndpointInformer.GetIndexer(),
		systemEndpointInformerSynced:  systemEndpointInformer.HasSynced,
		reconcileQueue:                workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
	}

	globalPolicyInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.handleGlobalPolicy,
			UpdateFunc: c.updateGlobalPolicy,
			DeleteFunc: c.handleGlobalPolicy,
		},
		resyncPeriod,
	)

	hostInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.handleHost,
			UpdateFunc: c.updateHost,
			DeleteFunc: c.handleHost,
		},
		resyncPeriod,
	)

	erClusterInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.handleEverouteCluster,
			UpdateFunc: c.updateEverouteCluster,
			DeleteFunc: c.handleEverouteCluster,
		},
		resyncPeriod,
	)

	systemEndpointInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.handleSystemEndpoints,
			UpdateFunc: c.updateSystemEndpoints,
			DeleteFunc: c.handleSystemEndpoints,
		},
		resyncPeriod,
	)

	_ = erClusterInformer.AddIndexers(cache.Indexers{
		elfClusterIndex: c.elfClusterIndexFunc,
	})

	_ = hostInformer.AddIndexers(cache.Indexers{
		elfClusterIndex: c.elfClusterIndexFunc,
	})

	return c
}

// Run begins processing items, and will continue until a value is sent down stopCh, or stopCh closed.
func (c *Controller) Run(workers uint, stopCh <-chan struct{}) {
	defer runtime.HandleCrash()
	defer c.reconcileQueue.ShutDown()

	if !cache.WaitForNamedCacheSync(c.name, stopCh,
		c.globalPolicyInformerSynced,
		c.hostInformerSynced,
		c.everouteClusterInformerSynced,
		c.systemEndpointInformerSynced,
	) {
		return
	}

	for i := uint(0); i < workers; i++ {
		go wait.Until(c.reconcileWorker, time.Second, stopCh)
	}

	<-stopCh
}

func (c *Controller) handleGlobalPolicy(obj interface{}) {
	unknow, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		obj = unknow.Obj
	}
	globalPolicy := obj.(*v1alpha1.GlobalPolicy)
	c.reconcileQueue.Add(globalPolicy.GetName())
}

func (c *Controller) updateGlobalPolicy(old, new interface{}) {
	oldGlobalPolicy := old.(*v1alpha1.GlobalPolicy)
	newGlobalPolicy := new.(*v1alpha1.GlobalPolicy)

	if reflect.DeepEqual(oldGlobalPolicy.Spec, newGlobalPolicy.Spec) {
		return
	}
	c.handleGlobalPolicy(newGlobalPolicy)
}

func (c *Controller) handleHost(obj interface{}) {
	unknow, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		obj = unknow.Obj
	}
	elfClusters, _ := c.everouteClusterLister.IndexKeys(elfClusterIndex, obj.(*schema.Host).Cluster.ID)
	if sets.NewString(elfClusters...).Has(c.everouteClusterID) {
		c.reconcileQueue.Add(DefaultGlobalPolicyName)
	}
}

func (c *Controller) updateHost(old, new interface{}) {
	oldHost := old.(*schema.Host)
	newHost := new.(*schema.Host)

	if newHost.ManagementIP == oldHost.ManagementIP {
		return
	}
	c.handleHost(newHost)
}

func (c *Controller) handleEverouteCluster(_ interface{}) {
	c.reconcileQueue.Add(DefaultGlobalPolicyName)
}

func (c *Controller) updateEverouteCluster(old, new interface{}) {
	oldERCluster := old.(*schema.EverouteCluster)
	newERCluster := new.(*schema.EverouteCluster)

	if newERCluster.ID == c.everouteClusterID {
		c.handleEverouteCluster(newERCluster)
		return
	}

	// handle controller instance ip changes
	if !reflect.DeepEqual(newERCluster.ControllerInstances, oldERCluster.ControllerInstances) {
		c.handleEverouteCluster(newERCluster)
	}
}

func (c *Controller) handleSystemEndpoints(_ interface{}) {
	c.reconcileQueue.Add(DefaultGlobalPolicyName)
}

func (c *Controller) updateSystemEndpoints(old, new interface{}) {
	oldSystemEndpoints := old.(*schema.SystemEndpoints)
	newSystemEndpoints := new.(*schema.SystemEndpoints)

	// handle systemEndpoints IP changes
	if !reflect.DeepEqual(newSystemEndpoints, oldSystemEndpoints) {
		c.handleSystemEndpoints(newSystemEndpoints)
	}
}

func (c *Controller) elfClusterIndexFunc(obj interface{}) ([]string, error) {
	var elfClusters []string

	switch o := obj.(type) {
	case *schema.EverouteCluster:
		for _, elfCluster := range o.AgentELFClusters {
			elfClusters = append(elfClusters, elfCluster.ID)
		}
	case *schema.Host:
		elfClusters = append(elfClusters, o.Cluster.ID)
	}

	return elfClusters, nil
}

func (c *Controller) reconcileWorker() {
	for {
		key, quit := c.reconcileQueue.Get()
		if quit {
			return
		}

		err := c.reconcileGlobalPolicy(key.(string))
		if err != nil {
			c.reconcileQueue.Done(key)
			c.reconcileQueue.AddRateLimited(key)
			klog.Errorf("got error while reconcile GlobalPolicy %s: %s", key.(string), err)
			continue
		}

		// stop the rate limiter from tracking the key
		c.reconcileQueue.Done(key)
		c.reconcileQueue.Forget(key)
	}
}

func (c *Controller) reconcileGlobalPolicy(name string) error {
	if name != DefaultGlobalPolicyName {
		klog.Infof("remove not default global policy %s", name)
		err := c.crdClient.SecurityV1alpha1().GlobalPolicies().Delete(context.Background(), name, metav1.DeleteOptions{})
		return ignoreNotFound(err)
	}

	var err error
	var globalPolicy *v1alpha1.GlobalPolicy

	obj, exists, _ := c.globalPolicyLister.GetByKey(name)
	if !exists {
		globalPolicy = new(v1alpha1.GlobalPolicy)
		globalPolicy.Name = DefaultGlobalPolicyName
		klog.Infof("create default global policy %+v", globalPolicy)
		globalPolicy, err = c.crdClient.SecurityV1alpha1().GlobalPolicies().Create(context.Background(), globalPolicy, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("create default global policy: %s", err)
		}
	} else {
		globalPolicy = obj.(*v1alpha1.GlobalPolicy).DeepCopy()
	}

	// get current global policy spec
	globalPolicy.Spec = c.getCurrentGlobalPolicySpec()

	klog.Infof("update global policy to %+v", globalPolicy)
	_, err = c.crdClient.SecurityV1alpha1().GlobalPolicies().Update(context.Background(), globalPolicy, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("update global policy: %s", err)
	}

	return nil
}

func (c *Controller) getCurrentGlobalPolicySpec() v1alpha1.GlobalPolicySpec {
	var globalPolicySpec v1alpha1.GlobalPolicySpec

	obj, exists, _ := c.everouteClusterLister.GetByKey(c.everouteClusterID)
	if exists {
		switch obj.(*schema.EverouteCluster).GlobalDefaultAction {
		case schema.GlobalPolicyActionAllow:
			globalPolicySpec.DefaultAction = v1alpha1.GlobalDefaultActionAllow
		case schema.GlobalPolicyActionDrop:
			globalPolicySpec.DefaultAction = v1alpha1.GlobalDefaultActionDrop
		}
		// add all hosts management ip to whitelist
		for _, elfCluster := range obj.(*schema.EverouteCluster).AgentELFClusters {
			hosts, _ := c.hostLister.ByIndex(elfClusterIndex, elfCluster.ID)
			for _, host := range hosts {
				globalPolicySpec.Whitelist = append(globalPolicySpec.Whitelist, networkingv1.IPBlock{
					CIDR: fmt.Sprintf("%s/32", host.(*schema.Host).ManagementIP),
				})
			}
		}
	} else {
		// if everoute cluster not found, use default action allow
		globalPolicySpec.DefaultAction = v1alpha1.GlobalDefaultActionAllow
	}

	// add all controllers ip to whitelist
	for _, erCluster := range c.everouteClusterLister.List() {
		for _, ins := range erCluster.(*schema.EverouteCluster).ControllerInstances {
			globalPolicySpec.Whitelist = append(globalPolicySpec.Whitelist, networkingv1.IPBlock{
				CIDR: fmt.Sprintf("%s/32", ins.IPAddr),
			})
		}
	}

	// add all system endpoints to whitelist
	for _, systemEndpoints := range c.systemEndpointLister.List() {
		for _, ipPortEndpoint := range systemEndpoints.(*schema.SystemEndpoints).IPPortEndpoints {
			globalPolicySpec.Whitelist = append(globalPolicySpec.Whitelist, networkingv1.IPBlock{
				CIDR: fmt.Sprintf("%s/32", ipPortEndpoint.IP),
			})
		}
	}

	return globalPolicySpec
}

func ignoreNotFound(err error) error {
	if errors.IsNotFound(err) {
		return nil
	}
	return err
}
