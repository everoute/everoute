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

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/client/clientset_generated/clientset"
	crd "github.com/everoute/everoute/pkg/client/informers_generated/externalversions"
	"github.com/everoute/everoute/plugin/tower/pkg/controller/policy"
	"github.com/everoute/everoute/plugin/tower/pkg/informer"
	"github.com/everoute/everoute/plugin/tower/pkg/schema"
)

const (
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

	globalPolicyInformer       cache.SharedIndexInformer
	globalPolicyLister         informer.Lister
	globalPolicyInformerSynced cache.InformerSynced

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
	erClusterInformer := towerFactory.EverouteCluster()

	c := &Controller{
		name:                          "GlobalPolicyController",
		everouteClusterID:             everouteClusterID,
		crdClient:                     crdClient,
		everouteClusterInformer:       erClusterInformer,
		everouteClusterLister:         erClusterInformer.GetIndexer(),
		everouteClusterInformerSynced: erClusterInformer.HasSynced,
		globalPolicyInformer:          globalPolicyInformer,
		globalPolicyLister:            globalPolicyInformer.GetIndexer(),
		globalPolicyInformerSynced:    globalPolicyInformer.HasSynced,
		reconcileQueue:                workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
	}

	_, _ = globalPolicyInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.handleGlobalPolicy,
			UpdateFunc: c.updateGlobalPolicy,
			DeleteFunc: c.handleGlobalPolicy,
		},
		resyncPeriod,
	)

	_, _ = erClusterInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.handleEverouteCluster,
			UpdateFunc: c.updateEverouteCluster,
			DeleteFunc: c.handleEverouteCluster,
		},
		resyncPeriod,
	)

	return c
}

// Run begins processing items, and will continue until a value is sent down stopCh, or stopCh closed.
func (c *Controller) Run(workers uint, stopCh <-chan struct{}) {
	defer runtime.HandleCrash()
	defer c.reconcileQueue.ShutDown()

	if !cache.WaitForNamedCacheSync(c.name, stopCh,
		c.globalPolicyInformerSynced,
		c.everouteClusterInformerSynced,
	) {
		return
	}

	for i := uint(0); i < workers; i++ {
		go wait.Until(informer.ReconcileWorker(c.name, c.reconcileQueue, c.reconcileGlobalPolicy), time.Second, stopCh)
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

func (c *Controller) handleEverouteCluster(_ interface{}) {
	c.reconcileQueue.Add(DefaultGlobalPolicyName)
}

func (c *Controller) updateEverouteCluster(old, new interface{}) {
	oldERCluster := old.(*schema.EverouteCluster)
	newERCluster := new.(*schema.EverouteCluster)

	// enqueue when default action changes or enable/disable logging
	if newERCluster.ID != c.everouteClusterID ||
		oldERCluster.GlobalDefaultAction == newERCluster.GlobalDefaultAction &&
			oldERCluster.EnableLogging == newERCluster.EnableLogging {
		return
	}
	c.handleEverouteCluster(newERCluster)
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
		globalPolicySpec.Logging = policy.NewLoggingOptionsFrom(obj.(*schema.EverouteCluster), nil)
	} else {
		// if everoute cluster not found, use default action allow
		globalPolicySpec.DefaultAction = v1alpha1.GlobalDefaultActionAllow
	}

	return globalPolicySpec
}

func ignoreNotFound(err error) error {
	if errors.IsNotFound(err) {
		return nil
	}
	return err
}
