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
	"net"
	"reflect"
	"strings"
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

	nameutil "github.com/everoute/everoute/pkg/agent/controller/policy/cache"
	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/client/clientset_generated/clientset"
	crd "github.com/everoute/everoute/pkg/client/informers_generated/externalversions"
	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/labels"
	"github.com/everoute/everoute/plugin/tower/pkg/controller/endpoint"
	"github.com/everoute/everoute/plugin/tower/pkg/informer"
	"github.com/everoute/everoute/plugin/tower/pkg/schema"
)

const (
	SecurityPolicyPrefix             = "tower.sp-"
	IsolationPolicyPrefix            = "tower.ip-"
	IsolationPolicyIngressPrefix     = "tower.ip.ingress-"
	IsolationPolicyEgressPrefix      = "tower.ip.egress-"
	SecurityPolicyCommunicablePrefix = "tower.sp.communicable-"

	SystemEndpointsPolicyName = "tower.sp.internal-system.endpoints"
	ControllerPolicyName      = "tower.sp.internal-controller"
	GlobalWhitelistPolicyName = "tower.sp.global-user.whitelist"

	vmIndex              = "vmIndex"
	labelIndex           = "labelIndex"
	securityPolicyIndex  = "towerSecurityPolicyIndex"
	isolationPolicyIndex = "towerIsolationPolicyIndex"
)

// Controller sync SecurityPolicy and IsolationPolicy as v1alpha1.SecurityPolicy
// from tower. For v1alpha1.SecurityPolicy, has the following naming rules:
//   1. If origin policy is SecurityPolicy, policy.name = {{SecurityPolicyPrefix}}{{SecurityPolicy.ID}}
//   2. If origin policy is IsolationPolicy, policy.name = {{IsolationPolicyPrefix}}{{IsolationPolicy.ID}}
//   3. If policy was generated to make intragroup communicable, policy.name = {{SecurityPolicyCommunicablePrefix}}{{SelectorHash}}-{{SecurityPolicy.ID}}
//   4. If origin policy is SystemEndpointsPolicy, policy.name = {{SystemEndpointsPolicyName}}
//   5. If origin policy is ControllerPolicy, policy.name = {{ControllerPolicyName}}
type Controller struct {
	// name of this controller
	name string

	// namespace which endpoint and security policy should create in
	namespace string
	// everouteCluster which should synchronize SecurityPolicy from
	everouteCluster string

	crdClient clientset.Interface

	vmInformer       cache.SharedIndexInformer
	vmLister         informer.Lister
	vmInformerSynced cache.InformerSynced

	labelInformer       cache.SharedIndexInformer
	labelLister         informer.Lister
	labelInformerSynced cache.InformerSynced

	securityPolicyInformer       cache.SharedIndexInformer
	securityPolicyLister         informer.Lister
	securityPolicyInformerSynced cache.InformerSynced

	isolationPolicyInformer       cache.SharedIndexInformer
	isolationPolicyLister         informer.Lister
	isolationPolicyInformerSynced cache.InformerSynced

	crdPolicyInformer       cache.SharedIndexInformer
	crdPolicyLister         informer.Lister
	crdPolicyInformerSynced cache.InformerSynced

	everouteClusterInformer       cache.SharedIndexInformer
	everouteClusterLister         informer.Lister
	everouteClusterInformerSynced cache.InformerSynced

	systemEndpointInformer       cache.SharedIndexInformer
	systemEndpointLister         informer.Lister
	systemEndpointInformerSynced cache.InformerSynced

	isolationPolicyQueue       workqueue.RateLimitingInterface
	securityPolicyQueue        workqueue.RateLimitingInterface
	systemEndpointPolicyQueue  workqueue.RateLimitingInterface
	everouteClusterPolicyQueue workqueue.RateLimitingInterface
}

// New creates a new instance of controller.
//nolint:funlen
func New(
	towerFactory informer.SharedInformerFactory,
	crdFactory crd.SharedInformerFactory,
	crdClient clientset.Interface,
	resyncPeriod time.Duration,
	namespace string,
	everouteCluster string,
) *Controller {
	crdPolicyInformer := crdFactory.Security().V1alpha1().SecurityPolicies().Informer()
	vmInformer := towerFactory.VM()
	labelInformer := towerFactory.Label()
	securityPolicyInformer := towerFactory.SecurityPolicy()
	isolationPolicyInformer := towerFactory.IsolationPolicy()
	erClusterInformer := towerFactory.EverouteCluster()
	systemEndpointInformer := towerFactory.SystemEndpoints()

	c := &Controller{
		name:                          "PolicyController",
		namespace:                     namespace,
		everouteCluster:               everouteCluster,
		crdClient:                     crdClient,
		vmInformer:                    vmInformer,
		vmLister:                      vmInformer.GetIndexer(),
		vmInformerSynced:              vmInformer.HasSynced,
		labelInformer:                 labelInformer,
		labelLister:                   labelInformer.GetIndexer(),
		labelInformerSynced:           labelInformer.HasSynced,
		securityPolicyInformer:        securityPolicyInformer,
		securityPolicyLister:          securityPolicyInformer.GetIndexer(),
		securityPolicyInformerSynced:  securityPolicyInformer.HasSynced,
		isolationPolicyInformer:       isolationPolicyInformer,
		isolationPolicyLister:         isolationPolicyInformer.GetIndexer(),
		isolationPolicyInformerSynced: isolationPolicyInformer.HasSynced,
		crdPolicyInformer:             crdPolicyInformer,
		crdPolicyLister:               crdPolicyInformer.GetIndexer(),
		crdPolicyInformerSynced:       crdPolicyInformer.HasSynced,
		everouteClusterInformer:       erClusterInformer,
		everouteClusterLister:         erClusterInformer.GetIndexer(),
		everouteClusterInformerSynced: erClusterInformer.HasSynced,
		systemEndpointInformer:        systemEndpointInformer,
		systemEndpointLister:          systemEndpointInformer.GetIndexer(),
		systemEndpointInformerSynced:  systemEndpointInformer.HasSynced,
		isolationPolicyQueue:          workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		securityPolicyQueue:           workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		systemEndpointPolicyQueue:     workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		everouteClusterPolicyQueue:    workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
	}

	// when vm's vnics changes, enqueue related IsolationPolicy
	vmInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.handleVM,
			UpdateFunc: c.updateVM,
			DeleteFunc: c.handleVM,
		},
		resyncPeriod,
	)

	// when labels key/value changes, enqueue related SecurityPolicy and IsolationPolicy
	labelInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.handleLabel,
			UpdateFunc: c.updateLabel,
			DeleteFunc: c.handleLabel,
		},
		resyncPeriod,
	)

	securityPolicyInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.handleSecurityPolicy,
			UpdateFunc: c.updateSecurityPolicy,
			DeleteFunc: c.handleSecurityPolicy,
		},
		resyncPeriod,
	)

	isolationPolicyInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.handleIsolationPolicy,
			UpdateFunc: c.updateIsolationPolicy,
			DeleteFunc: c.handleIsolationPolicy,
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

	// when policy changes, enqueue related SecurityPolicy and IsolationPolicy
	crdPolicyInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.handleCRDPolicy,
			UpdateFunc: c.updateCRDPolicy,
			DeleteFunc: c.handleCRDPolicy,
		},
		resyncPeriod,
	)

	// relate labels in selector
	_ = securityPolicyInformer.AddIndexers(cache.Indexers{
		labelIndex: c.labelIndexFunc,
	})

	// relate isolate vm and selected labels
	_ = isolationPolicyInformer.AddIndexers(cache.Indexers{
		vmIndex:    c.vmIndexFunc,
		labelIndex: c.labelIndexFunc,
	})

	// relate owner SecurityPolicy or IsolationPolicy
	_ = crdPolicyInformer.AddIndexers(cache.Indexers{
		securityPolicyIndex:  c.securityPolicyIndexFunc,
		isolationPolicyIndex: c.isolationPolicyIndexFunc,
	})

	return c
}

// Run begins processing items, and will continue until a value is sent down stopCh, or stopCh closed.
func (c *Controller) Run(workers uint, stopCh <-chan struct{}) {
	defer runtime.HandleCrash()
	defer c.securityPolicyQueue.ShutDown()
	defer c.isolationPolicyQueue.ShutDown()
	defer c.systemEndpointPolicyQueue.ShutDown()
	defer c.everouteClusterPolicyQueue.ShutDown()

	if !cache.WaitForNamedCacheSync(c.name, stopCh,
		c.vmInformerSynced,
		c.labelInformerSynced,
		c.securityPolicyInformerSynced,
		c.isolationPolicyInformerSynced,
		c.crdPolicyInformerSynced,
		c.everouteClusterInformerSynced,
		c.systemEndpointInformerSynced,
	) {
		return
	}

	for i := uint(0); i < workers; i++ {
		go wait.Until(informer.ReconcileWorker(c.name, c.securityPolicyQueue, c.syncSecurityPolicy), time.Second, stopCh)
		go wait.Until(informer.ReconcileWorker(c.name, c.isolationPolicyQueue, c.syncIsolationPolicy), time.Second, stopCh)
		go wait.Until(informer.ReconcileWorker(c.name, c.everouteClusterPolicyQueue, c.syncEverouteClusterPolicy), time.Second, stopCh)
	}
	// only ONE SystemEndpoints in tower
	go wait.Until(informer.ReconcileWorker(c.name, c.systemEndpointPolicyQueue, c.syncSystemEndpointsPolicy), time.Second, stopCh)

	<-stopCh
}

func (c *Controller) labelIndexFunc(obj interface{}) ([]string, error) {
	var labelReferences []schema.ObjectReference

	switch policy := obj.(type) {
	case *schema.SecurityPolicy:
		for _, peer := range policy.ApplyTo {
			labelReferences = append(labelReferences, peer.Selector...)
		}
		for _, peer := range append(policy.Ingress, policy.Egress...) {
			labelReferences = append(labelReferences, peer.Selector...)
		}
	case *schema.IsolationPolicy:
		for _, peer := range append(policy.Ingress, policy.Egress...) {
			labelReferences = append(labelReferences, peer.Selector...)
		}
	}

	labelKeys := make([]string, len(labelReferences))
	for _, labelReference := range labelReferences {
		labelKeys = append(labelKeys, labelReference.ID)
	}

	return labelKeys, nil
}

func (c *Controller) vmIndexFunc(obj interface{}) ([]string, error) {
	policy := obj.(*schema.IsolationPolicy)
	return []string{policy.VM.ID}, nil
}

func (c *Controller) securityPolicyIndexFunc(obj interface{}) ([]string, error) {
	policy := obj.(*v1alpha1.SecurityPolicy)

	if strings.HasPrefix(policy.GetName(), SecurityPolicyPrefix) {
		securityPolicyKey := strings.TrimPrefix(policy.GetName(), SecurityPolicyPrefix)
		return []string{securityPolicyKey}, nil
	}

	if strings.HasPrefix(policy.GetName(), SecurityPolicyCommunicablePrefix) {
		withoutPrefix := strings.TrimPrefix(policy.GetName(), SecurityPolicyCommunicablePrefix)
		securityPolicyKey := strings.Split(withoutPrefix, "-")[1]
		return []string{securityPolicyKey}, nil
	}

	return nil, nil
}

func (c *Controller) isolationPolicyIndexFunc(obj interface{}) ([]string, error) {
	policy := obj.(*v1alpha1.SecurityPolicy)

	if strings.HasPrefix(policy.GetName(), strings.TrimSuffix(IsolationPolicyPrefix, "-")) {
		if strings.HasPrefix(policy.GetName(), IsolationPolicyIngressPrefix) {
			return []string{strings.TrimPrefix(policy.GetName(), IsolationPolicyIngressPrefix)}, nil
		}
		if strings.HasPrefix(policy.GetName(), IsolationPolicyEgressPrefix) {
			return []string{strings.TrimPrefix(policy.GetName(), IsolationPolicyEgressPrefix)}, nil
		}
		return []string{strings.TrimPrefix(policy.GetName(), IsolationPolicyPrefix)}, nil
	}

	return nil, nil
}

func (c *Controller) handleVM(obj interface{}) {
	unknow, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		obj = unknow.Obj
	}
	policies, _ := c.isolationPolicyLister.ByIndex(vmIndex, obj.(*schema.VM).GetID())
	for _, policy := range policies {
		c.handleIsolationPolicy(policy)
	}

	// update systemEndpoints policy
	systemEndpoints := c.systemEndpointLister.List()
	if len(systemEndpoints) != 0 {
		// TODO: replace for loop with vmIndex
		for _, ep := range systemEndpoints[0].(*schema.SystemEndpoints).IDEndpoints {
			if ep.VMID == obj.(*schema.VM).GetID() {
				c.systemEndpointPolicyQueue.Add("key")
				break
			}
		}
	}
}

func (c *Controller) updateVM(old, new interface{}) {
	oldVM := old.(*schema.VM)
	newVM := new.(*schema.VM)

	if reflect.DeepEqual(newVM.VMNics, oldVM.VMNics) {
		return
	}
	c.handleVM(newVM)
}

func (c *Controller) handleLabel(obj interface{}) {
	unknow, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		obj = unknow.Obj
	}
	securityPolicies, _ := c.securityPolicyLister.ByIndex(labelIndex, obj.(*schema.Label).GetID())
	for _, securityPolicy := range securityPolicies {
		c.handleSecurityPolicy(securityPolicy)
	}
	isolationPolicies, _ := c.isolationPolicyLister.ByIndex(labelIndex, obj.(*schema.Label).GetID())
	for _, isolationPolicy := range isolationPolicies {
		c.handleIsolationPolicy(isolationPolicy)
	}
}

func (c *Controller) updateLabel(old, new interface{}) {
	oldLabel := old.(*schema.Label)
	newLabel := new.(*schema.Label)

	if oldLabel.Key == newLabel.Key && oldLabel.Value == newLabel.Value {
		return
	}
	c.handleLabel(newLabel)
}

func (c *Controller) handleSecurityPolicy(obj interface{}) {
	unknow, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		obj = unknow.Obj
	}
	policy := obj.(*schema.SecurityPolicy)
	// when policy delete, policy.EverouteCluster.ID would be empty
	if policy.EverouteCluster.ID == "" || policy.EverouteCluster.ID == c.everouteCluster {
		c.securityPolicyQueue.Add(policy.GetID())
	}
}

func (c *Controller) updateSecurityPolicy(old, new interface{}) {
	oldPolicy := old.(*schema.SecurityPolicy)
	newPolicy := new.(*schema.SecurityPolicy)

	if reflect.DeepEqual(newPolicy, oldPolicy) {
		return
	}
	c.handleSecurityPolicy(newPolicy)
}

func (c *Controller) handleIsolationPolicy(obj interface{}) {
	unknow, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		obj = unknow.Obj
	}
	policy := obj.(*schema.IsolationPolicy)
	// when policy delete, policy.EverouteCluster.ID would be empty
	if policy.EverouteCluster.ID == "" || policy.EverouteCluster.ID == c.everouteCluster {
		c.isolationPolicyQueue.Add(policy.GetID())
	}
}

func (c *Controller) updateIsolationPolicy(old, new interface{}) {
	oldPolicy := old.(*schema.IsolationPolicy)
	newPolicy := new.(*schema.IsolationPolicy)

	if reflect.DeepEqual(newPolicy, oldPolicy) {
		return
	}
	c.handleIsolationPolicy(newPolicy)
}

func (c *Controller) handleCRDPolicy(obj interface{}) {
	unknow, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		obj = unknow.Obj
	}

	securityPolicies, _ := c.securityPolicyIndexFunc(obj)
	for _, policy := range securityPolicies {
		c.securityPolicyQueue.Add(policy)
	}

	isolationPolicies, _ := c.isolationPolicyIndexFunc(obj)
	for _, policy := range isolationPolicies {
		c.isolationPolicyQueue.Add(policy)
	}

	if obj.(*v1alpha1.SecurityPolicy).Name == SystemEndpointsPolicyName {
		c.systemEndpointPolicyQueue.Add("key")
	}

	if obj.(*v1alpha1.SecurityPolicy).Name == ControllerPolicyName ||
		obj.(*v1alpha1.SecurityPolicy).Name == GlobalWhitelistPolicyName {
		c.everouteClusterPolicyQueue.Add("key")
	}
}

func (c *Controller) updateCRDPolicy(old, new interface{}) {
	oldPolicy := old.(*v1alpha1.SecurityPolicy)
	newPolicy := new.(*v1alpha1.SecurityPolicy)

	if reflect.DeepEqual(oldPolicy, newPolicy) {
		return
	}
	c.handleCRDPolicy(newPolicy)
}

func (c *Controller) handleEverouteCluster(_ interface{}) {
	c.everouteClusterPolicyQueue.Add("key")
}

func (c *Controller) updateEverouteCluster(old, new interface{}) {
	oldERCluster := old.(*schema.EverouteCluster)
	newERCluster := new.(*schema.EverouteCluster)

	if newERCluster.ID == c.everouteCluster {
		c.handleEverouteCluster(newERCluster)
		return
	}

	// handle controller instance ip changes
	if !reflect.DeepEqual(newERCluster.ControllerInstances, oldERCluster.ControllerInstances) {
		c.handleEverouteCluster(newERCluster)
	}
}

func (c *Controller) handleSystemEndpoints(_ interface{}) {
	c.systemEndpointPolicyQueue.Add("key")
}

func (c *Controller) updateSystemEndpoints(old, new interface{}) {
	oldSystemEndpoints := old.(*schema.SystemEndpoints)
	newSystemEndpoints := new.(*schema.SystemEndpoints)

	// handle systemEndpoints IP changes
	if !reflect.DeepEqual(newSystemEndpoints, oldSystemEndpoints) {
		c.handleSystemEndpoints(newSystemEndpoints)
	}
}

// syncSecurityPolicy sync SecurityPoicy to v1alpha1.SecurityPolicy
func (c *Controller) syncSecurityPolicy(key string) error {
	policy, exist, err := c.securityPolicyLister.GetByKey(key)
	if err != nil {
		klog.Errorf("get SecurityPolicy %s: %s", key, err)
		return err
	}

	if !exist {
		return c.deleteRelatedPolicies(securityPolicyIndex, key)
	}
	return c.processSecurityPolicyUpdate(policy.(*schema.SecurityPolicy))
}

// syncIsolationPolicy sync IsolationPolicy to v1alpha1.SecurityPolicy
func (c *Controller) syncIsolationPolicy(key string) error {
	policy, exist, err := c.isolationPolicyLister.GetByKey(key)
	if err != nil {
		klog.Errorf("get IsolationPolicy %s: %s", key, err)
		return err
	}

	if !exist {
		return c.deleteRelatedPolicies(isolationPolicyIndex, key)
	}
	return c.processIsolationPolicyUpdate(policy.(*schema.IsolationPolicy))
}

// syncSystemEndpointsPolicy sync SystemEndpoints to v1alpha1.SecurityPolicy
func (c *Controller) syncSystemEndpointsPolicy(key string) error {
	systemEndpointsList := c.systemEndpointLister.List()
	switch len(systemEndpointsList) {
	case 0:
		err := c.applyPoliciesChanges([]string{c.getSystemEndpointsPolicyKey()}, nil)
		if err != nil {
			klog.Errorf("unable delete systemEndpoints policies %+v: %s", key, err)
		}
		return err
	case 1:
		policy, _ := c.parseSystemEndpointsPolicy(systemEndpointsList[0].(*schema.SystemEndpoints))
		err := c.applyPoliciesChanges([]string{c.getSystemEndpointsPolicyKey()}, policy)
		if err != nil {
			klog.Errorf("unable update systemEndpoints policies %+v: %s", key, err)
		}
		return err
	default:
		return fmt.Errorf("invalid systemEndpoints in cluster, %+v", systemEndpointsList)
	}
}

// syncEverouteClusterPolicy sync EverouteCluster to v1alpha1.SecurityPolicy
func (c *Controller) syncEverouteClusterPolicy(key string) error {
	clusterList := c.everouteClusterLister.List()

	var clusters []*schema.EverouteCluster
	for _, cluster := range clusterList {
		clusters = append(clusters, cluster.(*schema.EverouteCluster))
	}

	// process controller ip policy
	ctrlPolicy, _ := c.parseControllerPolicy(clusters)
	err := c.applyPoliciesChanges([]string{c.getControllerPolicyKey()}, ctrlPolicy)
	if err != nil {
		return fmt.Errorf("unable update EverouteCluster policies : %s", err)
	}

	// process user-defined global whitelist
	currentCluster, exist, err := c.everouteClusterLister.GetByKey(c.everouteCluster)
	if err != nil {
		return fmt.Errorf("get everouteClustes error: %s", err)
	}
	if !exist {
		return fmt.Errorf("everouteCluste %s not found", c.everouteCluster)
	}

	whitelistPolicy, err := c.parseGlobalWhitelistPolicy(currentCluster.(*schema.EverouteCluster))
	if err != nil {
		return fmt.Errorf("create global whitelist policy error: %s", err)
	}
	err = c.applyPoliciesChanges([]string{c.getGlobalWhitelistPolicyKey()}, whitelistPolicy)
	if err != nil {
		return fmt.Errorf("unable update EverouteCluster policies: %s", err)
	}

	return nil
}

func (c *Controller) deleteRelatedPolicies(indexName, key string) error {
	policyKeys, err := c.crdPolicyLister.IndexKeys(indexName, key)
	if err != nil {
		klog.Errorf("list index %s=%s related policies: %s", indexName, key, err)
		return err
	}

	err = c.applyPoliciesChanges(policyKeys, nil)
	if err != nil {
		klog.Errorf("unable delete policies %+v: %s", policyKeys, err)
		return err
	}

	return nil
}

func (c *Controller) processSecurityPolicyUpdate(policy *schema.SecurityPolicy) error {
	policies, err := c.parseSecurityPolicy(policy)
	if err != nil {
		klog.Errorf("parse SecurityPolicy %+v to []v1alpha1.SecurityPolicy: %s", policy, err)
		return err
	}

	currentPolicyKeys, err := c.crdPolicyLister.IndexKeys(securityPolicyIndex, policy.GetID())
	if err != nil {
		klog.Errorf("list v1alpha1.SecurityPolicies: %s", err)
		return err
	}

	err = c.applyPoliciesChanges(currentPolicyKeys, policies)
	if err != nil {
		klog.Errorf("unable sync SecurityPolicies %+v: %s", policies, err)
		return err
	}

	return nil
}

func (c *Controller) processIsolationPolicyUpdate(policy *schema.IsolationPolicy) error {
	policies, err := c.parseIsolationPolicy(policy)
	if err != nil {
		klog.Errorf("parse IsolationPolicy %+v to []v1alpha1.SecurityPolicy: %s", policy, err)
		return err
	}

	currentPolicyKeys, err := c.crdPolicyLister.IndexKeys(isolationPolicyIndex, policy.GetID())
	if err != nil {
		klog.Errorf("list v1alpha1.SecurityPolicies: %s", err)
		return err
	}

	err = c.applyPoliciesChanges(currentPolicyKeys, policies)
	if err != nil {
		klog.Errorf("unable apply policies %+v: %s", policies, err)
		return err
	}

	return nil
}

func (c *Controller) applyPoliciesChanges(oldKeys []string, new []v1alpha1.SecurityPolicy) error {
	oldKeySet := sets.NewString(oldKeys...)

	for _, policy := range new {
		policyKey, _ := cache.MetaNamespaceKeyFunc(policy.DeepCopy())
		if oldKeySet.Has(policyKey) {
			obj, exist, err := c.crdPolicyLister.GetByKey(policyKey)
			if err != nil {
				return fmt.Errorf("get policy %s: %s", policyKey, err)
			}
			oldKeySet.Delete(policyKey)
			if exist {
				// update the policy
				oldPolicyMeta := obj.(*v1alpha1.SecurityPolicy).ObjectMeta
				policy.ObjectMeta = oldPolicyMeta
				if reflect.DeepEqual(policy.Spec, obj.(*v1alpha1.SecurityPolicy).Spec) {
					// ignore update if old and new are same
					continue
				}
				_, err := c.crdClient.SecurityV1alpha1().SecurityPolicies(policy.GetNamespace()).Update(context.Background(), policy.DeepCopy(), metav1.UpdateOptions{})
				if err != nil {
					return fmt.Errorf("update policy %+v: %s", policy, err)
				}
				klog.Infof("update policy %s: %+v", policyKey, policy)
				continue
			}
			// if not exist, create the policy
		}

		// create the policy
		_, err := c.crdClient.SecurityV1alpha1().SecurityPolicies(policy.GetNamespace()).Create(context.Background(), policy.DeepCopy(), metav1.CreateOptions{})
		if err != nil && !errors.IsAlreadyExists(err) {
			return fmt.Errorf("create policy %+v: %s", policy, err)
		}
		if err == nil {
			klog.Infof("create policy %s: %+v", policyKey, policy)
		}
	}

	for _, policyKey := range oldKeySet.List() {
		namespace, name, _ := cache.SplitMetaNamespaceKey(policyKey)
		err := c.crdClient.SecurityV1alpha1().SecurityPolicies(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("delete policy %s: %s", policyKey, err)
		}
		if err == nil {
			klog.Infof("delete policy %s", policyKey)
		}
	}

	return nil
}

// parseGlobalWhitelistPolicy convert schema.EverouteCluster Whitelist to []v1alpha1.SecurityPolicy
func (c *Controller) parseGlobalWhitelistPolicy(cluster *schema.EverouteCluster) ([]v1alpha1.SecurityPolicy, error) {
	if !cluster.GlobalWhitelist.Enable {
		return nil, nil
	}

	if len(cluster.GlobalWhitelist.Ingress) == 0 && len(cluster.GlobalWhitelist.Egress) == 0 {
		return nil, nil
	}

	ingress, egress, err := c.parseNetworkPolicyRules(cluster.GlobalWhitelist.Ingress, cluster.GlobalWhitelist.Egress)
	if err != nil {
		return nil, fmt.Errorf("parse NetworkPolicyRules error, err: %s", err)
	}

	sp := v1alpha1.SecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      GlobalWhitelistPolicyName,
			Namespace: c.namespace,
		},
		Spec: v1alpha1.SecurityPolicySpec{
			Tier:         constants.Tier2,
			DefaultRule:  v1alpha1.DefaultRuleNone,
			IngressRules: ingress,
			EgressRules:  egress,
			PolicyTypes:  []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		},
	}

	return []v1alpha1.SecurityPolicy{sp}, nil
}

// parseControllerPolicy convert schema.EverouteCluster Controller to []v1alpha1.SecurityPolicy
func (c *Controller) parseControllerPolicy(clusters []*schema.EverouteCluster) ([]v1alpha1.SecurityPolicy, error) {
	sp := v1alpha1.SecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ControllerPolicyName,
			Namespace: c.namespace,
		},
		Spec: v1alpha1.SecurityPolicySpec{
			Tier:         constants.Tier2,
			DefaultRule:  v1alpha1.DefaultRuleNone,
			IngressRules: []v1alpha1.Rule{{Name: "ingress"}},
			EgressRules:  []v1alpha1.Rule{{Name: "egress"}},
			PolicyTypes:  []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		},
	}
	for _, cluster := range clusters {
		for _, ctrl := range cluster.ControllerInstances {
			epName := endpoint.GetCtrlEndpointName(cluster.ID, ctrl)
			sp.Spec.AppliedTo = append(sp.Spec.AppliedTo, v1alpha1.ApplyToPeer{
				Endpoint: &epName,
			})
		}
	}
	if len(sp.Spec.AppliedTo) == 0 {
		return nil, nil
	}

	return []v1alpha1.SecurityPolicy{sp}, nil
}

// parseSystemEndpointsPolicy convert schema.SystemEndpoints to []v1alpha1.SecurityPolicy
func (c *Controller) parseSystemEndpointsPolicy(systemEndpoints *schema.SystemEndpoints) ([]v1alpha1.SecurityPolicy, error) {
	sp := v1alpha1.SecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SystemEndpointsPolicyName,
			Namespace: c.namespace,
		},
		Spec: v1alpha1.SecurityPolicySpec{
			Tier:         constants.Tier2,
			DefaultRule:  v1alpha1.DefaultRuleNone,
			IngressRules: []v1alpha1.Rule{{Name: "ingress"}},
			EgressRules:  []v1alpha1.Rule{{Name: "egress"}},
			PolicyTypes:  []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		},
	}
	for _, ip := range systemEndpoints.IPPortEndpoints {
		epName := endpoint.GetSystemEndpointName(ip.Key)
		sp.Spec.AppliedTo = append(sp.Spec.AppliedTo, v1alpha1.ApplyToPeer{
			Endpoint: &epName,
		})
	}
	for _, ep := range systemEndpoints.IDEndpoints {
		applies, err := c.vmAsAppliedTo(ep.VMID)
		if err != nil {
			klog.Errorf("invalid endpoint info: %s", err)
			continue
		}
		sp.Spec.AppliedTo = append(sp.Spec.AppliedTo, applies...)
	}
	if len(sp.Spec.AppliedTo) == 0 {
		return nil, nil
	}

	return []v1alpha1.SecurityPolicy{sp}, nil
}

// parseSecurityPolicy convert schema.SecurityPolicy to []v1alpha1.SecurityPolicy
func (c *Controller) parseSecurityPolicy(securityPolicy *schema.SecurityPolicy) ([]v1alpha1.SecurityPolicy, error) {
	var policyList []v1alpha1.SecurityPolicy

	applyToPeers, err := c.parseSecurityPolicyApplys(securityPolicy.ApplyTo)
	if err != nil {
		return nil, err
	}

	ingress, egress, err := c.parseNetworkPolicyRules(securityPolicy.Ingress, securityPolicy.Egress)
	if err != nil {
		return nil, err
	}

	policy := v1alpha1.SecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SecurityPolicyPrefix + securityPolicy.GetID(),
			Namespace: c.namespace,
		},
		Spec: v1alpha1.SecurityPolicySpec{
			Tier:          constants.Tier2,
			SymmetricMode: true,
			AppliedTo:     applyToPeers,
			IngressRules:  ingress,
			EgressRules:   egress,
			DefaultRule:   v1alpha1.DefaultRuleDrop,
			PolicyTypes:   []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		},
	}
	policyList = append(policyList, policy)

	for item := range securityPolicy.ApplyTo {
		if !securityPolicy.ApplyTo[item].Communicable {
			continue
		}
		// generate intra group policy
		policy, err := c.generateIntragroupPolicy(securityPolicy.GetID(), &securityPolicy.ApplyTo[item])
		if err != nil {
			return nil, err
		}
		policyList = append(policyList, *policy)
	}

	return policyList, nil
}

// parseIsolationPolicy convert schema.IsolationPolicy to []v1alpha1.SecurityPolicy
func (c *Controller) parseIsolationPolicy(isolationPolicy *schema.IsolationPolicy) ([]v1alpha1.SecurityPolicy, error) {
	applyToPeers, err := c.vmAsAppliedTo(isolationPolicy.VM.ID)
	if err != nil {
		return nil, err
	}
	if len(applyToPeers) == 0 {
		return nil, nil
	}

	var isolationPolices []v1alpha1.SecurityPolicy

	switch isolationPolicy.Mode {
	case schema.IsolationModeAll:
		// IsolationModeAll should not create ingress or egress rule
		isolationPolices = append(isolationPolices, c.generateIsolationPolicy(isolationPolicy.GetID(),
			schema.IsolationModeAll, applyToPeers, nil, nil)...)
	case schema.IsolationModePartial:
		ingress, egress, err := c.parseNetworkPolicyRules(isolationPolicy.Ingress, isolationPolicy.Egress)
		if err != nil {
			return nil, err
		}
		isolationPolices = append(isolationPolices, c.generateIsolationPolicy(isolationPolicy.GetID(),
			schema.IsolationModePartial, applyToPeers, ingress, egress)...)
	}

	return isolationPolices, nil
}

func (c *Controller) generateIsolationPolicy(id string, mode schema.IsolationMode, applyToPeers []v1alpha1.ApplyToPeer,
	ingress, egress []v1alpha1.Rule) []v1alpha1.SecurityPolicy {
	var isolationPolices []v1alpha1.SecurityPolicy
	switch mode {
	case schema.IsolationModeAll:
		policy := v1alpha1.SecurityPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      IsolationPolicyPrefix + id,
				Namespace: c.namespace,
			},
			Spec: v1alpha1.SecurityPolicySpec{
				SymmetricMode: true,
				Tier:          constants.Tier0,
				AppliedTo:     applyToPeers,
				DefaultRule:   v1alpha1.DefaultRuleDrop,
				PolicyTypes:   []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			},
		}
		isolationPolices = append(isolationPolices, policy)
	case schema.IsolationModePartial:
		// separate partial policy into ingress and egress policy
		ingressPolicy := v1alpha1.SecurityPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      IsolationPolicyIngressPrefix + id,
				Namespace: c.namespace,
			},
			Spec: v1alpha1.SecurityPolicySpec{
				SymmetricMode: true,
				AppliedTo:     applyToPeers,
				DefaultRule:   v1alpha1.DefaultRuleDrop,
				PolicyTypes:   []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				IngressRules:  ingress,
				Tier:          constants.Tier1,
			},
		}
		if len(ingress) == 0 {
			ingressPolicy.Spec.Tier = constants.Tier0
		}
		isolationPolices = append(isolationPolices, ingressPolicy)

		egressPolicy := v1alpha1.SecurityPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      IsolationPolicyEgressPrefix + id,
				Namespace: c.namespace,
			},
			Spec: v1alpha1.SecurityPolicySpec{
				SymmetricMode: true,
				AppliedTo:     applyToPeers,
				DefaultRule:   v1alpha1.DefaultRuleDrop,
				PolicyTypes:   []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				EgressRules:   egress,
				Tier:          constants.Tier1,
			},
		}
		if len(egress) == 0 {
			egressPolicy.Spec.Tier = constants.Tier0
		}
		isolationPolices = append(isolationPolices, egressPolicy)
	}

	return isolationPolices
}

func (c *Controller) generateIntragroupPolicy(securityPolicyID string, appliedPeer *schema.SecurityPolicyApply) (*v1alpha1.SecurityPolicy, error) {
	peerHash := nameutil.HashName(10, appliedPeer)

	endpointSelector, err := c.parseSelectors(appliedPeer.Selector)
	if err != nil {
		return nil, err
	}

	policy := v1alpha1.SecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SecurityPolicyCommunicablePrefix + peerHash + "-" + securityPolicyID,
			Namespace: c.namespace,
		},
		Spec: v1alpha1.SecurityPolicySpec{
			Tier: constants.Tier2,
			AppliedTo: []v1alpha1.ApplyToPeer{{
				EndpointSelector: endpointSelector,
			}},
			IngressRules: []v1alpha1.Rule{{
				Name: "ingress",
				From: []v1alpha1.SecurityPolicyPeer{{
					EndpointSelector: endpointSelector,
				}},
			}},
			EgressRules: []v1alpha1.Rule{{
				Name: "egress",
				To: []v1alpha1.SecurityPolicyPeer{{
					EndpointSelector: endpointSelector,
				}},
			}},
			DefaultRule: v1alpha1.DefaultRuleDrop,
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		},
	}

	return &policy, nil
}

func (c *Controller) parseSecurityPolicyApplys(peers []schema.SecurityPolicyApply) ([]v1alpha1.ApplyToPeer, error) {
	applyToPeers := make([]v1alpha1.ApplyToPeer, 0, len(peers))

	for _, peer := range peers {
		endpointSelector, err := c.parseSelectors(peer.Selector)
		if err != nil {
			return nil, err
		}
		applyToPeers = append(applyToPeers, v1alpha1.ApplyToPeer{
			EndpointSelector: endpointSelector,
		})
	}

	return applyToPeers, nil
}

func (c *Controller) vmAsAppliedTo(vmKey string) ([]v1alpha1.ApplyToPeer, error) {
	obj, exist, err := c.vmLister.GetByKey(vmKey)
	if err != nil {
		return nil, err
	}
	if !exist {
		return nil, fmt.Errorf("vm %s not found", vmKey)
	}

	applyToPeers := make([]v1alpha1.ApplyToPeer, 0, len(obj.(*schema.VM).VMNics))
	for _, vnic := range obj.(*schema.VM).VMNics {
		vnicID := vnic.GetID()
		applyToPeers = append(applyToPeers, v1alpha1.ApplyToPeer{
			Endpoint: &vnicID,
		})
	}
	return applyToPeers, nil
}

func (c *Controller) parseNetworkPolicyRules(ingressRules, egressRules []schema.NetworkPolicyRule) (ingress, egress []v1alpha1.Rule, err error) {
	ingress = make([]v1alpha1.Rule, 0, len(ingressRules))
	egress = make([]v1alpha1.Rule, 0, len(egressRules))

	for item := range ingressRules {
		peers, ports, err := c.parseNetworkPolicyRule(&ingressRules[item])
		if err != nil {
			return nil, nil, err
		}
		ingress = append(ingress, v1alpha1.Rule{
			Name:  fmt.Sprintf("ingress%d", item),
			Ports: ports,
			From:  peers,
		})
	}

	for item := range egressRules {
		peers, ports, err := c.parseNetworkPolicyRule(&egressRules[item])
		if err != nil {
			return nil, nil, err
		}
		egress = append(egress, v1alpha1.Rule{
			Name:  fmt.Sprintf("egress%d", item),
			Ports: ports,
			To:    peers,
		})
	}

	return ingress, egress, nil
}

// parseNetworkPolicyRule parse NetworkPolicyRule to []v1alpha1.SecurityPolicyPeer and []v1alpha1.SecurityPolicyPort
func (c *Controller) parseNetworkPolicyRule(rule *schema.NetworkPolicyRule) ([]v1alpha1.SecurityPolicyPeer, []v1alpha1.SecurityPolicyPort, error) {
	var policyPeers []v1alpha1.SecurityPolicyPeer
	var policyPorts = make([]v1alpha1.SecurityPolicyPort, 0, len(rule.Ports))

	for _, port := range rule.Ports {
		portRange := ""
		if port.Port != nil {
			portRange = strings.ReplaceAll(*port.Port, " ", "")
		}
		policyPorts = append(policyPorts, v1alpha1.SecurityPolicyPort{
			Protocol:  v1alpha1.Protocol(port.Protocol),
			PortRange: portRange,
		})
	}

	switch rule.Type {
	case schema.NetworkPolicyRuleTypeAll:
		// empty PolicyPeers match all
	case schema.NetworkPolicyRuleTypeIPBlock:
		if rule.IPBlock == nil {
			return nil, nil, fmt.Errorf("receive rule.Type %s but empty IPBlock", schema.NetworkPolicyRuleTypeIPBlock)
		}
		ipBlock, err := parseIPBlock(*rule.IPBlock)
		if err != nil {
			return nil, nil, fmt.Errorf("parse IPBlock %s: %s", *rule.IPBlock, err)
		}
		policyPeers = append(policyPeers, v1alpha1.SecurityPolicyPeer{
			IPBlock: &networkingv1.IPBlock{CIDR: ipBlock},
		})
	case schema.NetworkPolicyRuleTypeSelector:
		endpointSelector, err := c.parseSelectors(rule.Selector)
		if err != nil {
			return nil, nil, err
		}
		policyPeers = append(policyPeers, v1alpha1.SecurityPolicyPeer{
			EndpointSelector: endpointSelector,
		})
	}

	return policyPeers, policyPorts, nil
}

func (c *Controller) parseSelectors(selectors []schema.ObjectReference) (*labels.Selector, error) {
	var matchLabels = make(map[string]string)
	var extendMatchLabels = make(map[string][]string)

	for _, labelRef := range selectors {
		obj, exist, err := c.labelLister.GetByKey(labelRef.ID)
		if err != nil || !exist {
			return nil, fmt.Errorf("label %s not found", labelRef.ID)
		}
		label := obj.(*schema.Label)
		extendMatchLabels[label.Key] = append(extendMatchLabels[label.Key], label.Value)
	}

	// For backward compatibility, we set valid labels in selector.matchLabels,
	// and for other labels, we set them in selector.extendMatchLabels.
	for key, valueSet := range extendMatchLabels {
		if len(valueSet) != 1 {
			continue
		}
		isValid := endpoint.ValidKubernetesLabel(&schema.Label{Key: key, Value: valueSet[0]})
		if isValid {
			matchLabels[key] = valueSet[0]
			delete(extendMatchLabels, key)
		}
	}

	labelSelector := labels.Selector{
		LabelSelector:     metav1.LabelSelector{MatchLabels: matchLabels},
		ExtendMatchLabels: extendMatchLabels,
	}
	return &labelSelector, nil
}

func (c *Controller) getSystemEndpointsPolicyKey() string {
	return c.namespace + "/" + SystemEndpointsPolicyName
}

func (c *Controller) getControllerPolicyKey() string {
	return c.namespace + "/" + ControllerPolicyName
}

func (c *Controller) getGlobalWhitelistPolicyKey() string {
	return c.namespace + "/" + GlobalWhitelistPolicyName
}

func parseIPBlock(ipBlock string) (string, error) {
	_, _, err := net.ParseCIDR(ipBlock)
	if err == nil {
		return ipBlock, nil
	}

	ip := net.ParseIP(ipBlock)
	if ip.To4() != nil {
		return fmt.Sprintf("%s/%d", ipBlock, net.IPv4len*8), nil
	}
	if ip.To16() != nil {
		return fmt.Sprintf("%s/%d", ipBlock, net.IPv6len*8), nil
	}

	return "", fmt.Errorf("neither %s is cidr nor ipv4 nor ipv6", ipBlock)
}
