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

	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/client/clientset_generated/clientset"
	crd "github.com/everoute/everoute/pkg/client/informers_generated/externalversions"
	"github.com/everoute/everoute/pkg/constants"
	nameutil "github.com/everoute/everoute/pkg/controller/policy/cache"
	"github.com/everoute/everoute/plugin/tower/pkg/informer"
	"github.com/everoute/everoute/plugin/tower/pkg/schema"
)

const (
	SecurityPolicyPrefix             = "tower.sp-"
	IsolationPolicyPrefix            = "tower.ip-"
	SecurityPolicyCommunicablePrefix = "tower.sp.communicable-"

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

	isolationPolicyQueue workqueue.RateLimitingInterface
	securityPolicyQueue  workqueue.RateLimitingInterface
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
		isolationPolicyQueue:          workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		securityPolicyQueue:           workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
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

	if !cache.WaitForNamedCacheSync(c.name, stopCh,
		c.vmInformerSynced,
		c.labelInformerSynced,
		c.securityPolicyInformerSynced,
		c.isolationPolicyInformerSynced,
		c.crdPolicyInformerSynced,
	) {
		return
	}

	for i := uint(0); i < workers; i++ {
		go wait.Until(c.syncSecurityPolicyWorker, time.Second, stopCh)
		go wait.Until(c.syncIsolationPolicyWorker, time.Second, stopCh)
	}

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

	if strings.HasPrefix(policy.GetName(), IsolationPolicyPrefix) {
		isolationPolicyKey := strings.TrimPrefix(policy.GetName(), IsolationPolicyPrefix)
		return []string{isolationPolicyKey}, nil
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
	if policy.EverouteCluster.ID == c.everouteCluster {
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
	if policy.EverouteCluster.ID == c.everouteCluster {
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
}

func (c *Controller) updateCRDPolicy(old, new interface{}) {
	oldPolicy := old.(*v1alpha1.SecurityPolicy)
	newPolicy := new.(*v1alpha1.SecurityPolicy)

	if reflect.DeepEqual(oldPolicy, newPolicy) {
		return
	}
	c.handleCRDPolicy(newPolicy)
}

func (c *Controller) syncSecurityPolicyWorker() {
	for {
		key, quit := c.securityPolicyQueue.Get()
		if quit {
			return
		}

		err := c.syncSecurityPolicy(key.(string))
		if err != nil {
			c.securityPolicyQueue.Done(key)
			c.securityPolicyQueue.AddRateLimited(key)
			klog.Errorf("got error while sync SecurityPolicy %s: %s", key.(string), err)
			continue
		}

		// stop the rate limiter from tracking the key
		c.securityPolicyQueue.Done(key)
		c.securityPolicyQueue.Forget(key)
	}
}

func (c *Controller) syncIsolationPolicyWorker() {
	for {
		key, quit := c.isolationPolicyQueue.Get()
		if quit {
			return
		}

		err := c.syncIsolationPolicy(key.(string))
		if err != nil {
			c.isolationPolicyQueue.Done(key)
			c.isolationPolicyQueue.AddRateLimited(key)
			klog.Errorf("got error while sync IsolationPolicy %s: %s", key.(string), err)
			continue
		}

		// stop the rate limiter from tracking the key
		c.isolationPolicyQueue.Done(key)
		c.isolationPolicyQueue.Forget(key)
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
			Tier:          constants.Tier1,
			SymmetricMode: true,
			AppliedTo:     applyToPeers,
			IngressRules:  ingress,
			EgressRules:   egress,
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

	policy := v1alpha1.SecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      IsolationPolicyPrefix + isolationPolicy.GetID(),
			Namespace: c.namespace,
		},
		Spec: v1alpha1.SecurityPolicySpec{
			Tier:          constants.Tier0,
			SymmetricMode: true,
			AppliedTo:     applyToPeers,
			PolicyTypes:   []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		},
	}

	switch isolationPolicy.Mode {
	case schema.IsolationModeAll:
		// IsolationModeAll should not create ingress or egress rule
	case schema.IsolationModePartial:
		ingress, egress, err := c.parseNetworkPolicyRules(isolationPolicy.Ingress, isolationPolicy.Egress)
		if err != nil {
			return nil, err
		}
		policy.Spec.IngressRules = ingress
		policy.Spec.EgressRules = egress
	}

	return []v1alpha1.SecurityPolicy{policy}, nil
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
			Tier: constants.Tier1,
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
			portRange = *port.Port
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

func (c *Controller) parseSelectors(selectors []schema.ObjectReference) (*metav1.LabelSelector, error) {
	endpointSelector := metav1.LabelSelector{
		MatchLabels: make(map[string]string, len(selectors)),
	}
	for _, labelRef := range selectors {
		obj, exist, err := c.labelLister.GetByKey(labelRef.ID)
		if err != nil {
			return nil, fmt.Errorf("unable get label %s: %s", labelRef.ID, err)
		}
		if !exist {
			return nil, fmt.Errorf("label %s not found", labelRef.ID)
		}
		label := obj.(*schema.Label)
		endpointSelector.MatchLabels[label.Key] = label.Value
	}
	return &endpointSelector, nil
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
