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
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/source"

	agentv1alpha1 "github.com/everoute/everoute/pkg/apis/agent/v1alpha1"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	ctrltypes "github.com/everoute/everoute/pkg/controller/types"
	"github.com/everoute/everoute/pkg/types"
	"github.com/everoute/everoute/pkg/utils"
)

// EndpointReconciler watch endpoints and agentinfos resources, synchronize the
// endpoint status from agentinfo.
type EndpointReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	ifaceCacheLock sync.RWMutex
	ifaceCache     cache.Indexer
}

const (
	externalIDIndex              = "externalIDIndex"
	agentIndex                   = "agentIndex"
	endpointExternalIDKey        = "iface-id"
	k8sEndpointExternalIDKey     = "pod-uuid"
	ifaceIPAddrTimeout       int = 1800
	IfaceIPAddrCleanInterval int = 5
)

// Reconcile receive endpoint from work queue, synchronize the endpoint status
// from agentinfo.
func (r *EndpointReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	klog.V(2).Infof("EndpointReconciler received endpoint %s reconcile", req.NamespacedName)

	endpoint := securityv1alpha1.Endpoint{}
	if err := r.Get(ctx, req.NamespacedName, &endpoint); err != nil {
		klog.Errorf("unable to fetch endpointGroup %s: %s", req.Name, err.Error())
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Fetch enpoint status from agentinfo.
	expectStatus, err := r.fetchEndpointStatusFromAgentInfo(GetEndpointID(endpoint))
	if err != nil {
		klog.Errorf("while fetch endpoint status: %s", err.Error())
		return ctrl.Result{}, err
	}

	// Skip if none change for this endpoint.
	if EqualEndpointStatus(endpoint.Status, *expectStatus) {
		return ctrl.Result{}, nil
	}

	endpoint.Status = *expectStatus
	if err := r.Status().Update(ctx, &endpoint); err != nil {
		klog.Errorf("failed to update endpoint %s status: %s", endpoint.Name, err.Error())
		return ctrl.Result{}, err
	}
	klog.Infof("endpoint %s (ID: %s) status has been update to: %v", endpoint.Name, GetEndpointID(endpoint), endpoint.Status)

	return ctrl.Result{}, nil
}

// SetupWithManager create and add Endpoint Controller to the manager.
func (r *EndpointReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if mgr == nil {
		return fmt.Errorf("can't setup with nil manager")
	}

	c, err := controller.New("endpoint-controller", mgr, controller.Options{
		MaxConcurrentReconciles: constants.DefaultMaxConcurrentReconciles,
		Reconciler:              r,
	})
	if err != nil {
		return err
	}

	if r.ifaceCache == nil {
		r.ifaceCache = cache.NewIndexer(ifaceKeyFunc, cache.Indexers{
			agentIndex:      agentIndexFunc,
			externalIDIndex: externalIDIndexFunc,
		})
	}

	err = c.Watch(&source.Kind{Type: &agentv1alpha1.AgentInfo{}}, &handler.Funcs{
		CreateFunc: r.addAgentInfo,
		UpdateFunc: r.updateAgentInfo,
		DeleteFunc: r.deleteAgentInfo,
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &securityv1alpha1.Endpoint{}}, &handler.Funcs{
		CreateFunc: r.addEndpoint,
	})
	if err != nil {
		return err
	}

	err = mgr.Add(manager.RunnableFunc(func(stopChan <-chan struct{}) error {
		r.agentInfoCleaner(ifaceIPAddrTimeout, stopChan)
		return nil
	}))
	if err != nil {
		return err
	}

	return nil
}

func (r *EndpointReconciler) addEndpoint(e event.CreateEvent, q workqueue.RateLimitingInterface) {
	if e.Meta == nil {
		klog.Errorf("AddEndpoint received with no metadata event: %v", e)
		return
	}

	q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
		Namespace: e.Meta.GetNamespace(),
		Name:      e.Meta.GetName(),
	}})
}

func (r *EndpointReconciler) addAgentInfo(e event.CreateEvent, q workqueue.RateLimitingInterface) {
	agentInfo, ok := e.Object.(*agentv1alpha1.AgentInfo)
	if !ok {
		klog.Errorf("AddAgentInfo received with unavailable object event: %v", e)
		return
	}

	var epList = securityv1alpha1.EndpointList{}
	_ = r.List(context.Background(), &epList)

	r.ifaceCacheLock.Lock()
	defer r.ifaceCacheLock.Unlock()

	for _, bridge := range agentInfo.OVSInfo.Bridges {
		for _, port := range bridge.Ports {
			for _, ovsIface := range port.Interfaces {
				iface := &iface{
					agentName:           agentInfo.Name,
					name:                ovsIface.Name,
					externalIDs:         ovsIface.ExternalIDs,
					mac:                 ovsIface.Mac,
					ipLastUpdateTimeMap: ovsIface.IPMap,
				}
				_ = r.ifaceCache.Add(iface)
			}
		}
	}

	r.enqueueEndpointsOnAgentLocked(epList, agentInfo.Name, q)
}

func (r *EndpointReconciler) updateAgentInfo(e event.UpdateEvent, q workqueue.RateLimitingInterface) {
	newAgentInfo := e.ObjectNew.(*agentv1alpha1.AgentInfo)
	oldAgentInfo := e.ObjectOld.(*agentv1alpha1.AgentInfo)

	var epList securityv1alpha1.EndpointList
	_ = r.List(context.Background(), &epList)

	r.ifaceCacheLock.Lock()
	defer r.ifaceCacheLock.Unlock()

	r.enqueueEndpointsOnAgentLocked(epList, newAgentInfo.Name, q)
	ifaces, _ := r.ifaceCache.ByIndex(agentIndex, oldAgentInfo.GetName())
	for _, iface := range ifaces {
		_ = r.ifaceCache.Delete(iface)
	}
	for _, bridge := range newAgentInfo.OVSInfo.Bridges {
		for _, port := range bridge.Ports {
			for _, ovsIface := range port.Interfaces {
				iface := &iface{
					agentName:           newAgentInfo.Name,
					name:                ovsIface.Name,
					externalIDs:         ovsIface.ExternalIDs,
					mac:                 ovsIface.Mac,
					ipLastUpdateTimeMap: ovsIface.IPMap,
				}
				_ = r.ifaceCache.Add(iface)
			}
		}
	}
	r.enqueueEndpointsOnAgentLocked(epList, newAgentInfo.Name, q)
	r.updateCachedAgentInfo(newAgentInfo, q)
}

func (r *EndpointReconciler) deleteAgentInfo(e event.DeleteEvent, q workqueue.RateLimitingInterface) {
	agentInfo, ok := e.Object.(*agentv1alpha1.AgentInfo)
	if !ok {
		klog.Errorf("DeleteAgentInfo received with unavailable object event: %v", e)
		return
	}

	var epList securityv1alpha1.EndpointList
	_ = r.List(context.Background(), &epList)

	r.ifaceCacheLock.Lock()
	defer r.ifaceCacheLock.Unlock()

	r.enqueueEndpointsOnAgentLocked(epList, agentInfo.Name, q)
	ifaces, _ := r.ifaceCache.ByIndex(agentIndex, agentInfo.GetName())
	for _, iface := range ifaces {
		_ = r.ifaceCache.Delete(iface)
	}
}

func (r *EndpointReconciler) updateCachedAgentInfo(agentInfo *agentv1alpha1.AgentInfo, q workqueue.RateLimitingInterface) {
	ctx := context.Background()
	updateAgentInfoList := r.toUpdatedAgentInfo(agentInfo)

	for _, ai := range updateAgentInfoList {
		if err := r.Client.Update(ctx, ai); err != nil {
			klog.Errorf("couldn't update agentInfo %v to apiserver, error %v", ai, err)
		}
	}
}

func (r *EndpointReconciler) toUpdatedAgentInfo(newAgentInfo *agentv1alpha1.AgentInfo) []*agentv1alpha1.AgentInfo {
	var agentInfoList agentv1alpha1.AgentInfoList
	var updatedAgentInfoes []*agentv1alpha1.AgentInfo
	_ = r.List(context.Background(), &agentInfoList)

	for _, agentInfo := range agentInfoList.Items {
		var isAgentInfoUpdated bool = false
		var updatedAgentInfo agentv1alpha1.AgentInfo
		for i, bridge := range agentInfo.OVSInfo.Bridges {
			for j, port := range bridge.Ports {
				for k, ovsIface := range port.Interfaces {
					ipNeedDelete := r.getDeletedIP(agentInfo.Name, ovsIface, newAgentInfo)
					if ipNeedDelete.Len() == 0 {
						continue
					}

					for ip := range ovsIface.IPMap {
						if ipNeedDelete.Has(ip.String()) {
							delete(agentInfo.OVSInfo.Bridges[i].Ports[j].Interfaces[k].IPMap, ip)
						}
					}
					isAgentInfoUpdated = true
				}
			}
		}
		if isAgentInfoUpdated {
			agentInfo.DeepCopyInto(&updatedAgentInfo)
			updatedAgentInfoes = append(updatedAgentInfoes, &updatedAgentInfo)
		}
	}

	return updatedAgentInfoes
}

func (r *EndpointReconciler) getDeletedIP(agentName string, ovsInterface agentv1alpha1.OVSInterface, agentInfo *agentv1alpha1.AgentInfo) sets.String {
	for _, bridge := range agentInfo.OVSInfo.Bridges {
		for _, port := range bridge.Ports {
			for _, ovsIface := range port.Interfaces {
				if agentInfo.Name == agentName && ovsIface.Name == ovsInterface.Name {
					continue
				}
				ipNeedDelete := toIPStringSet(ovsIface.IPMap).Intersection(toIPStringSet(ovsInterface.IPMap))
				if ipNeedDelete.Len() != 0 {
					return ipNeedDelete
				}
			}
		}
	}

	return sets.String{}
}

// If an endpoint reference matches iface externalIDs on the agentinfo, the endpoint should be returned.
func (r *EndpointReconciler) enqueueEndpointsOnAgentLocked(epList securityv1alpha1.EndpointList, agentName string, queue workqueue.Interface) {
	for _, ep := range epList.Items {
		ifaces, _ := r.ifaceCache.ByIndex(externalIDIndex, GetEndpointID(ep).String())
		for _, cacheIface := range ifaces {
			if cacheIface.(*iface).agentName == agentName {
				queue.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
					Name:      ep.GetName(),
					Namespace: ep.GetNamespace(),
				}})
			}
		}
	}
}

func (r *EndpointReconciler) agentInfoCleaner(ipAddrTimeout int, stopChan <-chan struct{}) {
	timer := time.NewTicker(time.Duration(IfaceIPAddrCleanInterval) * time.Second)

	for {
		select {
		case <-timer.C:
			r.cleanExpiredIPFromAgentInfo(ipAddrTimeout)
		case <-stopChan:
			return
		}
	}
}

func (r *EndpointReconciler) cleanExpiredIPFromAgentInfo(ipAddrTimeout int) {
	r.ifaceCacheLock.RLock()

	expiredIPMap := make(map[string][]string)
	ifaces := r.ifaceCache.List()
	for _, cacheIface := range ifaces {
		ifaceID := getEndpointIfaceIDFromIfaceCache(cacheIface.(*iface))
		if ifaceID == "" {
			continue
		}
		expiredIPs := computeInterfaceExpiredIPs(ipAddrTimeout, cacheIface.(*iface))
		if len(expiredIPs) != 0 {
			expiredIPMap[ifaceID] = expiredIPs
		}
	}
	r.ifaceCacheLock.RUnlock()

	if len(expiredIPMap) != 0 {
		r.updateExpiredIface(expiredIPMap)
	}
}

func (r *EndpointReconciler) updateExpiredIface(expiredIPMap map[string][]string) {
	var agentInfoList agentv1alpha1.AgentInfoList
	var updateAgentInfoList []*agentv1alpha1.AgentInfo
	ctx := context.Background()
	_ = r.Client.List(ctx, &agentInfoList)

	for _, agentInfo := range agentInfoList.Items {
		var isAgentInfoUpdated bool = false
		var updateAgentInfo agentv1alpha1.AgentInfo
		for i, bridge := range agentInfo.OVSInfo.Bridges {
			for j, port := range bridge.Ports {
				for k, ovsIface := range port.Interfaces {
					ifaceID := getEndpointIfaceIDFromOvsIface(ovsIface)
					if ifaceID == "" {
						continue
					}
					expiredIPs, ok := expiredIPMap[ifaceID]
					if !ok {
						continue
					}
					for _, ip := range expiredIPs {
						delete(agentInfo.OVSInfo.Bridges[i].Ports[j].Interfaces[k].IPMap, types.IPAddress(ip))
					}
					isAgentInfoUpdated = true
				}
			}
		}
		if isAgentInfoUpdated {
			agentInfo.DeepCopyInto(&updateAgentInfo)
			updateAgentInfoList = append(updateAgentInfoList, &updateAgentInfo)
		}
	}

	for _, ai := range updateAgentInfoList {
		err := r.Client.Update(ctx, ai)
		if err != nil {
			klog.Errorf("couldn't update agentInfo: %s", err)
			return
		}
	}
}

func (r *EndpointReconciler) fetchEndpointStatusFromAgentInfo(id ctrltypes.ExternalID) (*securityv1alpha1.EndpointStatus, error) {
	r.ifaceCacheLock.RLock()
	defer r.ifaceCacheLock.RUnlock()

	ifaces, err := r.ifaceCache.ByIndex(externalIDIndex, id.String())
	if err != nil {
		return nil, err
	}
	switch len(ifaces) {
	case 0:
		// if no match iface found, return empty status
		return &securityv1alpha1.EndpointStatus{}, nil
	default:
		// combine all ifaces status into endpoint status
		ipsets := sets.NewString()
		for _, item := range ifaces {
			if len(item.(*iface).ipLastUpdateTimeMap) != 0 {
				for ip := range item.(*iface).ipLastUpdateTimeMap {
					ipsets.Insert(ip.String())
				}
			}
		}
		var ips []types.IPAddress
		for _, ip := range ipsets.List() {
			ips = append(ips, types.IPAddress(ip))
		}
		return &securityv1alpha1.EndpointStatus{
			IPs:        ips,
			MacAddress: ifaces[0].(*iface).mac,
		}, nil
	}
}

// EqualEndpointStatus return true if and only if the two endpoint has the same
// status.
func EqualEndpointStatus(s securityv1alpha1.EndpointStatus, e securityv1alpha1.EndpointStatus) bool {
	macEqual := s.MacAddress == e.MacAddress
	ipsEqual := utils.EqualIPs(s.IPs, e.IPs)

	return macEqual && ipsEqual
}

// GetEndpointID return ID of an endpoint, it's unique in one cluster.
func GetEndpointID(ep securityv1alpha1.Endpoint) ctrltypes.ExternalID {
	return ctrltypes.ExternalID{
		Name:  ep.Spec.Reference.ExternalIDName,
		Value: ep.Spec.Reference.ExternalIDValue,
	}
}

func computeInterfaceExpiredIPs(timeout int, iface *iface) []string {
	var expiredIPs []string
	for ip, t := range iface.ipLastUpdateTimeMap {
		expireTime := t.Add(time.Duration(timeout) * time.Second)
		if time.Now().After(expireTime) {
			expiredIPs = append(expiredIPs, ip.String())
		}
	}

	return expiredIPs
}

func getEndpointIfaceIDFromIfaceCache(iface *iface) string {
	// if normal vm endpoint attached to interface: endpointId k-v pair is
	// endpointExternalIDKey : endpointID
	if ifaceID, ok := iface.externalIDs[endpointExternalIDKey]; ok {
		return ifaceID
	}
	// if k8s endpoint attached to interface: endpointID k-v pair is
	// k8sEndpointExternalIDKey : endpointID
	if ifaceID, ok := iface.externalIDs[k8sEndpointExternalIDKey]; ok {
		return ifaceID
	}

	return ""
}

func getEndpointIfaceIDFromOvsIface(ovsIface agentv1alpha1.OVSInterface) string {
	// if normal vm endpoint attached to interface: endpointID k-v pair is
	// endpointExternalIDKey: endpointID
	if ifaceID, ok := ovsIface.ExternalIDs[endpointExternalIDKey]; ok {
		return ifaceID
	}
	// if k8s endpoint attached to interface: endpointID k-v pair is
	// k8sEndpointExternalIDKey : endpointID
	if ifaceID, ok := ovsIface.ExternalIDs[k8sEndpointExternalIDKey]; ok {
		return ifaceID
	}

	return ""
}

type iface struct {
	agentName string
	name      string

	externalIDs         map[string]string
	mac                 string
	ipLastUpdateTimeMap map[types.IPAddress]metav1.Time
}

func (i *iface) String() string {
	if i != nil {
		return fmt.Sprintf("%+v", *i)
	}
	return "<nil>"
}

func ifaceKeyFunc(obj interface{}) (string, error) {
	ifaceObj := obj.(*iface)
	return fmt.Sprintf("%s/%s", ifaceObj.agentName, ifaceObj.name), nil
}

func agentIndexFunc(obj interface{}) ([]string, error) {
	return []string{obj.(*iface).agentName}, nil
}

func externalIDIndexFunc(obj interface{}) ([]string, error) {
	var externalIDs []string
	for name, value := range obj.(*iface).externalIDs {
		externalIDs = append(externalIDs, ctrltypes.ExternalID{
			Name:  name,
			Value: value,
		}.String())
	}
	return externalIDs, nil
}

func toIPStringSet(ipMap map[types.IPAddress]metav1.Time) sets.String {
	ipStringSet := sets.NewString()
	for ip := range ipMap {
		ipStringSet.Insert(ip.String())
	}

	return ipStringSet
}
