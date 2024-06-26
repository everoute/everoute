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
	"k8s.io/klog/v2"
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
	"github.com/everoute/everoute/pkg/metrics"
	"github.com/everoute/everoute/pkg/types"
	"github.com/everoute/everoute/pkg/utils"
)

// EndpointReconciler watch endpoints and agentinfos resources, synchronize the
// endpoint status from agentinfo.
type EndpointReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	IPMigrateCount *metrics.IPMigrateCount

	ifaceCacheLock sync.RWMutex
	ifaceCache     cache.Indexer
}

const (
	externalIDIndex              = "externalIDIndex"
	ipAddrIndex                  = "ipaddrIndex"
	agentIndex                   = "agentIndex"
	k8sEndpointExternalIDKey     = "pod-uuid"
	IfaceIPAddrCleanInterval int = 5
)

// Reconcile receive endpoint from work queue, synchronize the endpoint status
// from agentinfo.
func (r *EndpointReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var err error
	klog.V(4).Infof("EndpointReconciler received endpoint %s reconcile", req.NamespacedName)

	endpoint := securityv1alpha1.Endpoint{}
	if err := r.Get(ctx, req.NamespacedName, &endpoint); err != nil {
		klog.Errorf("unable to fetch endpoint %s: %s", req.Name, err.Error())
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	var expectStatus *securityv1alpha1.EndpointStatus
	switch endpoint.Spec.Type {
	// Do not change endpoint status for EndpointStaticIP
	case securityv1alpha1.EndpointStatic:
		return ctrl.Result{}, nil
	// Fetch status by static IPs from agentinfo, instead of ExternalID
	case securityv1alpha1.EndpointStaticIP:
		if len(endpoint.Status.IPs) == 0 {
			return ctrl.Result{}, nil
		}
		expectStatus = r.fetchEndpointStatusByIP(endpoint.Status.IPs)
	default:
		// Fetch enpoint status from agentinfo.
		expectStatus, err = r.fetchEndpointStatusFromAgentInfo(endpoint)
		if err != nil {
			klog.Errorf("while fetch endpoint status: %s", err.Error())
			return ctrl.Result{}, err
		}
	}

	// Skip if none change for this endpoint.
	if EqualEndpointStatus(endpoint.Status, *expectStatus) {
		return ctrl.Result{}, nil
	}

	r.ipMigrateCountUpdate(endpoint.Status.IPs, expectStatus.IPs)
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
	if r.IPMigrateCount == nil {
		return fmt.Errorf("can't setup with nil IPMigrateCount")
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
			ipAddrIndex:     ipAddrIndexFunc,
		})
	}

	err = c.Watch(source.Kind(mgr.GetCache(), &agentv1alpha1.AgentInfo{}), &handler.Funcs{
		CreateFunc: r.addAgentInfo,
		UpdateFunc: r.updateAgentInfo,
		DeleteFunc: r.deleteAgentInfo,
	})
	if err != nil {
		return err
	}

	err = c.Watch(source.Kind(mgr.GetCache(), &securityv1alpha1.Endpoint{}), &handler.Funcs{
		CreateFunc: r.addEndpoint,
		UpdateFunc: r.updateEndpoint,
	})
	if err != nil {
		return err
	}

	return mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		r.agentInfoCleaner(constants.IfaceIPTimeoutDuration, ctx.Done())
		return nil
	}))
}

func (r *EndpointReconciler) addEndpoint(_ context.Context, e event.CreateEvent, q workqueue.RateLimitingInterface) {
	if e.Object == nil {
		klog.Errorf("AddEndpoint received with no metadata event: %v", e)
		return
	}

	q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
		Namespace: e.Object.GetNamespace(),
		Name:      e.Object.GetName(),
	}})
}

func (r *EndpointReconciler) updateEndpoint(_ context.Context, e event.UpdateEvent, q workqueue.RateLimitingInterface) {
	if e.ObjectNew == nil {
		klog.Errorf("UpdateEndpoint received with no metadata event: %v", e)
		return
	}

	q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
		Namespace: e.ObjectNew.GetNamespace(),
		Name:      e.ObjectNew.GetName(),
	}})
}

func (r *EndpointReconciler) addAgentInfo(_ context.Context, e event.CreateEvent, q workqueue.RateLimitingInterface) {
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
				t := metav1.Time{}
				agentInfo.Conditions[0].LastHeartbeatTime.DeepCopyInto(&t)
				iface := &iface{
					agentName:   agentInfo.Name,
					name:        ovsIface.Name,
					agentTime:   t,
					externalIDs: ovsIface.ExternalIDs,
					mac:         ovsIface.Mac,
					ipMap:       toIPTimeMap(ovsIface.IPMap),
				}
				_ = r.ifaceCache.Add(iface)
			}
		}
	}

	r.enqueueEndpointsOnAgentLocked(epList, agentInfo.Name, q)
}

func (r *EndpointReconciler) updateAgentInfo(_ context.Context, e event.UpdateEvent, q workqueue.RateLimitingInterface) {
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
				t := metav1.Time{}
				newAgentInfo.Conditions[0].LastHeartbeatTime.DeepCopyInto(&t)
				iface := &iface{
					agentName:   newAgentInfo.Name,
					name:        ovsIface.Name,
					agentTime:   t,
					externalIDs: ovsIface.ExternalIDs,
					mac:         ovsIface.Mac,
					ipMap:       toIPTimeMap(ovsIface.IPMap),
				}
				_ = r.ifaceCache.Add(iface)
			}
		}
	}
	r.enqueueEndpointsOnAgentLocked(epList, newAgentInfo.Name, q)
	r.updateCachedAgentInfo(newAgentInfo, q)
}

func (r *EndpointReconciler) ipMigrateCountUpdate(srcIPs, expIPs []types.IPAddress) {
	srcSets := sets.New[types.IPAddress](srcIPs...)
	for _, ip := range expIPs {
		if !srcSets.Has(ip) {
			r.IPMigrateCount.Inc(ip.String())
		}
	}
}

func (r *EndpointReconciler) deleteAgentInfo(_ context.Context, e event.DeleteEvent, q workqueue.RateLimitingInterface) {
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

func (r *EndpointReconciler) getDeletedIP(agentName string, ovsInterface agentv1alpha1.OVSInterface, agentInfo *agentv1alpha1.AgentInfo) sets.Set[string] {
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

	return sets.Set[string]{}
}

// If an endpoint reference matches iface externalIDs on the agentinfo, the endpoint should be returned.
func (r *EndpointReconciler) enqueueEndpointsOnAgentLocked(epList securityv1alpha1.EndpointList, agentName string, queue workqueue.Interface) {
	for _, ep := range epList.Items {
		var ifaces []interface{}
		ifacesExt, _ := r.ifaceCache.ByIndex(externalIDIndex, GetEndpointID(ep).String())
		ifaces = append(ifaces, ifacesExt...)
		if ep.Spec.Type == securityv1alpha1.EndpointStaticIP {
			for _, ip := range ep.Status.IPs {
				ifacesIPAddr, _ := r.ifaceCache.ByIndex(ipAddrIndex, ip.String())
				ifaces = append(ifaces, ifacesIPAddr...)
			}
		}

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

func (r *EndpointReconciler) agentInfoCleaner(ipAddrTimeout time.Duration, stopChan <-chan struct{}) {
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

func (r *EndpointReconciler) cleanExpiredIPFromAgentInfo(ipAddrTimeout time.Duration) {
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

func (r *EndpointReconciler) fetchEndpointStatusFromAgentInfo(endpoint securityv1alpha1.Endpoint) (*securityv1alpha1.EndpointStatus, error) {
	r.ifaceCacheLock.RLock()
	defer r.ifaceCacheLock.RUnlock()

	ifaces, err := r.ifaceCache.ByIndex(externalIDIndex, GetEndpointID(endpoint).String())
	if err != nil {
		return nil, err
	}
	switch len(ifaces) {
	case 0:
		// if no match iface found, return empty status
		return &securityv1alpha1.EndpointStatus{}, nil
	default:
		// combine all ifaces status into endpoint status
		ipMap := make(map[string]string)
		agentSets := sets.NewString()
		for _, item := range ifaces {
			if len(item.(*iface).ipMap) != 0 {
				agentSets.Insert(item.(*iface).agentName)
				for ip := range item.(*iface).ipMap {
					if v, ok := ipMap[ip.String()]; ok && v == "" {
						continue
					}
					ipMap[ip.String()] = item.(*iface).ipMap[ip].mac
				}
			}
		}
		endpointStatus := &securityv1alpha1.EndpointStatus{
			MacAddress: ifaces[0].(*iface).mac,
			Agents:     agentSets.List(),
		}
		for ip := range ipMap {
			if endpoint.Spec.StrictMac && ipMap[ip] != "" {
				continue
			}
			endpointStatus.IPs = append(endpointStatus.IPs, types.IPAddress(ip))
		}
		return endpointStatus, nil
	}
}

func (r *EndpointReconciler) fetchEndpointStatusByIP(ips []types.IPAddress) *securityv1alpha1.EndpointStatus {
	r.ifaceCacheLock.RLock()
	defer r.ifaceCacheLock.RUnlock()
	agents := sets.NewString()
	for _, ip := range ips {
		ifaces, _ := r.ifaceCache.ByIndex(ipAddrIndex, ip.String())
		for _, item := range ifaces {
			agents.Insert(item.(*iface).agentName)
		}
	}
	return &securityv1alpha1.EndpointStatus{
		IPs:    ips,
		Agents: agents.List(),
	}
}

// EqualEndpointStatus return true if and only if the two endpoint has the same
// status.
func EqualEndpointStatus(s securityv1alpha1.EndpointStatus, e securityv1alpha1.EndpointStatus) bool {
	macEqual := s.MacAddress == e.MacAddress
	ipsEqual := utils.EqualIPs(s.IPs, e.IPs)
	agentEqual := utils.EqualStringSlice(s.Agents, e.Agents)

	return macEqual && ipsEqual && agentEqual
}

// GetEndpointID return ID of an endpoint, it's unique in one cluster.
func GetEndpointID(ep securityv1alpha1.Endpoint) ctrltypes.ExternalID {
	return ctrltypes.ExternalID{
		Name:  ep.Spec.Reference.ExternalIDName,
		Value: ep.Spec.Reference.ExternalIDValue,
	}
}

func computeInterfaceExpiredIPs(timeout time.Duration, iface *iface) []string {
	var expiredIPs []string
	for ip, t := range iface.ipMap {
		expireTime := t.lastUpdateTime.Add(timeout)
		if iface.agentTime.After(expireTime) {
			expiredIPs = append(expiredIPs, ip.String())
		}
	}

	return expiredIPs
}

func getEndpointIfaceIDFromIfaceCache(iface *iface) string {
	// if normal vm endpoint attached to interface: endpointId k-v pair is
	// endpointExternalIDKey : endpointID
	if ifaceID, ok := iface.externalIDs[constants.EndpointExternalIDKey]; ok {
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
	if ifaceID, ok := ovsIface.ExternalIDs[constants.EndpointExternalIDKey]; ok {
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
	agentTime metav1.Time

	externalIDs map[string]string
	mac         string
	ipMap       map[types.IPAddress]ifaceIP
}

type ifaceIP struct {
	mac            string
	lastUpdateTime metav1.Time
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

func ipAddrIndexFunc(obj interface{}) ([]string, error) {
	var ipAddr []string
	for ip := range obj.(*iface).ipMap {
		ipAddr = append(ipAddr, ip.String())
	}
	return ipAddr, nil
}

func toIPStringSet(ipMap map[types.IPAddress]*agentv1alpha1.IPInfo) sets.Set[string] {
	ipStringSet := sets.New[string]()
	for ip := range ipMap {
		ipStringSet.Insert(ip.String())
	}

	return ipStringSet
}

func toIPTimeMap(ipMap map[types.IPAddress]*agentv1alpha1.IPInfo) map[types.IPAddress]ifaceIP {
	ipTimeMap := make(map[types.IPAddress]ifaceIP, len(ipMap))
	for ip, info := range ipMap {
		ipTimeMap[ip] = ifaceIP{
			lastUpdateTime: info.UpdateTime,
			mac:            info.Mac,
		}
	}
	return ipTimeMap
}
