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

package endpoint

import (
	"context"
	"fmt"
	"sync"

	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	agentv1alpha1 "github.com/smartxworks/lynx/pkg/apis/agent/v1alpha1"
	securityv1alpha1 "github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
	"github.com/smartxworks/lynx/pkg/constants"
	ctrltypes "github.com/smartxworks/lynx/pkg/controller/types"
	"github.com/smartxworks/lynx/pkg/types"
	"github.com/smartxworks/lynx/pkg/utils"
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
	externalIDIndex = "externalIDIndex"
	agentIndex      = "agentIndex"
)

// Reconcile receive endpoint from work queue, synchronize the endpoint status
// from agentinfo.
func (r *EndpointReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
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
		CreateFunc: func(e event.CreateEvent, q workqueue.RateLimitingInterface) {
			q.Add(reconcile.Request{NamespacedName: k8stypes.NamespacedName{
				Name:      e.Object.GetName(),
				Namespace: e.Object.GetNamespace(),
			}})
		},
	})
	if err != nil {
		return err
	}

	return nil
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
					agentName:   agentInfo.Name,
					name:        ovsIface.Name,
					externalIDs: ovsIface.ExternalIDs,
					mac:         ovsIface.Mac,
					ips:         ovsIface.IPs,
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
					agentName:   newAgentInfo.Name,
					name:        ovsIface.Name,
					externalIDs: ovsIface.ExternalIDs,
					mac:         ovsIface.Mac,
					ips:         ovsIface.IPs,
				}
				_ = r.ifaceCache.Add(iface)
			}
		}
	}
	r.enqueueEndpointsOnAgentLocked(epList, newAgentInfo.Name, q)
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
		// use the first iface status as endpoint status
		return &securityv1alpha1.EndpointStatus{
			IPs:        append([]types.IPAddress{}, ifaces[0].(*iface).ips...),
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

type iface struct {
	agentName string
	name      string

	externalIDs map[string]string
	mac         string
	ips         []types.IPAddress
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
