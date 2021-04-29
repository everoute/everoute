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

	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	agentv1alpha1 "github.com/smartxworks/lynx/pkg/apis/agent/v1alpha1"
	securityv1alpha1 "github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
	lynxctrl "github.com/smartxworks/lynx/pkg/controller"
	ctrltypes "github.com/smartxworks/lynx/pkg/controller/types"
	"github.com/smartxworks/lynx/pkg/types"
	"github.com/smartxworks/lynx/pkg/utils"
)

// EndpointReconciler watch endpoints and agentinfos resources, synchronize the
// endpoint status from agentinfo.
type EndpointReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

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
		MaxConcurrentReconciles: lynxctrl.DefaultMaxConcurrentReconciles,
		Reconciler:              r,
	})
	if err != nil {
		return err
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

	ports := []agentv1alpha1.OVSPort{}
	for _, bridge := range agentInfo.OVSInfo.Bridges {
		ports = append(ports, bridge.Ports...)
	}

	epList := securityv1alpha1.EndpointList{}
	_ = r.List(context.Background(), &epList)

	// Enqueue all endpoints for update status in the agentinfo.
	for _, ep := range epList.Items {
		if _, matches := GetEndpointID(ep).MatchPorts(ports); matches {
			q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
				Name: ep.Name,
			}})
		}
	}
}

func (r *EndpointReconciler) updateAgentInfo(e event.UpdateEvent, q workqueue.RateLimitingInterface) {
	ports := []agentv1alpha1.OVSPort{}

	newAgentInfo, ok := e.ObjectNew.(*agentv1alpha1.AgentInfo)
	if ok {
		for _, bridge := range newAgentInfo.OVSInfo.Bridges {
			ports = append(ports, bridge.Ports...)
		}
	}

	oldAgentInfo, ok := e.ObjectOld.(*agentv1alpha1.AgentInfo)
	if ok {
		for _, bridge := range oldAgentInfo.OVSInfo.Bridges {
			ports = append(ports, bridge.Ports...)
		}
	}

	epList := securityv1alpha1.EndpointList{}
	_ = r.List(context.Background(), &epList)

	// Enqueue all endpoints for update status in the agentinfo.
	for _, ep := range epList.Items {
		if _, matches := GetEndpointID(ep).MatchPorts(ports); matches {
			q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
				Name: ep.Name,
			}})
		}
	}
}

func (r *EndpointReconciler) deleteAgentInfo(e event.DeleteEvent, q workqueue.RateLimitingInterface) {
	agentInfo, ok := e.Object.(*agentv1alpha1.AgentInfo)
	if !ok {
		klog.Errorf("DeleteAgentInfo received with unavailable object event: %v", e)
		return
	}

	ports := []agentv1alpha1.OVSPort{}
	for _, bridge := range agentInfo.OVSInfo.Bridges {
		ports = append(ports, bridge.Ports...)
	}

	epList := securityv1alpha1.EndpointList{}
	_ = r.List(context.Background(), &epList)

	// Enqueue all endpoints for update status in the agentinfo.
	for _, ep := range epList.Items {
		if _, matches := GetEndpointID(ep).MatchPorts(ports); matches {
			q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
				Name: ep.Name,
			}})
		}
	}
}

func (r *EndpointReconciler) fetchEndpointStatusFromAgentInfo(id ctrltypes.ExternalID) (*securityv1alpha1.EndpointStatus, error) {
	agentInfoList := agentv1alpha1.AgentInfoList{}
	err := r.List(context.Background(), &agentInfoList)
	if err != nil {
		return nil, err
	}

	toEndpointStatus := func(port agentv1alpha1.OVSPort) (*securityv1alpha1.EndpointStatus, error) {
		status := new(securityv1alpha1.EndpointStatus)
		if len(port.Interfaces) != 1 {
			return nil, fmt.Errorf("an endpoint should has one interface")
		}

		status.IPs = make([]types.IPAddress, len(port.Interfaces[0].IPs))
		copy(status.IPs, port.Interfaces[0].IPs)
		status.MacAddress = port.Interfaces[0].Mac

		return status, nil
	}

	for _, agentInfo := range agentInfoList.Items {
		for _, bridge := range agentInfo.OVSInfo.Bridges {
			index, matches := id.MatchPorts(bridge.Ports)
			if matches {
				return toEndpointStatus(bridge.Ports[index])
			}
		}
	}

	return &securityv1alpha1.EndpointStatus{}, nil
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
