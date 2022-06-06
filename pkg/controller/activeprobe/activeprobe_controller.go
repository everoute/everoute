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

package activeprobe

import (
	"context"
	"fmt"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	activeprobev1alph1 "github.com/everoute/everoute/pkg/apis/activeprobe/v1alpha1"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	ctrltypes "github.com/everoute/everoute/pkg/controller/types"
	"github.com/everoute/everoute/pkg/types"
)

const (
	controllerName        = "activeprobe-controller"
	externalIDIndex       = "externalIDIndex"
	endpointExternalIDKey = "iface-id"
	// Min and max data plane tag for traceflow. minTagNum is 7 (0b000111), maxTagNum is 59 (0b111011).
	// As per RFC2474, 16 different DSCP values are we reserved for Experimental or Local Use, which we use as the 16 possible data plane tag values.
	// tagStep is 4 (0b100) to keep last 2 bits at 0b11.
	tagStep   uint8 = 0b100
	minTagNum uint8 = 0b1*tagStep + 0b11
	maxTagNum uint8 = 0b1110*tagStep + 0b11
)

type updateStatusItem struct {
	ipSrc string
	ipDst string
	tag   uint8
}

type ActiveprobeReconciler struct {
	client.Client
	Scheme                  *runtime.Scheme
	syncQueue               workqueue.RateLimitingInterface
	RunningActiveprobeMutex sync.Mutex
	RunningActiveprobe      map[uint8]string // tag->activeProbeName if ap.Status.State is Running
	IfaceCacheLock          sync.RWMutex
	IfaceCache              cache.Indexer
}

// SetupWithManager create and add Endpoint Controller to the manager.
func (r *ActiveprobeReconciler) SetupWithManager(mgr ctrl.Manager, ifaceCache cache.Indexer) error {
	if mgr == nil {
		return fmt.Errorf("can't setup with nil manager")
	}

	r.IfaceCache = ifaceCache

	c, err := controller.New(controllerName, mgr, controller.Options{
		MaxConcurrentReconciles: constants.DefaultMaxConcurrentReconciles,
		Reconciler:              r,
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &activeprobev1alph1.ActiveProbe{}}, &handler.Funcs{
		CreateFunc: r.AddActiveProbe,
		UpdateFunc: r.UpdateActiveProbe,
		DeleteFunc: r.RemoveActiveProbe,
	})
	if err != nil {
		return err
	}

	return nil
}

func (r *ActiveprobeReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	return ctrl.Result{}, nil
}

func (r *ActiveprobeReconciler) Run(stopChan <-chan struct{}) {
	defer r.syncQueue.ShutDown()
	klog.Infof("Starting %s", controllerName)
	defer klog.Infof("Shutting down %s", controllerName)

	go wait.Until(r.SyncActiveProbeWorker, 0, stopChan)
	<-stopChan
}

func (r *ActiveprobeReconciler) SyncActiveProbeWorker() {
	item, shutdown := r.syncQueue.Get()
	if shutdown {
		return
	}
	defer r.syncQueue.Done(item)
	// 1. lookup endpoint name from  endpoint agent

	objKey, ok := item.(k8stypes.NamespacedName)
	if !ok {
		r.syncQueue.Forget(item)
		klog.Errorf("Activeprobe %v was not found in workqueue", objKey)
		return
	}

	// TODO should support timeout and max retry
	if err := r.syncActiveProbe(objKey); err == nil {
		klog.Errorf("sync activeprobe  %v", objKey)
		r.syncQueue.Forget(item)
	} else {
		klog.Errorf("Failed to sync activeprobe %v, error: %v", objKey, err)
	}
}

func (r *ActiveprobeReconciler) syncActiveProbe(objKey k8stypes.NamespacedName) error {
	var err error
	ctx := context.Background()
	ap := activeprobev1alph1.ActiveProbe{}
	if err := r.Get(ctx, objKey, &ap); err != nil {
		klog.Errorf("unable to fetch activeprobe %s: %s", objKey, err.Error())
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return client.IgnoreNotFound(err)
	}

	switch ap.Status.State {
	case "":
		err = r.runActiveProbe(&ap)
	case activeprobev1alph1.ActiveProbeRunning:
		err = r.checkActiveProbeStatus(&ap)
	case activeprobev1alph1.ActiveProbeFailed:
		r.deallocateTagForAP(&ap)
	default:
	}

	return err
}

func (r *ActiveprobeReconciler) fetchEndpointStatus(id ctrltypes.ExternalID) (*securityv1alpha1.EndpointStatus, error) {
	r.IfaceCacheLock.RLock()
	defer r.IfaceCacheLock.RUnlock()

	ifaces, err := r.IfaceCache.ByIndex(externalIDIndex, id.String())
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
		agentSets := sets.NewString()
		for _, item := range ifaces {
			if len(item.(*iface).ipLastUpdateTimeMap) != 0 {
				agentSets.Insert(item.(*iface).agentName)
				for ip := range item.(*iface).ipLastUpdateTimeMap {
					ipsets.Insert(ip.String())
				}
			}
		}
		endpointStatus := &securityv1alpha1.EndpointStatus{
			MacAddress: ifaces[0].(*iface).mac,
			Agents:     agentSets.List(),
		}
		for _, ip := range ipsets.List() {
			endpointStatus.IPs = append(endpointStatus.IPs, types.IPAddress(ip))
		}
		return endpointStatus, nil
	}
}

func (r *ActiveprobeReconciler) AddEndpointInfo(ap *activeprobev1alph1.ActiveProbe) error {
	srcEpExternalIDValue := ap.Spec.Source.Endpoint
	srcEndpointID := ctrltypes.ExternalID{
		Name:  endpointExternalIDKey,
		Value: srcEpExternalIDValue,
	}

	srcIfaces, _ := r.IfaceCache.ByIndex(externalIDIndex, srcEndpointID.String())
	srcEndpointStatus, _ := r.fetchEndpointStatus(srcEndpointID)

	switch len(srcIfaces) {
	case 0:
		// if no match iface found, return empty status
		return nil
	default:
		ap.Spec.Source.IP = srcEndpointStatus.IPs[0].String()
		ap.Spec.Source.MAC = srcIfaces[0].(*iface).mac
		ap.Spec.Source.AgentName = srcIfaces[0].(*iface).agentName
		ap.Spec.Source.BridgeName = srcIfaces[0].(*iface).bridgeName
		ap.Spec.Source.Ofport = srcIfaces[0].(*iface).ofport
		return nil
	}

	dstEpExternalIDValue := ap.Spec.Destination.Endpoint
	dstEndpointID := ctrltypes.ExternalID{
		Name:  endpointExternalIDKey,
		Value: dstEpExternalIDValue,
	}

	dstIfaces, _ := r.IfaceCache.ByIndex(externalIDIndex, dstEndpointID.String())
	dstEndpointStatus, _ := r.fetchEndpointStatus(dstEndpointID)

	switch len(dstIfaces) {
	case 0:
		return nil
	default:
		ap.Spec.Destination.IP = dstEndpointStatus.IPs[0].String()
		ap.Spec.Destination.MAC = dstIfaces[0].(*iface).mac
		ap.Spec.Destination.AgentName = dstIfaces[0].(*iface).agentName
		ap.Spec.Destination.BridgeName = dstIfaces[0].(*iface).bridgeName
		ap.Spec.Destination.Ofport = dstIfaces[0].(*iface).ofport
	}

	return nil
}

func (r *ActiveprobeReconciler) allocateTag(name string) (uint8, error) {
	r.RunningActiveprobeMutex.Lock()
	defer r.RunningActiveprobeMutex.Unlock()

	for _, n := range r.RunningActiveprobe {
		if n == name {
			return 0, nil
		}
	}
	for i := minTagNum; i <= maxTagNum; i += tagStep {
		if _, ok := r.RunningActiveprobe[i]; !ok {
			r.RunningActiveprobe[i] = name
			return i, nil
		}
	}
	return 0, fmt.Errorf("number of on-going ActiveProve operations already reached the upper limit: %d", maxTagNum)
}

func (r *ActiveprobeReconciler) deallocateTagForAP(ap *activeprobev1alph1.ActiveProbe) {
	if ap.Status.Tag != 0 {
		r.deallocateTag(ap.Name, ap.Status.Tag)
	}
}

func (r *ActiveprobeReconciler) deallocateTag(name string, tag uint8) {
	r.RunningActiveprobeMutex.Lock()
	defer r.RunningActiveprobeMutex.Unlock()
	if existingActiveProbeName, ok := r.RunningActiveprobe[tag]; ok {
		if name == existingActiveProbeName {
			delete(r.RunningActiveprobe, tag)
		}
	}
}

func (r *ActiveprobeReconciler) validateActiveProbe(ap *activeprobev1alph1.ActiveProbe) error {

	return nil
}

func (r *ActiveprobeReconciler) updateActiveProbeStatus(ap *activeprobev1alph1.ActiveProbe,
	state activeprobev1alph1.ActiveProbeState, reason string, tag uint8) error {
	update := ap.DeepCopy()
	update.Status.State = state
	update.Status.Tag = tag
	if reason != "" {
		update.Status.Reason = reason
	}
	err := r.Client.Status().Update(context.TODO(), update, &client.UpdateOptions{})
	return err
}

/* TODO */
func (r *ActiveprobeReconciler) runActiveProbe(ap *activeprobev1alph1.ActiveProbe) error {
	if err := r.validateActiveProbe(ap); err != nil {
		klog.Errorf("Invalid ActiveProbe request %v", ap)
		return r.updateActiveProbeStatus(ap, activeprobev1alph1.ActiveProbeFailed, fmt.Sprintf("Invalid ActiveProbe request, err: %+v", err), 0)
	}

	updateItem := &updateStatusItem{}
	// Allocate data plane tag.
	tag, err := r.allocateTag(ap.Name)
	if err != nil {
		return err
	}
	if tag == 0 {
		return nil
	}
	updateItem.tag = tag

	err = r.AddEndpointInfo(ap)
	if err != nil {
		return err
	}

	err = r.updateActiveProbeStatus(ap, activeprobev1alph1.ActiveProbeRunning, "", tag)
	if err != nil {
		r.deallocateTag(ap.Name, tag)
	}
	return err
}

/* TODO */
func (r *ActiveprobeReconciler) checkActiveProbeStatus(ap *activeprobev1alph1.ActiveProbe) error {

	return nil
}
func (r *ActiveprobeReconciler) AddActiveProbe(e event.CreateEvent, q workqueue.RateLimitingInterface) {
	r.syncQueue.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
		Name:      e.Meta.GetName(),
		Namespace: e.Meta.GetNamespace(),
	}})
}

func (r *ActiveprobeReconciler) RemoveActiveProbe(e event.DeleteEvent, q workqueue.RateLimitingInterface) {
	r.syncQueue.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
		Name:      e.Meta.GetName(),
		Namespace: e.Meta.GetNamespace(),
	}})

}

func (r *ActiveprobeReconciler) UpdateActiveProbe(e event.UpdateEvent, q workqueue.RateLimitingInterface) {
	// should sync all object
	r.syncQueue.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
		Name:      e.MetaNew.GetName(),
		Namespace: e.MetaNew.GetNamespace(),
	}})

}

type iface struct {
	agentName string
	name      string
	agentTime metav1.Time

	externalIDs         map[string]string
	mac                 string
	ipLastUpdateTimeMap map[types.IPAddress]metav1.Time

	bridgeName string
	ofport     int32
}
