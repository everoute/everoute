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
	"errors"
	"fmt"
	"github.com/contiv/libOpenflow/protocol"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	"net"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/contiv/ofnet/ofctrl"
	"github.com/everoute/everoute/pkg/agent/datapath"
	activeprobev1alph1 "github.com/everoute/everoute/pkg/apis/activeprobe/v1alpha1"
	"github.com/everoute/everoute/pkg/client/clientset_generated/clientset"
	v1alpha1 "github.com/everoute/everoute/pkg/client/listers_generated/activeprobe/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
)

type ActiveprobeController struct {
	// K8sClient used to create/read/update activeprobe
	K8sClient client.Client
	Scheme    *runtime.Scheme

	DatapathManager *datapath.DpManager

	// for self registered controller
	crdClient           clientset.Interface
	activeProbeInformer cache.SharedIndexInformer
	// TODO activeProbe lister
	activeProbeLister         v1alpha1.ActiveProbeLister
	activeProbeInformerSynced cache.InformerSynced
	syncQueue                 workqueue.RateLimitingInterface
}

// NOTE if we use self registered controller,
//func NewActiveProbeController(
//	crdFactory crd.SharedInformerFactory,
//	crdClient clientset.Interface,
//	resyncPeriod time.Duration,
//) *ActiveprobeController {
//
//	activeProbeInformer := crdFactory.Activeprobe().V1alpha1().ActiveProbes().Informer()
//	c := &ActiveprobeController{
//		crdClient:                 crdClient,
//		activeProbeInformer:       activeProbeInformer,
//		activeProbeLister:         crdFactory.Activeprobe().V1alpha1().ActiveProbes().Lister(),
//		activeProbeInformerSynced: activeProbeInformer.HasSynced,
//		syncQueue:                 workqueue.NewRateLimitingQueue(workqueue.DefaultItemBasedRateLimiter()),
//	}
//
//	// NOTE just process active probe add ?
//	activeProbeInformer.AddEventHandlerWithResyncPeriod(
//		cache.ResourceEventHandlerFuncs{
//			AddFunc:    c.AddActiveProbe,
//			UpdateFunc: c.UpdateActiveProbe,
//			DeleteFunc: c.DeleteActiveProbe,
//		},
//		resyncPeriod,
//	)
//
//	c.RegisterPacketInHandlerForSelfCtrl()
//
//	return c
//}
//
//func (a *ActiveprobeController) RegisterPacketInHandlerForSelfCtrl() {
//	a.DatapathManager.RegisterPacketInHandler(datapath.PacketInHandlerFuncs{
//		PacketInHandlerFunc: func(packetIn *ofctrl.PacketIn) {
//			if err := a.HandlePacketIn(packetIn); err != nil {
//				klog.Errorf("Failed to parsing packet in: %v, error: %v", packetIn, err)
//			}
//		},
//	})
//}
//
//// NOTE if we use self registered controller, this is entrence function
//func (a *ActiveprobeController) Run(stopChan <-chan struct{}) {
//	defer a.syncQueue.ShutDown()
//
//	go wait.Until(a.SyncActiveProbeWorker, 0, stopChan)
//	<-stopChan
//}
//
//func (a *ActiveprobeController) SyncActiveProbeWorker() {
//	item, shutdown := a.syncQueue.Get()
//	if shutdown {
//		return
//	}
//	defer a.syncQueue.Done(item)
//
//	objKey, ok := item.(k8stypes.NamespacedName)
//	if !ok {
//		a.syncQueue.Forget(item)
//		klog.Errorf("Activeprobe %v was not found in workqueue", objKey)
//		return
//	}
//
//	// TODO should support timeout and max retry
//	if err := a.syncActiveProbe(objKey); err == nil {
//		klog.Errorf("sync activeprobe  %v", objKey)
//		a.syncQueue.Forget(item)
//	} else {
//		klog.Errorf("Failed to sync activeprobe %v, error: %v", objKey, err)
//	}
//}
//
//func (a *ActiveprobeController) syncActiveProbe(objKey k8stypes.NamespacedName) error {
//	var err error
//	ctx := context.Background()
//	ap := activeprobev1alph1.ActiveProbe{}
//	if err := a.K8sClient.Get(ctx, objKey, &ap); err != nil {
//		klog.Errorf("unable to fetch activeprobe %s: %s", objKey, err.Error())
//		// we'll ignore not-found errors, since they can't be fixed by an immediate
//		// requeue (we'll need to wait for a new notification), and we can get them
//		// on deleted requests.
//		return client.IgnoreNotFound(err)
//	}
//
//	switch ap.Status.State {
//	case activeprobev1alph1.ActiveProbeRunning:
//		err = a.runActiveProbe(&ap)
//	// TODO other state process
//	case activeprobev1alph1.ActiveProbeCompleted:
//	case activeprobev1alph1.ActiveProbeFailed:
//	default:
//	}
//
//	return err
//}
//
//func (a *ActiveprobeController) AddActiveProbe(new interface{}) {
//	obj := new.(*activeprobev1alph1.ActiveProbe)
//	a.syncQueue.Add(obj.GetName())
//}
//
//func (a *ActiveprobeController) UpdateActiveProbe(new, old interface{}) {
//	obj := new.(*activeprobev1alph1.ActiveProbe)
//	a.syncQueue.Add(obj.GetName())
//}
//
//func (a *ActiveprobeController) DeleteActiveProbe(old interface{}) {
//	obj := old.(*activeprobev1alph1.ActiveProbe)
//	a.syncQueue.Add(obj.GetName())
//}

// 1). received active probe request from work queue;
// 2). parsing it;
// 3). generate activeprobe flow rules and activeprobe packet
// 4). inject probe packet
// 5). (optional) register packet in handler in controller

func (a *ActiveprobeController) SetupWithManager(mgr ctrl.Manager) error {

	if mgr == nil {
		return fmt.Errorf("can't setup with nil manager")
	}

	c, err := controller.New("activeprobe_controller", mgr, controller.Options{
		MaxConcurrentReconciles: constants.DefaultMaxConcurrentReconciles,
		Reconciler:              reconcile.Func(a.ReconcileActiveProbe),
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &activeprobev1alph1.ActiveProbe{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	err = mgr.Add(manager.RunnableFunc(func(stopChan <-chan struct{}) error {
		a.RegisterPacketInHandler(stopChan)
		return nil
	}))
	if err != nil {
		return err
	}

	return nil
}

func (a *ActiveprobeController) RegisterPacketInHandler(stopChan <-chan struct{}) {
	a.DatapathManager.RegisterPacketInHandler(datapath.PacketInHandlerFuncs{
		PacketInHandlerFunc: func(packetIn *ofctrl.PacketIn) {
			if err := a.HandlePacketIn(packetIn); err != nil {
				klog.Errorf("Failed to parsing packet in: %v, error: %v", packetIn, err)
			}
		},
	})

	for {
		select {
		case <-stopChan:
			return
		}
	}
}

func (a *ActiveprobeController) HandlePacketIn(packetIn *ofctrl.PacketIn) error {
	// In contoller runtime frame work, it's not easy to register packetIn callback in activeprobe controller
	// but we need active probe controller process packetIn for telemetry result parsing.
	// FIXME if runnable callback register func is not work, we need another module to parsing telemetry result
	// and sync it to apiserver: update activeprobe status

	// Parsing packetIn generate activeProbe status

	//ap := activeprobev1alph1.ActiveProbe{}
	status := activeprobev1alph1.ActiveProbeStatus{}
	matchers := packetIn.GetMatches()
	println("matchers: ", matchers)
	if packetIn.Data.Ethertype == protocol.IPv4_MSG {
		ipPacket, ok := packetIn.Data.Data.(*protocol.IPv4)
		if !ok {
			return errors.New("invalid IPv4 packet")
		}
		tag := ipPacket.DSCP
		println("tag: ", tag)
		status.Tag = tag
	}

	return nil
}

func (a *ActiveprobeController) ReconcileActiveProbe(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	klog.V(2).Infof("ActiveprobeController received activeprobe %s reconcile", req.NamespacedName)

	ap := activeprobev1alph1.ActiveProbe{}
	if err := a.K8sClient.Get(ctx, req.NamespacedName, &ap); err != nil {
		klog.Errorf("unable to fetch activeprobe %v: %v", req.Name, err.Error())
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	return a.processActiveProbeUpdate(&ap)
}

func (a *ActiveprobeController) processActiveProbeUpdate(ap *activeprobev1alph1.ActiveProbe) (ctrl.Result, error) {
	// sync ap until timeout
	a.runActiveProbe(ap)
	return ctrl.Result{}, nil
}

func (a *ActiveprobeController) runActiveProbe(ap *activeprobev1alph1.ActiveProbe) error {
	var err error
	err = a.InstallActiveProbeRuleFlow()
	err = a.SendActiveProbePacket(ap)
	return err
}



func (a *ActiveprobeController) GenerateProbePacket(ap *activeprobev1alph1.ActiveProbe) (*datapath.Packet, error) {
	var packet *datapath.Packet
	//packet = a.ParseActiveProbeSpec(ap)
	//TO BE ADDED
	//packet.SrcMac =
	//packet.DstMac =
	//packet.SrcPort =
	//packet.DstPort =
	//packet.ICMPType =
	//packet.ICMPCode =
	srcMac, _ := net.ParseMAC("00:aa:aa:aa:aa:aa")
	dstMac, _ := net.ParseMAC("00:aa:aa:aa:aa:ab")
	srcIP := net.ParseIP("10.0.1.11")
	dstIP := net.ParseIP("10.0.1.12")

	packet = &datapath.Packet{
		SrcMac:     srcMac,
		DstMac:     dstMac,
		SrcIP:      srcIP,
		DstIP:      dstIP,
		IPProtocol: uint8(6),
		IPLength:   uint16(5),
		IPFlags:    uint16(0),
		TTL:        uint8(60),
		SrcPort:    uint16(8080),
		DstPort:    uint16(80),
		TCPFlags:   uint8(2),
	}

	return packet, nil
}

func (a *ActiveprobeController) SendActiveProbePacket(ap *activeprobev1alph1.ActiveProbe) error {
	// Send activeprobe packet from the bridge which contains with src endpoint in probe spec
	// 1. ovsbr Name; 2. agent id
	//var ovsbrName string
	//var tag uint8
	var packet datapath.Packet
	//var inPort, outPort uint32
	var err error

	srcMac, _ := net.ParseMAC("00:aa:aa:aa:aa:aa")
	dstMac, _ := net.ParseMAC("00:aa:aa:aa:aa:ab")
	srcIP := net.ParseIP("10.0.1.11")
	dstIP := net.ParseIP("10.0.1.12")

	packet = datapath.Packet{
		SrcMac:     srcMac,
		DstMac:     dstMac,
		SrcIP:      srcIP,
		DstIP:      dstIP,
		IPProtocol: uint8(6),
		IPLength:   uint16(5),
		IPFlags:    uint16(0),
		TTL:        uint8(60),
		SrcPort:    uint16(8080),
		DstPort:    uint16(80),
		TCPFlags:   uint8(2),
	}

	err = a.DatapathManager.SendActiveProbePacket("ovsbr1", packet, 16, 10, nil)

	return err
}

func (a *ActiveprobeController) InstallActiveProbeRuleFlow() error {
	//var ovsbrName string
	//var tag uint8
	var err error

	err = a.DatapathManager.InstallActiveProbeFlows("ovsbr1", 4)
	return err
}
