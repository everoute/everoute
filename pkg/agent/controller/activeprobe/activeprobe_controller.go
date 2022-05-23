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
	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/ofnet/ofctrl"
	"github.com/everoute/everoute/pkg/agent/datapath"
	activeprobev1alph1 "github.com/everoute/everoute/pkg/apis/activeprobe/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog"
	"net"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
	"sync"
)

const (
	// Min and max data plane tag for traceflow. minTagNum is 7 (0b000111), maxTagNum is 59 (0b111011).
	// As per RFC2474, 16 different DSCP values are we reserved for Experimental or Local Use, which we use as the 16 possible data plane tag values.
	// tagStep is 4 (0b100) to keep last 2 bits at 0b11.
	tagStep   uint8 = 0b100
	minTagNum uint8 = 0b1*tagStep + 0b11
	maxTagNum uint8 = 0b1110*tagStep + 0b11
)

type ActiveprobeController struct {
	// K8sClient used to create/read/update activeprobe
	K8sClient client.Client
	Scheme    *runtime.Scheme

	DatapathManager         *datapath.DpManager
	RunningActiveprobeMutex sync.Mutex
	RunningActiveprobe      map[uint8]string //tag->activeProbeName if ap.Status.State is Running
}

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
	var err error
	switch ap.Status.State {
	case "", activeprobev1alph1.ActiveProbeRunning:
		start := false
		a.RunningActiveprobeMutex.Lock()
		if _, ok := a.RunningActiveprobe[ap.Status.Tag]; !ok {
			start = true
		}
		a.RunningActiveprobeMutex.Unlock()
		if start {
			err = a.runActiveProbe(ap)
		}
	default:
		a.cleanupActiveProbe(ap.Name)
	}
	return ctrl.Result{}, err
}

func (a *ActiveprobeController) runActiveProbe(ap *activeprobev1alph1.ActiveProbe) error {
	ovsbrName := "ovsbr1"
	tag, err := a.allocateTag(ap.Name)
	ipDa := net.ParseIP(ap.Spec.Destination.IP)
	err = a.InstallActiveProbeRuleFlow(ovsbrName, tag, &ipDa)
	err = a.SendActiveProbePacket(ap, tag)
	return err
}

func (a *ActiveprobeController) ParseActiveProbeSpec(ap *activeprobev1alph1.ActiveProbe) *datapath.Packet {
	// Generate ip src && dst from endpoint name(or uuid), should store interface cache that contains ip
	var packet *datapath.Packet

	srcMac, _ := net.ParseMAC("00:aa:aa:aa:aa:aa")
	dstMac, _ := net.ParseMAC("00:aa:aa:aa:aa:ab")
	//srcEndpointStr := ap.Spec.Source.Endpoint
	//dstEndpointStr := ap.Spec.Destination.Endpoint
	//srcNamespaceStr := ap.Spec.Source.NameSpace
	//dstNamespaceStr := ap.Spec.Destination.NameSpace
	//dstServiceStr := ap.Spec.Destination.Service

	packet = &datapath.Packet{
		SrcIP:      net.ParseIP(ap.Spec.Source.IP),
		DstIP:      net.ParseIP(ap.Spec.Destination.IP),
		SrcMac:     srcMac,
		DstMac:     dstMac,
		IPProtocol: uint8(ap.Spec.Packet.IPHeader.Protocol),
		IPLength:   ap.Spec.Packet.Length,
		IPFlags:    uint16(ap.Spec.Packet.IPHeader.Flags),
		TTL:        uint8(ap.Spec.Packet.IPHeader.TTL),
		SrcPort:    8080,
		DstPort:    80,
	}

	if packet.IPProtocol == protocol.Type_ICMP {
		packet.ICMPEchoID = uint16(ap.Spec.Packet.TransportHeader.ICMP.ID)
		packet.ICMPEchoSeq = uint16(ap.Spec.Packet.TransportHeader.ICMP.Sequence)
	} else if packet.IPProtocol == protocol.Type_TCP {
		packet.SrcPort = uint16(ap.Spec.Packet.TransportHeader.TCP.SrcPort)
		packet.DstPort = uint16(ap.Spec.Packet.TransportHeader.TCP.DstPort)
		packet.TCPFlags = uint8(ap.Spec.Packet.TransportHeader.TCP.Flags)
	} else if packet.IPProtocol == protocol.Type_UDP {
		packet.SrcPort = uint16(ap.Spec.Packet.TransportHeader.UDP.SrcPort)
		packet.DstPort = uint16(ap.Spec.Packet.TransportHeader.UDP.DstPort)
	}

	return packet
}

func (a *ActiveprobeController) SendActiveProbePacket(ap *activeprobev1alph1.ActiveProbe, tag uint8) error {
	// Send activeprobe packet from the bridge which contains with src endpoint in probe spec
	// 1. ovsbr Name; 2. agent id
	var err error

	packet := a.ParseActiveProbeSpec(ap)
	sendTimes := ap.Spec.ProbeTimes

	for i := 0; i < int(sendTimes); i++ {
		err = a.DatapathManager.SendActiveProbePacket("ovsbr1", *packet, tag, 1, nil)
	}

	return err
}

func (a *ActiveprobeController) InstallActiveProbeRuleFlow(ovsbrName string, tag uint8, ipDa *net.IP) error {
	//var ovsbrName string
	//var tag uint8
	var err error

	err = a.DatapathManager.InstallActiveProbeFlows(ovsbrName, tag, ipDa)
	return err
}

func (a *ActiveprobeController) updateActiveProbeStatus(ap *activeprobev1alph1.ActiveProbe, state activeprobev1alph1.ActiveProbeState, apResult *activeprobev1alph1.AgentProbeResult, reason string, tag uint8) error {
	update := ap.DeepCopy()
	update.Status.State = state
	update.Status.Tag = tag
	if reason != "" {
		update.Status.Reason = reason
	}
	update.Status.Results = append(update.Status.Results, *apResult)
	err := a.K8sClient.Status().Update(context.TODO(), update, &client.UpdateOptions{})
	klog.Infof("Updated ActiveProbe %s: %+v", ap.Name, update.Status)
	fmt.Printf("Updated ActiveProbe %s: %+v\n", ap.Name, update.Status)
	return err
}

func (a *ActiveprobeController) allocateTag(name string) (uint8, error) {
	a.RunningActiveprobeMutex.Lock()
	defer a.RunningActiveprobeMutex.Unlock()

	for _, n := range a.RunningActiveprobe {
		if n == name {
			//The ActiveProbe request has been processed already.
			return 0, nil
		}
	}
	for i := minTagNum; i <= maxTagNum; i += tagStep {
		if _, ok := a.RunningActiveprobe[i]; !ok {
			a.RunningActiveprobe[i] = name
			return i, nil
		}
	}
	return 0, fmt.Errorf("number of on-going ActiveProve operations already reached the upper limit: %d", maxTagNum)
}

func (a *ActiveprobeController) deleteActiveProbeByName(apName string) (*string, uint8) {
	a.RunningActiveprobeMutex.Lock()
	defer a.RunningActiveprobeMutex.Unlock()
	for tag, name := range a.RunningActiveprobe {
		if name == apName {
			delete(a.RunningActiveprobe, tag)
			return &name, tag
		}
	}
	return nil, 0
}

func (a *ActiveprobeController) cleanupActiveProbe(apName string) {
	activeProbeName, tag := a.deleteActiveProbeByName(apName)
	ovsbrName := "ovsbr1"
	if activeProbeName != nil {
		err := a.DatapathManager.UninstallActiveProbeFlows(ovsbrName, tag)
		if err != nil {
			klog.Errorf("Failed to uninstall Traceflow %s flows: %v", activeProbeName, err)
		}
	}
}
