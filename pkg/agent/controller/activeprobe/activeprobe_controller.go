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
	"net"
	"sync"

	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/ofnet/ofctrl"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/everoute/everoute/pkg/agent/datapath"
	activeprobev1alph1 "github.com/everoute/everoute/pkg/apis/activeprobe/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/utils"
)

type activeProbeState struct {
	name string
	tag  uint8
}

type ActiveprobeController struct {
	// K8sClient used to create/read/update activeprobe
	K8sClient client.Client
	Scheme    *runtime.Scheme

	DatapathManager         *datapath.DpManager
	RunningActiveprobeMutex sync.Mutex
	RunningActiveprobe      map[uint8]*activeProbeState // tag->activeProbeState if ap.Status.State is Running
}

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

	a.RunningActiveprobe = make(map[uint8]*activeProbeState)

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
	var err error
	klog.V(2).Infof("ActiveprobeController received activeprobe %s reconcile", req.NamespacedName)

	ap := activeprobev1alph1.ActiveProbe{}
	if err = a.K8sClient.Get(ctx, req.NamespacedName, &ap); err != nil {
		klog.Errorf("unable to fetch activeprobe %v: %v", req.Name, err.Error())
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	curAgentName := utils.CurrentAgentName()
	if curAgentName != ap.Spec.Source.AgentName && curAgentName != ap.Spec.Destination.AgentName {
		return ctrl.Result{}, err
	}

	return a.processActiveProbeUpdate(&ap)
}

func (a *ActiveprobeController) processActiveProbeUpdate(ap *activeprobev1alph1.ActiveProbe) (ctrl.Result, error) {
	var err error
	switch ap.Status.State {
	case activeprobev1alph1.ActiveProbeRunning:
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
		a.cleanupActiveProbe(ap)
	}
	return ctrl.Result{}, err
}

func (a *ActiveprobeController) runActiveProbe(ap *activeprobev1alph1.ActiveProbe) error {
	var err error
	var ovsbrName string
	tag := ap.Status.Tag
	ipDa := net.ParseIP(ap.Spec.Destination.IP)

	curAgentName := utils.CurrentAgentName()
	if curAgentName == ap.Spec.Source.AgentName {
		ovsbrName = ap.Spec.Source.BridgeName
		err = a.InstallActiveProbeRuleFlow(ovsbrName, tag, &ipDa)
		if err != nil {
			return err
		}
		err = a.SendActiveProbePacket(ap)
		if err != nil {
			return err
		}
	} else if curAgentName == ap.Spec.Destination.AgentName {
		ovsbrName = ap.Spec.Destination.BridgeName
		err = a.InstallActiveProbeRuleFlow(ovsbrName, tag, &ipDa)
		if err != nil {
			return err
		}
	}
	return err
}

func (a *ActiveprobeController) ParseActiveProbeSpec(ap *activeprobev1alph1.ActiveProbe) *datapath.Packet {
	var packet *datapath.Packet

	srcMac, _ := net.ParseMAC(ap.Spec.Source.MAC)
	dstMac, _ := net.ParseMAC(ap.Spec.Destination.MAC)

	packet = &datapath.Packet{
		SrcIP:      net.ParseIP(ap.Spec.Source.IP),
		DstIP:      net.ParseIP(ap.Spec.Destination.IP),
		SrcMac:     srcMac,
		DstMac:     dstMac,
		IPProtocol: uint8(ap.Spec.Packet.IPHeader.Protocol),
		IPLength:   ap.Spec.Packet.Length,
		IPFlags:    uint16(ap.Spec.Packet.IPHeader.Flags),
		TTL:        uint8(ap.Spec.Packet.IPHeader.TTL),
	}

	switch packet.IPProtocol {
	case protocol.Type_ICMP:
		packet.ICMPEchoID = uint16(ap.Spec.Packet.TransportHeader.ICMP.ID)
		packet.ICMPEchoSeq = uint16(ap.Spec.Packet.TransportHeader.ICMP.Sequence)
	case protocol.Type_TCP:
		packet.SrcPort = uint16(ap.Spec.Packet.TransportHeader.TCP.SrcPort)
		packet.DstPort = uint16(ap.Spec.Packet.TransportHeader.TCP.DstPort)
		packet.TCPFlags = uint8(ap.Spec.Packet.TransportHeader.TCP.Flags)
	case protocol.Type_UDP:
		packet.SrcPort = uint16(ap.Spec.Packet.TransportHeader.UDP.SrcPort)
		packet.DstPort = uint16(ap.Spec.Packet.TransportHeader.UDP.DstPort)
	}

	return packet
}

func (a *ActiveprobeController) SendActiveProbePacket(ap *activeprobev1alph1.ActiveProbe) error {
	var err error
	ovsbrName := ap.Spec.Source.BridgeName
	inport := uint32(ap.Spec.Source.Ofport)
	tag := ap.Status.Tag
	packet := a.ParseActiveProbeSpec(ap)
	sendTimes := ap.Spec.ProbeTimes

	for i := 0; i < int(sendTimes); i++ {
		err = a.DatapathManager.SendActiveProbePacket(ovsbrName, *packet, tag, inport, nil)
	}

	return err
}

func (a *ActiveprobeController) InstallActiveProbeRuleFlow(ovsbrName string, tag uint8, ipDa *net.IP) error {
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

func (a *ActiveprobeController) deleteActiveProbeByName(apName string) *activeProbeState {
	a.RunningActiveprobeMutex.Lock()
	defer a.RunningActiveprobeMutex.Unlock()
	for tag, apState := range a.RunningActiveprobe {
		if apState.name == apName {
			delete(a.RunningActiveprobe, tag)
			return apState
		}
	}
	return nil
}

func (a *ActiveprobeController) cleanupActiveProbe(ap *activeprobev1alph1.ActiveProbe) {
	var ovsbrName string

	curAgentName := utils.CurrentAgentName()
	if curAgentName == ap.Spec.Source.AgentName {
		ovsbrName = ap.Spec.Source.BridgeName
	} else if curAgentName == ap.Spec.Destination.AgentName {
		ovsbrName = ap.Spec.Destination.BridgeName
	}

	apState := a.deleteActiveProbeByName(ap.Name)

	if apState != nil {
		err := a.DatapathManager.UninstallActiveProbeFlows(ovsbrName, apState.tag)
		if err != nil {
			klog.Errorf("Failed to uninstall Traceflow %s flows: %v", apState.name, err)
		}
	}
}
