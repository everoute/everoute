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
	"time"

	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/ofnet/ofctrl"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
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

type Controller struct {
	// K8sClient used to create/read/update activeprobe
	K8sClient client.Client
	Scheme    *runtime.Scheme

	DatapathManager         *datapath.DpManager
	RunningActiveprobeMutex sync.Mutex
	RunningActiveprobe      map[uint8]*activeProbeState // tag->activeProbeState if ap.Status.State is Running
}

func (a *Controller) SetupWithManager(mgr ctrl.Manager) error {
	klog.Infof("start func SetupWithManager")
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

func (a *Controller) RegisterPacketInHandler(stopChan <-chan struct{}) {
	a.DatapathManager.RegisterPacketInHandler(datapath.PacketInHandlerFuncs{
		PacketInHandlerFunc: func(packetIn *ofctrl.PacketIn) {
			if err := a.HandlePacketIn(packetIn); err != nil {
				klog.Errorf("Failed to parsing packet in: %v, error: %v", packetIn, err)
			}
		},
	})

	for range stopChan {
		return
	}
}

func (a *Controller) ReconcileActiveProbe(req ctrl.Request) (ctrl.Result, error) {
	klog.Infof("start func ReconcileActiveProbe")
	ctx := context.Background()
	var err error
	klog.V(2).Infof("Controller received activeprobe %s reconcile", req.NamespacedName)

	ap := activeprobev1alph1.ActiveProbe{}
	if err = a.K8sClient.Get(ctx, req.NamespacedName, &ap); err != nil {
		klog.Errorf("unable to fetch activeprobe %v: %v", req.Name, err.Error())
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	klog.Infof("succeed fetch activeprobe %v", req.Name)

	curAgentName := utils.CurrentAgentName()
	if curAgentName != ap.Spec.Source.AgentName && curAgentName != ap.Spec.Destination.AgentName {
		klog.Infof("curAgent: %v unequal activeprobe srcAgent: %v or dstAgent: %v", curAgentName, ap.Spec.Source.AgentName, ap.Spec.Destination.AgentName)
		return ctrl.Result{}, err
	}

	return a.processActiveProbeUpdate(&ap)
}

func (a *Controller) processActiveProbeUpdate(ap *activeprobev1alph1.ActiveProbe) (ctrl.Result, error) {
	klog.Infof("start func processActiveProbeUpdate")
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
	case activeprobev1alph1.ActiveProbeCompleted, activeprobev1alph1.ActiveProbeFailed:
		a.cleanupActiveProbe(ap)
	default:
	}
	return ctrl.Result{}, err
}

func (a *Controller) runActiveProbe(ap *activeprobev1alph1.ActiveProbe) error {
	klog.Infof("start func runActiveProbe")
	var err error
	var ovsbrName string
	tag := ap.Status.Tag
	a.RunningActiveprobeMutex.Lock()
	apState := &activeProbeState{
		tag:  tag,
		name: ap.Name,
	}
	a.RunningActiveprobe[tag] = apState
	defer a.RunningActiveprobeMutex.Unlock()
	ipDa := net.ParseIP(ap.Spec.Destination.IP)

	curAgentName := utils.CurrentAgentName()
	if curAgentName == ap.Spec.Source.AgentName {
		ovsbrName = ap.Spec.Source.BridgeName
		err = a.InstallActiveProbeRuleFlow(ovsbrName, tag, &ipDa)
		if err != nil {
			klog.Errorf("src agent install activeprobe flows failed, error: %v", err)
		}
		klog.Info("src agent install activeprobe flows succeed")
		err = a.SendActiveProbePacket(ap)
		if err != nil {
			klog.Errorf("src agent send activeprobe packet failed, error: %v", err)
		}
		klog.Errorf("src agent send activeprobe packet succeed")
	}
	if curAgentName == ap.Spec.Destination.AgentName {
		ovsbrName = ap.Spec.Destination.BridgeName
		err = a.InstallActiveProbeRuleFlow(ovsbrName, tag, &ipDa)
		if err != nil {
			klog.Errorf("dst agent install activeprobe flows failed, error: %v", err)
		}
		klog.Info("dst agent install activeprobe flows succeed")
	}

	return err
}

func (a *Controller) ParseActiveProbeSpec(ap *activeprobev1alph1.ActiveProbe) *datapath.Packet {
	klog.Infof("start ParseActiveProbeSpec")
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

func (a *Controller) SendActiveProbePacket(ap *activeprobev1alph1.ActiveProbe) error {
	klog.Infof("start func SendActiveProbePacket")
	var err error
	ovsbrName := ap.Spec.Source.BridgeName
	inport := uint32(ap.Spec.Source.Ofport)
	tag := ap.Status.Tag
	packet := a.ParseActiveProbeSpec(ap)
	sendTimes := ap.Spec.ProbeTimes

	for i := 0; i < int(sendTimes); i++ {
		packet.IPId = uint16(i)
		err = a.DatapathManager.SendActiveProbePacket(ovsbrName, *packet, tag, inport, nil)
		time.Sleep(time.Millisecond * 10)
	}

	klog.Infof("%d packets has been send finished from srcIp: %v", sendTimes, ap.Spec.Source.IP)

	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		namespacedName := types.NamespacedName{
			Namespace: "",
			Name:      ap.Name,
		}
		if err := a.K8sClient.Get(context.TODO(), namespacedName, ap); err != nil {
			klog.Warningf("Update ActiveProbe failed: %+v", err)
		}

		update := ap.DeepCopy()
		update.Status.State = activeprobev1alph1.ActiveProbeSendFinshed
		err = a.K8sClient.Status().Update(context.TODO(), update, &client.UpdateOptions{})
		if err != nil {
			klog.Errorf("update activeprobe failed reason: %v", err)
			return err
		}
		klog.Infof("sendActiveProbePacket over, state change: running -> sendFinished")
		return nil
	})
	if err != nil {
		klog.Errorf("retry Update ActiveProbe failed: %+v", err)
	}

	return err
}

func (a *Controller) InstallActiveProbeRuleFlow(ovsbrName string, tag uint8, ipDa *net.IP) error {
	err := a.DatapathManager.InstallActiveProbeFlows(ovsbrName, tag, ipDa)
	return err
}

func (a *Controller) updateActiveProbeStatus(ap *activeprobev1alph1.ActiveProbe, apResult *activeprobev1alph1.AgentProbeResult, reason string) error {
	klog.Infof("start func updateActiveProbeStatus")
	update := ap.DeepCopy()
	if reason != "" {
		update.Status.Reason = reason
	}

	if update.Status.Results == nil {
		update.Status.Results = make(map[string]activeprobev1alph1.AgenProbeRecord)
	}
	curAgentName := utils.CurrentAgentName()
	update.Status.Results[curAgentName] = append(update.Status.Results[curAgentName], apResult)

	err := a.K8sClient.Status().Update(context.TODO(), update, &client.UpdateOptions{})
	if err != nil {
		klog.Errorf("update activeprobe failed reason: %v", err)
	}
	return err
}

func (a *Controller) deleteActiveProbeByName(apName string) *activeProbeState {
	klog.Infof("start func delete ActiveProbeByName")
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

func (a *Controller) cleanupActiveProbe(ap *activeprobev1alph1.ActiveProbe) {
	klog.Infof("start func cleanupActiveProbe")
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
			klog.Errorf("Failed to uninstall ActiveProbe %s flows: %v", apState.name, err)
		}
		klog.Infof("uninstall ActiveProbe %s flows succeed, tag: %d", apState.name, apState.tag)
	}
}
