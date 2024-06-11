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

package datapath

import (
	"fmt"
	"net"

	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ofctrl"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	proxycache "github.com/everoute/everoute/pkg/agent/controller/proxy/cache"
	"github.com/everoute/everoute/pkg/agent/datapath/cache"
	everoutesvc "github.com/everoute/everoute/pkg/apis/service/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	ertype "github.com/everoute/everoute/pkg/types"
)

var (
	NatBrInputTable                uint8 = 0
	NatBrInPortTable               uint8 = 4
	NatBrCTZoneTable               uint8 = 5
	NatBrCTStateTable              uint8 = 10
	NatBrSessionAffinityTable      uint8 = 30
	NatBrServiceLBTable            uint8 = 35
	NatBrSessionAffinityLearnTable uint8 = 40
	NatBrDnatTable                 uint8 = 50
	NatBrL3ForwardTable            uint8 = 90
	NatBrOutputTable               uint8 = 100
)

var (
	CTZoneReg                       = "nxm_nx_reg0"
	CTZoneRange *openflow13.NXRange = openflow13.NewNXRange(0, 15)

	ChooseBackendFlagReg   string              = "nxm_nx_reg0"
	ChooseBackendFlagRange *openflow13.NXRange = openflow13.NewNXRange(16, 16)
	ChooseBackendFlagStart int                 = 16
	NeedChoose             uint8               = 0
	NoNeedChoose           uint8               = 1

	BackendIPReg         string              = "nxm_nx_reg1"
	BackendIPRegNumber   int                 = 1
	BackendIPRange       *openflow13.NXRange = openflow13.NewNXRange(0, 31)
	BackendPortReg       string              = "nxm_nx_reg2"
	BackendPortRegNumber int                 = 2
	BackendPortRange     *openflow13.NXRange = openflow13.NewNXRange(0, 15)

	ChooseBackendFlagLength uint16 = 1
)

const (
	SelectGroupWeight = 100
)

type NatBridge struct {
	BaseBridge

	inputTable                *ofctrl.Table
	inPortTable               *ofctrl.Table
	ctZoneTable               *ofctrl.Table
	ctStateTable              *ofctrl.Table
	sessionAffinityTable      *ofctrl.Table
	serviceLBTable            *ofctrl.Table
	sessionAffinityLearnTable *ofctrl.Table
	dnatTable                 *ofctrl.Table
	l3ForwardTable            *ofctrl.Table
	outputTable               *ofctrl.Table

	svcIndexCache *cache.SvcIndex // service flow and group database
	// l3FlowMap the key is interface uuid, the value is l3ForwardTable flow
	l3FlowMap map[string]*ofctrl.Flow

	kubeProxyReplace bool
}

func NewNatBridge(brName string, datapathManager *DpManager) *NatBridge {
	natBr := new(NatBridge)
	natBr.name = fmt.Sprintf("%s-nat", brName)
	natBr.ovsBrName = brName
	natBr.datapathManager = datapathManager

	return natBr
}

func (n *NatBridge) BridgeInit() {}

func (n *NatBridge) BridgeInitCNI() {
	if !n.datapathManager.IsEnableProxy() {
		return
	}
	n.svcIndexCache = cache.NewSvcIndex()
	n.l3FlowMap = make(map[string]*ofctrl.Flow)
	n.kubeProxyReplace = n.datapathManager.Config.CNIConfig.KubeProxyReplace

	sw := n.OfSwitch

	_ = ofctrl.DeleteGroup(sw, openflow13.OFPG_ALL)

	n.inputTable = sw.DefaultTable()
	n.inPortTable, _ = sw.NewTable(NatBrInPortTable)
	n.ctZoneTable, _ = sw.NewTable(NatBrCTZoneTable)
	n.ctStateTable, _ = sw.NewTable(NatBrCTStateTable)
	n.sessionAffinityTable, _ = sw.NewTable(NatBrSessionAffinityTable)
	n.serviceLBTable, _ = sw.NewTable(NatBrServiceLBTable)
	n.sessionAffinityLearnTable, _ = sw.NewTable(NatBrSessionAffinityLearnTable)
	n.dnatTable, _ = sw.NewTable(NatBrDnatTable)
	n.l3ForwardTable, _ = sw.NewTable(NatBrL3ForwardTable)
	n.outputTable, _ = sw.NewTable(NatBrOutputTable)

	if err := n.initInputTable(); err != nil {
		log.Fatalf("Init Input table %d of nat bridge failed: %s", NatBrInputTable, err)
	}
	if err := n.initInPortTable(); err != nil {
		log.Fatalf("Init InPort table %d of nat bridge failed: %s", NatBrInPortTable, err)
	}
	if err := n.initCTZoneTable(); err != nil {
		log.Fatalf("Init CTZone table %d of nat bridge failed: %s", NatBrCTZoneTable, err)
	}
	if err := n.initCTStateTable(); err != nil {
		log.Fatalf("Init CTState table %d of nat bridge failed: %s", NatBrCTStateTable, err)
	}
	if err := n.initSessionAffinityTable(); err != nil {
		log.Fatalf("Init SessionAffinity table %d of nat bridge failed: %s", NatBrSessionAffinityTable, err)
	}
	if err := n.initServiceLBTable(); err != nil {
		log.Fatalf("Init ServiceLB table %d of nat bridge failed: %s", NatBrServiceLBTable, err)
	}
	if err := n.initSessionAffinityLearnTable(); err != nil {
		log.Fatalf("Init SessionAffinityLearn table %d of nat bridge failed: %s", NatBrSessionAffinityLearnTable, err)
	}
	if err := n.initL3ForwardTable(); err != nil {
		log.Fatalf("Init L3Forward table %d of nat bridge failed: %s", NatBrL3ForwardTable, err)
	}
	if err := n.initOutputTable(); err != nil {
		log.Fatalf("Init Output table %d of nat bridge failed: %s", NatBrOutputTable, err)
	}
}

func (n *NatBridge) BridgeReset() {}

func (n *NatBridge) AddLocalEndpoint(endpoint *Endpoint) error {
	if endpoint == nil {
		return nil
	}
	if n.l3FlowMap[endpoint.InterfaceUUID] != nil {
		log.Infof("The endpoint %+v related flow has been installed, skip add again", endpoint)
		return nil
	}

	macAddr, err := net.ParseMAC(endpoint.MacAddrStr)
	if err != nil {
		log.Errorf("The endpoint %+v has invalid mac addr, err: %s", endpoint, err)
		return err
	}

	if endpoint.IPAddr == nil {
		log.Infof("the endpoint %+v IPAddr is empty, skip add flow to l3 forward of nat bridge", endpoint)
		return nil
	}

	if endpoint.IPAddr.To4() == nil {
		log.Errorf("Failed to add local endpoint flow to l3 forward of nat bridge: the endpoint %+v IPAddr is not valid ipv4", endpoint)
		return fmt.Errorf("the endpoint %+v IPAddr is not valid ipv4", endpoint)
	}

	flow, err := n.l3ForwardTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
		IpDa:      &endpoint.IPAddr,
	})
	if err != nil {
		log.Errorf("Failed to new a flow in l3Forward table %d for endpoint %+v, err: %s", NatBrL3ForwardTable, endpoint, err)
		return err
	}

	if err := flow.SetMacDa(macAddr); err != nil {
		log.Errorf("Failed to add setMacDa action to flow %+v, endpoint %+v, err: %s", flow, endpoint, err)
		return err
	}

	if err := flow.Resubmit(nil, &NatBrOutputTable); err != nil {
		log.Errorf("Failed to add resubmit action to flow  %+v, endpoint: %+v, err: %s", flow, endpoint, err)
		return err
	}

	if err := flow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install flow %+v, endpoint: %+v, err: %s", flow, endpoint, err)
		return err
	}
	n.l3FlowMap[endpoint.InterfaceUUID] = flow
	log.Infof("Nat bridge success add flow %+v for local endpoint interfaceUUID %s", flow, endpoint.InterfaceUUID)
	return nil
}

func (n *NatBridge) RemoveLocalEndpoint(endpoint *Endpoint) error {
	if endpoint == nil {
		return nil
	}

	if flow, ok := n.l3FlowMap[endpoint.InterfaceUUID]; ok && flow != nil {
		if err := flow.Delete(); err != nil {
			log.Errorf("Delete endpoint correspond l3 forward flow failed, endpoint: %+v, err: %s", endpoint, err)
			return err
		}
	}
	delete(n.l3FlowMap, endpoint.InterfaceUUID)
	log.Infof("Nat bridge success delete l3 forward flow for local endpoint interfaceUUID %s", endpoint.InterfaceUUID)
	return nil
}

func (n *NatBridge) GetSvcIndexCache() *cache.SvcIndex {
	return n.svcIndexCache
}

func (n *NatBridge) AddLBFlow(svcLB *proxycache.SvcLB) error {
	svcID := svcLB.SvcID
	var ipDa net.IP
	if svcLB.IP != "" {
		ipDa = net.ParseIP(svcLB.IP)
		if ipDa == nil {
			log.Errorf("Invalid ip %s for service %s", svcLB.IP, svcID)
			return fmt.Errorf("invalid lb ip: %s", svcLB.IP)
		}
	}

	svcOvsCache := n.svcIndexCache.GetSvcOvsInfoAndInitIfEmpty(svcID)
	if svcOvsCache.GetLBFlow(svcLB.IP, svcLB.Port.Name) != nil {
		log.Infof("The lb flow has been installed for service lb info %v, skip create it", *svcLB)
		return nil
	}

	gp, err := svcOvsCache.GetGroupAndCreateIfEmpty(svcLB.Port.Name, svcLB.TrafficPolicy, n.createEmptyGroup)
	if err != nil {
		log.Errorf("Failed to create a empty group for service %s, lbip: %s, portname: %s, traffic policy: %s, err: %s", svcID,
			svcLB.IP, svcLB.Port.Name, svcLB.TrafficPolicy, err)
		return err
	}
	gpID := gp.GroupID

	var lbFlow *ofctrl.Flow
	if ipDa != nil {
		lbFlow, err = n.newLBFlow(&ipDa, svcLB.Port.Protocol, svcLB.Port.Port)
		if err != nil {
			log.Errorf("Failed to new a lb flow for service %s, ip: %s, portname: %s, traffic policy: %s, err: %s", svcID, svcLB.IP, svcLB.Port.Name, svcLB.TrafficPolicy, err)
			return err
		}
	} else {
		lbFlow, err = n.newLBFlowForNodePort(svcLB.Port.Protocol, svcLB.Port.NodePort)
		if err != nil {
			log.Errorf("Failed to new a lb flow for service %s nodeport, portname: %s, traffic policy: %s, err: %s", svcID, svcLB.Port.Name, svcLB.TrafficPolicy, err)
			return err
		}
	}

	if svcLB.TrafficPolicy == ertype.TrafficPolicyLocal && svcLB.IsExternal() {
		ofRange := openflow13.NewNXRange(constants.SvcLocalPktMarkBit, constants.SvcLocalPktMarkBit)
		if err := lbFlow.LoadField("nxm_nx_pkt_mark", constants.PktMarkSetValue, ofRange); err != nil {
			log.Errorf("Failed to setup set pkt mark for svc lb info %v with ExternalTrafficPolicy=Local flow load field action: %s", *svcLB, err)
			return err
		}
	}
	if err := lbFlow.SetGroup(gpID); err != nil {
		log.Errorf("Failed to set group action to lb flow: %+v, err: %s", lbFlow, err)
		return err
	}

	if err := lbFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install lb flow: %+v, err: %s", lbFlow, err)
		return err
	}

	svcOvsCache.SetLBFlow(svcLB.IP, svcLB.Port.Name, lbFlow)
	log.Infof("Dp success to add lb flow for svclb %v", *svcLB)
	return nil
}

func (n *NatBridge) DelLBFlow(svcLB *proxycache.SvcLB) error {
	svcID := svcLB.SvcID
	if n.svcIndexCache.GetSvcOvsInfo(svcID) == nil {
		log.Infof("Has no lb flow for svcID: %s", svcID)
		return nil
	}
	svcOvsCache := n.svcIndexCache.GetSvcOvsInfo(svcID)
	lbFlow := svcOvsCache.GetLBFlow(svcLB.IP, svcLB.Port.Name)
	if lbFlow == nil {
		return nil
	}
	if err := lbFlow.Delete(); err != nil {
		klog.Errorf("Failed to delete lb flow for svc lb info %v, err: %s", *svcLB, err)
		return err
	}
	svcOvsCache.SetLBFlow(svcLB.IP, svcLB.Port.Name, nil)
	n.svcIndexCache.TryCleanSvcOvsInfoCache(svcID)
	log.Infof("Dp success delete lbflow for svclb %v", *svcLB)
	return nil
}

func (n *NatBridge) AddSessionAffinityFlow(svcLB *proxycache.SvcLB) error {
	if svcLB.SessionAffinity == corev1.ServiceAffinityNone {
		return nil
	}
	if svcLB.SessionAffinityTimeout <= 0 {
		return fmt.Errorf("invalid sessionAffinityTimeout for service lb info %v", *svcLB)
	}
	svcID := svcLB.SvcID
	var ipDa net.IP
	if svcLB.IP != "" {
		ipDa = net.ParseIP(svcLB.IP)
		if ipDa == nil {
			log.Errorf("Invalid ip %s for service %s", svcLB.IP, svcID)
			return fmt.Errorf("invalid lb ip: %s", svcLB.IP)
		}
	}

	svcOvsCache := n.svcIndexCache.GetSvcOvsInfoAndInitIfEmpty(svcID)
	if svcOvsCache.GetSessionAffinityFlow(svcLB.IP, svcLB.Port.Name) != nil {
		log.Infof("The session affinity flow has been installed for service lb info %v, skip create it", *svcLB)
		return nil
	}

	var sessionFlow *ofctrl.Flow
	var err error
	sessionFlow, err = n.addSessionAffinityFlow(ipDa, svcLB)
	if err != nil {
		log.Errorf("Failed to add a session affinity flow for service lb info %v, err: %s", *svcLB, err)
		return err
	}

	svcOvsCache.SetSessionAffinityFlow(svcLB.IP, svcLB.Port.Name, sessionFlow)
	log.Infof("Dp success to add sessionAffinity flow for svclb %v", *svcLB)
	return nil
}

func (n *NatBridge) DelSessionAffinityFlow(svcLB *proxycache.SvcLB) error {
	svcID := svcLB.SvcID
	if n.svcIndexCache.GetSvcOvsInfo(svcID) == nil {
		log.Infof("Has no lb flow for svcID: %s", svcID)
		return nil
	}
	svcOvsCache := n.svcIndexCache.GetSvcOvsInfo(svcID)
	sAFlow := svcOvsCache.GetSessionAffinityFlow(svcLB.IP, svcLB.Port.Name)
	if sAFlow == nil {
		return nil
	}
	if err := sAFlow.Delete(); err != nil {
		log.Errorf("Failed to delete service session affinity flow for lb info %v, err: %s", *svcLB, err)
		return err
	}
	svcOvsCache.SetSessionAffinityFlow(svcLB.IP, svcLB.Port.Name, nil)
	n.svcIndexCache.TryCleanSvcOvsInfoCache(svcID)
	log.Infof("Dp success to delete sessionAffinity flow for svclb %v", *svcLB)
	return nil
}

func (n *NatBridge) UpdateLBGroup(svcID, portName string, backends []everoutesvc.Backend, tp ertype.TrafficPolicyType) error {
	svcOvsCache := n.svcIndexCache.GetSvcOvsInfoAndInitIfEmpty(svcID)
	var err error
	gp, err := svcOvsCache.GetGroupAndCreateIfEmpty(portName, tp, n.createEmptyGroup)
	if err != nil {
		log.Errorf("Failed to create a empty group for svc %s portname %s, err: %s", svcID, portName, err)
		return err
	}

	buckets := make([]*ofctrl.Bucket, 0, len(backends))
	for i := range backends {
		b, err := newBucketForLBGroup(backends[i].IP, backends[i].Port)
		if err != nil {
			log.Errorf("Failed to new a bucket for service %s with backend %+v, err: %s", svcID, backends[i], err)
			return nil
		}
		buckets = append(buckets, b)
	}
	gp.ResetBuckets(buckets)

	log.Infof("Dp success to update LB group for service %s port %s, backends: %+v", svcID, portName, backends)
	return nil
}

func (n *NatBridge) DelLBGroup(svcID, portName string) error {
	svcOvsCache := n.svcIndexCache.GetSvcOvsInfo(svcID)
	if svcOvsCache == nil {
		log.Infof("The Service %s has no related ovs group for port %s", svcID, portName)
		return nil
	}
	for _, tp := range []ertype.TrafficPolicyType{ertype.TrafficPolicyCluster, ertype.TrafficPolicyLocal} {
		svcOvsCache.DeleteGroupIfExist(portName, tp)
	}

	// when a group is deleted, the flow referenced it will be deleted automatically
	svcOvsCache.DeleteLBFlowsByPortName(portName)
	n.svcIndexCache.TryCleanSvcOvsInfoCache(svcID)
	log.Infof("Success delete service %s ovs group related port %s", svcID, portName)
	return nil
}

func (n *NatBridge) AddDnatFlow(ip string, protocol corev1.Protocol, port int32) error {
	ipByte := net.ParseIP(ip)
	if ipByte == nil {
		log.Errorf("Invalid dnat ip %s", ip)
		return fmt.Errorf("invalid dnat ip: %s", ip)
	}
	dnatKey := cache.GenDnatMapKey(ip, string(protocol), port)
	if f := n.svcIndexCache.GetDnatFlow(dnatKey); f != nil {
		log.Infof("The dnat flow has been exists, skip it. ip: %s, protocol: %s, port: %d, flow: %+v", ip, protocol, port, f)
		return nil
	}

	ipProtocol, err := k8sProtocolToOvsProtocol(protocol)
	if err != nil {
		log.Errorf("Transfer protocol failed: %s", err)
		return err
	}
	regs := []*ofctrl.NXRegister{
		{
			RegID: BackendIPRegNumber,
			Data:  ipv4ToUint32(ipByte),
			Range: BackendIPRange,
		}, {
			RegID: BackendPortRegNumber,
			Data:  uint32(port),
			Range: BackendPortRange,
		},
	}
	flow, err := n.dnatTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
		IpProto:   uint8(ipProtocol),
		Regs:      regs,
	})
	if err != nil {
		log.Errorf("Failed to new a dnat flow for ip %s protocol %s port %d, err: %s", ip, protocol, port, err)
		return err
	}

	natAct, _ := ofctrl.NewDNatAction(ofctrl.NewIPRange(ipByte), ofctrl.NewPortRange(uint16(port))).ToOfAction()
	ctAct, err := ofctrl.NewConntrackActionWithZoneField(true, false, &NatBrL3ForwardTable, CTZoneReg, CTZoneRange, natAct)
	if err != nil {
		log.Errorf("Failed to new a conntrack action for ip %s, protocol %s, port %d, err: %s", ip, protocol, port, err)
		return err
	}
	_ = flow.SetConntrack(ctAct)
	if err := flow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install dnat flow for ip %s protocol %s port %d, err: %s", ip, protocol, port, err)
		return err
	}

	n.svcIndexCache.SetDnatFlow(dnatKey, flow)
	log.Infof("Success add a dnat flow %+v for ip %s protocol: %s port: %d", flow, ip, protocol, port)
	return nil
}

func (n *NatBridge) DelDnatFlow(ip string, protocol corev1.Protocol, port int32) error {
	ipByte := net.ParseIP(ip)
	if ipByte == nil {
		log.Errorf("Invalid dnat ip %s", ip)
		return fmt.Errorf("invalid dnat ip: %s", ip)
	}

	dnatKey := cache.GenDnatMapKey(ip, string(protocol), port)
	flow := n.svcIndexCache.GetDnatFlow(dnatKey)
	if flow == nil {
		log.Infof("The dnat flow has been deleted, skip it. ip: %s, protocol: %s, port: %d", ip, protocol, port)
		return nil
	}

	if err := flow.Delete(); err != nil {
		log.Errorf("Delete dnat flow %+v for %s failed, err: %s", flow, dnatKey, err)
		return err
	}

	n.svcIndexCache.DeleteDnatFlow(dnatKey)
	log.Infof("Success delete dnat flow for %s", dnatKey)
	return nil
}

func (n *NatBridge) newLBFlowForNodePort(protocol corev1.Protocol, nodePort int32) (*ofctrl.Flow, error) {
	var pktMask uint32 = 1 << constants.ExternalSvcPktMarkBit
	if protocol == corev1.ProtocolTCP {
		newFlow, err := n.serviceLBTable.NewFlow(ofctrl.FlowMatch{
			Priority:       NORMAL_MATCH_FLOW_PRIORITY,
			Ethertype:      PROTOCOL_IP,
			IpProto:        PROTOCOL_TCP,
			TcpDstPort:     uint16(nodePort),
			TcpDstPortMask: PortMaskMatchFullBit,
			PktMark:        1 << constants.ExternalSvcPktMarkBit,
			PktMarkMask:    &pktMask,
		})
		return newFlow, err
	}

	if protocol == corev1.ProtocolUDP {
		newFlow, err := n.serviceLBTable.NewFlow(ofctrl.FlowMatch{
			Priority:       NORMAL_MATCH_FLOW_PRIORITY,
			Ethertype:      PROTOCOL_IP,
			IpProto:        PROTOCOL_UDP,
			UdpDstPort:     uint16(nodePort),
			UdpDstPortMask: PortMaskMatchFullBit,
			PktMark:        1 << constants.ExternalSvcPktMarkBit,
			PktMarkMask:    &pktMask,
		})
		return newFlow, err
	}

	return nil, fmt.Errorf("invalid protocol: %s", protocol)
}

func (n *NatBridge) newLBFlow(ipDa *net.IP, protocol corev1.Protocol, port int32) (*ofctrl.Flow, error) {
	if protocol == corev1.ProtocolTCP {
		newFlow, err := n.serviceLBTable.NewFlow(ofctrl.FlowMatch{
			Priority:       MID_MATCH_FLOW_PRIORITY,
			Ethertype:      PROTOCOL_IP,
			IpProto:        PROTOCOL_TCP,
			IpDa:           ipDa,
			IpDaMask:       &IPMaskMatchFullBit,
			TcpDstPort:     uint16(port),
			TcpDstPortMask: PortMaskMatchFullBit,
		})
		return newFlow, err
	}

	if protocol == corev1.ProtocolUDP {
		newFlow, err := n.serviceLBTable.NewFlow(ofctrl.FlowMatch{
			Priority:       MID_MATCH_FLOW_PRIORITY,
			Ethertype:      PROTOCOL_IP,
			IpProto:        PROTOCOL_UDP,
			IpDa:           ipDa,
			IpDaMask:       &IPMaskMatchFullBit,
			UdpDstPort:     uint16(port),
			UdpDstPortMask: PortMaskMatchFullBit,
		})
		return newFlow, err
	}

	return nil, fmt.Errorf("invalid protocol: %s", protocol)
}

func (n *NatBridge) createEmptyGroup() (*ofctrl.Group, error) {
	newGp, err := n.newEmptyGroup()
	if err != nil {
		log.Errorf("Failed to new a empty group, err: %s", err)
		return nil, err
	}
	if err := newGp.Install(); err != nil {
		log.Errorf("Failed to install group: %+v, err: %s", *newGp, err)
		return nil, err
	}
	return newGp, nil
}

func (n *NatBridge) newEmptyGroup() (*ofctrl.Group, error) {
	sw := n.OfSwitch
	groupID, err := getGroupID()
	if err != nil {
		log.Errorf("Allocate a new group id failed, err: %s", err)
		return nil, err
	}
	newGp, err := sw.NewGroup(groupID, uint8(openflow13.OFPGT_SELECT))
	if err != nil {
		log.Errorf("Failed to new a group, err: %s", err)
		return nil, err
	}
	return newGp, nil
}

func (n *NatBridge) initInputTable() error {
	ipFlow, err := n.inputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
	})
	if err != nil {
		log.Errorf("Failed to new a flow match ip in Input table %d: %s", NatBrInputTable, err)
		return err
	}
	if err = ipFlow.Resubmit(nil, &NatBrInPortTable); err != nil {
		log.Errorf("Failed to add resubmit action to flow in Input table %d: %s", NatBrInputTable, err)
		return err
	}
	if err = ipFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install flow in Input table %d: %s", NatBrInputTable, err)
		return err
	}

	dropFlow, err := n.inputTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_DROP_FLOW_PRIORITY,
	})
	if err != nil {
		log.Errorf("Failed to new a flow in Input table %d: %s", NatBrInputTable, err)
		return err
	}
	if err = dropFlow.Next(n.OfSwitch.DropAction()); err != nil {
		log.Errorf("Failed to install a default drop flow in Input table %d: %s", NatBrInputTable, err)
		return err
	}
	return nil
}

func (n *NatBridge) setCTZone(zone uint64, portType string) error {
	flow, err := n.inPortTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		InputPort: n.datapathManager.BridgeChainPortMap[n.ovsBrName][portType],
	})
	if err != nil {
		log.Errorf("Failed to new a flow in InPort table %d: %s", NatBrInPortTable, err)
		return err
	}
	if err = flow.LoadField(CTZoneReg, zone, CTZoneRange); err != nil {
		log.Errorf("Failed to add load action to flow in InPort table %d: %s", NatBrInPortTable, err)
		return err
	}
	if err = flow.Resubmit(nil, &NatBrCTZoneTable); err != nil {
		log.Errorf("Failed to add resubmit action to flow in InPort table %d: %s", NatBrInPortTable, err)
		return err
	}
	if err = flow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install flow in InPort table %d: %s", NatBrInPortTable, err)
		return err
	}
	return nil
}

func (n *NatBridge) initInPortTable() error {
	if err := n.setCTZone(constants.CTZoneNatBrFromLocal, NatToLocalSuffix); err != nil {
		return fmt.Errorf("failed to set from local ct zone: %s", err)
	}

	if n.kubeProxyReplace {
		if err := n.setCTZone(constants.CTZoneNatBrFromUplink, NatToUplinkSuffix); err != nil {
			return fmt.Errorf("failed to set from uplink ct zone: %s", err)
		}
	}

	return nil
}

func (n *NatBridge) initCTZoneTable() error {
	flow, err := n.ctZoneTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
	})
	if err != nil {
		log.Errorf("Failed to new a flow in CTZone table %d: %s", NatBrCTZoneTable, err)
		return err
	}
	ctAct, err := ofctrl.NewConntrackActionWithZoneField(false, false, &NatBrCTStateTable, CTZoneReg, CTZoneRange)
	if err != nil {
		log.Errorf("Failed to new a ct action: %s", err)
		return err
	}
	_ = flow.SetConntrack(ctAct)
	if err = flow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install flow in CTZone table %d: %s", NatBrCTZoneTable, err)
		return err
	}
	return nil
}

func (n *NatBridge) initCTStateTable() error {
	// -new+trk flow commit immediately, and do dnat or snat according to conntrack table
	ctState := openflow13.NewCTStates()
	ctState.UnsetNew()
	ctState.SetTrk()
	trkFlow, err := n.ctStateTable.NewFlow(ofctrl.FlowMatch{
		Priority:  HIGH_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
		CtStates:  ctState,
	})
	if err != nil {
		log.Errorf("Failed to new a flow in CTState table %d: %s", NatBrCTStateTable, err)
		return err
	}
	natAct, _ := ofctrl.NewNatAction().ToOfAction()
	ctAct, err := ofctrl.NewConntrackActionWithZoneField(true, false, &NatBrL3ForwardTable, CTZoneReg, CTZoneRange, natAct)
	if err != nil {
		log.Errorf("Failed to new a ct action with nat: %s", err)
		return err
	}
	_ = trkFlow.SetConntrack(ctAct)
	if err = trkFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install flow in CTState table %d: %s", NatBrCTStateTable, err)
		return err
	}

	// the first packet of pod->svc, should choose backend ip
	svcIP := n.datapathManager.Info.ClusterCIDR.IP
	svcMask := (net.IP)(n.datapathManager.Info.ClusterCIDR.Mask)
	svcFlow, err := n.ctStateTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
		IpDa:      &svcIP,
		IpDaMask:  &svcMask,
	})
	if err != nil {
		log.Errorf("Failed to new a flow in CTState table %d: %s", NatBrCTStateTable, err)
		return err
	}
	if err := svcFlow.Resubmit(nil, &NatBrSessionAffinityTable); err != nil {
		log.Errorf("Failed to add a resubmit action to CTState table %d: %s", NatBrCTStateTable, err)
		return err
	}
	if err := svcFlow.Resubmit(nil, &NatBrServiceLBTable); err != nil {
		log.Errorf("Failed to add a resubmit action to CTState table %d: %s", NatBrCTStateTable, err)
		return err
	}
	if err := svcFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install flow in CTState table %d: %s", NatBrCTStateTable, err)
		return err
	}

	if n.kubeProxyReplace {
		var pktMask uint32 = 1 << constants.ExternalSvcPktMarkBit
		svcPktFlow, _ := n.ctStateTable.NewFlow(ofctrl.FlowMatch{
			Priority:    NORMAL_MATCH_FLOW_PRIORITY,
			InputPort:   n.datapathManager.BridgeChainPortMap[n.ovsBrName][NatToUplinkSuffix],
			PktMark:     1 << constants.ExternalSvcPktMarkBit,
			PktMarkMask: &pktMask,
		})
		if err := svcPktFlow.Resubmit(nil, &NatBrSessionAffinityTable); err != nil {
			log.Errorf("Failed to add a resubmit action for svc pkt mark flow to CTState table %d: %s", NatBrCTStateTable, err)
			return err
		}
		if err := svcPktFlow.Resubmit(nil, &NatBrServiceLBTable); err != nil {
			log.Errorf("Failed to add a resubmit action for svc pkt mark flow to CTState table %d: %s", NatBrCTStateTable, err)
			return err
		}
		if err := svcPktFlow.Next(ofctrl.NewEmptyElem()); err != nil {
			log.Errorf("Failed to install for svc pkt mark flow in CTState table %d: %s", NatBrCTStateTable, err)
			return err
		}
	}

	// non-service flow, output indirect
	defaultFlow, err := n.ctStateTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err != nil {
		log.Errorf("Failed to new flow in CTState table %d: %s", NatBrCTStateTable, err)
		return err
	}
	if err := defaultFlow.Resubmit(nil, &NatBrOutputTable); err != nil {
		log.Errorf("Failed to add resubmit action to flow in CTState table %d: %s", NatBrCTStateTable, err)
		return err
	}
	if err := defaultFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install flow in CTState table %d: %s", NatBrCTStateTable, err)
		return err
	}

	return nil
}

func (n *NatBridge) initSessionAffinityTable() error {
	defaultFlow, err := n.sessionAffinityTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err != nil {
		log.Errorf("Failed to new a flow in SessionAffinity table %d: %s", NatBrSessionAffinityTable, err)
		return err
	}
	if err := defaultFlow.LoadField(ChooseBackendFlagReg, uint64(NeedChoose), ChooseBackendFlagRange); err != nil {
		log.Errorf("Failed to add a load field action to flow in SessionAffinity table %d: %s", NatBrSessionAffinityTable, err)
		return err
	}
	if err := defaultFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install flow in SessionAffinity table %d: %s", NatBrSessionAffinityTable, err)
		return err
	}
	return nil
}

func (n *NatBridge) addNoNeedChooseEndpointTable(table *ofctrl.Table) error {
	flow, _ := table.NewFlow(ofctrl.FlowMatch{
		Priority: HIGH_MATCH_FLOW_PRIORITY,
		Regs: []*ofctrl.NXRegister{
			{
				RegID: constants.OVSReg0,
				Data:  uint32(NoNeedChoose) << uint32(ChooseBackendFlagStart),
				Range: ChooseBackendFlagRange,
			},
		},
	})
	var err error
	if err = flow.Resubmit(nil, &NatBrDnatTable); err != nil {
		log.Errorf("Failed to add resubmit action to no need choose endpoint flow: %s", err)
		return err
	}
	if err = flow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install no need choose endpoint flow: %s", err)
		return err
	}
	return nil
}

func (n *NatBridge) initServiceLBTable() error {
	if err := n.addNoNeedChooseEndpointTable(n.serviceLBTable); err != nil {
		return fmt.Errorf("failed to add no need choose endpoint flow in clusterIP svc lb table: %s", err)
	}
	return nil
}

func (n *NatBridge) buildLearnActOfSessionAffinityLearnTable(ipProto uint8, learnActionTimeout int32, isNP bool) (*ofctrl.LearnAction, error) {
	ethTypeField := ofctrl.LearnField{Name: "nxm_of_eth_type", Start: 0}
	ipSrcField := ofctrl.LearnField{Name: "nxm_of_ip_src", Start: 0}
	ipDstField := ofctrl.LearnField{Name: "nxm_of_ip_dst", Start: 0}

	ipProtoField := ofctrl.LearnField{Name: "nxm_of_ip_proto", Start: 0}
	tcpDstField := ofctrl.LearnField{Name: "nxm_of_tcp_dst", Start: 0}
	udpDstField := ofctrl.LearnField{Name: "nxm_of_udp_dst", Start: 0}

	backendIPField := ofctrl.LearnField{Name: BackendIPReg, Start: 0}
	backendPortField := ofctrl.LearnField{Name: BackendPortReg, Start: 0}
	chooseBackendFlagField := ofctrl.LearnField{Name: ChooseBackendFlagReg, Start: uint16(ChooseBackendFlagStart)}
	unsnatFlagField := ofctrl.LearnField{Name: "nxm_nx_pkt_mark", Start: constants.SvcLocalPktMarkBit}
	externalFlagField := ofctrl.LearnField{Name: "nxm_nx_pkt_mark", Start: constants.ExternalSvcPktMarkBit}

	cookieID, err := getLearnCookieID()
	if err != nil {
		return nil, err
	}
	priority := MID_MATCH_FLOW_PRIORITY
	if isNP {
		priority = NORMAL_MATCH_FLOW_PRIORITY
	}
	learnAct := ofctrl.NewLearnAction(NatBrSessionAffinityTable, uint16(priority), 0, uint16(learnActionTimeout), 0, 0, cookieID)
	learnAct.SetDeleteLearned()

	if err := learnAct.AddLearnedMatch(&ethTypeField, EtherTypeLength, nil, uintToByteBigEndian(uint16(PROTOCOL_IP))); err != nil {
		return nil, err
	}
	if err := learnAct.AddLearnedMatch(&ipSrcField, IPv4Lenth, &ipSrcField, nil); err != nil {
		return nil, err
	}
	if isNP {
		if err := learnAct.AddLearnedMatch(&externalFlagField, 1, nil, uintToByteBigEndian(uint16(constants.PktMarkSetValue))); err != nil {
			return nil, err
		}
	} else {
		if err := learnAct.AddLearnedMatch(&ipDstField, IPv4Lenth, &ipDstField, nil); err != nil {
			return nil, err
		}
	}

	switch ipProto {
	case PROTOCOL_TCP:
		if err := learnAct.AddLearnedMatch(&ipProtoField, ProtocolLength, nil, uintToByteBigEndian(uint16(PROTOCOL_TCP))); err != nil {
			return nil, err
		}
		if err := learnAct.AddLearnedMatch(&tcpDstField, PortLength, &tcpDstField, nil); err != nil {
			return nil, err
		}
	case PROTOCOL_UDP:
		if err := learnAct.AddLearnedMatch(&ipProtoField, ProtocolLength, nil, uintToByteBigEndian(uint16(PROTOCOL_UDP))); err != nil {
			return nil, err
		}
		if err := learnAct.AddLearnedMatch(&udpDstField, PortLength, &udpDstField, nil); err != nil {
			return nil, err
		}
	default:
		log.Errorf("No support for this ip protocol number: %d", ipProto)
		return nil, fmt.Errorf("unsupported ip protocol number %d", ipProto)
	}

	if err := learnAct.AddLearnedLoadAction(&backendIPField, IPv4Lenth, &backendIPField, nil); err != nil {
		return nil, err
	}
	if err := learnAct.AddLearnedLoadAction(&backendPortField, PortLength, &backendPortField, nil); err != nil {
		return nil, err
	}
	if err := learnAct.AddLearnedLoadAction(&chooseBackendFlagField, ChooseBackendFlagLength, nil, uintToByteBigEndian(uint16(NoNeedChoose))); err != nil {
		return nil, err
	}

	if err := learnAct.AddLearnedLoadAction(&unsnatFlagField, 1, &unsnatFlagField, nil); err != nil {
		return nil, err
	}

	return learnAct, nil
}

func (n *NatBridge) newSessionAffinityFlow(dstIP net.IP, protocol corev1.Protocol, dstPort int32) (*ofctrl.Flow, error) {
	var flow *ofctrl.Flow
	var ipProto uint8
	var err error
	switch protocol {
	case corev1.ProtocolTCP:
		ipProto = PROTOCOL_TCP
		flow, err = n.sessionAffinityLearnTable.NewFlow(ofctrl.FlowMatch{
			Priority:       MID_MATCH_FLOW_PRIORITY,
			Ethertype:      PROTOCOL_IP,
			IpProto:        ipProto,
			IpDa:           &dstIP,
			IpDaMask:       &IPMaskMatchFullBit,
			TcpDstPort:     uint16(dstPort),
			TcpDstPortMask: PortMaskMatchFullBit,
		})
		if err != nil {
			log.Errorf("Failed to new session affinity flow for ip %s protocol %s port %d: %s", dstIP, protocol, dstPort, err)
			return nil, err
		}
	case corev1.ProtocolUDP:
		ipProto = PROTOCOL_UDP
		flow, err = n.sessionAffinityLearnTable.NewFlow(ofctrl.FlowMatch{
			Priority:       MID_MATCH_FLOW_PRIORITY,
			Ethertype:      PROTOCOL_IP,
			IpProto:        ipProto,
			IpDa:           &dstIP,
			IpDaMask:       &IPMaskMatchFullBit,
			UdpDstPort:     uint16(dstPort),
			UdpDstPortMask: PortMaskMatchFullBit,
		})
		if err != nil {
			log.Errorf("Failed to new session affinity flow for ip %s protocol %s port %d: %s", dstIP, protocol, dstPort, err)
			return nil, err
		}
	default:
		log.Errorf("Unsupport service protocol %s", protocol)
		return nil, fmt.Errorf("unsupport service protocol %s", protocol)
	}
	return flow, nil
}

func (n *NatBridge) newSessionAffinityFlowForNodePort(protocol corev1.Protocol, dstNodePort int32) (*ofctrl.Flow, error) {
	var flow *ofctrl.Flow
	var ipProto uint8
	var err error
	var pktMask uint32 = 1 << constants.ExternalSvcPktMarkBit
	switch protocol {
	case corev1.ProtocolTCP:
		ipProto = PROTOCOL_TCP
		flow, err = n.sessionAffinityLearnTable.NewFlow(ofctrl.FlowMatch{
			Priority:       NORMAL_MATCH_FLOW_PRIORITY,
			Ethertype:      PROTOCOL_IP,
			IpProto:        ipProto,
			TcpDstPort:     uint16(dstNodePort),
			TcpDstPortMask: PortMaskMatchFullBit,
			PktMark:        1 << constants.ExternalSvcPktMarkBit,
			PktMarkMask:    &pktMask,
		})
		if err != nil {
			log.Errorf("Failed to new session affinity flow for protocol %s nodeport %d: %s", protocol, dstNodePort, err)
			return nil, err
		}
	case corev1.ProtocolUDP:
		ipProto = PROTOCOL_UDP
		flow, err = n.sessionAffinityLearnTable.NewFlow(ofctrl.FlowMatch{
			Priority:       MID_MATCH_FLOW_PRIORITY,
			Ethertype:      PROTOCOL_IP,
			IpProto:        ipProto,
			UdpDstPort:     uint16(dstNodePort),
			UdpDstPortMask: PortMaskMatchFullBit,
			PktMark:        1 << constants.ExternalSvcPktMarkBit,
			PktMarkMask:    &pktMask,
		})
		if err != nil {
			log.Errorf("Failed to new session affinity flow for protocol %s nodeport %d: %s", protocol, dstNodePort, err)
			return nil, err
		}
	default:
		log.Errorf("Unsupport service protocol %s", protocol)
		return nil, fmt.Errorf("unsupport service protocol %s", protocol)
	}
	return flow, nil
}

func (n *NatBridge) addSessionAffinityFlow(dstIP net.IP, svcLB *proxycache.SvcLB) (*ofctrl.Flow, error) {
	var flow *ofctrl.Flow
	var err error
	var ipProto uint8
	isNP := dstIP == nil
	if isNP {
		flow, err = n.newSessionAffinityFlowForNodePort(svcLB.Port.Protocol, svcLB.Port.NodePort)
	} else {
		flow, err = n.newSessionAffinityFlow(dstIP, svcLB.Port.Protocol, svcLB.Port.Port)
	}
	if err != nil {
		log.Errorf("Failed to new session affinity flow for svclb %v, err: %s", *svcLB, err)
		return nil, err
	}

	ipProto = PROTOCOL_TCP
	if svcLB.Port.Protocol == corev1.ProtocolUDP {
		ipProto = PROTOCOL_UDP
	}

	learnAct, err := n.buildLearnActOfSessionAffinityLearnTable(ipProto, svcLB.SessionAffinityTimeout, isNP)
	if err != nil {
		log.Errorf("Failed to build a learn action: %s", err)
		return nil, err
	}
	if err = flow.Learn(learnAct); err != nil {
		log.Errorf("Failed to add learn action to session affinity flow for svclb %v: %s", *svcLB, err)
		return nil, err
	}
	if err = flow.Resubmit(nil, &NatBrDnatTable); err != nil {
		log.Errorf("Failed to add a resubmit action to session affinity flow for for svclb %v: %s", *svcLB, err)
		return nil, err
	}
	if err = flow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install session affinity flow %+v for for svclb %v: %s", flow, *svcLB, err)
		return nil, err
	}

	return flow, nil
}

func (n *NatBridge) initSessionAffinityLearnTable() error {
	defaultFlow, err := n.sessionAffinityLearnTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err != nil {
		log.Errorf("Failed to new default flow SessionAffinityLearn table %d: %s", NatBrSessionAffinityLearnTable, err)
		return err
	}
	if err := defaultFlow.Resubmit(nil, &NatBrDnatTable); err != nil {
		log.Errorf("Failed to add a resubmit action to default flow in SessionAffinityLearn table %d: %s", NatBrSessionAffinityLearnTable, err)
		return err
	}
	if err := defaultFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install flow in SessionAffinityLearn table %d: %s", NatBrSessionAffinityLearnTable, err)
		return err
	}
	return nil
}

func (n *NatBridge) initL3ForwardTable() error {
	defaultFlow, err := n.l3ForwardTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err != nil {
		log.Errorf("Failed to new a flow in L3Forward table %d: %s", NatBrL3ForwardTable, err)
		return err
	}
	if err := defaultFlow.Resubmit(nil, &NatBrOutputTable); err != nil {
		log.Errorf("Failed to add resubmit action to flow in L3Forward table %d: %s", NatBrL3ForwardTable, err)
		return err
	}
	if err := defaultFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install flow in L3Forward table %d: %s", NatBrL3ForwardTable, err)
		return err
	}

	return nil
}

func (n *NatBridge) initOutputTable() error {
	defaultFlow, err := n.outputTable.NewFlow(ofctrl.FlowMatch{
		Priority: NORMAL_MATCH_FLOW_PRIORITY,
	})
	if err != nil {
		log.Errorf("Failed to new a flow in L3Forward table %d: %s", NatBrOutputTable, err)
		return err
	}
	outputPort, err := n.OfSwitch.OutputPort(openflow13.P_IN_PORT)
	if err != nil {
		log.Errorf("Failed to make outputPort: %s", err)
		return err
	}
	if err := defaultFlow.Next(outputPort); err != nil {
		log.Errorf("Failed to install flow in L3Forward table %d: %s", NatBrOutputTable, err)
		return err
	}

	return nil
}

func newBucketForLBGroup(ip string, port int32) (*ofctrl.Bucket, error) {
	bucket := ofctrl.NewBucket(SelectGroupWeight)
	ipByte := net.ParseIP(ip)
	if ipByte == nil {
		log.Errorf("Invalid backend ip %s", ip)
		return nil, fmt.Errorf("invalid backend ip: %s", ip)
	}
	act1, err := ofctrl.NewNXLoadAction(BackendIPReg, ipv4ToUint64(ipByte), BackendIPRange)
	if err != nil {
		log.Errorf("Failed to new a NXLoadAction for backend ip %s, err: %s", ip, err)
		return nil, err
	}
	bucket.AddAction(act1)

	act2, err := ofctrl.NewNXLoadAction(BackendPortReg, uint64(port), BackendPortRange)
	if err != nil {
		log.Errorf("Failed to new a NXLoadAction for backend port %d, err: %s", port, err)
		return nil, err
	}
	bucket.AddAction(act2)

	act3 := ofctrl.NewResubmitAction(nil, &NatBrSessionAffinityLearnTable)
	bucket.AddAction(act3)
	return bucket, nil
}
