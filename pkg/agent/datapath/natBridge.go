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
	"sync"
	"time"

	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/ofnet/ofctrl"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"

	proxycache "github.com/everoute/everoute/pkg/agent/controller/proxy/cache"
	"github.com/everoute/everoute/pkg/agent/datapath/cache"
	everoutesvc "github.com/everoute/everoute/pkg/apis/service/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	cniconst "github.com/everoute/everoute/pkg/constants/cni"
	ertype "github.com/everoute/everoute/pkg/types"
)

var (
	NatBrInputTable                uint8
	NatBrInPortTable               uint8 = 4
	NatBrCTZoneTable               uint8 = 5
	NatBrCTStateTable              uint8 = 10
	NatBrSessionAffinityTable      uint8 = 30
	NatBrServiceLBTable            uint8 = 35
	NatBrSessionAffinityLearnTable uint8 = 40
	NatBrDnatTable                 uint8 = 50
	NatBrL3ForwardTable            uint8 = 90
	NatBrOutputTable               uint8 = 100
	NatBrSvcEmptyTable             uint8 = 200
)

var (
	CTZoneReg                       = "nxm_nx_reg0"
	CTZoneRange *openflow13.NXRange = openflow13.NewNXRange(0, 15)

	ChooseBackendFlagReg                       = "nxm_nx_reg0"
	ChooseBackendFlagRange *openflow13.NXRange = openflow13.NewNXRange(16, 16)
	ChooseBackendFlagStart                     = 16
	NeedChoose             uint8
	NoNeedChoose           uint8 = 1

	BackendIPReg                             = "nxm_nx_reg1"
	BackendIPRegNumber                       = 1
	BackendIPRange       *openflow13.NXRange = openflow13.NewNXRange(0, 31)
	BackendPortReg                           = "nxm_nx_reg2"
	BackendPortRegNumber                     = 2
	BackendPortRange     *openflow13.NXRange = openflow13.NewNXRange(0, 15)

	ChooseBackendFlagLength uint16 = 1
)

const (
	SelectGroupWeight = 100

	LbFlowForIPPri uint16 = MID_MATCH_FLOW_PRIORITY
	LbFlowForNPPri uint16 = NORMAL_MATCH_FLOW_PRIORITY
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
	svcEmptyTable             *ofctrl.Table

	svcIndexCache *cache.SvcIndex // service flow and group database
	// l3FlowMap the key is interface uuid, the value is l3ForwardTable flow
	l3FlowMap map[string]*ofctrl.Flow

	kubeProxyReplace bool

	// groupid related config
	curMaxGroupID    uint32
	groupIDAllocator *GroupIDAllocator
	groupIDFileLock  sync.RWMutex
	iterLock         sync.RWMutex
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
	if err := n.initGroupIDConfig(); err != nil {
		log.Fatalf("Bridge %s init group ID related config failed: %s", n.GetName(), err)
	}

	sw := n.OfSwitch

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
	n.svcEmptyTable, _ = sw.NewTable(NatBrSvcEmptyTable)

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
	if err := n.initSvcEmptyTable(); err != nil {
		log.Fatalf("Init Svc Empty table %d of nat bridge failed: %s", NatBrSvcEmptyTable, err)
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
	if svcOvsCache.GetLBFlow(svcLB.IP, svcLB.Port.Name) != cache.UnexistFlowID {
		log.Infof("The lb flow has been installed for service lb info %v, skip create it", *svcLB)
		return nil
	}

	gpID, err := svcOvsCache.GetGroupAndCreateIfEmpty(svcLB.Port.Name, svcLB.TrafficPolicy, n.createEmptyGroup)
	if err != nil {
		log.Errorf("Failed to create a empty group for service %s, lbip: %s, portname: %s, traffic policy: %s, err: %s", svcID,
			svcLB.IP, svcLB.Port.Name, svcLB.TrafficPolicy, err)
		return err
	}

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
		ofRange := openflow13.NewNXRange(cniconst.SvcLocalPktMarkBit, cniconst.SvcLocalPktMarkBit)
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

	svcOvsCache.SetLBFlow(svcLB.IP, svcLB.Port.Name, lbFlow.FlowID)
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
	lbFlowID := svcOvsCache.GetLBFlow(svcLB.IP, svcLB.Port.Name)
	if lbFlowID == cache.UnexistFlowID {
		return nil
	}

	if err := ofctrl.DeleteFlow(n.serviceLBTable, n.getFlowPriBySvcLB(svcLB), lbFlowID); err != nil {
		log.Errorf("Failed to delete lb flow for svc lb info %v, err: %s", *svcLB, err)
		return err
	}
	svcOvsCache.SetLBFlow(svcLB.IP, svcLB.Port.Name, cache.UnexistFlowID)
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
	if svcOvsCache.GetSessionAffinityFlow(svcLB.IP, svcLB.Port.Name) != cache.UnexistFlowID {
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

	svcOvsCache.SetSessionAffinityFlow(svcLB.IP, svcLB.Port.Name, sessionFlow.FlowID)
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
	sAFlowID := svcOvsCache.GetSessionAffinityFlow(svcLB.IP, svcLB.Port.Name)
	if sAFlowID == cache.UnexistFlowID {
		return nil
	}
	if err := ofctrl.DeleteFlow(n.sessionAffinityLearnTable, n.getFlowPriBySvcLB(svcLB), sAFlowID); err != nil {
		log.Errorf("Failed to delete service session affinity flow for lb info %v, err: %s", *svcLB, err)
		return err
	}
	svcOvsCache.SetSessionAffinityFlow(svcLB.IP, svcLB.Port.Name, cache.UnexistFlowID)
	n.svcIndexCache.TryCleanSvcOvsInfoCache(svcID)
	log.Infof("Dp success to delete sessionAffinity flow for svclb %v", *svcLB)
	return nil
}

func (n *NatBridge) UpdateLBGroup(svcID, portName string, backends []everoutesvc.Backend, tp ertype.TrafficPolicyType) error {
	svcOvsCache := n.svcIndexCache.GetSvcOvsInfoAndInitIfEmpty(svcID)
	var err error
	gpID, err := svcOvsCache.GetGroupAndCreateIfEmpty(portName, tp, n.createEmptyGroup)
	if err != nil {
		log.Errorf("Failed to create a empty group for svc %s portname %s, err: %s", svcID, portName, err)
		return err
	}
	gp := n.OfSwitch.GetGroup(gpID)
	if gp == nil {
		log.Errorf("Group with groupID %d is nil", gpID)
		return fmt.Errorf("group is nil")
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
	if len(buckets) == 0 {
		buckets = append(buckets, n.getDefaultBucket())
	}
	gp.ResetBuckets(buckets)

	log.Infof("Dp success to update LB group for service %s port %s, backends: %+v", svcID, portName, backends)
	return nil
}

func (n *NatBridge) ResetLBGroup(svcID, portName string) error {
	svcOvsCache := n.svcIndexCache.GetSvcOvsInfo(svcID)
	if svcOvsCache == nil {
		log.Infof("The Service %s has no related ovs group for port %s, skip", svcID, portName)
		return nil
	}

	for _, tp := range []ertype.TrafficPolicyType{ertype.TrafficPolicyCluster, ertype.TrafficPolicyLocal} {
		gpID := svcOvsCache.GetGroup(portName, tp)
		if gpID == cache.UnexistGroupID {
			continue
		}
		if err := n.UpdateLBGroup(svcID, portName, nil, tp); err != nil {
			log.Errorf("Failed to reset svc %s lb group for port %s with traffic policy type %s, err: %s", svcID, portName, tp, err)
			return err
		}
	}
	log.Infof("Dp success to reset LB group for service %s port %s", svcID, portName)
	return nil
}

func (n *NatBridge) DelLBGroup(svcID, portName string) error {
	svcOvsCache := n.svcIndexCache.GetSvcOvsInfo(svcID)
	if svcOvsCache == nil {
		log.Infof("The Service %s has no related ovs group for port %s, skip delete group", svcID, portName)
		return nil
	}
	for _, tp := range []ertype.TrafficPolicyType{ertype.TrafficPolicyCluster, ertype.TrafficPolicyLocal} {
		svcOvsCache.DeleteGroupIfExist(portName, tp, n.deleteGroup)
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
	if f := n.svcIndexCache.GetDnatFlow(dnatKey); f != cache.UnexistFlowID {
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
		IpProto:   ipProtocol,
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

	n.svcIndexCache.SetDnatFlow(dnatKey, flow.FlowID)
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
	flowID := n.svcIndexCache.GetDnatFlow(dnatKey)
	if flowID == cache.UnexistFlowID {
		log.Infof("The dnat flow has been deleted, skip it. ip: %s, protocol: %s, port: %d", ip, protocol, port)
		return nil
	}

	if err := ofctrl.DeleteFlow(n.dnatTable, MID_MATCH_FLOW_PRIORITY, flowID); err != nil {
		log.Errorf("Delete dnat flow for %s failed, err: %s", dnatKey, err)
		return err
	}

	n.svcIndexCache.DeleteDnatFlow(dnatKey)
	log.Infof("Success delete dnat flow for %s", dnatKey)
	return nil
}

func (n *NatBridge) newLBFlowForNodePort(protocol corev1.Protocol, nodePort int32) (*ofctrl.Flow, error) {
	var pktMask uint32 = 1 << cniconst.ExternalSvcPktMarkBit
	if protocol == corev1.ProtocolTCP {
		newFlow, err := n.serviceLBTable.NewFlow(ofctrl.FlowMatch{
			Priority:       LbFlowForNPPri,
			Ethertype:      PROTOCOL_IP,
			IpProto:        PROTOCOL_TCP,
			TcpDstPort:     uint16(nodePort),
			TcpDstPortMask: PortMaskMatchFullBit,
			PktMark:        1 << cniconst.ExternalSvcPktMarkBit,
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
			PktMark:        1 << cniconst.ExternalSvcPktMarkBit,
			PktMarkMask:    &pktMask,
		})
		return newFlow, err
	}

	return nil, fmt.Errorf("invalid protocol: %s", protocol)
}

func (n *NatBridge) newLBFlow(ipDa *net.IP, protocol corev1.Protocol, port int32) (*ofctrl.Flow, error) {
	if protocol == corev1.ProtocolTCP {
		newFlow, err := n.serviceLBTable.NewFlow(ofctrl.FlowMatch{
			Priority:       LbFlowForIPPri,
			Ethertype:      PROTOCOL_IP,
			IpProto:        PROTOCOL_TCP,
			IpDa:           ipDa,
			IpDaMask:       &net.IPv4bcast,
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
			IpDaMask:       &net.IPv4bcast,
			UdpDstPort:     uint16(port),
			UdpDstPortMask: PortMaskMatchFullBit,
		})
		return newFlow, err
	}

	return nil, fmt.Errorf("invalid protocol: %s", protocol)
}

func (n *NatBridge) deleteGroup(gpID uint32) {
	_ = ofctrl.DeleteGroup(n.OfSwitch, gpID)
	n.groupIDAllocator.Release(gpID)
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

	newGp.ResetBuckets([]*ofctrl.Bucket{n.getDefaultBucket()})

	return newGp, nil
}

func (n *NatBridge) getDefaultBucket() *ofctrl.Bucket {
	defaultBucket := ofctrl.NewBucket(SelectGroupWeight)
	defaultBucket.AddAction(ofctrl.NewControllerAction(n.OfSwitch.ControllerID, 0))
	defaultBucket.AddAction(ofctrl.NewResubmitAction(nil, &NatBrSvcEmptyTable))

	return defaultBucket
}

func (n *NatBridge) newEmptyGroup() (*ofctrl.Group, error) {
	sw := n.OfSwitch
	groupID := n.groupIDAllocator.Allocate()
	if groupID == InvalidGroupID {
		log.Error("Allocate a new group id failed, doesn't has available groupid")
		return nil, fmt.Errorf("has no available groupid")
	}
	if err := n.updateMaxGroupID(groupID); err != nil {
		log.Errorf("Failed to update maxGroupID to file, err: %s", err)
		n.groupIDAllocator.Release(groupID)
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
	if err := n.setCTZone(cniconst.CTZoneNatBrFromLocal, NatToLocalSuffix); err != nil {
		return fmt.Errorf("failed to set from local ct zone: %s", err)
	}

	if n.kubeProxyReplace {
		if err := n.setCTZone(cniconst.CTZoneNatBrFromUplink, NatToUplinkSuffix); err != nil {
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
		var pktMask uint32 = 1 << cniconst.ExternalSvcPktMarkBit
		svcPktFlow, _ := n.ctStateTable.NewFlow(ofctrl.FlowMatch{
			Priority:    NORMAL_MATCH_FLOW_PRIORITY,
			InputPort:   n.datapathManager.BridgeChainPortMap[n.ovsBrName][NatToUplinkSuffix],
			PktMark:     1 << cniconst.ExternalSvcPktMarkBit,
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

func (n *NatBridge) initSvcEmptyTable() error {
	defaultFlow, err := n.svcEmptyTable.NewFlow(ofctrl.FlowMatch{
		Priority: NORMAL_MATCH_FLOW_PRIORITY,
	})
	if err != nil {
		log.Errorf("Failed to new a flow in L3Forward table %d: %s", NatBrOutputTable, err)
		return err
	}
	if err = defaultFlow.SendToController(ofctrl.NewControllerAction(n.OfSwitch.ControllerID, 0)); err != nil {
		return err
	}

	return defaultFlow.Next(ofctrl.NewEmptyElem())
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
	unsnatFlagField := ofctrl.LearnField{Name: "nxm_nx_pkt_mark", Start: cniconst.SvcLocalPktMarkBit}
	externalFlagField := ofctrl.LearnField{Name: "nxm_nx_pkt_mark", Start: cniconst.ExternalSvcPktMarkBit}

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
			IpDaMask:       &net.IPv4bcast,
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
			Priority:       LbFlowForIPPri,
			Ethertype:      PROTOCOL_IP,
			IpProto:        ipProto,
			IpDa:           &dstIP,
			IpDaMask:       &net.IPv4bcast,
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
	var pktMask uint32 = 1 << cniconst.ExternalSvcPktMarkBit
	switch protocol {
	case corev1.ProtocolTCP:
		ipProto = PROTOCOL_TCP
		flow, err = n.sessionAffinityLearnTable.NewFlow(ofctrl.FlowMatch{
			Priority:       LbFlowForNPPri,
			Ethertype:      PROTOCOL_IP,
			IpProto:        ipProto,
			TcpDstPort:     uint16(dstNodePort),
			TcpDstPortMask: PortMaskMatchFullBit,
			PktMark:        1 << cniconst.ExternalSvcPktMarkBit,
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
			PktMark:        1 << cniconst.ExternalSvcPktMarkBit,
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

func (n *NatBridge) getFlowPriBySvcLB(s *proxycache.SvcLB) uint16 {
	if s.IP == "" {
		return LbFlowForNPPri
	}
	return LbFlowForIPPri
}

func (n *NatBridge) initGroupIDConfig() error {
	n.iterLock.Lock()
	defer n.iterLock.Unlock()
	gpIDs, err := n.getGroupIDInfo()
	if err != nil {
		log.Errorf("Failed to get GroupIDInfo: %s", err)
		return err
	}
	nextIter := gpIDs.GetNextIter()
	if nextIter > cniconst.MaxGroupIter || gpIDs.TooManyGroups() {
		log.Infof("No available groupid iter or there is too many groups to be deleted, so delete all groups for bridge %s", n.GetName())
		// no available groupid iter
		_ = ofctrl.DeleteGroup(n.OfSwitch, openflow13.OFPG_ALL)
		nextIter = 0
		n.curMaxGroupID = cniconst.GroupIDUpdateUnit
		n.groupIDAllocator = NewGroupIDAllocate(nextIter)
		newGpIDs := &GroupIDInfo{Exists: make(map[uint32]uint32)}
		newGpIDs.Exists[nextIter] = n.curMaxGroupID
		if err := SetGroupIDInfo(n.GetName(), newGpIDs); err != nil {
			log.Errorf("Failed to write new groupid info to file, err: %s", err)
			return err
		}
		return nil
	}

	n.groupIDAllocator = NewGroupIDAllocate(nextIter)
	n.curMaxGroupID = nextIter<<(32-cniconst.BitWidthGroupIter) + cniconst.GroupIDUpdateUnit
	newGpIDs := gpIDs.Clone()
	if newGpIDs.Exists == nil {
		newGpIDs.Exists = make(map[uint32]uint32, 1)
	}
	newGpIDs.Exists[nextIter] = n.curMaxGroupID
	if err := SetGroupIDInfo(n.GetName(), newGpIDs); err != nil {
		log.Errorf("Failed to write new groupid info to file, err: %s", err)
		return err
	}
	go n.cleanStaleGroupIDs(gpIDs, n.groupIDAllocator.GetIter())
	return nil
}

func (n *NatBridge) cleanStaleGroupIDs(gpID *GroupIDInfo, curIter uint32) {
	if gpID == nil || gpID.Exists == nil {
		return
	}
	time.Sleep(15 * time.Second)
	for iter := range gpID.Exists {
		if n.cleanStaleGroupIDsByIter(curIter, iter) {
			return
		}
	}
}

// returns exit clean or not
func (n *NatBridge) cleanStaleGroupIDsByIter(curIter, delIter uint32) bool {
	n.iterLock.RLock()
	defer n.iterLock.RUnlock()

	// bridge has init again
	if curIter != n.groupIDAllocator.GetIter() {
		return true
	}

	gpIDs, err := n.getGroupIDInfo()
	if err != nil {
		log.Errorf("Can't clean groupids by iter %d, failed to get GroupIDInfo: %s", delIter, err)
		return false
	}
	if gpIDs == nil || gpIDs.Exists == nil {
		return false
	}
	end, ok := gpIDs.Exists[delIter]
	if !ok {
		return false
	}
	log.Infof("Bridge %s begin to delete group for iter %d", n.GetName(), delIter)
	start := delIter<<(32-cniconst.BitWidthGroupIter) + 1
	for curGp := start; curGp <= end; curGp++ {
		_ = ofctrl.DeleteGroup(n.OfSwitch, curGp)
	}
	log.Infof("Bridge %s end to delete group for iter %d", n.GetName(), delIter)
	n.deleteIterFromFile(delIter)
	return false
}

func (n *NatBridge) getGroupIDInfo() (*GroupIDInfo, error) {
	n.groupIDFileLock.RLock()
	defer n.groupIDFileLock.RUnlock()

	return GetGroupIDInfo(n.GetName())
}

func (n *NatBridge) deleteIterFromFile(iter uint32) {
	n.groupIDFileLock.Lock()
	defer n.groupIDFileLock.Unlock()
	gpIDs, err := GetGroupIDInfo(n.GetName())
	if err != nil {
		log.Errorf("Bridge %s failed to get GroupIDInfo from file: %s, can't delete iter %d", n.GetName(), err, iter)
		return
	}
	if gpIDs == nil || gpIDs.Exists == nil {
		log.Warnf("Bridge %s exists groupIDs is nil, don't need to delete iter %d", n.GetName(), iter)
		return
	}
	if _, ok := gpIDs.Exists[iter]; !ok {
		log.Warnf("Bridge %s exists groupIDs has no iter %d", n.GetName(), iter)
		return
	}
	delete(gpIDs.Exists, iter)
	err = SetGroupIDInfo(n.GetName(), gpIDs)
	if err != nil {
		log.Errorf("Bridge %s failed to delete iter %d from file, err: %s", n.GetName(), iter, err)
		return
	}
	log.Infof("Bridge %s success to delete groupid for iter %d from file", n.GetName(), iter)
}

func (n *NatBridge) updateMaxGroupID(curGpID uint32) error {
	n.groupIDFileLock.Lock()
	defer n.groupIDFileLock.Unlock()

	if curGpID <= n.curMaxGroupID {
		return nil
	}

	newMax := n.groupIDAllocator.Max()
	if n.groupIDAllocator.Max()-n.curMaxGroupID > cniconst.GroupIDUpdateUnit {
		newMax = n.curMaxGroupID + cniconst.GroupIDUpdateUnit
	}
	curIter := n.groupIDAllocator.GetIter()
	gpIDs, err := GetGroupIDInfo(n.GetName())
	if err != nil {
		log.Errorf("Bridge %s failed to get GroupIDInfo from file: %s, can't update maxGroupID to %d for iter %d", n.GetName(), err, newMax, curIter)
		return err
	}

	if gpIDs.Exists == nil {
		gpIDs.Exists = make(map[uint32]uint32, 1)
	}
	gpIDs.Exists[curIter] = newMax
	err = SetGroupIDInfo(n.GetName(), gpIDs)
	if err != nil {
		log.Errorf("Bridge %s failed to update maxGroupID to %d for iter %d, err: %s", n.GetName(), newMax, curIter, err)
		return err
	}
	n.curMaxGroupID = newMax
	log.Infof("Bridge %s success to update maxGroupID to %d for iter %d", n.GetName(), newMax, curIter)
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

func (n *NatBridge) PacketRcvd(_ *ofctrl.OFSwitch, pkt *ofctrl.PacketIn) {
	if pkt.Data.Ethertype != protocol.IPv4_MSG {
		return
	}
	if pkt.Match.Type != openflow13.MatchType_OXM {
		return
	}

	var inport uint32
inport_check:
	for _, field := range pkt.Match.Fields {
		if field.Class != openflow13.OXM_CLASS_OPENFLOW_BASIC ||
			field.Field != openflow13.OXM_FIELD_IN_PORT {
			continue
		}
		switch t := field.Value.(type) {
		case *openflow13.InPortField:
			inport = t.InPort
			break inport_check
		}
	}
	if inport == 0 {
		return
	}

	newPkt := &ofctrl.Packet{
		SrcMac:     pkt.Data.HWDst,
		DstMac:     pkt.Data.HWSrc,
		SrcIP:      pkt.Data.Data.(*protocol.IPv4).NWDst,
		DstIP:      pkt.Data.Data.(*protocol.IPv4).NWSrc,
		IPProtocol: PROTOCOL_ICMP,
		TTL:        0xff,
		ICMPType:   0x3, // unreachable
		ICMPCode:   0x3, // destination port unreachable
	}
	pktOut := ofctrl.ConstructPacketOut(newPkt)
	pktOut.OutPort = &inport
	originData, _ := pkt.Data.Data.MarshalBinary()
	originLen := 20 + 8 // ip header and 8 bytes for nested pkt
	if len(originData) > originLen {
		originData = originData[:originLen]
	}
	pktOut.Header.ICMPHeader.Data = originData
	if err := ofctrl.SendPacket(n.OfSwitch, pktOut); err != nil {
		log.Errorf("failed to send pkt %+v, err = %s", newPkt, err)
	}
}
