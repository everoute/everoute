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
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/ofnet/ofctrl"

	"github.com/everoute/everoute/pkg/constants"
)

//nolint
const (
	VLAN_INPUT_TABLE                   = 0
	L2_FORWARDING_TABLE                = 5
	L2_LEARNING_TABLE                  = 10
	FROM_LOCAL_REDIRECT_TABLE          = 15
	FROM_LOCAL_ARP_PASS_TABLE          = 20
	FROM_LOCAL_ARP_TO_CONTROLLER_TABLE = 25
	CNI_CT_COMMIT_TABLE                = 100
	CNI_CT_REDIRECT_TABLE              = 105
	FACK_MAC                           = "ee:ee:ee:ee:ee:ee"
	P_NONE                             = 0xffff
	CNI_CONNTRACK_ZONE                 = 65510
)

type LocalBridge struct {
	BaseBridge

	vlanInputTable                 *ofctrl.Table // Table 0
	localEndpointL2ForwardingTable *ofctrl.Table // Table 5
	localEndpointL2LearningTable   *ofctrl.Table // table 10
	fromLocalRedirectTable         *ofctrl.Table // Table 15
	fromLocalArpPassTable          *ofctrl.Table // Table 20
	fromLocalArpSendToCtrlTable    *ofctrl.Table // Table 25
	cniConntrackCommitTable        *ofctrl.Table // Table 100
	cniConntrackRedirectTable      *ofctrl.Table // Table 105

	// Table 0
	fromLocalEndpointFlow map[uint32]*ofctrl.Flow // map local endpoint interface ofport to its fromLocalEndpointFlow
	// Table 5
	localToLocalBUMFlow      map[uint32]*ofctrl.Flow
	learnedIPAddressMapMutex sync.RWMutex
	learnedIPAddressMap      map[string]IPAddressReference
}

type IPAddressReference struct {
	lastUpdateTime time.Time
	updateTimes    int
}

func NewLocalBridge(brName string, datapathManager *DpManager) *LocalBridge {
	localBridge := new(LocalBridge)
	localBridge.name = brName
	localBridge.datapathManager = datapathManager
	localBridge.fromLocalEndpointFlow = make(map[uint32]*ofctrl.Flow)
	localBridge.localToLocalBUMFlow = make(map[uint32]*ofctrl.Flow)
	localBridge.learnedIPAddressMap = make(map[string]IPAddressReference)

	return localBridge
}

func (l *LocalBridge) PacketRcvd(sw *ofctrl.OFSwitch, pkt *ofctrl.PacketIn) {
	switch pkt.Data.Ethertype {
	case PROTOCOL_ARP:
		if (pkt.Match.Type == openflow13.MatchType_OXM) &&
			(pkt.Match.Fields[0].Class == openflow13.OXM_CLASS_OPENFLOW_BASIC) &&
			(pkt.Match.Fields[0].Field == openflow13.OXM_FIELD_IN_PORT) {
			// Get the input port number
			switch t := pkt.Match.Fields[0].Value.(type) {
			case *openflow13.InPortField:
				var inPortFld openflow13.InPortField
				inPortFld = *t
				l.processArp(pkt.Data, inPortFld.InPort)
			default:
				log.Errorf("error inport filed")
			}
		}

	case protocol.IPv4_MSG: // other type of packet that must processing by controller
		log.Errorf("controller received non arp packet error.")
		return
	}
}

func (l *LocalBridge) MultipartReply(sw *ofctrl.OFSwitch, rep *openflow13.MultipartReply) {
}

func (l *LocalBridge) processArp(pkt protocol.Ethernet, inPort uint32) {
	switch t := pkt.Data.(type) {
	case *protocol.ARP:
		var arpIn protocol.ARP = *t

		l.learnedIPAddressMapMutex.Lock()
		defer l.learnedIPAddressMapMutex.Unlock()
		l.setLocalEndpointIPAddr(arpIn, inPort)
		ipReference, ok := l.learnedIPAddressMap[arpIn.IPSrc.String()]
		if !ok {
			l.processLocalEndpointUpdate(arpIn, inPort)
		} else if ok && ipReference.updateTimes > 0 {
			l.processLocalEndpointUpdate(arpIn, inPort)
		}

		select {
		case l.datapathManager.ArpChan <- ArpInfo{InPort: inPort, Pkt: arpIn, BrName: l.name}:
		default: // Non-block when arpChan is full
		}
	default:
		log.Infof("error pkt type")
	}
}

func (l *LocalBridge) cleanLocalIPAddressCacheWorker(cycle, timeout int, stopChan <-chan struct{}) {
	ticker := time.NewTicker(time.Duration(cycle) * time.Second)
	for {
		select {
		case <-ticker.C:
			l.cleanLocalIPAddressCache(timeout)
		case <-stopChan:
			return
		}
	}
}

func (l *LocalBridge) cleanLocalIPAddressCache(timeout int) {
	l.learnedIPAddressMapMutex.Lock()
	defer l.learnedIPAddressMapMutex.Unlock()
	for ip, t := range l.learnedIPAddressMap {
		ipExpiredTime := t.lastUpdateTime.Add(time.Duration(timeout) * time.Second)
		if time.Now().After(ipExpiredTime) {
			delete(l.learnedIPAddressMap, ip)
		}
	}
}

func (l *LocalBridge) cleanLocalEndpointIPAddrWorker(cycle, timeout int, stopChan <-chan struct{}) {
	ticker := time.NewTicker(time.Duration(cycle) * time.Second)
	for {
		select {
		case <-ticker.C:
			l.cleanLocalIPAddr(timeout)
		case <-stopChan:
			return
		}
	}
}

func (l *LocalBridge) cleanLocalIPAddr(timeout int) {
	for endpointObj := range l.datapathManager.localEndpointDB.IterBuffered() {
		endpoint := endpointObj.Val.(*Endpoint)
		endpoint.IPAddrMutex.Lock()
		if endpoint.IPAddr == nil {
			endpoint.IPAddrMutex.Unlock()
			continue
		}
		ipExpiredTime := endpoint.IPAddrLastUpdateTime.Add(time.Duration(timeout) * time.Second)
		if time.Now().After(ipExpiredTime) {
			endpoint.IPAddr = nil
		}
		endpoint.IPAddrMutex.Unlock()
	}
}

func (l *LocalBridge) setLocalEndpointIPAddr(arpIn protocol.ARP, inPort uint32) {
	endpoint, isExist := l.getEndpointByPort(inPort)
	if !isExist {
		return
	}
	endpoint.IPAddrMutex.Lock()
	defer endpoint.IPAddrMutex.Unlock()
	if endpoint.MacAddrStr == arpIn.HWSrc.String() && endpoint.IPAddr == nil {
		copy(endpoint.IPAddr, arpIn.IPSrc)
		endpoint.IPAddrLastUpdateTime = time.Now()
	}
}

func (l *LocalBridge) processLocalEndpointUpdate(arpIn protocol.ARP, inPort uint32) {
	endpoint, isExist := l.getEndpointByPort(inPort)
	if !isExist {
		return
	}

	if endpoint.MacAddrStr != arpIn.HWSrc.String() && endpoint.IPAddr != nil {
		return
	}

	l.notifyLocalEndpointUpdate(arpIn, inPort)
	ipReference, ok := l.learnedIPAddressMap[arpIn.IPSrc.String()]
	if !ok {
		l.learnedIPAddressMap[arpIn.IPSrc.String()] = IPAddressReference{
			lastUpdateTime: time.Now(),
			updateTimes:    MaxIPAddressLearningFrenquency,
		}
	} else {
		l.learnedIPAddressMap[arpIn.IPSrc.String()] = IPAddressReference{
			lastUpdateTime: ipReference.lastUpdateTime,
			updateTimes:    ipReference.updateTimes - 1,
		}
	}
}

func (l *LocalBridge) getEndpointByPort(inPort uint32) (*Endpoint, bool) {
	for endpointObj := range l.datapathManager.localEndpointDB.IterBuffered() {
		endpoint := endpointObj.Val.(*Endpoint)
		if endpoint.BridgeName == l.name && endpoint.PortNo == inPort {
			return endpoint, true
		}
	}

	return nil, false
}

func (l *LocalBridge) notifyLocalEndpointUpdate(arpIn protocol.ARP, ofPort uint32) {
	updatedOfPortInfo := make(map[string]net.IP)
	updatedOfPortInfo[fmt.Sprintf("%s-%d", l.name, ofPort)] = arpIn.IPSrc
	l.datapathManager.ofPortIPAddressUpdateChan <- updatedOfPortInfo
}

// specific type Bridge interface
func (l *LocalBridge) BridgeInit() {
	sw := l.OfSwitch

	l.vlanInputTable = sw.DefaultTable()
	l.localEndpointL2ForwardingTable, _ = sw.NewTable(L2_FORWARDING_TABLE)
	l.localEndpointL2LearningTable, _ = sw.NewTable(L2_LEARNING_TABLE)
	l.fromLocalRedirectTable, _ = sw.NewTable(FROM_LOCAL_REDIRECT_TABLE)
	l.fromLocalArpPassTable, _ = sw.NewTable(FROM_LOCAL_ARP_PASS_TABLE)
	l.fromLocalArpSendToCtrlTable, _ = sw.NewTable(FROM_LOCAL_ARP_TO_CONTROLLER_TABLE)

	if err := l.initVlanInputTable(sw); err != nil {
		log.Fatalf("Failed to init local bridge vlanInput table, error: %v", err)
	}
	if err := l.initL2ForwardingTable(sw); err != nil {
		log.Fatalf("Failed to init local bridge l2 forwarding table, error: %v", err)
	}
	if err := l.initFromLocalL2LearningTable(); err != nil {
		log.Fatalf("Failed to init local bridge l2 learning table, error: %v", err)
	}
	if err := l.initFromLocalRedirectTable(sw); err != nil {
		log.Fatalf("Failed to init local bridge from local redirect table, error: %v", err)
	}
	if err := l.initFromLocalArpPassTable(sw); err != nil {
		log.Fatalf("Failed to init local bridge from local arp pass table, error: %v", err)
	}
	if err := l.initFromLocalArpSendToCtrlTable(sw); err != nil {
		log.Fatalf("Failed to init local bridge from local redirect table, error: %v", err)
	}
}

func (l *LocalBridge) BridgeInitCNI() {
	if l.datapathManager.Config.EnableCNI {
		sw := l.OfSwitch
		l.cniConntrackCommitTable, _ = sw.NewTable(CNI_CT_COMMIT_TABLE)
		l.cniConntrackRedirectTable, _ = sw.NewTable(CNI_CT_REDIRECT_TABLE)

		if err := l.initCniRelatedFlow(sw); err != nil {
			log.Fatalf("Failed to init cni related flows, error: %v", err)
		}
	}
}

func (l *LocalBridge) initLocalGwArpFlow(sw *ofctrl.OFSwitch) error {
	// arp response flow

	// target for local pod
	arpPodFlow, _ := l.vlanInputTable.NewFlow(ofctrl.FlowMatch{
		Priority:   HIGH_MATCH_FLOW_PRIORITY,
		InputPort:  l.datapathManager.Info.LocalGwOfPort,
		Ethertype:  PROTOCOL_ARP,
		ArpTpa:     &l.datapathManager.Info.PodCIDR[0].IP,
		ArpTpaMask: (*net.IP)(&l.datapathManager.Info.PodCIDR[0].Mask),
	})
	flood, _ := sw.OutputPort(openflow13.P_FLOOD)
	if err := arpPodFlow.Next(flood); err != nil {
		return fmt.Errorf("failed to install flow, error: %v", err)
	}

	// target for other ip, response arp with uplink gateway mac address
	arpGwFlow, _ := l.vlanInputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		InputPort: l.datapathManager.Info.LocalGwOfPort,
		Ethertype: PROTOCOL_ARP,
	})
	// set actions for arp response
	if err := arpGwFlow.MoveField(32, 0, 0, "nxm_of_arp_tpa", "nxm_of_arp_spa", false); err != nil {
		return err
	}
	if err := arpGwFlow.LoadField("nxm_nx_arp_sha", ParseMacToUint64(l.datapathManager.Info.GatewayMac), openflow13.NewNXRange(0, 47)); err != nil {
		return err
	}
	if err := arpGwFlow.MoveField(48, 0, 0, "nxm_nx_arp_sha", "nxm_nx_arp_tha", false); err != nil {
		return err
	}
	if err := arpGwFlow.LoadField("nxm_of_arp_op", 0x0002, openflow13.NewNXRange(0, 15)); err != nil {
		return err
	}
	fakeMac, _ := net.ParseMAC(FACK_MAC)
	if err := arpGwFlow.SetMacSa(fakeMac); err != nil {
		return err
	}
	if err := arpGwFlow.MoveField(48, 0, 0, "nxm_of_eth_src", "nxm_of_eth_dst", false); err != nil {
		return err
	}

	outputInPort, _ := sw.OutputPort(openflow13.P_IN_PORT)
	if err := arpGwFlow.Next(outputInPort); err != nil {
		return fmt.Errorf("failed to install from arpGwFlow flow, error: %v", err)
	}

	// target for other ip, response arp with uplink gateway mac address
	arpGwFlowHigh, _ := l.vlanInputTable.NewFlow(ofctrl.FlowMatch{
		Priority:   HIGH_MATCH_FLOW_PRIORITY + FLOW_MATCH_OFFSET,
		InputPort:  l.datapathManager.Info.LocalGwOfPort,
		Ethertype:  PROTOCOL_ARP,
		ArpTpa:     &l.datapathManager.Info.GatewayIP,
		ArpTpaMask: &net.IPv4bcast,
	})
	// set actions for arp response
	if err := arpGwFlowHigh.MoveField(32, 0, 0, "nxm_of_arp_tpa", "nxm_of_arp_spa", false); err != nil {
		return err
	}
	if err := arpGwFlowHigh.LoadField("nxm_nx_arp_sha", ParseMacToUint64(l.datapathManager.Info.GatewayMac), openflow13.NewNXRange(0, 47)); err != nil {
		return err
	}
	if err := arpGwFlowHigh.MoveField(48, 0, 0, "nxm_nx_arp_sha", "nxm_nx_arp_tha", false); err != nil {
		return err
	}
	if err := arpGwFlowHigh.LoadField("nxm_of_arp_op", 0x0002, openflow13.NewNXRange(0, 15)); err != nil {
		return err
	}
	if err := arpGwFlowHigh.SetMacSa(fakeMac); err != nil {
		return err
	}
	if err := arpGwFlowHigh.MoveField(48, 0, 0, "nxm_of_eth_src", "nxm_of_eth_dst", false); err != nil {
		return err
	}
	if err := arpGwFlowHigh.Next(outputInPort); err != nil {
		return fmt.Errorf("failed to install from arpGwFlowHigh flow, error: %v", err)
	}
	return nil
}

func (l *LocalBridge) initToLocalGwFlow(sw *ofctrl.OFSwitch) error {
	localToLocalGw, _ := l.fromLocalRedirectTable.NewFlow(ofctrl.FlowMatch{
		Priority:  HIGH_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
		IpDa:      &l.datapathManager.Info.ClusterCIDR.IP,
		IpDaMask:  (*net.IP)(&l.datapathManager.Info.ClusterCIDR.Mask),
	})
	_ = localToLocalGw.LoadField("nxm_of_eth_dst", ParseMacToUint64(l.datapathManager.Info.LocalGwMac),
		openflow13.NewNXRange(0, 47))
	_ = localToLocalGw.LoadField("nxm_nx_pkt_mark", 0x1,
		openflow13.NewNXRange(29, 29))
	outputPortLocalGateWay, _ := sw.OutputPort(l.datapathManager.Info.LocalGwOfPort)
	if err := localToLocalGw.Next(outputPortLocalGateWay); err != nil {
		return fmt.Errorf("failed to install from localToLocalGw flow, error: %v", err)
	}

	pktMarkMask := uint32(0x20000000)
	outToLocalGwBypassLocal, _ := l.vlanInputTable.NewFlow(ofctrl.FlowMatch{
		Priority:    HIGH_MATCH_FLOW_PRIORITY + FLOW_MATCH_OFFSET,
		Ethertype:   PROTOCOL_IP,
		InputPort:   uint32(l.datapathManager.BridgeChainPortMap[l.name][LocalToPolicySuffix]),
		PktMark:     0x20000000,
		PktMarkMask: &pktMarkMask,
	})
	if err := outToLocalGwBypassLocal.Resubmit(nil, &l.localEndpointL2ForwardingTable.TableId); err != nil {
		return fmt.Errorf("failed to install outToLocalGwBypassLocal flow, error: %v", err)
	}
	if err := outToLocalGwBypassLocal.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install outToLocalGwBypassLocal flow, error: %v", err)
	}

	outToLocalGw, _ := l.vlanInputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  HIGH_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
		InputPort: uint32(l.datapathManager.BridgeChainPortMap[l.name][LocalToPolicySuffix]),
	})
	if err := outToLocalGw.LoadField("nxm_of_eth_dst", ParseMacToUint64(l.datapathManager.Info.LocalGwMac),
		openflow13.NewNXRange(0, 47)); err != nil {
		return err
	}
	if err := outToLocalGw.Next(outputPortLocalGateWay); err != nil {
		return fmt.Errorf("failed to install from outToLocalGw flow, error: %v", err)
	}

	// Commit CT for traffic from Pod (These traffic will bypass local gateway)

	// Bypass default with higher priority, transmit all ip pkt to ct commit table
	var cniConntrackZone uint16 = CNI_CONNTRACK_ZONE
	var cniCommitTalbe uint8 = CNI_CT_COMMIT_TABLE
	ctAction := ofctrl.NewConntrackAction(false, false, &cniCommitTalbe, &cniConntrackZone)
	cniDefaultNoraml, _ := l.fromLocalRedirectTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY + FLOW_MATCH_OFFSET,
		Ethertype: PROTOCOL_IP,
	})
	_ = cniDefaultNoraml.SetConntrack(ctAction)

	// Commit all traffic to CNI CT zone
	// This CT commit is in OVS, but the reverse traffic will process by netfilter.
	// So this flow do not match ct state, and commit all traffic to CT. It will avoid the state miss
	// match like TCP syn_sent,syn_recv which is not OVS.
	var cniRedirectTable uint8 = CNI_CT_REDIRECT_TABLE
	cniCommitCT, _ := l.cniConntrackCommitTable.NewFlow(ofctrl.FlowMatch{
		Priority:  NORMAL_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
	})
	ctCommitAction := ofctrl.NewConntrackAction(true, false, &cniRedirectTable, &cniConntrackZone)
	_ = cniCommitCT.SetConntrack(ctCommitAction)

	// Redirect traffic back to policy bridge
	cniConntrackRedirect, _ := l.cniConntrackRedirectTable.NewFlow(ofctrl.FlowMatch{
		Priority: NORMAL_MATCH_FLOW_PRIORITY,
	})
	outputPortPolicy, _ := sw.OutputPort(l.datapathManager.BridgeChainPortMap[l.name][LocalToPolicySuffix])
	if err := cniConntrackRedirect.Next(outputPortPolicy); err != nil {
		return fmt.Errorf("failed to install cniConntrackRedirect localGwToPolicy flow, error: %v", err)
	}

	return nil
}

func (l *LocalBridge) initFromLocalGwFlow(sw *ofctrl.OFSwitch) error {
	pktMarkMask := uint32(0x20000000)
	localGwToPolicy, _ := l.vlanInputTable.NewFlow(ofctrl.FlowMatch{
		Priority:    HIGH_MATCH_FLOW_PRIORITY,
		Ethertype:   PROTOCOL_IP,
		InputPort:   l.datapathManager.Info.LocalGwOfPort,
		PktMark:     0x20000000,
		PktMarkMask: &pktMarkMask,
	})
	if err := localGwToPolicy.LoadField("nxm_of_eth_src", ParseMacToUint64(l.datapathManager.Info.LocalGwMac),
		openflow13.NewNXRange(0, 47)); err != nil {
		return err
	}
	outputPortPolicy, _ := sw.OutputPort(uint32(l.datapathManager.BridgeChainPortMap[l.name][LocalToPolicySuffix]))
	if err := localGwToPolicy.Next(outputPortPolicy); err != nil {
		return fmt.Errorf("failed to install localGwToPolicy flow, error: %v", err)
	}

	localGwToLocal, _ := l.vlanInputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
		InputPort: l.datapathManager.Info.LocalGwOfPort,
	})
	if err := localGwToLocal.LoadField("nxm_of_eth_src", ParseMacToUint64(l.datapathManager.Info.LocalGwMac),
		openflow13.NewNXRange(0, 47)); err != nil {
		return err
	}
	if err := localGwToLocal.Resubmit(nil, &l.localEndpointL2ForwardingTable.TableId); err != nil {
		return fmt.Errorf("failed to install localGwToLocal flow, error: %v", err)
	}
	if err := localGwToLocal.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install localGwToLocal flow, error: %v", err)
	}

	return nil
}

func (l *LocalBridge) initCniRelatedFlow(sw *ofctrl.OFSwitch) error {
	if err := l.initLocalGwArpFlow(sw); err != nil {
		return err
	}

	// traffic into local gateway
	if err := l.initToLocalGwFlow(sw); err != nil {
		return err
	}

	// traffic from local gateway
	if err := l.initFromLocalGwFlow(sw); err != nil {
		return err
	}

	return nil
}

func (l *LocalBridge) InitFromLocalLearnAction(fromLocalLearnAction *ofctrl.LearnAction) error {
	learnDstMatchField1 := &ofctrl.LearnField{
		Name:  "nxm_of_vlan_tci",
		Start: 0,
	}
	learnSrcMatchField1 := &ofctrl.LearnField{
		Name:  "nxm_of_vlan_tci",
		Start: 0,
	}
	learnDstMatchField2 := &ofctrl.LearnField{
		Name:  "nxm_of_eth_dst",
		Start: 0,
	}
	learnSrcMatchField2 := &ofctrl.LearnField{
		Name:  "nxm_of_eth_src",
		Start: 0,
	}

	err := fromLocalLearnAction.AddLearnedMatch(learnDstMatchField1, 12, learnSrcMatchField1, nil)
	if err != nil {
		return fmt.Errorf("failed to initialize learn action, AddLearnedMatch nxm_of_vlan_tci failure, error: %v", err)
	}
	err = fromLocalLearnAction.AddLearnedMatch(learnDstMatchField2, 48, learnSrcMatchField2, nil)
	if err != nil {
		return fmt.Errorf("failed to initialize learn action, AddLearnedMatch nxm_of_eth_dst failure, error: %v", err)
	}

	srcValue := make([]byte, 2)
	binary.BigEndian.PutUint16(srcValue, uint16(0))
	err = fromLocalLearnAction.AddLearnedLoadAction(&ofctrl.LearnField{Name: "nxm_of_vlan_tci", Start: 0}, 13, nil, srcValue)
	if err != nil {
		return fmt.Errorf("failed to initialize learn action, AddLearnedLoadAction: load:0x0->NXM_OF_vlan_tci[] failure, error: %v", err)
	}
	err = fromLocalLearnAction.AddLearnedOutputAction(&ofctrl.LearnField{Name: "nxm_of_in_port", Start: 0}, 16)
	if err != nil {
		return fmt.Errorf("failed to initialize learn action: AddLearnedOutputAction output:nxm_of_in_port failure, error: %v", err)
	}

	return nil
}

func (l *LocalBridge) InitFromLocalTrunkPortLearnAction(fromLocalLearnAction *ofctrl.LearnAction) error {
	learnDstMatchField1 := &ofctrl.LearnField{
		Name:  "nxm_of_vlan_tci",
		Start: 0,
	}
	learnSrcMatchField1 := &ofctrl.LearnField{
		Name:  "nxm_of_vlan_tci",
		Start: 0,
	}
	learnDstMatchField2 := &ofctrl.LearnField{
		Name:  "nxm_of_eth_dst",
		Start: 0,
	}
	learnSrcMatchField2 := &ofctrl.LearnField{
		Name:  "nxm_of_eth_src",
		Start: 0,
	}

	err := fromLocalLearnAction.AddLearnedMatch(learnDstMatchField1, 12, learnSrcMatchField1, nil)
	if err != nil {
		return fmt.Errorf("failed to initialize learn action, AddLearnedMatch nxm_of_vlan_tci failure, error: %v", err)
	}
	err = fromLocalLearnAction.AddLearnedMatch(learnDstMatchField2, 48, learnSrcMatchField2, nil)
	if err != nil {
		return fmt.Errorf("failed to initialize learn action, AddLearnedMatch nxm_of_eth_dst failure, error: %v", err)
	}

	err = fromLocalLearnAction.AddLearnedOutputAction(&ofctrl.LearnField{Name: "nxm_of_in_port", Start: 0}, 16)
	if err != nil {
		return fmt.Errorf("failed to initialize learn action: AddLearnedOutputAction output:nxm_of_in_port failure, error: %v", err)
	}

	return nil
}

func (l *LocalBridge) initVlanInputTable(sw *ofctrl.OFSwitch) error {
	// vlanInput table
	fromUpstreamFlow, _ := l.vlanInputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		InputPort: uint32(l.datapathManager.BridgeChainPortMap[l.name][LocalToPolicySuffix]),
	})
	if err := fromUpstreamFlow.Next(l.localEndpointL2ForwardingTable); err != nil {
		return fmt.Errorf("failed to install from upstream flow, error: %v", err)
	}

	vlanInputTableDefaultFlow, _ := l.vlanInputTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := vlanInputTableDefaultFlow.Resubmit(nil, &l.localEndpointL2LearningTable.TableId); err != nil {
		return fmt.Errorf("failed to setup vlan input table default flow resubmit to learning table action, error: %v", err)
	}
	if err := vlanInputTableDefaultFlow.Resubmit(nil, &l.fromLocalRedirectTable.TableId); err != nil {
		return fmt.Errorf("failed to setup vlan input table default flow resubmit to redirect table action, error: %v", err)
	}
	if err := vlanInputTableDefaultFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install vlan input table default flow, error: %v", err)
	}

	return nil
}

func (l *LocalBridge) initL2ForwardingTable(sw *ofctrl.OFSwitch) error {
	// l2 forwarding table
	localToLocalBUMDefaultFlow, _ := l.localEndpointL2ForwardingTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	outputPort, _ := sw.OutputPort(openflow13.P_NORMAL)
	if err := localToLocalBUMDefaultFlow.Next(outputPort); err != nil {
		return fmt.Errorf("failed to install local to local bum default flow, error: %v", err)
	}

	return nil
}

func (l *LocalBridge) initFromLocalL2LearningTable() error {
	// l2 learning table
	// NOTE whether cookie id need to be sync
	l2LearningFlow, _ := l.localEndpointL2LearningTable.NewFlow(ofctrl.FlowMatch{
		Priority: NORMAL_MATCH_FLOW_PRIORITY,
	})

	fromLocalLearnAction := ofctrl.NewLearnAction(L2_FORWARDING_TABLE, MID_MATCH_FLOW_PRIORITY+3,
		LocalBridgeL2ForwardingTableIdleTimeout, LocalBridgeL2ForwardingTableHardTimeout, 0, 0, 0)
	if err := l.InitFromLocalLearnAction(fromLocalLearnAction); err != nil {
		return fmt.Errorf("failed to initialize from local learn action, error: %v", err)
	}

	if err := l2LearningFlow.Learn(fromLocalLearnAction); err != nil {
		return fmt.Errorf("failed to install l2Learning flow learn action, error: %v", err)
	}
	if err := l2LearningFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install l2Learning flow, error: %v", err)
	}

	trunkPortL2LearningFlow, _ := l.localEndpointL2LearningTable.NewFlow(ofctrl.FlowMatch{
		Priority: NORMAL_MATCH_FLOW_PRIORITY,
		Regs: []*ofctrl.NXRegister{
			{
				RegID: constants.OVSReg3,
				Data:  0x1,
				Range: openflow13.NewNXRange(0, 1),
			},
		},
	})

	fromLocalTrunkLearnAction := ofctrl.NewLearnAction(L2_FORWARDING_TABLE, MID_MATCH_FLOW_PRIORITY+3,
		LocalBridgeL2ForwardingTableIdleTimeout, LocalBridgeL2ForwardingTableHardTimeout, 0, 0, 0)
	if err := l.InitFromLocalTrunkPortLearnAction(fromLocalTrunkLearnAction); err != nil {
		return fmt.Errorf("failed to initialize from local learn action, error: %v", err)
	}

	if err := trunkPortL2LearningFlow.Learn(fromLocalTrunkLearnAction); err != nil {
		return fmt.Errorf("failed to install from trunk port l2Learning flow learn action, error: %v", err)
	}
	if err := trunkPortL2LearningFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install form trunk port l2Learning flow, error: %v", err)
	}

	return nil
}

func (l *LocalBridge) initFromLocalRedirectTable(sw *ofctrl.OFSwitch) error {
	// from local arp, duplicate it, send one to of controller to ip learning; send other to local to policy port
	fromLocalArpFlow, _ := l.fromLocalRedirectTable.NewFlow(ofctrl.FlowMatch{
		Priority:  HIGH_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_ARP,
	})
	if err := fromLocalArpFlow.Resubmit(nil, &l.fromLocalArpPassTable.TableId); err != nil {
		return err
	}
	if err := fromLocalArpFlow.Resubmit(nil, &l.fromLocalArpSendToCtrlTable.TableId); err != nil {
		return err
	}
	if err := fromLocalArpFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install from local arp redirect flow, error: %v", err)
	}

	// from local other protocol type, send to local to policy port
	fromLocalOtherRedirectFlow, _ := l.fromLocalRedirectTable.NewFlow(ofctrl.FlowMatch{
		Priority: MID_MATCH_FLOW_PRIORITY,
	})
	outputPort, _ := sw.OutputPort(l.datapathManager.BridgeChainPortMap[l.name][LocalToPolicySuffix])
	if err := fromLocalOtherRedirectFlow.Next(outputPort); err != nil {
		return fmt.Errorf("failed to install from local other redirect flow, error: %v", err)
	}

	return nil
}

func (l *LocalBridge) initFromLocalArpPassTable(sw *ofctrl.OFSwitch) error {
	fromLocalArpPassFlow, _ := l.fromLocalArpPassTable.NewFlow(ofctrl.FlowMatch{
		Priority:  HIGH_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_ARP,
	})
	outputPort, _ := l.OfSwitch.OutputPort(l.datapathManager.BridgeChainPortMap[l.name][LocalToPolicySuffix])
	if err := fromLocalArpPassFlow.Next(outputPort); err != nil {
		return fmt.Errorf("failed to install from local arp pass flow, error: %v", err)
	}

	return nil
}

func (l *LocalBridge) initFromLocalArpSendToCtrlTable(sw *ofctrl.OFSwitch) error {
	fromLocalArpSendToCtrlFlow, _ := l.fromLocalArpSendToCtrlTable.NewFlow(ofctrl.FlowMatch{
		Priority:  HIGH_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_ARP,
	})
	sendToControllerAct := fromLocalArpSendToCtrlFlow.NewControllerAction(sw.ControllerID, 0)
	_ = fromLocalArpSendToCtrlFlow.SendToController(sendToControllerAct)
	if err := fromLocalArpSendToCtrlFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install from local arp send to controller flow, error: %v", err)
	}

	return nil
}

func (l *LocalBridge) BridgeReset() {
}

func (l *LocalBridge) AddLocalEndpoint(endpoint *Endpoint) error {
	// skip ovs patch port
	if strings.HasSuffix(endpoint.InterfaceName, LocalToPolicySuffix) {
		return nil
	}
	if strings.HasSuffix(endpoint.InterfaceName, LocalToNatSuffix) {
		return nil
	}
	// skip cni gateway
	if l.datapathManager.Info.LocalGwName == endpoint.InterfaceName {
		return nil
	}

	// Table 0, from local endpoint
	var vlanIDMask uint16 = 0x1fff
	vlanInputTableFromLocalFlow, _ := l.vlanInputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		InputPort: endpoint.PortNo,
	})
	if endpoint.VlanID != 0 {
		if err := vlanInputTableFromLocalFlow.SetVlan(endpoint.VlanID); err != nil {
			return err
		}
	}
	if endpoint.Trunk != "" {
		if err := vlanInputTableFromLocalFlow.LoadField("nxm_nx_reg3", uint64(1),
			openflow13.NewNXRange(0, 1)); err != nil {
			return err
		}
	}
	if err := vlanInputTableFromLocalFlow.LoadField("nxm_nx_pkt_mark", uint64(endpoint.PortNo),
		openflow13.NewNXRange(0, 15)); err != nil {
		return err
	}
	if err := vlanInputTableFromLocalFlow.Resubmit(nil, &l.localEndpointL2LearningTable.TableId); err != nil {
		return err
	}
	if err := vlanInputTableFromLocalFlow.Resubmit(nil, &l.fromLocalRedirectTable.TableId); err != nil {
		return err
	}
	if err := vlanInputTableFromLocalFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return err
	}
	log.Infof("add from local endpoint flow: %v", vlanInputTableFromLocalFlow)
	l.fromLocalEndpointFlow[endpoint.PortNo] = vlanInputTableFromLocalFlow

	// Table 1, from local to local bum redirect flow
	if endpoint.Trunk == "" {
		endpointMac, _ := net.ParseMAC(endpoint.MacAddrStr)
		localToLocalBUMFlow, _ := l.localEndpointL2ForwardingTable.NewFlow(ofctrl.FlowMatch{
			Priority:   MID_MATCH_FLOW_PRIORITY,
			MacSa:      &endpointMac,
			VlanId:     endpoint.VlanID,
			VlanIdMask: &vlanIDMask,
		})
		if err := localToLocalBUMFlow.LoadField("nxm_of_vlan_tci", 0, openflow13.NewNXRange(0, 12)); err != nil {
			return err
		}
		if err := localToLocalBUMFlow.LoadField("nxm_of_in_port", uint64(endpoint.PortNo), openflow13.NewNXRange(0, 15)); err != nil {
			return err
		}
		if err := localToLocalBUMFlow.Next(l.OfSwitch.NormalLookup()); err != nil {
			return err
		}
		log.Infof("add local to local flow: %v", localToLocalBUMFlow)
		l.localToLocalBUMFlow[endpoint.PortNo] = localToLocalBUMFlow
	} else {
		endpointMac, _ := net.ParseMAC(endpoint.MacAddrStr)
		localToLocalBUMFlow, _ := l.localEndpointL2ForwardingTable.NewFlow(ofctrl.FlowMatch{
			Priority: MID_MATCH_FLOW_PRIORITY,
			MacSa:    &endpointMac,
		})
		if err := localToLocalBUMFlow.LoadField("nxm_of_in_port", uint64(endpoint.PortNo), openflow13.NewNXRange(0, 15)); err != nil {
			return err
		}
		if err := localToLocalBUMFlow.Next(l.OfSwitch.NormalLookup()); err != nil {
			return err
		}
		log.Infof("add local to local flow: %v", localToLocalBUMFlow)
		l.localToLocalBUMFlow[endpoint.PortNo] = localToLocalBUMFlow
	}

	return nil
}

func (l *LocalBridge) RemoveLocalEndpoint(endpoint *Endpoint) error {
	// remove table 0 from local endpoing flow
	if localEndpointFlow, ok := l.fromLocalEndpointFlow[endpoint.PortNo]; ok {
		log.Infof("remove from local endpoint flow: %v", localEndpointFlow)
		if err := localEndpointFlow.Delete(); err != nil {
			return err
		}
		delete(l.fromLocalEndpointFlow, endpoint.PortNo)
	}

	// remote table 1 local to local bum redirect flow
	log.Infof("remove from local to local flow: %v", l.localToLocalBUMFlow[endpoint.PortNo])
	if err := l.localToLocalBUMFlow[endpoint.PortNo].Delete(); err != nil {
		return err
	}
	delete(l.localToLocalBUMFlow, endpoint.PortNo)

	return nil
}

func (l *LocalBridge) AddMicroSegmentRule(rule *EveroutePolicyRule, direction uint8, tier uint8, mode string) (*FlowEntry, error) {
	return nil, nil
}

func (l *LocalBridge) RemoveMicroSegmentRule(rule *EveroutePolicyRule) error {
	return nil
}

func (l *LocalBridge) AddVNFInstance() error {
	return nil
}

func (l *LocalBridge) RemoveVNFInstance() error {
	return nil
}

func (l *LocalBridge) AddSFCRule() error {
	return nil
}

func (l *LocalBridge) RemoveSFCRule() error {
	return nil
}
