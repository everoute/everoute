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
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/ofnet/ofctrl"
)

//nolint
const (
	VLAN_INPUT_TABLE          = 0
	L2_FORWARDING_TABLE       = 5
	L2_LEARNING_TABLE         = 10
	FROM_LOCAL_REDIRECT_TABLE = 15
	FACK_MAC                  = "ee:ee:ee:ee:ee:ee"
)

type LocalBridge struct {
	name            string
	OfSwitch        *ofctrl.OFSwitch
	datapathManager *DpManager

	vlanInputTable                 *ofctrl.Table // Table 0
	localEndpointL2ForwardingTable *ofctrl.Table // Table 5
	localEndpointL2LearningTable   *ofctrl.Table // table 10
	fromLocalRedirectTable         *ofctrl.Table // Table 15

	// Table 0
	fromLocalEndpointFlow map[uint32]*ofctrl.Flow // map local endpoint interface ofport to its fromLocalEndpointFlow
	// Table 5
	localToLocalBUMFlow map[uint32]*ofctrl.Flow

	localSwitchStatusMuxtex sync.RWMutex
	isLocalSwitchConnected  bool
}

func NewLocalBridge(brName string, datapathManager *DpManager) *LocalBridge {
	localBridge := new(LocalBridge)
	localBridge.name = brName
	localBridge.datapathManager = datapathManager
	localBridge.fromLocalEndpointFlow = make(map[uint32]*ofctrl.Flow)
	localBridge.localToLocalBUMFlow = make(map[uint32]*ofctrl.Flow)

	return localBridge
}

// Controller interface
func (l *LocalBridge) SwitchConnected(sw *ofctrl.OFSwitch) {
	log.Infof("Switch %s connected", l.name)

	l.OfSwitch = sw

	l.localSwitchStatusMuxtex.Lock()
	l.isLocalSwitchConnected = true
	l.localSwitchStatusMuxtex.Unlock()
}

func (l *LocalBridge) SwitchDisconnected(sw *ofctrl.OFSwitch) {
	log.Infof("Switch %s disconnected", l.name)

	l.localSwitchStatusMuxtex.Lock()
	l.isLocalSwitchConnected = false
	l.localSwitchStatusMuxtex.Unlock()

	l.OfSwitch = nil
}

func (l *LocalBridge) IsSwitchConnected() bool {
	l.localSwitchStatusMuxtex.Lock()
	defer l.localSwitchStatusMuxtex.Unlock()

	return l.isLocalSwitchConnected
}

func (l *LocalBridge) WaitForSwitchConnection() {
	for i := 0; i < 20; i++ {
		time.Sleep(1 * time.Second)
		l.localSwitchStatusMuxtex.Lock()
		if l.isLocalSwitchConnected {
			l.localSwitchStatusMuxtex.Unlock()
			return
		}
		l.localSwitchStatusMuxtex.Unlock()
	}

	log.Fatalf("OVS switch %s Failed to connect", l.name)
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

		l.processLocalEndpointUpdate(arpIn, inPort)
		// NOTE output to local-to-policy-patch port
		l.arpOutput(pkt, inPort, uint32(LOCAL_TO_POLICY_PORT))
	default:
		log.Infof("error pkt type")
	}
}

func (l *LocalBridge) processLocalEndpointUpdate(arpIn protocol.ARP, inPort uint32) {
	for endpointObj := range l.datapathManager.localEndpointDB.IterBuffered() {
		endpoint := endpointObj.Val.(*Endpoint)
		if endpoint.PortNo == inPort {
			l.notifyLocalEndpointUpdate(arpIn, inPort)
		}
	}
}

func (l *LocalBridge) notifyLocalEndpointUpdate(arpIn protocol.ARP, ofPort uint32) {
	updatedOfPortInfo := make(map[string]net.IP)
	updatedOfPortInfo[fmt.Sprintf("%s-%d", l.name, ofPort)] = arpIn.IPSrc
	l.datapathManager.ofPortIPAddressUpdateChan <- updatedOfPortInfo
}

func (l *LocalBridge) arpOutput(pkt protocol.Ethernet, inPort uint32, outputPort uint32) {
	arpIn := pkt.Data.(*protocol.ARP)

	ethPkt := protocol.NewEthernet()
	ethPkt.VLANID = pkt.VLANID
	ethPkt.HWDst = pkt.HWDst
	ethPkt.HWSrc = pkt.HWSrc
	ethPkt.Ethertype = PROTOCOL_ARP
	ethPkt.Data = arpIn

	pktOut := openflow13.NewPacketOut()
	pktOut.InPort = inPort
	pktOut.Data = ethPkt
	pktOut.AddAction(openflow13.NewActionOutput(outputPort))

	l.OfSwitch.Send(pktOut)
}

// specific type Bridge interface
func (l *LocalBridge) BridgeInit() {
	sw := l.OfSwitch

	l.vlanInputTable = sw.DefaultTable()
	l.localEndpointL2ForwardingTable, _ = sw.NewTable(L2_FORWARDING_TABLE)
	l.localEndpointL2LearningTable, _ = sw.NewTable(L2_LEARNING_TABLE)
	l.fromLocalRedirectTable, _ = sw.NewTable(FROM_LOCAL_REDIRECT_TABLE)

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
}

func (l *LocalBridge) BridgeInitCNI() {
	if l.datapathManager.AgentInfo.EnableCNI {
		sw := l.OfSwitch
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
		InputPort:  uint32(LOCAL_GATEWAY_PORT),
		Ethertype:  PROTOCOL_ARP,
		ArpTpa:     &l.datapathManager.AgentInfo.PodCIDR[0].IP,
		ArpTpaMask: (*net.IP)(&l.datapathManager.AgentInfo.PodCIDR[0].Mask),
	})
	flood, _ := sw.OutputPort(openflow13.P_FLOOD)
	if err := arpPodFlow.Next(flood); err != nil {
		return fmt.Errorf("failed to install flow, error: %v", err)
	}

	// target for other ip, response arp with uplink gateway mac address
	arpGwFlow, _ := l.vlanInputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		InputPort: uint32(LOCAL_GATEWAY_PORT),
		Ethertype: PROTOCOL_ARP,
	})
	// set actions for arp response
	if err := arpGwFlow.MoveField(32, 0, 0, "nxm_of_arp_tpa", "nxm_of_arp_spa", false); err != nil {
		return err
	}
	if err := arpGwFlow.LoadField("nxm_nx_arp_sha", ParseMacToUint64(l.datapathManager.AgentInfo.GatewayMac), openflow13.NewNXRange(0, 47)); err != nil {
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
		InputPort:  uint32(LOCAL_GATEWAY_PORT),
		Ethertype:  PROTOCOL_ARP,
		ArpTpa:     &l.datapathManager.AgentInfo.GatewayIP,
		ArpTpaMask: &net.IPv4bcast,
	})
	// set actions for arp response
	if err := arpGwFlowHigh.MoveField(32, 0, 0, "nxm_of_arp_tpa", "nxm_of_arp_spa", false); err != nil {
		return err
	}
	if err := arpGwFlowHigh.LoadField("nxm_nx_arp_sha", ParseMacToUint64(l.datapathManager.AgentInfo.GatewayMac), openflow13.NewNXRange(0, 47)); err != nil {
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
	})
	_ = localToLocalGw.LoadField("nxm_of_eth_dst", ParseMacToUint64(l.datapathManager.AgentInfo.LocalGwMac),
		openflow13.NewNXRange(0, 47))
	outputPortLocalGateWay, _ := sw.OutputPort(LOCAL_GATEWAY_PORT)
	if err := localToLocalGw.Next(outputPortLocalGateWay); err != nil {
		return fmt.Errorf("failed to install from localToLocalGw flow, error: %v", err)
	}

	outToLocalGw, _ := l.vlanInputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  HIGH_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
		InputPort: uint32(LOCAL_TO_POLICY_PORT),
	})
	if err := outToLocalGw.LoadField("nxm_of_eth_dst", ParseMacToUint64(l.datapathManager.AgentInfo.LocalGwMac),
		openflow13.NewNXRange(0, 47)); err != nil {
		return err
	}
	if err := outToLocalGw.Next(outputPortLocalGateWay); err != nil {
		return fmt.Errorf("failed to install from outToLocalGw flow, error: %v", err)
	}

	gwToLocalGw, _ := l.vlanInputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  HIGH_MATCH_FLOW_PRIORITY + 3*FLOW_MATCH_OFFSET,
		Ethertype: PROTOCOL_IP,
		InputPort: uint32(LOCAL_TO_POLICY_PORT),
		IpSa:      &l.datapathManager.AgentInfo.GatewayIP,
		IpSaMask:  &net.IPv4bcast,
	})
	if err := gwToLocalGw.LoadField("nxm_of_eth_dst", ParseMacToUint64(l.datapathManager.AgentInfo.LocalGwMac),
		openflow13.NewNXRange(0, 47)); err != nil {
		return err
	}
	if err := gwToLocalGw.Next(outputPortLocalGateWay); err != nil {
		return fmt.Errorf("failed to install from gwToLocalGw flow, error: %v", err)
	}

	fromPolicyBypass, _ := l.vlanInputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  HIGH_MATCH_FLOW_PRIORITY + 2*FLOW_MATCH_OFFSET,
		Ethertype: PROTOCOL_IP,
		InputPort: uint32(LOCAL_TO_POLICY_PORT),
		IpSa:      &l.datapathManager.AgentInfo.PodCIDR[0].IP,
		IpSaMask:  (*net.IP)(&l.datapathManager.AgentInfo.PodCIDR[0].Mask),
	})
	if err := fromPolicyBypass.Resubmit(nil, &l.localEndpointL2ForwardingTable.TableId); err != nil {
		return fmt.Errorf("failed to install fromPolicyBypass flow, error: %v", err)
	}
	if err := fromPolicyBypass.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install fromPolicyBypass flow, error: %v", err)
	}
	return nil
}

func (l *LocalBridge) initFromLocalGwFlow(sw *ofctrl.OFSwitch) error {
	localGwToPolicy, _ := l.vlanInputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  HIGH_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
		InputPort: uint32(LOCAL_GATEWAY_PORT),
		IpSa:      &l.datapathManager.AgentInfo.PodCIDR[0].IP,
		IpSaMask:  (*net.IP)(&l.datapathManager.AgentInfo.PodCIDR[0].Mask),
	})
	if err := localGwToPolicy.LoadField("nxm_of_eth_src", ParseMacToUint64(l.datapathManager.AgentInfo.LocalGwMac),
		openflow13.NewNXRange(0, 47)); err != nil {
		return err
	}
	outputPortPolicy, _ := sw.OutputPort(LOCAL_TO_POLICY_PORT)
	if err := localGwToPolicy.Next(outputPortPolicy); err != nil {
		return fmt.Errorf("failed to install localGwToPolicy flow, error: %v", err)
	}

	localGwResumit, _ := l.vlanInputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
		InputPort: uint32(LOCAL_GATEWAY_PORT),
	})
	if err := localGwResumit.LoadField("nxm_of_eth_src", ParseMacToUint64(l.datapathManager.AgentInfo.LocalGwMac),
		openflow13.NewNXRange(0, 47)); err != nil {
		return err
	}
	if err := localGwResumit.Resubmit(nil, &l.localEndpointL2ForwardingTable.TableId); err != nil {
		return fmt.Errorf("failed to install localGwResumit flow, error: %v", err)
	}
	if err := localGwResumit.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install localGwResumit flow, error: %v", err)
	}

	localGwResumitHigh, _ := l.vlanInputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  HIGH_MATCH_FLOW_PRIORITY + FLOW_MATCH_OFFSET,
		Ethertype: PROTOCOL_IP,
		InputPort: uint32(LOCAL_GATEWAY_PORT),
		IpSa:      &l.datapathManager.AgentInfo.GatewayIP,
		IpSaMask:  &net.IPv4bcast,
	})
	if err := localGwResumitHigh.LoadField("nxm_of_eth_src", ParseMacToUint64(l.datapathManager.AgentInfo.LocalGwMac),
		openflow13.NewNXRange(0, 47)); err != nil {
		return err
	}
	if err := localGwResumitHigh.Resubmit(nil, &l.localEndpointL2ForwardingTable.TableId); err != nil {
		return fmt.Errorf("failed to install localGwResumitHigh flow, error: %v", err)
	}
	if err := localGwResumitHigh.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install localGwResumitHigh flow, error: %v", err)
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
	err = fromLocalLearnAction.AddLearnedLoadAction(&ofctrl.LearnField{Name: "nxm_of_vlan_tci", Start: 0}, 12, nil, srcValue)
	if err != nil {
		return fmt.Errorf("failed to initialize learn action, AddLearnedLoadAction: load:0x0->NXM_OF_vlan_tci[] failure, error: %v", err)
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
		InputPort: uint32(LOCAL_TO_POLICY_PORT),
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
	outputPort, _ := sw.OutputPort(openflow13.P_ALL)
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

	fromLocalLearnAction := ofctrl.NewLearnAction(L2_FORWARDING_TABLE, MID_MATCH_FLOW_PRIORITY+3, 0, 0, 0, 0, 0)
	if err := l.InitFromLocalLearnAction(fromLocalLearnAction); err != nil {
		return fmt.Errorf("failed to initialize from local learn action, error: %v", err)
	}

	if err := l2LearningFlow.Learn(fromLocalLearnAction); err != nil {
		return fmt.Errorf("failed to install l2Learning flow learn action, error: %v", err)
	}
	if err := l2LearningFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install l2Learning flow, error: %v", err)
	}

	return nil
}

func (l *LocalBridge) initFromLocalRedirectTable(sw *ofctrl.OFSwitch) error {
	// Table 6 from local redirect flow
	fromLocalArpRedirectFlow, _ := l.fromLocalRedirectTable.NewFlow(ofctrl.FlowMatch{
		Priority:  HIGH_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_ARP,
	})
	sendToControllerAct := fromLocalArpRedirectFlow.NewControllerAction(sw.ControllerID, 0)
	_ = fromLocalArpRedirectFlow.SendToController(sendToControllerAct)
	if err := fromLocalArpRedirectFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install from local arp redirect flow, error: %v", err)
	}

	fromLocalRedirectFlow, _ := l.fromLocalRedirectTable.NewFlow(ofctrl.FlowMatch{
		Priority: NORMAL_MATCH_FLOW_PRIORITY,
	})
	outputPort, _ := sw.OutputPort(LOCAL_TO_POLICY_PORT)
	if err := fromLocalRedirectFlow.Next(outputPort); err != nil {
		return fmt.Errorf("failed to install from local redirect flow, error: %v", err)
	}

	return nil
}

func (l *LocalBridge) BridgeReset() {
}

func (l *LocalBridge) AddLocalEndpoint(endpoint *Endpoint) error {
	// Table 0, from local endpoint
	var vlanIDMask uint16 = 0x1fff
	vlanInputTableFromLocalFlow, _ := l.vlanInputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		InputPort: endpoint.PortNo,
	})
	if err := vlanInputTableFromLocalFlow.LoadField("nxm_of_vlan_tci", uint64(endpoint.VlanID), openflow13.NewNXRange(0, 11)); err != nil {
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

	return nil
}

func (l *LocalBridge) RemoveLocalEndpoint(endpoint *Endpoint) error {
	// remove table 0 from local endpoing flow
	if err := l.fromLocalEndpointFlow[endpoint.PortNo].Delete(); err != nil {
		return err
	}
	delete(l.fromLocalEndpointFlow, endpoint.PortNo)

	// remote table 1 local to local bum redirect flow
	if err := l.localToLocalBUMFlow[endpoint.PortNo].Delete(); err != nil {
		return err
	}
	delete(l.localToLocalBUMFlow, endpoint.PortNo)

	return nil
}

func (l *LocalBridge) AddMicroSegmentRule(rule *EveroutePolicyRule, direction uint8, tier uint8) (*FlowEntry, error) {
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
