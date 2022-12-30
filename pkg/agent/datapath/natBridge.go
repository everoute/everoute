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
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ofctrl"

	"github.com/everoute/everoute/pkg/constants"
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
	CTZoneReg             string              = "nxm_nx_reg0"
	CTZoneRange           *openflow13.NXRange = openflow13.NewNXRange(0, 15)
	CTZoneForPktFromLocal uint16              = 65505

	ChooseBackendFlagReg   string              = "nxm_nx_reg0"
	ChooseBackendFlagRange *openflow13.NXRange = openflow13.NewNXRange(16, 16)
	ChooseBackendFlagStart int                 = 16
	NeedChoose             uint8               = 0
	NoNeedChoose           uint8               = 1

	BackendIPReg     string              = "nxm_nx_reg1"
	BackendIPRange   *openflow13.NXRange = openflow13.NewNXRange(0, 31)
	BackendPortReg   string              = "nxm_nx_reg2"
	BackendPortRange *openflow13.NXRange = openflow13.NewNXRange(0, 15)

	EtherTypeLength         uint16 = 16
	IPv4Lenth               uint16 = 32
	ProtocolLength          uint16 = 8
	PortLength              uint16 = 16
	ChooseBackendFlagLength uint16 = 1

	LearnActionTimeout uint16 = 300
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
}

func NewNatBridge(brName string, datapathManager *DpManager) *NatBridge {
	natBr := new(NatBridge)
	natBr.name = fmt.Sprintf("%s-nat", brName)
	natBr.datapathManager = datapathManager

	return natBr
}

func (n *NatBridge) BridgeInit() {}

func (n *NatBridge) BridgeInitCNI() {
	if !n.datapathManager.Config.EnableCNI || n.datapathManager.Config.CNIConfig == nil {
		return
	}
	if !n.datapathManager.Config.CNIConfig.EnableProxy {
		return
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
	return nil
}

func (n *NatBridge) RemoveLocalEndpoint(endpoint *Endpoint) error {
	return nil
}

func (n *NatBridge) AddVNFInstance() error {
	return nil
}

func (n *NatBridge) RemoveVNFInstance() error {
	return nil
}

func (n *NatBridge) AddSFCRule() error {
	return nil
}

func (n *NatBridge) RemoveSFCRule() error {
	return nil
}

func (n *NatBridge) AddMicroSegmentRule(rule *EveroutePolicyRule, direction uint8, tier uint8, mode string) (*FlowEntry, error) {
	return nil, nil
}

func (n *NatBridge) RemoveMicroSegmentRule(rule *EveroutePolicyRule) error {
	return nil
}

// Controller received a packet from the switch
func (n *NatBridge) PacketRcvd(sw *ofctrl.OFSwitch, pkt *ofctrl.PacketIn) {}

// Controller received a multi-part reply from the switch
func (n *NatBridge) MultipartReply(sw *ofctrl.OFSwitch, rep *openflow13.MultipartReply) {}

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
		log.Errorf("failed to install a default drop flow in Input table %d: %s", NatBrInputTable, err)
		return err
	}
	return nil
}

func (n *NatBridge) initInPortTable() error {
	localBrName := strings.TrimSuffix(n.name, "-nat")

	flow, err := n.inPortTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		InputPort: n.datapathManager.BridgeChainPortMap[localBrName][NatToLocalSuffix],
	})
	if err != nil {
		log.Errorf("Failed to new a flow in InPort table %d: %s", NatBrInPortTable, err)
		return err
	}
	if err = flow.LoadField(CTZoneReg, uint64(CTZoneForPktFromLocal), CTZoneRange); err != nil {
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

func (n *NatBridge) initCTZoneTable() error {
	flow, err := n.ctZoneTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
	})
	if err != nil {
		log.Errorf("Failed to new a flow in CTZone table %d: %s", NatBrCTZoneTable, err)
		return err
	}
	ctAct, err := ofctrl.NewConntrackActionWitchZoneField(false, false, &NatBrCTStateTable, CTZoneReg, CTZoneRange)
	if err != nil {
		log.Errorf("Failed to new a ct action: %s", err)
		return err
	}
	if err = flow.SetConntrack(ctAct); err != nil {
		log.Errorf("Failed to set conntrack in CTZone table %d: %s", NatBrCTZoneTable, err)
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
	ctAct, err := ofctrl.NewConntrackActionWitchZoneField(true, false, &NatBrL3ForwardTable, CTZoneReg, CTZoneRange, natAct)
	if err != nil {
		log.Errorf("Failed to new a ct action with nat: %s", err)
		return err
	}
	if err = trkFlow.SetConntrack(ctAct); err != nil {
		log.Errorf("Failed to set conntrack to flow in CTState table %d: %s", NatBrCTStateTable, err)
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

func (n *NatBridge) initServiceLBTable() error {
	flow, err := n.serviceLBTable.NewFlow(ofctrl.FlowMatch{
		Priority: HIGH_MATCH_FLOW_PRIORITY,
		Regs: []*ofctrl.NXRegister{
			{
				RegID: constants.OVSReg0,
				Data:  uint32(NoNeedChoose),
				Range: ChooseBackendFlagRange,
			},
		},
	})
	if err != nil {
		log.Errorf("Failed to new a flow in ServiceLB table %d: %s", NatBrServiceLBTable, err)
		return err
	}
	if err = flow.Resubmit(nil, &NatBrDnatTable); err != nil {
		log.Errorf("Failed to add resubmit action to flow in ServiceLB table %d: %s", NatBrServiceLBTable, err)
		return err
	}
	if err = flow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install flow in ServiceLB table %d: %s", NatBrServiceLBTable, err)
		return err
	}
	return nil
}

func (n *NatBridge) buildLearnActOfSessionAffinityLearnTable(ipProto uint8) (*ofctrl.LearnAction, error) {
	ethTypeField := ofctrl.LearnField{Name: "nxm_of_eth_type", Start: 0}
	ipSrcField := ofctrl.LearnField{Name: "nxm_of_ip_src", Start: 0}
	ipDstField := ofctrl.LearnField{Name: "nxm_of_ip_dst", Start: 0}

	ipProtoField := ofctrl.LearnField{Name: "nxm_of_ip_proto", Start: 0}
	tcpDstField := ofctrl.LearnField{Name: "nxm_of_tcp_dst", Start: 0}
	udpDstField := ofctrl.LearnField{Name: "nxm_of_udp_dst", Start: 0}

	backendIPField := ofctrl.LearnField{Name: BackendIPReg, Start: 0}
	backendPortField := ofctrl.LearnField{Name: BackendPortReg, Start: 0}
	chooseBackendFlagField := ofctrl.LearnField{Name: ChooseBackendFlagReg, Start: uint16(ChooseBackendFlagStart)}

	cookieID, err := getLearnCookieID()
	if err != nil {
		return nil, err
	}
	learnAct := ofctrl.NewLearnAction(NatBrSessionAffinityTable, MID_MATCH_FLOW_PRIORITY, 0, LearnActionTimeout, 0, 0, cookieID)
	learnAct.SetDeleteLearned()

	if err := learnAct.AddLearnedMatch(&ethTypeField, EtherTypeLength, nil, uintToByteBigEndian(uint16(PROTOCOL_IP))); err != nil {
		return nil, err
	}
	if err := learnAct.AddLearnedMatch(&ipSrcField, IPv4Lenth, &ipSrcField, nil); err != nil {
		return nil, err
	}
	if err := learnAct.AddLearnedMatch(&ipDstField, IPv4Lenth, &ipDstField, nil); err != nil {
		return nil, err
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

	return learnAct, nil
}

func (n *NatBridge) initLearnFlowOfSessionAffinityLearnTable(ipProto uint8) error {
	flow, err := n.sessionAffinityLearnTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
		IpProto:   ipProto,
	})
	if err != nil {
		log.Errorf("Failed to new flow in SessionAffinityLearn table %d: %s", NatBrSessionAffinityLearnTable, err)
		return err
	}
	learnAct, err := n.buildLearnActOfSessionAffinityLearnTable(ipProto)
	if err != nil {
		log.Errorf("Failed to build a learn action: %s", err)
		return err
	}
	if err = flow.Learn(learnAct); err != nil {
		log.Errorf("Failed to add learn action to flow in SessionAffinityLearn table %d: %s", NatBrSessionAffinityLearnTable, err)
		return err
	}
	if err = flow.Resubmit(nil, &NatBrDnatTable); err != nil {
		log.Errorf("Failed to add a resubmit action to flow in SessionAffinityLearn table %d: %s", NatBrSessionAffinityLearnTable, err)
		return err
	}
	if err = flow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install flow in SessionAffinityLearn table %d: %s", NatBrSessionAffinityLearnTable, err)
		return err
	}

	return nil
}

func (n *NatBridge) initSessionAffinityLearnTable() error {
	if err := n.initLearnFlowOfSessionAffinityLearnTable(PROTOCOL_TCP); err != nil {
		log.Errorf("Failed to init tcp learn flow in SessionAffinityLearn table %d: %s", NatBrSessionAffinityLearnTable, err)
		return err
	}
	if err := n.initLearnFlowOfSessionAffinityLearnTable(PROTOCOL_UDP); err != nil {
		log.Errorf("Failed to init udp learn flow in SessionAffinityLearn table %d: %s", NatBrSessionAffinityLearnTable, err)
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
