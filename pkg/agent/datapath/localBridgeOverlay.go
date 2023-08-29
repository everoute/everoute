package datapath

import (
	"fmt"
	"net"

	openflow "github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ofctrl"
	log "github.com/sirupsen/logrus"

	"github.com/everoute/everoute/pkg/constants"
)

var (
	LBOArpProxyTable       uint8 = 10
	LBOInPortTable         uint8 = 30
	LBOFromNatTable        uint8 = 40
	LBOFromPolicyTable     uint8 = 50
	LBOFromLocalTable      uint8 = 60
	LBOForwardToLocalTable uint8 = 80
	LBOPaddingL2Table      uint8 = 90
	LBOOutputTable         uint8 = 110
)

var (
	LBOOutputPortReg                     = "nxm_nx_reg2"
	LBOOutputPortStart                   = 0
	LBOOutputPortRange *openflow.NXRange = openflow.NewNXRange(LBOOutputPortStart, 15)
)

type LocalBridgeOverlay struct {
	BaseBridge

	inputTable          *ofctrl.Table
	arpProxyTable       *ofctrl.Table
	inPortTable         *ofctrl.Table
	fromNatTable        *ofctrl.Table
	fromPolicyTable     *ofctrl.Table
	fromLocalTable      *ofctrl.Table
	forwardToLocalTable *ofctrl.Table
	paddingL2Table      *ofctrl.Table
	outputTable         *ofctrl.Table

	enableProxy    bool
	natPort        uint32
	localEpFlowMap map[string]*ofctrl.Flow
}

func newLocalBridgeOverlay(brName string, datapathManager *DpManager) *LocalBridgeOverlay {
	if !datapathManager.IsEnableOverlay() {
		log.Fatalf("Can't new overlay local bridge when disable overlay")
	}

	localBridge := &LocalBridgeOverlay{}
	localBridge.name = brName
	localBridge.datapathManager = datapathManager
	localBridge.localEpFlowMap = make(map[string]*ofctrl.Flow)

	return localBridge
}

func (l *LocalBridgeOverlay) BridgeInitCNI() {
	l.enableProxy = l.datapathManager.IsEnableProxy()
	if l.enableProxy {
		l.natPort = l.datapathManager.BridgeChainPortMap[l.name][LocalToNatSuffix]
	} else {
		l.natPort = l.datapathManager.Info.LocalGwOfPort
	}

	sw := l.OfSwitch

	l.inputTable = sw.DefaultTable()
	l.arpProxyTable, _ = sw.NewTable(LBOArpProxyTable)
	l.inPortTable, _ = sw.NewTable(LBOInPortTable)
	l.fromNatTable, _ = sw.NewTable(LBOFromNatTable)
	l.fromPolicyTable, _ = sw.NewTable(LBOFromPolicyTable)
	l.fromLocalTable, _ = sw.NewTable(LBOFromLocalTable)
	l.forwardToLocalTable, _ = sw.NewTable(LBOForwardToLocalTable)
	l.paddingL2Table, _ = sw.NewTable(LBOPaddingL2Table)
	l.outputTable, _ = sw.NewTable(LBOOutputTable)

	if err := l.initInputTable(); err != nil {
		log.Fatalf("Failed to init input table of local bridge overlay, err: %v", err)
	}
	if err := l.initArpProxytable(); err != nil {
		log.Fatalf("Failed to init arp proxy table of local bridge overlay, err: %v", err)
	}
	if err := l.initInPortTable(); err != nil {
		log.Fatalf("Failed to init in port table of local bridge overlay, err: %v", err)
	}
	if err := l.initFromNatTable(); err != nil {
		log.Fatalf("Failed to init from nat table of local bridge overlay, err: %v", err)
	}
	if err := l.initFromPolicyTable(); err != nil {
		log.Fatalf("Failed to init from policy table of local bridge overlay, err: %v", err)
	}
	if err := l.initFromLocalTable(); err != nil {
		log.Fatalf("Failed to init from local table of local bridge overlay, err: %v", err)
	}
	if err := l.initForwardToLocalTable(); err != nil {
		log.Fatalf("Failed to init forward to local table of local bridge overlay, err: %v", err)
	}
	if err := l.initPaddingL2table(); err != nil {
		log.Fatalf("Failed to init padding l2 table of local bridge overlay, err: %v", err)
	}
	if err := l.initOutputTable(); err != nil {
		log.Fatalf("Failed to init output table of local bridge overlay, err: %v", err)
	}
}

func (l *LocalBridgeOverlay) AddLocalEndpoint(endpoint *Endpoint) error {
	if endpoint == nil {
		return nil
	}
	if l.localEpFlowMap[endpoint.InterfaceUUID] != nil {
		log.Infof("Local bridge overlay, the endpoint %+v related flow in forward to local table has been installed, skip add again", endpoint)
		return nil
	}
	macAddr, err := net.ParseMAC(endpoint.MacAddrStr)
	if err != nil {
		log.Errorf("The endpoint %+v has invalid mac addr, err: %s", endpoint, err)
		return err
	}

	if endpoint.IPAddr == nil {
		log.Infof("The endpoint %+v IPAddr is empty, skip add flow to forward to local table for local bridge overlay", endpoint)
		return nil
	}

	if endpoint.IPAddr.To4() == nil {
		log.Errorf("Failed to add flow to forward to local table for local bridge overlay: the endpoint %+v IPAddr is not valid ipv4", endpoint)
		return fmt.Errorf("the endpoint %+v IPAddr is not valid ipv4", endpoint)
	}

	flow, _ := l.forwardToLocalTable.NewFlow(ofctrl.FlowMatch{
		Priority:  HIGH_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
		IpDa:      &endpoint.IPAddr,
	})
	if err := flow.SetMacDa(macAddr); err != nil {
		log.Errorf("Failed to setup forward to local table flow set dst mac action in local bridge overlay for endpoint: %+v, err: %v", endpoint, err)
		return err
	}
	if err := flow.LoadField(LBOOutputPortReg, uint64(endpoint.PortNo), LBOOutputPortRange); err != nil {
		log.Errorf("Failed to setup forward to local table flow load field action in local bridge overlay for endpoint: %+v, err: %v", endpoint, err)
		return err
	}
	if err := flow.Resubmit(nil, &LBOPaddingL2Table); err != nil {
		log.Errorf("Failed to setup forward to local table flow resubmit action in local bridge overlay for endpoint: %+v, err: %v", endpoint, err)
		return err
	}
	if err := flow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install forward to local table flow in local bridge overlay for endpoint: %+v, err: %v", endpoint, err)
		return err
	}
	l.localEpFlowMap[endpoint.InterfaceUUID] = flow
	log.Infof("Local bridge overlay, success to add local endpoint flow in forward to local table, endpoint: %+v", endpoint)
	return nil
}

func (l *LocalBridgeOverlay) RemoveLocalEndpoint(endpoint *Endpoint) error {
	if endpoint == nil {
		return nil
	}
	delFlow := l.localEpFlowMap[endpoint.InterfaceUUID]
	if delFlow == nil {
		return nil
	}
	if err := delFlow.Delete(); err != nil {
		log.Errorf("Failed to delete local endpoint flow in forward to local table, endpoint: %+v, err: %v", endpoint, err)
		return err
	}
	delete(l.localEpFlowMap, endpoint.InterfaceUUID)
	log.Infof("Local bridge overlay: success delete local endpoint flow in forward to local table, endpoint: %+v", endpoint)
	return nil
}

func (l *LocalBridgeOverlay) initInputTable() error {
	sw := l.OfSwitch

	arpFlow, _ := l.inputTable.NewFlow(ofctrl.FlowMatch{
		Ethertype: PROTOCOL_ARP,
		Priority:  NORMAL_MATCH_FLOW_PRIORITY,
	})
	if err := arpFlow.Resubmit(nil, &LBOArpProxyTable); err != nil {
		return fmt.Errorf("failed to setup input table arp flow resubmit to arp proxy table action, err: %v", err)
	}
	if err := arpFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("faile to install input table arp flow, err: %v", err)
	}

	ipFlow, _ := l.inputTable.NewFlow(ofctrl.FlowMatch{
		Ethertype: PROTOCOL_IP,
		Priority:  NORMAL_MATCH_FLOW_PRIORITY,
	})
	if err := ipFlow.Resubmit(nil, &LBOInPortTable); err != nil {
		return fmt.Errorf("failed to setup input table ip flow resubmit to in port table action, err: %v", err)
	}
	if err := ipFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install input table ip flow, err: %v", err)
	}

	defaultFlow, _ := l.inputTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := defaultFlow.Next(sw.DropAction()); err != nil {
		return fmt.Errorf("failed to install input table default flow, err: %v", err)
	}

	return nil
}

func (l *LocalBridgeOverlay) initArpProxytable() error {
	sw := l.OfSwitch
	inportOutput, _ := sw.OutputPort(openflow.P_IN_PORT)

	arpProxyFlow, _ := l.arpProxyTable.NewFlow(ofctrl.FlowMatch{
		Ethertype:  PROTOCOL_ARP,
		ArpTpa:     &l.datapathManager.Info.ClusterPodCIDR.IP,
		ArpTpaMask: (*net.IP)(&l.datapathManager.Info.ClusterPodCIDR.Mask),
		Priority:   MID_MATCH_FLOW_PRIORITY,
	})
	fakeMac, _ := net.ParseMAC(FACK_MAC)
	if err := setupArpProxyFlowAction(arpProxyFlow, fakeMac); err != nil {
		return fmt.Errorf("failed to setup arp proxy table pod cidr arp proxy flow action, err: %v", err)
	}
	if err := arpProxyFlow.Next(inportOutput); err != nil {
		return fmt.Errorf("failed to install arp proxy table pod cidr arp proxy flow, err: %v", err)
	}

	if !l.enableProxy {
		gwLocalProxyFlow, _ := l.arpProxyTable.NewFlow(ofctrl.FlowMatch{
			Ethertype:  PROTOCOL_ARP,
			InputPort:  l.datapathManager.Info.LocalGwOfPort,
			ArpTpa:     &l.datapathManager.Info.LocalGwIP,
			ArpTpaMask: &IPMaskMatchFullBit,
			Priority:   HIGH_MATCH_FLOW_PRIORITY,
		})
		if err := setupArpProxyFlowAction(gwLocalProxyFlow, l.datapathManager.Info.LocalGwMac); err != nil {
			return fmt.Errorf("failed to setup arp proxy table gw local proxy flow action, err: %v", err)
		}
		if err := gwLocalProxyFlow.Next(inportOutput); err != nil {
			return fmt.Errorf("failed to install arp proxy table gw local arp proxy flow, err: %v", err)
		}
	}

	defaultFlow, _ := l.arpProxyTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := defaultFlow.Next(sw.DropAction()); err != nil {
		return fmt.Errorf("failed to install arp proxy table default flow, err: %v", err)
	}

	return nil
}

func (l *LocalBridgeOverlay) initInPortTable() error {
	sw := l.OfSwitch

	fromNatFlow, _ := l.inPortTable.NewFlow(ofctrl.FlowMatch{
		Ethertype: PROTOCOL_IP,
		InputPort: l.natPort,
		Priority:  HIGH_MATCH_FLOW_PRIORITY,
	})
	if err := fromNatFlow.Resubmit(nil, &LBOFromNatTable); err != nil {
		return fmt.Errorf("failed to setup in port table from nat flow resubmit action, err: %v", err)
	}
	if err := fromNatFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install in port table from nat flow, err: %v", err)
	}

	fromPolicyFlow, _ := l.inPortTable.NewFlow(ofctrl.FlowMatch{
		Ethertype: PROTOCOL_IP,
		InputPort: l.datapathManager.BridgeChainPortMap[l.name][LocalToPolicySuffix],
		Priority:  HIGH_MATCH_FLOW_PRIORITY,
	})
	if err := fromPolicyFlow.Resubmit(nil, &LBOFromPolicyTable); err != nil {
		return fmt.Errorf("failed to setup in port table from policy flow resubmit action, err: %v", err)
	}
	if err := fromPolicyFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install in port table from policy flow, err: %v", err)
	}

	fromLocalFlow, _ := l.inPortTable.NewFlow(ofctrl.FlowMatch{
		Ethertype: PROTOCOL_IP,
		Priority:  MID_MATCH_FLOW_PRIORITY,
	})
	if err := fromLocalFlow.Resubmit(nil, &LBOFromLocalTable); err != nil {
		return fmt.Errorf("failed to setup in port table from local flow resubmit action, err: %v", err)
	}
	if err := fromLocalFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install in port table from local flow, err: %v", err)
	}

	defaultFlow, _ := l.arpProxyTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := defaultFlow.Next(sw.DropAction()); err != nil {
		return fmt.Errorf("failed to install arp proxy table default flow, err: %v", err)
	}

	return nil
}

func (l *LocalBridgeOverlay) initFromNatTable() error {
	toPolicyFlow, _ := l.fromNatTable.NewFlow(ofctrl.FlowMatch{
		PktMark:     SvcPktMark,
		PktMarkMask: &SvcPktMarkMask,
		Priority:    HIGH_MATCH_FLOW_PRIORITY,
	})
	if err := toPolicyFlow.LoadField(LBOOutputPortReg, uint64(l.datapathManager.BridgeChainPortMap[l.name][LocalToPolicySuffix]), LBOOutputPortRange); err != nil {
		return fmt.Errorf("failed to setup from nat table to policy flow load field action, err: %v", err)
	}
	if err := toPolicyFlow.Resubmit(nil, &LBOPaddingL2Table); err != nil {
		return fmt.Errorf("failed to setup from nat table to policy flow resubmit action, err: %v", err)
	}
	if err := toPolicyFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install from nat table to policy flow, err: %v", err)
	}

	toLocalFlow, _ := l.fromNatTable.NewFlow(ofctrl.FlowMatch{
		Priority: NORMAL_MATCH_FLOW_PRIORITY,
	})
	if err := toLocalFlow.Resubmit(nil, &LBOForwardToLocalTable); err != nil {
		return fmt.Errorf("failed to setup from nat table to local flow resubmit action, err: %v", err)
	}
	if err := toLocalFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install from nat table to local flow, err: %v", err)
	}
	return nil
}

func (l *LocalBridgeOverlay) initFromPolicyTable() error {
	toLocalFlow, _ := l.fromPolicyTable.NewFlow(ofctrl.FlowMatch{
		PktMark:     SvcPktMark,
		PktMarkMask: &SvcPktMarkMask,
		Priority:    HIGH_MATCH_FLOW_PRIORITY,
	})
	if err := toLocalFlow.Resubmit(nil, &LBOForwardToLocalTable); err != nil {
		return fmt.Errorf("failed to setup from policy table to local flow resubmit action, err: %v", err)
	}
	if err := toLocalFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install from policy table to local flow, err: %v", err)
	}

	toNatFlow, _ := l.fromPolicyTable.NewFlow(ofctrl.FlowMatch{
		Priority: NORMAL_MATCH_FLOW_PRIORITY,
	})
	if err := toNatFlow.LoadField(LBOOutputPortReg, uint64(l.natPort), LBOOutputPortRange); err != nil {
		return fmt.Errorf("failed to setup from policy table to nat flow load field action, err: %v", err)
	}
	if err := toNatFlow.Resubmit(nil, &LBOPaddingL2Table); err != nil {
		return fmt.Errorf("failed to setup from policy table to nat flow resubmit action, err: %v", err)
	}
	if err := toNatFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install from policy table to nat flow, err: %v", err)
	}

	return nil
}

func (l *LocalBridgeOverlay) initFromLocalTable() error {
	svcFlow, _ := l.fromLocalTable.NewFlow(ofctrl.FlowMatch{
		Ethertype: PROTOCOL_IP,
		IpDa:      &l.datapathManager.Info.ClusterCIDR.IP,
		IpDaMask:  (*net.IP)(&l.datapathManager.Info.ClusterCIDR.Mask),
		Priority:  HIGH_MATCH_FLOW_PRIORITY,
	})
	if err := svcFlow.LoadField("nxm_nx_pkt_mark", SvcPktMarkValue, SvcPktMarkRange); err != nil {
		return fmt.Errorf("failed to setup from local table svc flow set svc mark action, err: %v", err)
	}
	if err := svcFlow.LoadField(LBOOutputPortReg, uint64(l.natPort), LBOOutputPortRange); err != nil {
		return fmt.Errorf("failed to setup from local table svc flow load output port action, err: %v", err)
	}
	if err := svcFlow.Resubmit(nil, &LBOPaddingL2Table); err != nil {
		return fmt.Errorf("failed to setup from local table svc flow resubmit action, err: %v", err)
	}
	if err := svcFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install from local table svc flow, err: %v", err)
	}

	podFlow, _ := l.fromLocalTable.NewFlow(ofctrl.FlowMatch{
		Ethertype: PROTOCOL_IP,
		Priority:  NORMAL_MATCH_FLOW_PRIORITY,
	})
	if err := podFlow.LoadField(LBOOutputPortReg, uint64(l.datapathManager.BridgeChainPortMap[l.name][LocalToPolicySuffix]), LBOOutputPortRange); err != nil {
		return fmt.Errorf("failed to setup from local table pod flow load output port action, err: %v", err)
	}
	if l.enableProxy {
		if err := podFlow.Resubmit(nil, &LBOOutputTable); err != nil {
			return fmt.Errorf("failed to setup from local table pod flow resubmit action, err: %v", err)
		}
	} else {
		var cniConntrackZone uint16 = CNI_CONNTRACK_ZONE
		ctAction := ofctrl.NewConntrackAction(true, false, &LBOOutputTable, &cniConntrackZone)
		_ = podFlow.SetConntrack(ctAction)
	}
	if err := podFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install from local table pod flow, err: %v", err)
	}

	return nil
}

func (l *LocalBridgeOverlay) initForwardToLocalTable() error {
	sw := l.OfSwitch
	defaultFlow, _ := l.forwardToLocalTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := defaultFlow.Next(sw.DropAction()); err != nil {
		return fmt.Errorf("failed to install forward to local table default drop flow, err: %v", err)
	}
	return nil
}

func (l *LocalBridgeOverlay) initPaddingL2table() error {
	toPolicyFlow, _ := l.paddingL2Table.NewFlow(ofctrl.FlowMatch{
		Priority: MID_MATCH_FLOW_PRIORITY,
		Regs: []*ofctrl.NXRegister{
			{
				RegID: constants.OVSReg2,
				Data:  l.datapathManager.BridgeChainPortMap[l.name][LocalToPolicySuffix],
				Range: LBOOutputPortRange,
			},
		},
	})
	if err := toPolicyFlow.Resubmit(nil, &LBOOutputTable); err != nil {
		return fmt.Errorf("failed to setup paddling l2 table to policy flow resubmit action, err: %v", err)
	}
	if err := toPolicyFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install padding l2 table to poicy flow, err: %v", err)
	}

	toNatFlow, _ := l.paddingL2Table.NewFlow(ofctrl.FlowMatch{
		Priority: MID_MATCH_FLOW_PRIORITY,
		Regs: []*ofctrl.NXRegister{
			{
				RegID: constants.OVSReg2,
				Data:  l.natPort,
				Range: LBOOutputPortRange,
			},
		},
	})
	if !l.enableProxy {
		if err := toNatFlow.SetMacDa(l.datapathManager.Info.LocalGwMac); err != nil {
			return fmt.Errorf("failed to setup padding l2 table to nat flow set dst mac action, err: %v", err)
		}
	}
	if err := toNatFlow.Resubmit(nil, &LBOOutputTable); err != nil {
		return fmt.Errorf("failed to setup paddling l2 table to nat flow resubmit action, err: %v", err)
	}
	if err := toNatFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install padding l2 table to nat flow, err: %v", err)
	}

	toLocalFlow, _ := l.paddingL2Table.NewFlow(ofctrl.FlowMatch{
		Priority: NORMAL_MATCH_FLOW_PRIORITY,
	})
	fakeMac, _ := net.ParseMAC(FACK_MAC)
	if err := toLocalFlow.SetMacSa(fakeMac); err != nil {
		return fmt.Errorf("failed to setup paddling l2 table to local flow set src mac action, err: %v", err)
	}
	if err := toLocalFlow.Resubmit(nil, &LBOOutputTable); err != nil {
		return fmt.Errorf("failed to setup paddling l2 table to local flow resubmit action, err: %v", err)
	}
	if err := toLocalFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install padding l2 table to local flow, err: %v", err)
	}

	return nil
}

func (l *LocalBridgeOverlay) initOutputTable() error {
	sw := l.OfSwitch
	flow, _ := l.outputTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	outputPort, err := sw.OutputPortReg(LBOOutputPortReg, uint16(LBOOutputPortStart))
	if err != nil {
		return fmt.Errorf("failed to new output port reg, err: %v", err)
	}
	if err := flow.Next(outputPort); err != nil {
		return fmt.Errorf("failed to install output table flow, err: %v", err)
	}

	return nil
}
