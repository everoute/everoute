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
	UBOArpProxyTable         uint8 = 10
	UBOForwardToLocalTable   uint8 = 30
	UBOForwardToGwTable      uint8 = 40
	UBOForwardToTunnelTable  uint8 = 35
	UBOSetRemoteIPTable      uint8 = 70
	UBOSetTunnelOutPortTable uint8 = 75
	UBOPaddingL2Table        uint8 = 100
	UBOOutputTable           uint8 = 110
)

var (
	UBOOutputPortReg                     = "nxm_nx_reg2"
	UBOOutputPortStart                   = 0
	UBOOutputPortRange *openflow.NXRange = openflow.NewNXRange(UBOOutputPortStart, 15)

	TunnelDstReg = "nxm_nx_tun_ipv4_dst"
)

type UplinkBridgeOverlay struct {
	BaseBridge

	inputTable            *ofctrl.Table
	arpProxyTable         *ofctrl.Table
	forwardToLocalTable   *ofctrl.Table
	forwardToGwTable      *ofctrl.Table
	forwardToTunnelTable  *ofctrl.Table
	setRemoteIPTable      *ofctrl.Table
	setTunnelOutPortTable *ofctrl.Table
	paddingL2Table        *ofctrl.Table
	outputTable           *ofctrl.Table

	ovsBrName       string
	localEpFlowMap  map[string]*ofctrl.Flow
	remoteEpFlowMap map[string]*ofctrl.Flow
}

func newUplinkBridgeOverlay(brName string, datapathManager *DpManager) *UplinkBridgeOverlay {
	if !datapathManager.IsEnableOverlay() {
		log.Fatalf("Can't new overlay uplink bridge when disable overlay")
	}
	uplinkBridge := new(UplinkBridgeOverlay)
	uplinkBridge.name = fmt.Sprintf("%s-uplink", brName)
	uplinkBridge.datapathManager = datapathManager
	uplinkBridge.ovsBrName = brName
	return uplinkBridge
}

func (u *UplinkBridgeOverlay) BridgeInitCNI() {
	u.localEpFlowMap = make(map[string]*ofctrl.Flow)
	u.remoteEpFlowMap = make(map[string]*ofctrl.Flow)

	sw := u.OfSwitch
	u.inputTable = sw.DefaultTable()
	u.arpProxyTable, _ = sw.NewTable(UBOArpProxyTable)
	u.forwardToLocalTable, _ = sw.NewTable(UBOForwardToLocalTable)
	u.forwardToGwTable, _ = sw.NewTable(UBOForwardToGwTable)
	u.forwardToTunnelTable, _ = sw.NewTable(UBOForwardToTunnelTable)
	u.setRemoteIPTable, _ = sw.NewTable(UBOSetRemoteIPTable)
	u.setTunnelOutPortTable, _ = sw.NewTable(UBOSetTunnelOutPortTable)
	u.paddingL2Table, _ = sw.NewTable(UBOPaddingL2Table)
	u.outputTable, _ = sw.NewTable(UBOOutputTable)

	if err := u.initInputTable(); err != nil {
		log.Fatalf("Failed to init input table of uplink bridge overlay, err: %v", err)
	}
	if err := u.initArpProxytable(); err != nil {
		log.Fatalf("Failed to init arp proxy table of uplink bridge overlay, err: %v", err)
	}
	if err := u.initForwardToLocalTable(); err != nil {
		log.Fatalf("Failed to init forward to local table of uplink bridge overlay, err: %v", err)
	}
	if err := u.initForwardToGwTable(); err != nil {
		log.Fatalf("Failed to init forward to gw table of uplink bridge overlay, err: %v", err)
	}
	if err := u.initForwardToTunnelTable(); err != nil {
		log.Fatalf("Failed to init forward to tunnel table of uplink bridge overlay, err: %v", err)
	}
	if err := u.initSetRemoteIPTable(); err != nil {
		log.Fatalf("Failed to init set remote ip table of uplink bridge overlay, err: %v", err)
	}
	if err := u.initSetTunnelOutPortTable(); err != nil {
		log.Fatalf("Failed to init set tunnel out port table of uplink bridge overlay, err: %v", err)
	}
	if err := u.initPaddingL2table(); err != nil {
		log.Fatalf("Failed to init padding l2 table of uplink bridge overlay, err: %v", err)
	}
	if err := u.initOutputTable(); err != nil {
		log.Fatalf("Failed to init output table of uplink bridge overlay, err: %v", err)
	}
}

func (u *UplinkBridgeOverlay) AddLocalEndpoint(endpoint *Endpoint) error {
	if endpoint == nil {
		return nil
	}
	if u.localEpFlowMap[endpoint.InterfaceUUID] != nil {
		log.Infof("Uplink bridge overlay, the endpoint %+v related flow in forward to local table has been installed, skip add again", endpoint)
		return nil
	}

	if endpoint.IPAddr == nil {
		log.Infof("the endpoint %+v IPAddr is empty, skip add flow to forward to local table for uplink bridge overlay", endpoint)
		return nil
	}

	if endpoint.IPAddr.To4() == nil {
		log.Errorf("Failed to add flow to forward to local table for uplink bridge overlay: the endpoint %+v IPAddr is not valid ipv4", endpoint)
		return fmt.Errorf("the endpoint %+v IPAddr is not valid ipv4", endpoint)
	}

	flow, _ := u.forwardToLocalTable.NewFlow(ofctrl.FlowMatch{
		Priority:  HIGH_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
		IpDa:      &endpoint.IPAddr,
	})
	if err := flow.LoadField(UBOOutputPortReg, uint64(u.datapathManager.BridgeChainPortMap[u.ovsBrName][UplinkToClsSuffix]), UBOOutputPortRange); err != nil {
		log.Errorf("Failed to setup forward to local table flow load field action in uplink bridge overlay for endpoint: %+v, err: %v", endpoint, err)
		return err
	}
	if err := flow.Resubmit(nil, &LBOOutputTable); err != nil {
		log.Errorf("Failed to setup forward to local table flow resubmit action in uplink bridge overlay for endpoint: %+v, err: %v", endpoint, err)
		return err
	}
	if err := flow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install forward to local table flow in uplink bridge overlay for endpoint %+v, err: %v", endpoint, err)
		return err
	}

	u.localEpFlowMap[endpoint.InterfaceUUID] = flow
	log.Infof("Uplink bridge overlay, success to add local endpoint flow in forward to local table, endpoint: %+v", endpoint)
	return nil
}

func (u *UplinkBridgeOverlay) RemoveLocalEndpoint(endpoint *Endpoint) error {
	if endpoint == nil {
		return nil
	}

	delFlow := u.localEpFlowMap[endpoint.InterfaceUUID]
	if delFlow == nil {
		return nil
	}
	if err := delFlow.Delete(); err != nil {
		log.Errorf("Failed to delete local endpoint flow in forward to local table of uplink bridge overlay, endpoint: %+v, err: %v", endpoint, err)
		return err
	}
	delete(u.localEpFlowMap, endpoint.InterfaceUUID)
	log.Infof("Uplink bridge overlay: success delete local endpoint flow in forward to local table, endpoint: %+v", endpoint)
	return nil
}

func (u *UplinkBridgeOverlay) AddRemoteEndpoint(epIP, remoteNodeIP net.IP) error {
	if u.remoteEpFlowMap[epIP.String()] != nil {
		log.Infof("Remote endpoint %v flow has been add, flow: %v", epIP, u.remoteEpFlowMap[epIP.String()])
		return nil
	}

	flow, _ := u.setRemoteIPTable.NewFlow(ofctrl.FlowMatch{
		Priority:  HIGH_MATCH_FLOW_PRIORITY,
		Ethertype: PROTOCOL_IP,
		IpDa:      &epIP,
	})
	if err := flow.SetTunnelDstIP(remoteNodeIP); err != nil {
		log.Errorf("Failed to setup set remote ip table flow set tunnel dst ip action, epIP: %v, remoteNodeIP: %v, err: %v", epIP, remoteNodeIP, err)
		return err
	}
	if err := flow.Resubmit(nil, &UBOSetTunnelOutPortTable); err != nil {
		log.Errorf("Failed to setup set remote ip table flow resubmit action, epIP: %v, remoteNodeIP: %v, err: %v", epIP, remoteNodeIP, err)
		return err
	}
	if err := flow.Next(ofctrl.NewEmptyElem()); err != nil {
		log.Errorf("Failed to install set remote ip table flow, epIP: %v, remoteNodeIP: %v, err: %v", epIP, remoteNodeIP, err)
		return err
	}

	u.remoteEpFlowMap[epIP.String()] = flow
	log.Infof("Success add remote endpoint flow, epIP: %v, remoteNodeIP: %v", epIP, remoteNodeIP)
	return nil
}

func (u *UplinkBridgeOverlay) RemoveRemoteEndpoint(epIPStr string) error {
	if u.remoteEpFlowMap[epIPStr] == nil {
		log.Infof("Remote endpoint %s flow has been removed", epIPStr)
		return nil
	}
	if err := u.remoteEpFlowMap[epIPStr].Delete(); err != nil {
		log.Errorf("Failed to remove remote endpoint %s flow, err: %v", epIPStr, err)
		return err
	}

	delete(u.remoteEpFlowMap, epIPStr)
	log.Infof("Success to remove remote endpoint %s flow", epIPStr)
	return nil
}

//nolint
func (u *UplinkBridgeOverlay) initInputTable() error {
	sw := u.OfSwitch

	arpFlow, _ := u.inputTable.NewFlow(ofctrl.FlowMatch{
		Ethertype: PROTOCOL_ARP,
		Priority:  NORMAL_MATCH_FLOW_PRIORITY,
	})
	if err := arpFlow.Resubmit(nil, &UBOArpProxyTable); err != nil {
		return fmt.Errorf("failed to setup input table arp flow resubmit to arp proxy table action, err: %v", err)
	}
	if err := arpFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("faile to install input table arp flow, err: %v", err)
	}

	ipFlow, _ := u.inputTable.NewFlow(ofctrl.FlowMatch{
		Ethertype: PROTOCOL_IP,
		Priority:  NORMAL_MATCH_FLOW_PRIORITY,
	})
	if err := ipFlow.Resubmit(nil, &UBOForwardToLocalTable); err != nil {
		return fmt.Errorf("failed to setup input table ip flow resubmit to forward to local table action, err: %v", err)
	}
	if err := ipFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install input table ip flow, err: %v", err)
	}

	defaultFlow, _ := u.inputTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := defaultFlow.Next(sw.DropAction()); err != nil {
		return fmt.Errorf("failed to install input table default flow, err: %v", err)
	}

	return nil
}

func (u *UplinkBridgeOverlay) initArpProxytable() error {
	sw := u.OfSwitch
	inportOutput, _ := sw.OutputPort(openflow.P_IN_PORT)

	gwProxyFlow, _ := u.arpProxyTable.NewFlow(ofctrl.FlowMatch{
		Ethertype:  PROTOCOL_ARP,
		ArpTpa:     &u.datapathManager.Info.GatewayIP,
		ArpTpaMask: &IPMaskMatchFullBit,
		ArpOper:    ArpOperRequest,
		Priority:   HIGH_MATCH_FLOW_PRIORITY,
	})
	if err := setupArpProxyFlowAction(gwProxyFlow, u.datapathManager.Info.GatewayMac); err != nil {
		return fmt.Errorf("failed to setup arp proxy table gateway ip arp proxy flow action, err: %v", err)
	}
	if err := gwProxyFlow.Next(inportOutput); err != nil {
		return fmt.Errorf("failed to install arp proxy table gateway ip arp proxy flow, err: %v", err)
	}

	podProxyFlow, _ := u.arpProxyTable.NewFlow(ofctrl.FlowMatch{
		Ethertype:  PROTOCOL_ARP,
		ArpTpa:     &u.datapathManager.Info.ClusterPodCIDR.IP,
		ArpTpaMask: (*net.IP)(&u.datapathManager.Info.ClusterPodCIDR.Mask),
		ArpOper:    ArpOperRequest,
		Priority:   MID_MATCH_FLOW_PRIORITY,
	})
	fakeMac, _ := net.ParseMAC(FACK_MAC)
	if err := setupArpProxyFlowAction(podProxyFlow, fakeMac); err != nil {
		return fmt.Errorf("failed to setup arp proxy table pod cidr arp proxy flow action, err: %v", err)
	}
	if err := podProxyFlow.Next(inportOutput); err != nil {
		return fmt.Errorf("failed to install arp proxy table pod cidr arp proxy flow, err: %v", err)
	}

	defaultFlow, _ := u.arpProxyTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := defaultFlow.Next(sw.DropAction()); err != nil {
		return fmt.Errorf("failed to install arp proxy table default flow, err: %v", err)
	}

	return nil
}

func (u *UplinkBridgeOverlay) initForwardToLocalTable() error {
	toGwIPFlow, _ := u.forwardToLocalTable.NewFlow(ofctrl.FlowMatch{
		Ethertype: PROTOCOL_IP,
		IpDa:      &u.datapathManager.Info.GatewayIP,
		IpDaMask:  &IPMaskMatchFullBit,
		Priority:  HIGH_MATCH_FLOW_PRIORITY,
	})
	if err := toGwIPFlow.LoadField(UBOOutputPortReg, uint64(u.datapathManager.Info.GatewayOfPort), UBOOutputPortRange); err != nil {
		return fmt.Errorf("failed to setup forward to local table to gw ip flow load field action, err: %v", err)
	}
	if err := toGwIPFlow.Resubmit(nil, &UBOPaddingL2Table); err != nil {
		return fmt.Errorf("failed to setup forward to local table to gw ip flow resubmit action, err: %v", err)
	}
	if err := toGwIPFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install forward to local table to gw ip flow, err: %v", err)
	}

	toRemotePodFlow, _ := u.forwardToLocalTable.NewFlow(ofctrl.FlowMatch{
		Ethertype: PROTOCOL_IP,
		IpDa:      &u.datapathManager.Info.ClusterPodCIDR.IP,
		IpDaMask:  (*net.IP)(&u.datapathManager.Info.ClusterPodCIDR.Mask),
		Priority:  MID_MATCH_FLOW_PRIORITY,
	})
	if err := toRemotePodFlow.Resubmit(nil, &UBOForwardToTunnelTable); err != nil {
		return fmt.Errorf("failed to setup forward to local table to remote pod flow resubmit action, err: %v", err)
	}
	if err := toRemotePodFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install forward to local table to remote pod flow, err: %v", err)
	}

	toGwFlow, _ := u.forwardToLocalTable.NewFlow(ofctrl.FlowMatch{
		Ethertype: PROTOCOL_IP,
		Priority:  NORMAL_MATCH_FLOW_PRIORITY,
	})
	if err := toGwFlow.Resubmit(nil, &UBOForwardToGwTable); err != nil {
		return fmt.Errorf("failed to setup forward to local table to gw flow resubmit action, err: %v", err)
	}
	if err := toGwFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install forward to local table to gw flow, err: %v", err)
	}

	return nil
}

func (u *UplinkBridgeOverlay) initForwardToTunnelTable() error {
	sw := u.OfSwitch

	dropFlow, _ := u.forwardToTunnelTable.NewFlow(ofctrl.FlowMatch{
		InputPort: u.datapathManager.Info.TunnelOfPort,
		Priority:  MID_MATCH_FLOW_PRIORITY,
	})
	if err := dropFlow.Next(sw.DropAction()); err != nil {
		return fmt.Errorf("failed to install forward to tunnel table drop flow, err: %v", err)
	}

	tunnelFlow, _ := u.forwardToTunnelTable.NewFlow(ofctrl.FlowMatch{
		Priority: NORMAL_MATCH_FLOW_PRIORITY,
	})
	if err := tunnelFlow.Resubmit(nil, &UBOSetRemoteIPTable); err != nil {
		return fmt.Errorf("failed to setup forward to tunnel table tunnel flow resubmit action, err: %v", err)
	}
	if err := tunnelFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install forward to tunnel table tunnel flow, err: %v", err)
	}

	return nil
}

func (u *UplinkBridgeOverlay) initForwardToGwTable() error {
	sw := u.OfSwitch

	dropFlow, _ := u.forwardToGwTable.NewFlow(ofctrl.FlowMatch{
		InputPort: u.datapathManager.Info.GatewayOfPort,
		Priority:  MID_MATCH_FLOW_PRIORITY,
	})
	if err := dropFlow.Next(sw.DropAction()); err != nil {
		return fmt.Errorf("failed to install forward to gw table drop flow, err: %v", err)
	}

	gwFlow, _ := u.forwardToGwTable.NewFlow(ofctrl.FlowMatch{
		Priority: NORMAL_MATCH_FLOW_PRIORITY,
	})
	if err := gwFlow.LoadField(UBOOutputPortReg, uint64(u.datapathManager.Info.GatewayOfPort), UBOOutputPortRange); err != nil {
		return fmt.Errorf("failed to setup forward to gw table gw flow load field action, err: %v", err)
	}
	if err := gwFlow.Resubmit(nil, &UBOPaddingL2Table); err != nil {
		return fmt.Errorf("failed to setup forward to gw table gw flow resubmit action, err: %v", err)
	}
	if err := gwFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install forward to gw table gw flow, err: %v", err)
	}

	return nil
}

func (u *UplinkBridgeOverlay) initSetRemoteIPTable() error {
	sw := u.OfSwitch

	dropFlow, _ := u.setRemoteIPTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := dropFlow.Next(sw.DropAction()); err != nil {
		return fmt.Errorf("failed to install set remote ip table drop flow, err: %v", err)
	}

	return nil
}

func (u *UplinkBridgeOverlay) initSetTunnelOutPortTable() error {
	flow, _ := u.setTunnelOutPortTable.NewFlow(ofctrl.FlowMatch{
		Priority: NORMAL_MATCH_FLOW_PRIORITY,
	})
	if err := flow.LoadField(UBOOutputPortReg, uint64(u.datapathManager.Info.TunnelOfPort), UBOOutputPortRange); err != nil {
		return fmt.Errorf("failed to setup set tunnel out port table flow load field action, err: %v", err)
	}
	if err := flow.Resubmit(nil, &UBOOutputTable); err != nil {
		return fmt.Errorf("failed to setup set tunnel out port table flow resubmit action, err: %v", err)
	}
	if err := flow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install set tunnel out port table flow, err: %v", err)
	}
	return nil
}

func (u *UplinkBridgeOverlay) initPaddingL2table() error {
	sw := u.OfSwitch

	toGwFlow, _ := u.paddingL2Table.NewFlow(ofctrl.FlowMatch{
		Priority: MID_MATCH_FLOW_PRIORITY,
		Regs: []*ofctrl.NXRegister{
			{
				RegID: constants.OVSReg2,
				Data:  u.datapathManager.Info.GatewayOfPort,
				Range: UBOOutputPortRange,
			},
		},
	})
	fackMac, _ := net.ParseMAC(FACK_MAC)
	if err := toGwFlow.SetMacSa(fackMac); err != nil {
		return fmt.Errorf("failed to setup padding l2 table to gw flow set src mac action, err: %v", err)
	}
	if err := toGwFlow.SetMacDa(u.datapathManager.Info.GatewayMac); err != nil {
		return fmt.Errorf("failed to setup padding l2 table to gw flow set dst mac action, err: %v", err)
	}

	if err := toGwFlow.Resubmit(nil, &UBOOutputTable); err != nil {
		return fmt.Errorf("failed to setup paddling l2 table to gw flow resubmit action, err: %v", err)
	}
	if err := toGwFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install padding l2 table to gw flow, err: %v", err)
	}

	dropFlow, _ := u.paddingL2Table.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := dropFlow.Next(sw.DropAction()); err != nil {
		return fmt.Errorf("failed to install padding l2 table default drop flow, err: %v", err)
	}
	return nil
}

func (u *UplinkBridgeOverlay) initOutputTable() error {
	sw := u.OfSwitch
	inportOutput, _ := sw.OutputPort(openflow.P_IN_PORT)

	inPortFlow, _ := u.outputTable.NewFlow(ofctrl.FlowMatch{
		InputPort: u.datapathManager.BridgeChainPortMap[u.ovsBrName][UplinkToClsSuffix],
		Regs: []*ofctrl.NXRegister{
			{
				RegID: constants.OVSReg2,
				Data:  u.datapathManager.BridgeChainPortMap[u.ovsBrName][UplinkToClsSuffix],
				Range: UBOOutputPortRange,
			},
		},
		Priority: HIGH_MATCH_FLOW_PRIORITY,
	})
	if err := inPortFlow.Next(inportOutput); err != nil {
		return fmt.Errorf("failed to install output table inport output flow, err :%v", err)
	}

	defaultFlow, _ := u.outputTable.NewFlow(ofctrl.FlowMatch{
		Priority: NORMAL_MATCH_FLOW_PRIORITY,
	})
	outputPort, err := sw.OutputPortReg(UBOOutputPortReg, uint16(UBOOutputPortStart))
	if err != nil {
		return fmt.Errorf("failed to new output port reg, err: %v", err)
	}
	if err := defaultFlow.Next(outputPort); err != nil {
		return fmt.Errorf("failed to install output table default flow, err: %v", err)
	}

	return nil
}
