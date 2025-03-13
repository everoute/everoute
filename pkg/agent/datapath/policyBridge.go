package datapath

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/ofnet/ofctrl"
	"github.com/samber/lo"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	klog "k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/everoute/everoute/pkg/constants"
)

const (
	// the lower 28bit of cookie is used to specify ovs flow for policy bridge
	// 0x0->0x7ffffff (mask is 0x07ffffff, and the 28th bit is fixed to 0) is used by general ovs flow and auto allocated
	CookieAutoAllocBitWidthForPolicyBr uint64 = 27
	// 0x8000000->0x83fffff (mask is 0x3fffff) is used by rule flows
	CookieRuleUsedBitWidth uint64 = 22
	CookieRuleSeqIDMask    uint64 = 0x0000_0000_003f_ffff
	CookieRuleFix          uint64 = 0x0000_0000_0800_0000
)

// //nolint
const (
	INPUT_TABLE                 = 0
	CT_STATE_TABLE              = 1
	PASSTHROUGH_TABLE           = 5
	DIRECTION_SELECTION_TABLE   = 10
	EGRESS_TIER1_TABLE          = 20
	EGRESS_TIER2_MONITOR_TABLE  = 24
	EGRESS_TIER2_TABLE          = 25
	EGRESS_TIER_ECP_TABLE       = 28
	EGRESS_TIER3_MONITOR_TABLE  = 29
	EGRESS_TIER3_TABLE          = 30
	INGRESS_TIER1_TABLE         = 50
	INGRESS_TIER2_MONITOR_TABLE = 54
	INGRESS_TIER2_TABLE         = 55
	INGRESS_TIER_ECP_TABLE      = 58
	INGRESS_TIER3_MONITOR_TABLE = 59
	INGRESS_TIER3_TABLE         = 60
	CT_COMMIT_TABLE             = 70
	CT_DROP_TABLE               = 71
	SFC_POLICY_TABLE            = 80
	POLICY_FORWARDING_TABLE     = 90
	TO_LOCAL_TABLE              = 141

	RoundNumXXREG0BitStart              = 0 // codepoint0 bit start
	RoundNumXXREG0BitEnd                = 3 // codepoint0 bit end
	RoundNumXXREG0BitSize               = RoundNumXXREG0BitEnd - RoundNumXXREG0BitStart + 1
	MonitorTier2FlowSpaceXXREG0BitStart = 4  // codepoint1 bit start
	MonitorTier2FlowSpaceXXREG0BitEnd   = 31 // codepoint1 bit end
	MonitorTier3FlowSpaceXXREG0BitStart = 32 // codepoint2 bit start
	MonitorTier3FlowSpaceXXREG0BitEnd   = 59 // codepoint2 bit end
	MonitorTier3FlowSpaceXXREG0BitSize  = MonitorTier3FlowSpaceXXREG0BitEnd - MonitorTier3FlowSpaceXXREG0BitStart + 1
	WorkPolicyActionXXREG0Bit           = 127 // codepoint6
	MonitorTier3PolicyActionXXREG0Bit   = 126 // codepoint5
)

var (
	WorkPolicyActionDenyMatchCTLabel             = [16]byte{0x80} // 1 << WorkPolicyActionXXREG0Bit
	WorkPolicyActionDenyMatchCTLabelMask         = [16]byte{0x80} // 1 << WorkPolicyActionXXREG0Bit
	MonitorTier3PolicyActionDenyMatchCTLabel     = [16]byte{0x40} // 1 << MonitorTier3PolicyActionXXREG0Bit
	MonitorTier3PolicyActionDenyMatchCTLabelMask = [16]byte{0x40} // 1 << MonitorTier3PolicyActionXXREG0Bit

	RoundNumNXRange                 = openflow13.NewNXRange(RoundNumXXREG0BitStart, RoundNumXXREG0BitEnd)
	MonitorTier2FlowSpaceNXRange    = openflow13.NewNXRange(MonitorTier2FlowSpaceXXREG0BitStart, MonitorTier2FlowSpaceXXREG0BitEnd)
	MonitorTier3FlowSpaceNXRange    = openflow13.NewNXRange(MonitorTier3FlowSpaceXXREG0BitStart, MonitorTier3FlowSpaceXXREG0BitEnd)
	WorkPolicyActionNXRange         = openflow13.NewNXRange(WorkPolicyActionXXREG0Bit, WorkPolicyActionXXREG0Bit)
	MonitorTier3PolicyActionNXRange = openflow13.NewNXRange(MonitorTier3PolicyActionXXREG0Bit, MonitorTier3PolicyActionXXREG0Bit)
)

type PolicyBridge struct {
	BaseBridge

	inputTable                     *ofctrl.Table
	ctStateTable                   *ofctrl.Table
	passthroughTable               *ofctrl.Table
	directionSelectionTable        *ofctrl.Table
	egressTier1PolicyTable         *ofctrl.Table
	egressTier2PolicyMonitorTable  *ofctrl.Table
	egressTier2PolicyTable         *ofctrl.Table
	egressTierECPPolicyTable       *ofctrl.Table
	egressTier3PolicyMonitorTable  *ofctrl.Table
	egressTier3PolicyTable         *ofctrl.Table
	ingressTier1PolicyTable        *ofctrl.Table
	ingressTier2PolicyMonitorTable *ofctrl.Table
	ingressTier2PolicyTable        *ofctrl.Table
	ingressTierECPPolicyTable      *ofctrl.Table
	ingressTier3PolicyMonitorTable *ofctrl.Table
	ingressTier3PolicyTable        *ofctrl.Table
	ctCommitTable                  *ofctrl.Table
	ctDropTable                    *ofctrl.Table
	sfcPolicyTable                 *ofctrl.Table
	policyForwardingTable          *ofctrl.Table
	toLocalTable                   *ofctrl.Table
}

func NewPolicyBridge(brName string, datapathManager *DpManager) *PolicyBridge {
	policyBridge := new(PolicyBridge)
	policyBridge.name = fmt.Sprintf("%s-policy", brName)
	policyBridge.datapathManager = datapathManager
	return policyBridge
}

func (p *PolicyBridge) PacketRcvd(_ *ofctrl.OFSwitch, _ *ofctrl.PacketIn) {
}

func (p *PolicyBridge) MultipartReply(_ *ofctrl.OFSwitch, _ *openflow13.MultipartReply) {
}

func (p *PolicyBridge) BridgeInit() {
	sw := p.OfSwitch

	p.inputTable = sw.DefaultTable()
	p.ctStateTable, _ = sw.NewTable(CT_STATE_TABLE)
	p.passthroughTable, _ = sw.NewTable(PASSTHROUGH_TABLE)
	p.directionSelectionTable, _ = sw.NewTable(DIRECTION_SELECTION_TABLE)
	p.ingressTier1PolicyTable, _ = sw.NewTable(INGRESS_TIER1_TABLE)
	p.ingressTier2PolicyMonitorTable, _ = sw.NewTable(INGRESS_TIER2_MONITOR_TABLE)
	p.ingressTier2PolicyTable, _ = sw.NewTable(INGRESS_TIER2_TABLE)
	p.ingressTierECPPolicyTable, _ = sw.NewTable(INGRESS_TIER_ECP_TABLE)
	p.ingressTier3PolicyMonitorTable, _ = sw.NewTable(INGRESS_TIER3_MONITOR_TABLE)
	p.ingressTier3PolicyTable, _ = sw.NewTable(INGRESS_TIER3_TABLE)
	p.egressTier1PolicyTable, _ = sw.NewTable(EGRESS_TIER1_TABLE)
	p.egressTier2PolicyMonitorTable, _ = sw.NewTable(EGRESS_TIER2_MONITOR_TABLE)
	p.egressTier2PolicyTable, _ = sw.NewTable(EGRESS_TIER2_TABLE)
	p.egressTierECPPolicyTable, _ = sw.NewTable(EGRESS_TIER_ECP_TABLE)
	p.egressTier3PolicyMonitorTable, _ = sw.NewTable(EGRESS_TIER3_MONITOR_TABLE)
	p.egressTier3PolicyTable, _ = sw.NewTable(EGRESS_TIER3_TABLE)
	p.ctCommitTable, _ = sw.NewTable(CT_COMMIT_TABLE)
	p.ctDropTable, _ = sw.NewTable(CT_DROP_TABLE)
	p.sfcPolicyTable, _ = sw.NewTable(SFC_POLICY_TABLE)
	p.policyForwardingTable, _ = sw.NewTable(POLICY_FORWARDING_TABLE)
	p.toLocalTable, _ = sw.NewTable(TO_LOCAL_TABLE)

	// Initialize in reverse order of the flow table order for everoute upgrade
	if err := p.initToLocalFlow(); err != nil {
		klog.Fatalf("Failed to init to local table, error: %s", err)
	}
	if err := p.initInputTable(sw); err != nil {
		klog.Fatalf("Failed to init inputTable, error: %v", err)
	}
	if err := p.initDuplicateDropFlow(); err != nil {
		klog.Fatalf("Failed to init duplicate packets drop flow: %s", err)
	}
	if err := p.initPassthroughTable(sw); err != nil {
		klog.Fatalf("Failed to init passthroughTable, error: %v", err)
	}
	if err := p.initCTFlow(sw); err != nil {
		klog.Fatalf("Failed to init ct table, error: %v", err)
	}
	if err := p.initALGFlow(sw); err != nil {
		klog.Fatalf("Failed to init alg flow, error: %v", err)
	}
	if err := p.initDirectionSelectionTable(); err != nil {
		klog.Fatalf("Failed to init directionSelection table, error: %v", err)
	}
	if err := p.initPolicyTable(); err != nil {
		klog.Fatalf("Failed to init policy table, error: %v", err)
	}
	if err := p.initPolicyForwardingTable(sw); err != nil {
		klog.Fatalf("Failed to init policy forwarding table, error: %v", err)
	}
}

func (p *PolicyBridge) initDirectionSelectionTable() error {
	localBrName := strings.TrimSuffix(p.name, "-policy")
	fromLocalToEgressFlow, _ := p.directionSelectionTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		InputPort: p.datapathManager.BridgeChainPortMap[localBrName][PolicyToLocalSuffix],
	})
	if err := fromLocalToEgressFlow.Next(p.egressTier1PolicyTable); err != nil {
		return fmt.Errorf("failed to install from local to egress flow, error: %v", err)
	}
	fromUpstreamToIngressFlow, _ := p.directionSelectionTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		InputPort: p.datapathManager.BridgeChainPortMap[localBrName][PolicyToClsSuffix],
	})
	if err := fromUpstreamToIngressFlow.Next(p.ingressTier1PolicyTable); err != nil {
		return fmt.Errorf("failed to install from upstream to ingress flow, error: %v", err)
	}

	return nil
}

func (p *PolicyBridge) initInputTable(_ *ofctrl.OFSwitch) error {
	// Table 0, icmpv6 RS/RA/NS/NA passthrough
	ndpPassthroughFlow, _ := p.inputTable.NewFlow(ofctrl.FlowMatch{
		// TODO: maybe some problems with CNI flows
		Priority:  HIGH_MATCH_FLOW_PRIORITY + FLOW_MATCH_OFFSET,
		Ethertype: protocol.IPv6_MSG,
		IpProto:   protocol.Type_IPv6ICMP,
		Icmp6Type: lo.ToPtr(uint8(ipv6.ICMPTypeRouterSolicitation)),
	})
	if err := ndpPassthroughFlow.Next(p.passthroughTable); err != nil {
		return fmt.Errorf("failed to install icmpv6 ndp rs passthrough flow, error: %v", err)
	}

	ndpPassthroughFlow.Match.Icmp6Type = lo.ToPtr(uint8(ipv6.ICMPTypeRouterAdvertisement))
	if err := ndpPassthroughFlow.ForceAddInstall(); err != nil {
		return fmt.Errorf("failed to install icmpv6 ndp ra passthrough flow, error: %v", err)
	}

	ndpPassthroughFlow.Match.Icmp6Type = lo.ToPtr(uint8(ipv6.ICMPTypeNeighborSolicitation))
	if err := ndpPassthroughFlow.ForceAddInstall(); err != nil {
		return fmt.Errorf("failed to install icmpv6 ndp ns passthrough flow, error: %v", err)
	}

	ndpPassthroughFlow.Match.Icmp6Type = lo.ToPtr(uint8(ipv6.ICMPTypeNeighborAdvertisement))
	if err := ndpPassthroughFlow.ForceAddInstall(); err != nil {
		return fmt.Errorf("failed to install icmpv6 ndp na passthrough flow, error: %v", err)
	}

	ndpPassthroughFlow.Match.Icmp6Type = lo.ToPtr(uint8(ipv6.ICMPTypeRedirect))
	if err := ndpPassthroughFlow.ForceAddInstall(); err != nil {
		return fmt.Errorf("failed to install icmpv6 ndp redirect passthrough flow, error: %v", err)
	}

	var ctStateTableID uint8 = CT_STATE_TABLE
	var policyConntrackZone = constants.CTZoneForPolicy
	ctAction := ofctrl.NewConntrackAction(false, false, &ctStateTableID, &policyConntrackZone)
	inputIPRedirectFlow, _ := p.inputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  HIGH_MATCH_FLOW_PRIORITY,
		Ethertype: protocol.IPv4_MSG,
	})
	_ = inputIPRedirectFlow.SetConntrack(ctAction)
	if err := inputIPRedirectFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install input ip redirect flow, error: %v", err)
	}

	inputIPRedirectFlow.Match.Ethertype = protocol.IPv6_MSG
	if err := inputIPRedirectFlow.ForceAddInstall(); err != nil {
		return fmt.Errorf("failed to install input ip redirect ipv6 flow, error: %v", err)
	}

	// Table 0, default flow
	inputDefaultFlow, _ := p.inputTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := inputDefaultFlow.Next(p.passthroughTable); err != nil {
		return fmt.Errorf("failed to install input default flow, error: %v", err)
	}

	return nil
}

func (p *PolicyBridge) initPassthroughTable(sw *ofctrl.OFSwitch) error {
	// Table 5, from local bridge flow
	localBrName := strings.TrimSuffix(p.name, "-policy")
	inputFromLocalFlow, _ := p.passthroughTable.NewFlow(ofctrl.FlowMatch{
		Priority:  NORMAL_MATCH_FLOW_PRIORITY,
		InputPort: p.datapathManager.BridgeChainPortMap[localBrName][PolicyToLocalSuffix],
	})
	outputPort, _ := sw.OutputPort(p.datapathManager.BridgeChainPortMap[localBrName][PolicyToClsSuffix])
	if err := inputFromLocalFlow.Next(outputPort); err != nil {
		return fmt.Errorf("failed to install input from local flow, error: %v", err)
	}

	// Table 5, from cls bridge flow
	inputFromUpstreamFlow, _ := p.passthroughTable.NewFlow(ofctrl.FlowMatch{
		Priority:  NORMAL_MATCH_FLOW_PRIORITY,
		InputPort: p.datapathManager.BridgeChainPortMap[localBrName][PolicyToClsSuffix],
	})
	outputPort, _ = sw.OutputPort(p.datapathManager.BridgeChainPortMap[localBrName][PolicyToLocalSuffix])
	if err := inputFromUpstreamFlow.Next(outputPort); err != nil {
		return fmt.Errorf("failed to install input from upstream flow, error: %v", err)
	}

	return nil
}

//nolint:funlen
func (p *PolicyBridge) initCTFlow(_ *ofctrl.OFSwitch) error {
	var policyConntrackZone = constants.CTZoneForPolicy
	// Table 1, ctState table, est state flow
	// FIXME. should add ctEst flow and ctInv flow with same priority. With different, it have no side effect to flow intent.
	ctEstState := openflow13.NewCTStates()
	ctEstState.UnsetNew()
	ctEstState.SetEst()
	ctStateFlow, _ := p.ctStateTable.NewFlow(ofctrl.FlowMatch{
		Priority: MID_MATCH_FLOW_PRIORITY,
		CtStates: ctEstState,
	})
	if err := ctStateFlow.Next(p.ctCommitTable); err != nil {
		return fmt.Errorf("failed to install ct est state flow, error: %v", err)
	}

	// Table 1. default flow
	ctStateDefaultFlow, _ := p.ctStateTable.NewFlow(ofctrl.FlowMatch{
		Priority:  DEFAULT_FLOW_MISS_PRIORITY,
		Ethertype: protocol.IPv4_MSG,
	})
	if err := ctStateDefaultFlow.Next(p.directionSelectionTable); err != nil {
		klog.Fatalf("failed to install ct state default flow, error: %v", err)
	}

	ctStateDefaultFlow.Match.Ethertype = protocol.IPv6_MSG
	if err := ctStateDefaultFlow.ForceAddInstall(); err != nil {
		klog.Fatalf("failed to install ct state default ipv6 flow, error: %v", err)
	}

	// Table 70 conntrack commit table
	// DONOT commit new tcp without syn flag, otherwise an +new+est CT flow
	// will generate by conntrack module automatically. If happen to receive
	// a reverse pkt, valid CT flow will be created, and drop rule does not work.
	ctTrkState := openflow13.NewCTStates()
	ctTrkState.SetNew()
	ctTrkState.SetTrk()
	zeroFlag := uint16(0)
	tcpSynMask := uint16(0x2)
	ctCommitFilterFlow, _ := p.ctCommitTable.NewFlow(ofctrl.FlowMatch{
		Priority:  HIGH_MATCH_FLOW_PRIORITY,
		Ethertype: protocol.IPv4_MSG,
		IpProto:   ofctrl.IP_PROTO_TCP,
		CtStates:  ctTrkState,
		Regs: []*ofctrl.NXRegister{
			{
				RegID: constants.OVSReg4,
				Data:  0x20,
				Range: openflow13.NewNXRange(0, 15),
			},
		},
		TcpFlags:     &zeroFlag,
		TcpFlagsMask: &tcpSynMask,
	})
	if err := ctCommitFilterFlow.Next(p.ctDropTable); err != nil {
		return fmt.Errorf("failed to install ct tcp est state flow, error: %v", err)
	}

	ctCommitFilterFlow.Match.Ethertype = protocol.IPv6_MSG
	if err := ctCommitFilterFlow.ForceAddInstall(); err != nil {
		return fmt.Errorf("failed to install ct tcp est state ipv6 flow, error: %v", err)
	}

	// drop pkt with CT_LABEL[127]=1, even if EST state
	ctDropFilterFlow, _ := p.ctCommitTable.NewFlow(ofctrl.FlowMatch{
		Priority:    HIGH_MATCH_FLOW_PRIORITY,
		Ethertype:   protocol.IPv4_MSG,
		CTLabel:     &WorkPolicyActionDenyMatchCTLabel,
		CTLabelMask: &WorkPolicyActionDenyMatchCTLabelMask,
	})
	if err := ctDropFilterFlow.LoadField("nxm_nx_reg4", 0x20, openflow13.NewNXRange(0, 15)); err != nil {
		return err
	}
	if err := ctDropFilterFlow.Next(p.ctDropTable); err != nil {
		return fmt.Errorf("failed to install ct drop resubmit flow, error: %v", err)
	}

	ctDropFilterFlow.Match.Ethertype = protocol.IPv6_MSG
	if err := ctDropFilterFlow.ForceAddInstall(); err != nil {
		return fmt.Errorf("failed to install ct drop resubmit ipv6 flow, error: %v", err)
	}

	// commit normal ip packet into ct
	ctCommitFlow, _ := p.ctCommitTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		Ethertype: protocol.IPv4_MSG,
		CtStates:  ctTrkState,
	})
	var ctDropTable uint8 = CT_DROP_TABLE
	srcField, _ := openflow13.FindFieldHeaderByName("nxm_nx_xxreg0", false)
	dstField, _ := openflow13.FindFieldHeaderByName("nxm_nx_ct_label", false)
	moveAct := openflow13.NewNXActionRegMove(128, 0, 0, srcField, dstField)
	ctCommitAction := ofctrl.NewConntrackAction(true, false, &ctDropTable, &policyConntrackZone, moveAct)
	_ = ctCommitFlow.SetConntrack(ctCommitAction)
	if err := ctCommitFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install ct normal commit flow, error: %v", err)
	}

	ctCommitFlow.Match.Ethertype = protocol.IPv6_MSG
	if err := ctCommitFlow.ForceAddInstall(); err != nil {
		return fmt.Errorf("failed to install ct normal commit flow, error: %v", err)
	}

	ctCommitTableDefaultFlow, _ := p.ctCommitTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := ctCommitTableDefaultFlow.Next(p.ctDropTable); err != nil {
		return fmt.Errorf("failed to install ct commit flow, error: %v", err)
	}

	// ct drop table: 71
	ctByPassFlow1, _ := p.ctDropTable.NewFlow(ofctrl.FlowMatch{
		Priority: MID_MATCH_FLOW_PRIORITY + FLOW_MATCH_OFFSET,
		Regs: []*ofctrl.NXRegister{
			{
				RegID: constants.OVSReg4,
				Data:  0x20,
				Range: openflow13.NewNXRange(0, 15),
			},
		},
	})
	if err := ctByPassFlow1.Next(p.OfSwitch.DropAction()); err != nil {
		return fmt.Errorf("failed to install ct drop flow, error: %v", err)
	}
	ctByPassFlow2, _ := p.ctDropTable.NewFlow(ofctrl.FlowMatch{
		Priority: MID_MATCH_FLOW_PRIORITY + FLOW_MATCH_OFFSET,
		Regs: []*ofctrl.NXRegister{
			{
				RegID: constants.OVSReg4,
				Data:  0x30,
				Range: openflow13.NewNXRange(0, 15),
			},
		},
	})
	if err := ctByPassFlow2.Resubmit(nil, &p.sfcPolicyTable.TableId); err != nil {
		return fmt.Errorf("failed to install ct bypass flow 2, error: %v", err)
	}
	if err := ctByPassFlow2.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install ct bypass flow 2, error: %v", err)
	}

	ctPassDefaultFlow, _ := p.ctDropTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := ctPassDefaultFlow.Next(p.sfcPolicyTable); err != nil {
		return fmt.Errorf("failed to install egress tier3 drop table flow, error: %v", err)
	}

	return nil
}

//nolint:funlen
func (p *PolicyBridge) initPolicyTable() error {
	// egress policy table
	egressTier1DefaultFlow, _ := p.egressTier1PolicyTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := egressTier1DefaultFlow.Next(p.egressTier2PolicyMonitorTable); err != nil {
		return fmt.Errorf("failed to install egress tier1 default flow, error: %v", err)
	}
	egressTier2MonitorDefaultFlow, _ := p.egressTier2PolicyMonitorTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := egressTier2MonitorDefaultFlow.Next(p.egressTier2PolicyTable); err != nil {
		return fmt.Errorf("failed to install egress tier2 monitor table default flow, error: %v", err)
	}
	egressTier2DefaultFlow, _ := p.egressTier2PolicyTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := egressTier2DefaultFlow.Next(p.egressTierECPPolicyTable); err != nil {
		return fmt.Errorf("failed to install egress tier2 default flow, error: %v", err)
	}
	egressTierECPDefaultFlow, _ := p.egressTierECPPolicyTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := egressTierECPDefaultFlow.Next(p.egressTier3PolicyMonitorTable); err != nil {
		return fmt.Errorf("failed to install egress tier ecp default flow, error: %v", err)
	}
	egressTier3MonitorDefaultFlow, _ := p.egressTier3PolicyMonitorTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := egressTier3MonitorDefaultFlow.Next(p.egressTier3PolicyTable); err != nil {
		return fmt.Errorf("failed to install egress tier2 monitor table default flow, error: %v", err)
	}
	egressTier3DefaultFlow, _ := p.egressTier3PolicyTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := egressTier3DefaultFlow.Next(p.ctCommitTable); err != nil {
		return fmt.Errorf("failed to install egress tier3 default flow, error: %v", err)
	}

	// ingress policy table
	ingressTier1DefaultFlow, _ := p.ingressTier1PolicyTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := ingressTier1DefaultFlow.Next(p.ingressTier2PolicyMonitorTable); err != nil {
		return fmt.Errorf("failed to install ingress tier1 default flow, error: %v", err)
	}
	ingressTier2MonitorDefaultFlow, _ := p.ingressTier2PolicyMonitorTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := ingressTier2MonitorDefaultFlow.Next(p.ingressTier2PolicyTable); err != nil {
		return fmt.Errorf("failed to install ingress tier2 monitor table default flow, error: %v", err)
	}
	ingressTier2DefaultFlow, _ := p.ingressTier2PolicyTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := ingressTier2DefaultFlow.Next(p.ingressTierECPPolicyTable); err != nil {
		return fmt.Errorf("failed to install ingress tier2 default flow, error: %v", err)
	}
	ingressTierECPDefaultFlow, _ := p.ingressTierECPPolicyTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := ingressTierECPDefaultFlow.Next(p.ingressTier3PolicyMonitorTable); err != nil {
		return fmt.Errorf("failed to install ingress tier2 default flow, error: %v", err)
	}
	ingressTier3MonitorDropMatchFlow, _ := p.ingressTier3PolicyMonitorTable.NewFlow(ofctrl.FlowMatch{
		Priority:    constants.MaxSecurityPolicyRulePriority + 100,
		Ethertype:   protocol.IPv4_MSG,
		CTLabel:     &MonitorTier3PolicyActionDenyMatchCTLabel,
		CTLabelMask: &MonitorTier3PolicyActionDenyMatchCTLabelMask,
	})
	if err := ingressTier3MonitorDropMatchFlow.MoveField(
		1,
		MonitorTier3PolicyActionXXREG0Bit,
		MonitorTier3PolicyActionXXREG0Bit,
		"nxm_nx_ct_label", "nxm_nx_xxreg0", false); err != nil {
		return fmt.Errorf("failed to install ingress tier3 monitor table drop match flow, error: %v", err)
	}
	if err := ingressTier3MonitorDropMatchFlow.MoveField(
		MonitorTier3FlowSpaceXXREG0BitSize,
		MonitorTier3FlowSpaceXXREG0BitStart,
		MonitorTier3FlowSpaceXXREG0BitStart,
		"nxm_nx_ct_label", "nxm_nx_xxreg0", false); err != nil {
		return fmt.Errorf("failed to install ingress tier3 monitor table drop match flow, error: %v", err)
	}
	if err := ingressTier3MonitorDropMatchFlow.MoveField(
		RoundNumXXREG0BitSize,
		RoundNumXXREG0BitStart,
		RoundNumXXREG0BitStart,
		"nxm_nx_ct_label", "nxm_nx_xxreg0", false); err != nil {
		return fmt.Errorf("failed to install ingress tier3 monitor table drop match flow, error: %v", err)
	}
	if err := ingressTier3MonitorDropMatchFlow.Next(p.ingressTier3PolicyTable); err != nil {
		return fmt.Errorf("failed to install ingress tier3 monitor table drop match flow, error: %v", err)
	}

	ingressTier3MonitorDropMatchFlow.Match.Ethertype = protocol.IPv6_MSG
	if err := ingressTier3MonitorDropMatchFlow.ForceAddInstall(); err != nil {
		return fmt.Errorf("failed to install ingress tier3 monitor table drop match ipv6 flow, error: %v", err)
	}

	ingressTier3MonitorDefaultFlow, _ := p.ingressTier3PolicyMonitorTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := ingressTier3MonitorDefaultFlow.MoveField(
		1,
		MonitorTier3PolicyActionXXREG0Bit,
		MonitorTier3PolicyActionXXREG0Bit,
		"nxm_nx_ct_label", "nxm_nx_xxreg0", false); err != nil {
		return fmt.Errorf("failed to install ingress tier3 monitor table default flow, error: %v", err)
	}
	if err := ingressTier3MonitorDefaultFlow.MoveField(
		MonitorTier3FlowSpaceXXREG0BitSize,
		MonitorTier3FlowSpaceXXREG0BitStart,
		MonitorTier3FlowSpaceXXREG0BitStart,
		"nxm_nx_ct_label", "nxm_nx_xxreg0", false); err != nil {
		return fmt.Errorf("failed to install ingress tier3 monitor table default flow, error: %v", err)
	}
	if err := ingressTier3MonitorDefaultFlow.MoveField(
		RoundNumXXREG0BitSize,
		RoundNumXXREG0BitStart,
		RoundNumXXREG0BitStart,
		"nxm_nx_ct_label", "nxm_nx_xxreg0", false); err != nil {
		return fmt.Errorf("failed to install ingress tier3 monitor table default flow, error: %v", err)
	}
	if err := ingressTier3MonitorDefaultFlow.Next(p.ingressTier3PolicyTable); err != nil {
		return fmt.Errorf("failed to install ingress tier3 monitor table default flow, error: %v", err)
	}
	ingressTier3DefaultFlow, _ := p.ingressTier3PolicyTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := ingressTier3DefaultFlow.Next(p.ctCommitTable); err != nil {
		return fmt.Errorf("failed to install ingress tier3 default flow, error: %v", err)
	}

	// sfc policy table
	sfcPolicyTableDefaultFlow, _ := p.sfcPolicyTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_MISS_PRIORITY,
	})
	if err := sfcPolicyTableDefaultFlow.Next(p.policyForwardingTable); err != nil {
		return fmt.Errorf("failed to install sfc policy table default flow, error: %v", err)
	}

	return nil
}

func (p *PolicyBridge) initPolicyForwardingTable(sw *ofctrl.OFSwitch) error {
	localBrName := strings.TrimSuffix(p.name, "-policy")
	// policy forwarding table
	fromLocalOutputFlow, _ := p.policyForwardingTable.NewFlow(ofctrl.FlowMatch{
		Priority:  NORMAL_MATCH_FLOW_PRIORITY,
		InputPort: p.datapathManager.BridgeChainPortMap[localBrName][PolicyToLocalSuffix],
		Regs: []*ofctrl.NXRegister{
			{
				RegID: constants.OVSReg6,
				Data:  0,
				Range: openflow13.NewNXRange(0, 15),
			},
		},
	})
	outputPort, _ := sw.OutputPort(p.datapathManager.BridgeChainPortMap[localBrName][PolicyToClsSuffix])
	if err := fromLocalOutputFlow.Next(outputPort); err != nil {
		return fmt.Errorf("failed to install from local output flow, error: %v", err)
	}

	fromUpstreamOutputFlow, _ := p.policyForwardingTable.NewFlow(ofctrl.FlowMatch{
		Priority:  NORMAL_MATCH_FLOW_PRIORITY,
		InputPort: p.datapathManager.BridgeChainPortMap[localBrName][PolicyToClsSuffix],
		Regs: []*ofctrl.NXRegister{
			{
				RegID: constants.OVSReg6,
				Data:  0,
				Range: openflow13.NewNXRange(0, 15),
			},
		},
	})
	if err := fromUpstreamOutputFlow.Next(p.toLocalTable); err != nil {
		return fmt.Errorf("failed to install from upstream output flow, error: %v", err)
	}

	return nil
}

func (p *PolicyBridge) initALGFlow(_ *ofctrl.OFSwitch) error {
	// Table 1, ctState table, rel state flow
	ctRelState := openflow13.NewCTStates()
	ctRelState.SetRel()
	ctRelState.SetTrk()
	ctRelFlow, _ := p.ctStateTable.NewFlow(ofctrl.FlowMatch{
		Priority: MID_MATCH_FLOW_PRIORITY,
		CtStates: ctRelState,
	})
	if err := ctRelFlow.Next(p.ctCommitTable); err != nil {
		return fmt.Errorf("failed to install ct rel state flow, err: %v", err)
	}

	ctTrkState := openflow13.NewCTStates()
	ctTrkState.SetNew()
	ctTrkState.SetTrk()
	var policyConntrackZone = constants.CTZoneForPolicy
	var ctDropTable uint8 = CT_DROP_TABLE
	srcField, _ := openflow13.FindFieldHeaderByName("nxm_nx_xxreg0", false)
	dstField, _ := openflow13.FindFieldHeaderByName("nxm_nx_ct_label", false)
	moveAct := openflow13.NewNXActionRegMove(128, 0, 0, srcField, dstField)

	// Table 70 commit ct with alg=ftp
	ftpFlow, _ := p.ctCommitTable.NewFlow(ofctrl.FlowMatch{
		Priority:       MID_MATCH_FLOW_PRIORITY + FLOW_MATCH_OFFSET,
		Ethertype:      protocol.IPv4_MSG,
		IpProto:        PROTOCOL_TCP,
		TcpDstPort:     FTPPort,
		TcpDstPortMask: PortMaskMatchFullBit,
		CtStates:       ctTrkState,
	})
	ftpAction := ofctrl.NewConntrackAction(true, false, &ctDropTable, &policyConntrackZone, moveAct)
	ftpAction.SetAlg(FTPPort)
	_ = ftpFlow.SetConntrack(ftpAction)
	if err := ftpFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install ftp flow, err: %v", err)
	}

	ftpFlow.Match.Ethertype = protocol.IPv6_MSG
	if err := ftpFlow.ForceAddInstall(); err != nil {
		return fmt.Errorf("failed to install ftp ipv6 flow, err: %v", err)
	}

	// Table 70 commit ct with alg=tftp
	tftpFlow, _ := p.ctCommitTable.NewFlow(ofctrl.FlowMatch{
		Priority:       MID_MATCH_FLOW_PRIORITY + FLOW_MATCH_OFFSET,
		Ethertype:      PROTOCOL_IP,
		IpProto:        PROTOCOL_UDP,
		UdpDstPort:     TFTPPort,
		UdpDstPortMask: PortMaskMatchFullBit,
		CtStates:       ctTrkState,
	})
	tftpAction := ofctrl.NewConntrackAction(true, false, &ctDropTable, &policyConntrackZone, moveAct)
	tftpAction.SetAlg(TFTPPort)
	_ = tftpFlow.SetConntrack(tftpAction)
	if err := tftpFlow.Next(ofctrl.NewEmptyElem()); err != nil {
		return fmt.Errorf("failed to install tftp flow, err: %v", err)
	}

	tftpFlow.Match.Ethertype = protocol.IPv6_MSG
	if err := tftpFlow.ForceAddInstall(); err != nil {
		return fmt.Errorf("failed to install tftp ipv6 flow, err: %v", err)
	}

	return nil
}

func (p *PolicyBridge) initToLocalFlow() error {
	// set pkt mark for to local packets
	pktMarkRange := openflow13.NewNXRange(constants.DuplicatePktMarkBit, constants.DuplicatePktMarkBit)
	pktMarkSetAct, err := ofctrl.NewNXLoadAction("nxm_nx_pkt_mark", constants.PktMarkSetValue, pktMarkRange)
	if err != nil {
		return err
	}
	localBrName := strings.TrimSuffix(p.name, "-policy")
	outputAct := ofctrl.NewOutputAction(p.datapathManager.BridgeChainPortMap[localBrName][PolicyToLocalSuffix])
	flow, _ := p.toLocalTable.NewFlow(ofctrl.FlowMatch{
		Priority: HIGH_MATCH_FLOW_PRIORITY,
	})
	if err := flow.AddAction(pktMarkSetAct, outputAct); err != nil {
		return err
	}
	err = flow.Next(ofctrl.NewEmptyElem())
	return err
}

func (p *PolicyBridge) initDuplicateDropFlow() error {
	localBrName := strings.TrimSuffix(p.name, "-policy")
	// duplicate packets from Local bridge will drop
	var pktMask uint32 = 1 << constants.DuplicatePktMarkBit
	duplicateDropFlow, _ := p.inputTable.NewFlow(ofctrl.FlowMatch{
		InputPort:   p.datapathManager.BridgeChainPortMap[localBrName][PolicyToLocalSuffix],
		PktMark:     1 << constants.DuplicatePktMarkBit,
		PktMarkMask: &pktMask,
		Priority:    HIGH_MATCH_FLOW_PRIORITY + LARGE_FLOW_MATCH_OFFSET + FLOW_MATCH_OFFSET,
	})
	if err := duplicateDropFlow.Next(p.OfSwitch.DropAction()); err != nil {
		return fmt.Errorf("failed to install duplicate packets: %s", err)
	}
	return nil
}

func (p *PolicyBridge) BridgeReset() {
}

func (p *PolicyBridge) AddLocalEndpoint(_ *Endpoint) error {
	return nil
}

func (p *PolicyBridge) RemoveLocalEndpoint(_ *Endpoint) error {
	return nil
}

func (p *PolicyBridge) GetTierTable(direction uint8, tier uint8, mode string) (*ofctrl.Table, *ofctrl.Table, error) {
	var policyTable, nextTable *ofctrl.Table
	// POLICY_TIER0 for endpoint isolation policy:
	// 1) high priority rule is whitelist for support forensic policyrule, thus packet that match
	//    that rules should passthrough other policy tier ---- send to ctCommitTable;
	// 2) low priority rule is blacklist for support general isolation policyrule.
	switch mode {
	case "work":
		switch direction {
		case POLICY_DIRECTION_OUT:
			switch tier {
			case POLICY_TIER1:
				policyTable = p.egressTier1PolicyTable
				nextTable = p.ctCommitTable
			case POLICY_TIER2:
				policyTable = p.egressTier2PolicyTable
				nextTable = p.ctCommitTable
			case POLICY_TIER3:
				policyTable = p.egressTier3PolicyTable
				nextTable = p.ctCommitTable
			case POLICY_TIER_ECP:
				policyTable = p.egressTierECPPolicyTable
				nextTable = p.ctCommitTable
			default:
				return nil, nil, errors.New("unknown policy tier")
			}
		case POLICY_DIRECTION_IN:
			switch tier {
			case POLICY_TIER1:
				policyTable = p.ingressTier1PolicyTable
				nextTable = p.ctCommitTable
			case POLICY_TIER2:
				policyTable = p.ingressTier2PolicyTable
				nextTable = p.ctCommitTable
			case POLICY_TIER3:
				policyTable = p.ingressTier3PolicyTable
				nextTable = p.ctCommitTable
			case POLICY_TIER_ECP:
				policyTable = p.ingressTierECPPolicyTable
				nextTable = p.ctCommitTable
			default:
				return nil, nil, errors.New("unknown policy tier")
			}
		}
	case "monitor":
		switch direction {
		case POLICY_DIRECTION_OUT:
			switch tier {
			case POLICY_TIER1:
				return nil, nil, fmt.Errorf("policy tier1 without monitor mode support")
			case POLICY_TIER2:
				policyTable = p.egressTier2PolicyMonitorTable
				nextTable = p.egressTier2PolicyTable
			case POLICY_TIER3:
				policyTable = p.egressTier3PolicyMonitorTable
				nextTable = p.egressTier3PolicyTable
			case POLICY_TIER_ECP:
				return nil, nil, fmt.Errorf("monitor mode doesn't support tier-ecp")
			default:
				return nil, nil, errors.New("unknown policy tier")
			}
		case POLICY_DIRECTION_IN:
			switch tier {
			case POLICY_TIER1:
				return nil, nil, fmt.Errorf("policy tier1 without monitor mode support")
			case POLICY_TIER2:
				policyTable = p.ingressTier2PolicyMonitorTable
				nextTable = p.ingressTier2PolicyTable
			case POLICY_TIER3:
				policyTable = p.ingressTier3PolicyMonitorTable
				nextTable = p.ingressTier3PolicyTable
			case POLICY_TIER_ECP:
				return nil, nil, fmt.Errorf("monitor mode doesn't support tier-ecp")
			default:
				return nil, nil, errors.New("unknown policy tier")
			}
		}
	default:
		return nil, nil, fmt.Errorf("unknown work mode (%s)", mode)
	}

	return policyTable, nextTable, nil
}

//nolint:funlen
func (p *PolicyBridge) AddMicroSegmentRule(ctx context.Context, seqID uint32, rule *EveroutePolicyRule, direction uint8, tier uint8, mode string) (*FlowEntry, error) {
	log := ctrl.LoggerFrom(ctx)
	var ipDa, ipDaMask, ipSa, ipSaMask *net.IP
	var err error

	// make sure switch is connected
	if !p.IsSwitchConnected() {
		p.WaitForSwitchConnection()
	}

	flowID, err := AssemblyRuleFlowID(p.roundNum, seqID)
	if err != nil {
		return nil, err
	}
	// Different tier have different nextTable select strategy:
	policyTable, nextTable, e := p.GetTierTable(direction, tier, mode)
	if e != nil {
		log.Error(err, "Failed to get policy table tier", "tier", tier)
		return nil, fmt.Errorf("failed get policy table, err:%s", e)
	}

	// Parse dst ip
	ipDa, ipDaMask, err = ParseIPAddrMaskString(rule.DstIPAddr)
	if err != nil {
		log.Error(err, "Failed to parse dst ip", "ip", rule.DstIPAddr)
		return nil, err
	}

	// parse src ip
	ipSa, ipSaMask, err = ParseIPAddrMaskString(rule.SrcIPAddr)
	if err != nil {
		log.Error(err, "Failed to parse src ip", "ip", rule.SrcIPAddr)
		return nil, err
	}

	var icmpType uint8
	if rule.IcmpTypeEnable && rule.IPProtocol == PROTOCOL_ICMP {
		icmpType = rule.IcmpType
	}
	// Install the rule in policy table
	ruleFlow, err := policyTable.NewFlowWithFlowID(ofctrl.FlowMatch{
		Priority:       uint16(rule.Priority),
		IpProto:        rule.IPProtocol,
		TcpSrcPort:     rule.SrcPort,
		TcpSrcPortMask: rule.SrcPortMask,
		TcpDstPort:     rule.DstPort,
		TcpDstPortMask: rule.DstPortMask,
		UdpSrcPort:     rule.SrcPort,
		UdpSrcPortMask: rule.SrcPortMask,
		UdpDstPort:     rule.DstPort,
		UdpDstPortMask: rule.DstPortMask,
		IcmpType:       icmpType,
	}, flowID)
	if err != nil {
		log.Error(err, "Failed to add flow for rule")
		return nil, err
	}

	if rule.IPFamily == unix.AF_INET {
		ruleFlow.Match.Ethertype = protocol.IPv4_MSG
		ruleFlow.Match.IpDa = ipDa
		ruleFlow.Match.IpDaMask = ipDaMask
		ruleFlow.Match.IpSa = ipSa
		ruleFlow.Match.IpSaMask = ipSaMask
	}
	if rule.IPFamily == unix.AF_INET6 {
		ruleFlow.Match.Ethertype = protocol.IPv6_MSG
		ruleFlow.Match.Ipv6Da = ipDa
		ruleFlow.Match.Ipv6DaMask = ipDaMask
		ruleFlow.Match.Ipv6Sa = ipSa
		ruleFlow.Match.Ipv6SaMask = ipSaMask
	}

	switch mode {
	case "monitor":
		if err := ruleFlow.LoadField("nxm_nx_xxreg0", ruleFlow.FlowID>>FLOW_SEQ_NUM_LENGTH, RoundNumNXRange); err != nil {
			log.Error(err, "Failed to load field")
			return nil, err
		}

		switch tier {
		case POLICY_TIER2:
			if err := ruleFlow.LoadField("nxm_nx_xxreg0", ruleFlow.FlowID&FLOW_SEQ_NUM_MASK, MonitorTier2FlowSpaceNXRange); err != nil {
				log.Error(err, "Failed to load field")
				return nil, err
			}
		case POLICY_TIER3:
			if rule.Action == "deny" {
				if err := ruleFlow.LoadField("nxm_nx_xxreg0", 0x1, MonitorTier3PolicyActionNXRange); err != nil {
					log.Error(err, "Failed to load field")
					return nil, err
				}
			}
			if err := ruleFlow.LoadField("nxm_nx_xxreg0", ruleFlow.FlowID&FLOW_SEQ_NUM_MASK, MonitorTier3FlowSpaceNXRange); err != nil {
				log.Error(err, "Failed to load field")
				return nil, err
			}
		}

		if err := ruleFlow.Next(nextTable); err != nil {
			return nil, err
		}
	case "work":
		switch rule.Action {
		case "allow":
			if rule.Priority == GLOBAL_DEFAULT_POLICY_FLOW_PRIORITY {
				if err := ruleFlow.LoadField("nxm_nx_reg4", 0x30, openflow13.NewNXRange(0, 15)); err != nil {
					log.Error(err, "Failed to load field")
					return nil, err
				}
			}
		case "deny":
			if err := ruleFlow.LoadField("nxm_nx_reg4", 0x20, openflow13.NewNXRange(0, 15)); err != nil {
				log.Error(err, "Failed to load field")
				return nil, err
			}
			if err := ruleFlow.LoadField("nxm_nx_xxreg0", 0x1, WorkPolicyActionNXRange); err != nil {
				log.Error(err, "Failed to load field")
				return nil, err
			}
		default:
			err := fmt.Errorf("unknown action")
			log.Error(err, "unknown rule action", "ruleAction", rule.Action)
			return nil, err
		}

		if err := ruleFlow.LoadField("nxm_nx_xxreg0", ruleFlow.FlowID>>FLOW_SEQ_NUM_LENGTH, RoundNumNXRange); err != nil {
			log.Error(err, "Failed to load field")
			return nil, err
		}
		if err := ruleFlow.LoadField("nxm_nx_xxreg0", ruleFlow.FlowID&FLOW_SEQ_NUM_MASK, openflow13.NewNXRange(60, 87)); err != nil {
			log.Error(err, "Failed to load field")
			return nil, err
		}

		if err := ruleFlow.Next(nextTable); err != nil {
			log.Error(err, "Failed to install flow")
			return nil, err
		}
	}

	log.V(2).Info("Success add flow for rule")
	return &FlowEntry{
		Table:    policyTable,
		Priority: ruleFlow.Match.Priority,
		FlowID:   ruleFlow.FlowID,
	}, nil
}

func (p *PolicyBridge) AddVNFInstance() error {
	return nil
}

func (p *PolicyBridge) RemoveVNFInstance() error {
	return nil
}

func (p *PolicyBridge) AddSFCRule() error {
	return nil
}

func (p *PolicyBridge) RemoveSFCRule() error {
	return nil
}

func (p *PolicyBridge) BridgeInitCNI() {

}
