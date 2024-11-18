package datapath

import (
	"net"

	"github.com/contiv/ofnet/ofctrl"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	EveroutePolicyAllow string = "allow"
	EveroutePolicyDeny  string = "deny"
)

type EveroutePolicyRule struct {
	RuleID         string // Unique identifier for the rule
	Priority       int    // Priority for the rule (1..100. 100 is highest)
	SrcIPAddr      string // source IP addrss and mask
	DstIPAddr      string // Destination IP address and mask
	IPProtocol     uint8  // IP protocol number
	SrcPort        uint16 // Source port
	SrcPortMask    uint16
	DstPort        uint16 // destination port
	DstPortMask    uint16
	IcmpType       uint8
	IcmpTypeEnable bool
	Action         string // rule action: 'allow' or 'deny'
}

func (r *EveroutePolicyRule) toEveroutePolicyRuleForCT() EveroutePolicyRuleForCT {
	res := EveroutePolicyRuleForCT{
		RuleID:         r.RuleID,
		IPProtocol:     r.IPProtocol,
		SrcPort:        r.SrcPort,
		SrcPortMask:    r.SrcPortMask,
		DstPort:        r.DstPort,
		DstPortMask:    r.DstPortMask,
		IcmpTypeEnable: r.IcmpTypeEnable,
		IcmpType:       r.IcmpType,
	}
	if r.SrcIPAddr != "" {
		if _, ipNet, err := net.ParseCIDR(r.SrcIPAddr); err == nil {
			res.SrcIPNet = ipNet
		} else {
			ip := net.ParseIP(r.SrcIPAddr)
			res.SrcIP = &ip
		}
	}
	if r.DstIPAddr != "" {
		if _, ipNet, err := net.ParseCIDR(r.DstIPAddr); err == nil {
			res.DstIPNet = ipNet
		} else {
			ip := net.ParseIP(r.DstIPAddr)
			res.DstIP = &ip
		}
	}
	return res
}

type FlowEntry struct {
	Table    *ofctrl.Table
	Priority uint16
	FlowID   uint64
}

type PolicyRuleRef struct {
	Policy string
	Rule   string
}

type EveroutePolicyRuleEntry struct {
	EveroutePolicyRule  *EveroutePolicyRule
	Direction           uint8
	Tier                uint8
	Mode                string
	RuleFlowMap         map[string]*FlowEntry
	PolicyRuleReference map[PolicyRuleRef]struct{}
}

type RuleBaseInfo struct {
	Ref       PolicyRuleRef
	Direction uint8
	Tier      uint8
	Mode      string
}

type EveroutePolicyRuleForCT struct {
	RuleID         string
	SrcIPNet       *net.IPNet
	SrcIP          *net.IP
	DstIPNet       *net.IPNet
	DstIP          *net.IP
	IPProtocol     uint8  // IP protocol number
	SrcPort        uint16 // Source port
	SrcPortMask    uint16
	DstPort        uint16 // destination port
	DstPortMask    uint16
	IcmpTypeEnable bool
	IcmpType       uint8
}

func (r EveroutePolicyRuleForCT) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	if flow.FamilyType != unix.AF_INET {
		return false
	}
	return r.matchIPTuple(flow.Forward) || r.matchIPTuple(flow.Reverse)
}

func (r EveroutePolicyRuleForCT) matchIPTuple(tuple netlink.IpTuple) bool {
	if r.IPProtocol != 0 && r.IPProtocol != tuple.Protocol {
		return false
	}
	if !r.matchSrcIP(tuple.SrcIP) {
		return false
	}
	if !r.matchDstIP(tuple.DstIP) {
		return false
	}
	if r.SrcPort != 0 && !matchPort(r.SrcPortMask, r.SrcPort, tuple.SrcPort) {
		return false
	}
	if r.DstPort != 0 && !matchPort(r.DstPortMask, r.DstPort, tuple.DstPort) {
		return false
	}
	if r.IcmpTypeEnable && r.IcmpType != tuple.ICMPType {
		return false
	}

	return true
}

func (r *EveroutePolicyRuleForCT) matchSrcIP(ip net.IP) bool {
	if r.SrcIP != nil {
		return r.SrcIP.Equal(ip)
	}
	if r.SrcIPNet != nil {
		return r.SrcIPNet.Contains(ip)
	}
	return true
}

func (r *EveroutePolicyRuleForCT) matchDstIP(ip net.IP) bool {
	if r.DstIP != nil {
		return r.DstIP.Equal(ip)
	}
	if r.DstIPNet != nil {
		return r.DstIPNet.Contains(ip)
	}
	return true
}

func matchPort(mask, port1, port2 uint16) bool {
	if mask == 0 {
		return port1 == port2
	}
	return port1&mask == port2&mask
}

type EveroutePolicyRuleList []EveroutePolicyRuleForCT

func (list EveroutePolicyRuleList) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	for _, rule := range list {
		if rule.MatchConntrackFlow(flow) {
			return true
		}
	}
	return false
}
