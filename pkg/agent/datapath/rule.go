package datapath

import (
	"fmt"

	"github.com/contiv/ofnet/ofctrl"

	"github.com/everoute/everoute/pkg/agent/datapath/conntrack"
	"github.com/everoute/everoute/pkg/utils"
)

const (
	EveroutePolicyAllow string = "allow"
	EveroutePolicyDeny  string = "deny"

	MSModuleName string = "microsegmentation"
)

type EveroutePolicyRule struct {
	RuleID         string // Unique identifier for the rule
	Priority       int    // Priority for the rule (1..100. 100 is highest)
	SrcIPAddr      string // source IP address and mask
	DstIPAddr      string // destination IP address and mask
	IPProtocol     uint8  // IP protocol number
	IPFamily       uint8  // IP family
	SrcPort        uint16 // Source port
	SrcPortMask    uint16
	DstPort        uint16 // destination port
	DstPortMask    uint16
	IcmpType       uint8
	IcmpTypeEnable bool
	SrcVNicRef     string
	DstVNicRef     string
	Action         string // rule action: 'allow' or 'deny'
}

func (r *EveroutePolicyRule) DeepCopy() *EveroutePolicyRule {
	return &EveroutePolicyRule{
		RuleID:         r.RuleID,
		Priority:       r.Priority,
		SrcIPAddr:      r.SrcIPAddr,
		DstIPAddr:      r.DstIPAddr,
		IPProtocol:     r.IPProtocol,
		IPFamily:       r.IPFamily,
		SrcPort:        r.SrcPort,
		SrcPortMask:    r.SrcPortMask,
		DstPort:        r.DstPort,
		DstPortMask:    r.DstPortMask,
		IcmpType:       r.IcmpType,
		IcmpTypeEnable: r.IcmpTypeEnable,
		SrcVNicRef:     r.SrcVNicRef,
		DstVNicRef:     r.DstVNicRef,
		Action:         r.Action,
	}
}

func (r *EveroutePolicyRule) ToMatcher() (conntrack.Matcher, error) {
	res := conntrack.Matcher{
		ID:             r.RuleID,
		IPProtocol:     r.IPProtocol,
		IPFamily:       r.IPFamily,
		SrcPort:        r.SrcPort,
		SrcPortMask:    r.SrcPortMask,
		DstPort:        r.DstPort,
		DstPortMask:    r.DstPortMask,
		IcmpTypeEnable: r.IcmpTypeEnable,
		IcmpType:       r.IcmpType,
	}
	if r.SrcIPAddr != "" {
		ip, prefixLen, ok := utils.ParseIPStringToIPAndSubnetPrefixLen(r.SrcIPAddr)
		if !ok {
			return conntrack.Matcher{}, fmt.Errorf("failed to parse src ip: %s", r.SrcIPAddr)
		}
		res.SrcIP = ip.As16()
		if prefixLen != 0 && ip.Is4() {
			// Add 96 for IPv4-mapped (::ffff:0:0/96) when storing IPv4 in 128-bit space
			prefixLen += 96
		}
		res.SrcIPPrefixLen = prefixLen
	}
	if r.DstIPAddr != "" {
		ip, prefixLen, ok := utils.ParseIPStringToIPAndSubnetPrefixLen(r.DstIPAddr)
		if !ok {
			return conntrack.Matcher{}, fmt.Errorf("failed to parse dst ip: %s", r.DstIPAddr)
		}
		res.DstIP = ip.As16()
		if prefixLen != 0 && ip.Is4() {
			// Add 96 for IPv4-mapped (::ffff:0:0/96) when storing IPv4 in 128-bit space
			prefixLen += 96
		}
		res.DstIPPrefixLen = prefixLen
	}
	return res, nil
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

func NewPolicyFlowIDAlloctor() *FlowIDAlloctor {
	return NewFlowIDAlloctor(MSModuleName, uint32(CookieRuleFix), uint32(1<<CookieRuleUsedBitWidth-1+CookieRuleFix), 0x0)
}
