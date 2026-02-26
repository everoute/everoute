package conntrack

import (
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/utils"
)

type Matcher struct {
	ID string
	// IPv6 address or IPv4 over IPv6 address
	SrcIP [16]byte
	// for single IP address, it is equal to the bit length of the IP address
	// for any IP address, it is 0
	SrcIPPrefixLen int
	// IPv6 address or IPv4 over IPv6 address
	DstIP [16]byte
	// for single IP address, it is equal to the bit length of the IP address
	// for any IP address, it is 0
	DstIPPrefixLen int
	// IP family
	IPFamily uint8
	// IP protocol number
	IPProtocol uint8
	// Source port
	SrcPort     uint16
	SrcPortMask uint16
	// Destination port
	DstPort        uint16
	DstPortMask    uint16
	IcmpTypeEnable bool
	IcmpType       uint8
}

func (r *Matcher) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	return r.matchIPTuple(&flow.Forward) || r.matchIPTuple(&flow.Reverse)
}

func (r *Matcher) matchIPTuple(tuple *netlink.IPTuple) bool {
	if r.IPProtocol != 0 && r.IPProtocol != tuple.Protocol {
		return false
	}
	switch tuple.Protocol {
	case unix.IPPROTO_TCP, unix.IPPROTO_UDP:
		if r.SrcPort != 0 && !matchPort(r.SrcPortMask, r.SrcPort, tuple.SrcPort) {
			return false
		}
		if r.DstPort != 0 && !matchPort(r.DstPortMask, r.DstPort, tuple.DstPort) {
			return false
		}
	case unix.IPPROTO_ICMP, unix.IPPROTO_ICMPV6:
		if r.IcmpTypeEnable && r.IcmpType != tuple.ICMPType {
			return false
		}
	}
	if !matchIP(r.SrcIP, [16]byte(tuple.SrcIP), r.SrcIPPrefixLen) {
		return false
	}
	if !matchIP(r.DstIP, [16]byte(tuple.DstIP), r.DstIPPrefixLen) {
		return false
	}

	return true
}

// matchIP checks whether ip1 and ip2 match in the first prefixLen bits.
func matchIP(ip1, ip2 [16]byte, prefixLen int) bool {
	if prefixLen == 0 {
		return true // any IP
	}
	// NOTE: do not use bytes.Equal in this function, to avoid runtime.makeslice
	if prefixLen == 128 {
		return ip1[0] == ip2[0] &&
			ip1[1] == ip2[1] &&
			ip1[2] == ip2[2] &&
			ip1[3] == ip2[3] &&
			ip1[4] == ip2[4] &&
			ip1[5] == ip2[5] &&
			ip1[6] == ip2[6] &&
			ip1[7] == ip2[7] &&
			ip1[8] == ip2[8] &&
			ip1[9] == ip2[9] &&
			ip1[10] == ip2[10] &&
			ip1[11] == ip2[11] &&
			ip1[12] == ip2[12] &&
			ip1[13] == ip2[13] &&
			ip1[14] == ip2[14] &&
			ip1[15] == ip2[15]
	}
	return matchIPPrefix(ip1, ip2, prefixLen)
}
func matchIPPrefix(ip1, ip2 [16]byte, prefixLen int) bool {
	prefixByteCount := prefixLen >> 3
	prefixBitCount := prefixLen & 0x07

	// check byte by byte
	i := 0
startLoop:
	if ip1[i] != ip2[i] {
		return false
	}
	i++
	if i < prefixByteCount {
		goto startLoop
	}

	// prefixLen < 128 implies prefixByteCount < 16, so no out-of-range access
	if prefixBitCount > 0 {
		mask := uint8(0xff) << (8 - prefixBitCount)
		return (ip1[prefixByteCount] & mask) == (ip2[prefixByteCount] & mask)
	}
	return true
}

func matchPort(mask, port1, port2 uint16) bool {
	if mask == 0 {
		return port1 == port2
	}
	return port1&mask == port2&mask
}

//nolint:gocritic
func CookMatcherBatch(matchers []Matcher) MatcherBatch {
	matcherIDs := make([]string, len(matchers))

	exactIPMatchers := make(map[[16]byte]*MatcherNodeValue, len(matchers)/2)
	// Use slab allocator to reduce malloc count: O(nodes) -> O(nodes/chunkSize)
	alloc := utils.NewSlabBinaryTrieNodeAllocator[MatcherNodeValue](0)
	prefixIPMatchers := alloc.Allocate()
	anyIPMatchers := &MatcherNodeValue{}
	for i := range matchers {
		matcherIDs[i] = matchers[i].ID

		var value *MatcherNodeValue

		if matchers[i].DstIPPrefixLen == 128 || matchers[i].SrcIPPrefixLen == 128 {
			// containsexact IP
			ip := matchers[i].SrcIP
			if matchers[i].DstIPPrefixLen == 128 {
				ip = matchers[i].DstIP
			}
			var ok bool
			value, ok = exactIPMatchers[ip]
			if !ok {
				value = &MatcherNodeValue{}
				exactIPMatchers[ip] = value
			}
			value.HasMatchers = true
		} else if matchers[i].DstIPPrefixLen > 0 || matchers[i].SrcIPPrefixLen > 0 {
			// contains IP subnet
			ip := matchers[i].SrcIP[:]
			ipPrefixLen := matchers[i].SrcIPPrefixLen
			if matchers[i].DstIPPrefixLen > 0 {
				ip = matchers[i].DstIP[:]
				ipPrefixLen = matchers[i].DstIPPrefixLen
			}
			node := utils.GetBinaryTrieNode(
				prefixIPMatchers, ip, ipPrefixLen, alloc,
			)
			node.Value.HasMatchers = true
			value = &node.Value
		} else {
			// any IP to any IP
			value = anyIPMatchers
			value.HasMatchers = true
		}

		switch matchers[i].IPProtocol {
		case unix.IPPROTO_TCP:
			if value.TCPMatchers == nil {
				value.TCPMatchers = make([]Matcher, 0, 4)
			}
			value.TCPMatchers = append(value.TCPMatchers, matchers[i])
		case unix.IPPROTO_UDP:
			if value.UDPMatchers == nil {
				value.UDPMatchers = make([]Matcher, 0, 4)
			}
			value.UDPMatchers = append(value.UDPMatchers, matchers[i])
		case unix.IPPROTO_ICMP, unix.IPPROTO_ICMPV6:
			if value.ICMPMatchers == nil {
				value.ICMPMatchers = make([]Matcher, 0, 4)
			}
			value.ICMPMatchers = append(value.ICMPMatchers, matchers[i])
		default:
			if value.OtherMatchers == nil {
				value.OtherMatchers = make([]Matcher, 0, 4)
			}
			value.OtherMatchers = append(value.OtherMatchers, matchers[i])
		}
	}
	return MatcherBatch{
		IDs:              matcherIDs,
		ExactIPMatchers:  exactIPMatchers,
		PrefixIPMatchers: prefixIPMatchers,
		AnyIPMatchers:    anyIPMatchers,
	}
}

// MatcherBatch batches policy matchers for matching conntrack flows.
// Usually the dst IP is the server IP and changes less often than the src IP,
// so we check dst matchers before src matchers.
type MatcherBatch struct {
	IDs []string // for logging

	// Fast lookup for matchers with prefix length 128 (exact IP, or /32 for IPv4).
	ExactIPMatchers map[[16]byte]*MatcherNodeValue

	// Trie for matchers with prefix length in (0, 128).
	PrefixIPMatchers *utils.BinaryTrieNode[MatcherNodeValue]
	// Matchers matching any IP (0.0.0.0/0 or ::/0). No children in this node, only value is set.
	AnyIPMatchers *MatcherNodeValue
}

type MatcherNodeValue struct {
	HasMatchers   bool      // all matchers are nil
	TCPMatchers   []Matcher // matching TCP protocol
	UDPMatchers   []Matcher // matching UDP protocol
	ICMPMatchers  []Matcher // matching ICMP protocol
	OtherMatchers []Matcher // matching other protocols or any protocol
}

var MatcherNodeValueAllocator = utils.NewSlabBinaryTrieNodeAllocator[MatcherNodeValue](0)

func (bm *MatcherBatch) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	// Convert IPv4 to IPv4-mapped format. Callers can assume IP length is 16 after this.
	oldSrcIP := flow.Forward.SrcIP
	oldDstIP := flow.Forward.DstIP
	oldReverseSrcIP := flow.Reverse.SrcIP
	oldReverseDstIP := flow.Reverse.DstIP

	ipv6Bytes := [64]byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
		flow.Forward.SrcIP[0], flow.Forward.SrcIP[1], flow.Forward.SrcIP[2], flow.Forward.SrcIP[3],
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
		flow.Forward.DstIP[0], flow.Forward.DstIP[1], flow.Forward.DstIP[2], flow.Forward.DstIP[3],
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
		flow.Reverse.SrcIP[0], flow.Reverse.SrcIP[1], flow.Reverse.SrcIP[2], flow.Reverse.SrcIP[3],
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
		flow.Reverse.DstIP[0], flow.Reverse.DstIP[1], flow.Reverse.DstIP[2], flow.Reverse.DstIP[3],
	}
	if len(flow.Forward.SrcIP) == net.IPv4len {
		flow.Forward.SrcIP = ipv6Bytes[0:16]
	}
	if len(flow.Forward.DstIP) == net.IPv4len {
		flow.Forward.DstIP = ipv6Bytes[16:32]
	}
	if len(flow.Reverse.SrcIP) == net.IPv4len {
		flow.Reverse.SrcIP = ipv6Bytes[32:48]
	}
	if len(flow.Reverse.DstIP) == net.IPv4len {
		flow.Reverse.DstIP = ipv6Bytes[48:64]
	}
	matched := bm.matchConntrackFlow(flow)
	flow.Forward.SrcIP = oldSrcIP
	flow.Forward.DstIP = oldDstIP
	flow.Reverse.SrcIP = oldReverseSrcIP
	flow.Reverse.DstIP = oldReverseDstIP
	return matched
}

func (bm *MatcherBatch) matchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	// not everoute conntrack flows, skip
	if flow.Zone < constants.CTZoneForPolicyMin || flow.Zone > constants.CTZoneForPolicyMax {
		return false
	}
	// not labeled, skip
	if !flow.HasLabels {
		return false
	}

	// the caller should ensure that flow.Forward.SrcIP and flow.Forward.DstIP are 16 bytes
	ips := [][16]byte{
		[16]byte(flow.Forward.SrcIP),
		[16]byte(flow.Forward.DstIP),
	}

	for _, ip := range ips {
		matcher, ok := bm.ExactIPMatchers[ip]
		if ok && matcher != nil {
			if matchConntrackFlow(matcher, flow) {
				return true
			}
		}
	}

	for _, ip := range ips {
		if matchConntrackFlowWithTrie(bm.PrefixIPMatchers, flow.FamilyType, ip, flow) {
			return true
		}
	}
	return matchConntrackFlow(bm.AnyIPMatchers, flow)
}

func matchConntrackFlow(matcher *MatcherNodeValue, flow *netlink.ConntrackFlow) bool {
	if !matcher.HasMatchers {
		return false
	}
	switch flow.Forward.Protocol {
	case unix.IPPROTO_TCP:
		matchers := matcher.TCPMatchers
		for i := range matchers {
			if matchers[i].MatchConntrackFlow(flow) {
				return true
			}
		}
	case unix.IPPROTO_UDP:
		matchers := matcher.UDPMatchers
		for i := range matchers {
			if matchers[i].MatchConntrackFlow(flow) {
				return true
			}
		}
	case unix.IPPROTO_ICMP, unix.IPPROTO_ICMPV6:
		matchers := matcher.ICMPMatchers
		for i := range matchers {
			if matchers[i].MatchConntrackFlow(flow) {
				return true
			}
		}
	}
	matchers := matcher.OtherMatchers // other protocols, or any protocol when IPProtocol is 0
	for i := range matchers {
		if matchers[i].MatchConntrackFlow(flow) {
			return true
		}
	}
	return false
}

// matchConntrackFlowWithTrie visits trie nodes along the IP prefix path (hot path).
func matchConntrackFlowWithTrie(
	node *utils.BinaryTrieNode[MatcherNodeValue],
	family uint8, ip [16]byte,
	flow *netlink.ConntrackFlow,
) (matched bool) {
	_ = family // not used currently
	visitor := func(n *utils.BinaryTrieNode[MatcherNodeValue]) (exit bool) {
		// Fast path: most nodes have no matchers; only leaf nodes have matchers when prefixLen=128.
		if !n.Value.HasMatchers {
			return false
		}
		switch flow.Forward.Protocol {
		case unix.IPPROTO_TCP:
			matchers := n.Value.TCPMatchers
			for i := range matchers {
				if matchers[i].MatchConntrackFlow(flow) {
					matched = true
					return true
				}
			}
		case unix.IPPROTO_UDP:
			matchers := n.Value.UDPMatchers
			for i := range matchers {
				if matchers[i].MatchConntrackFlow(flow) {
					matched = true
					return true
				}
			}
		case unix.IPPROTO_ICMP, unix.IPPROTO_ICMPV6:
			matchers := n.Value.ICMPMatchers
			for i := range matchers {
				if matchers[i].MatchConntrackFlow(flow) {
					matched = true
					return true
				}
			}
		default:
			matchers := n.Value.OtherMatchers
			for i := range matchers {
				if matchers[i].MatchConntrackFlow(flow) {
					matched = true
					return true
				}
			}
		}
		return false
	}
	utils.VisitBinaryTriePrefixes(node, ip[:], 128, visitor)
	return matched
}
