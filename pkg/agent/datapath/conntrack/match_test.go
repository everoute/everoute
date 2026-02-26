package conntrack

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/utils"
)

// ipTo16 converts IP string to [16]byte (IPv4-mapped for IPv4)
func ipTo16(s string) [16]byte {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return addr.As16()
}

func toIpv6PrefixLen(len int) int {
	return 96 + len
}

// parseCIDRToPrefixLen parses CIDR and returns prefix length for 128-bit space.
// For IPv4 /n, returns 96+n. For IPv6 /n, returns n.
func parseCIDRToPrefixLen(cidr string) int {
	if prefix, err := netip.ParsePrefix(cidr); err == nil {
		if prefix.Addr().Is4() {
			return toIpv6PrefixLen(prefix.Bits())
		}
		return prefix.Bits()
	}
	addr, err := netip.ParseAddr(cidr)
	if err != nil {
		panic(err)
	}
	return toIpv6PrefixLen(addr.BitLen())
}

func TestMatchIP(t *testing.T) {
	testCases := []struct {
		ipRaw       string
		ip          string
		shouldMatch bool
	}{
		// IPv4 subnet /20
		{
			ipRaw:       "192.168.16.1/20",
			ip:          "192.168.20.1",
			shouldMatch: true,
		},
		{
			ipRaw:       "192.168.16.1/20",
			ip:          "192.168.31.255",
			shouldMatch: true,
		},
		{
			ipRaw:       "192.168.16.1/20",
			ip:          "192.168.32.1",
			shouldMatch: false,
		},
		// IPv4 single IP
		{
			ipRaw:       "192.168.16.1",
			ip:          "192.168.20.1",
			shouldMatch: false,
		},
		{
			ipRaw:       "192.168.16.1",
			ip:          "192.168.16.1",
			shouldMatch: true,
		},
		// IPv4 subnet /24
		{
			ipRaw:       "10.0.0.0/24",
			ip:          "10.0.0.1",
			shouldMatch: true,
		},
		{
			ipRaw:       "10.0.0.0/24",
			ip:          "10.0.0.255",
			shouldMatch: true,
		},
		{
			ipRaw:       "10.0.0.0/24",
			ip:          "10.0.1.0",
			shouldMatch: false,
		},
		// IPv4 subnet /16
		{
			ipRaw:       "172.16.0.0/16",
			ip:          "172.16.255.255",
			shouldMatch: true,
		},
		{
			ipRaw:       "172.16.0.0/16",
			ip:          "172.17.0.1",
			shouldMatch: false,
		},
		// IPv4 subnet /8
		{
			ipRaw:       "10.0.0.0/8",
			ip:          "10.255.255.255",
			shouldMatch: true,
		},
		{
			ipRaw:       "10.0.0.0/8",
			ip:          "11.0.0.0",
			shouldMatch: false,
		},
		// IPv4 subnet /30 (small subnet)
		{
			ipRaw:       "192.168.1.0/30",
			ip:          "192.168.1.2",
			shouldMatch: true,
		},
		{
			ipRaw:       "192.168.1.0/30",
			ip:          "192.168.1.4",
			shouldMatch: false,
		},
	}
	for i, tc := range testCases {
		t.Run(fmt.Sprintf("tc%02d", i), func(t *testing.T) {
			var matcherIP, testIP [16]byte
			var prefixLen int
			if _, _, ok := utils.ParseIPStringToIPAndSubnetPrefixLen(tc.ipRaw); ok {
				prefix, err := netip.ParsePrefix(tc.ipRaw)
				if err != nil {
					addr, _ := netip.ParseAddr(tc.ipRaw)
					matcherIP = addr.As16()
					prefixLen = toIpv6PrefixLen(addr.BitLen())
				} else {
					matcherIP = prefix.Addr().As16()
					prefixLen = parseCIDRToPrefixLen(tc.ipRaw)
				}
			} else {
				addr, err := netip.ParseAddr(tc.ipRaw)
				if err != nil {
					t.Fatal(err)
				}
				matcherIP = addr.As16()
				prefixLen = toIpv6PrefixLen(addr.BitLen())
			}
			testAddr, _ := netip.ParseAddr(tc.ip)
			testIP = testAddr.As16()
			got := matchIP(matcherIP, testIP, prefixLen)
			if got != tc.shouldMatch {
				t.Errorf("matchIP(%q, %q, %d) = %t, want %t",
					tc.ipRaw, tc.ip, prefixLen, got, tc.shouldMatch)
			}
		})
	}
}

func TestMatchIP_PrefixLenZero(t *testing.T) {
	// prefixLen 0 means any IP, should always match
	matcherIP := ipTo16("192.168.1.1")
	testIP := ipTo16("10.0.0.1")
	if !matchIP(matcherIP, testIP, 0) {
		t.Error("matchIP with prefixLen 0 should always return true")
	}
}

func TestMatchPort(t *testing.T) {
	testCases := []struct {
		portMask    uint16
		port1       uint16
		port2       uint16
		shouldMatch bool
	}{
		{
			portMask:    0,
			port1:       20,
			port2:       20,
			shouldMatch: true,
		},
		{
			portMask:    0,
			port1:       20,
			port2:       22,
			shouldMatch: false,
		},
		{
			portMask:    65520,
			port1:       20,
			port2:       22,
			shouldMatch: true,
		},
		{
			portMask:    65520,
			port1:       20,
			port2:       32,
			shouldMatch: false,
		},
		// port 0
		{
			portMask:    0,
			port1:       0,
			port2:       0,
			shouldMatch: true,
		},
		{
			portMask:    0,
			port1:       0,
			port2:       1,
			shouldMatch: false,
		},
		// max port
		{
			portMask:    0xffff,
			port1:       65535,
			port2:       65535,
			shouldMatch: true,
		},
		// mask 0xfff0: match high 12 bits (96-111 map to same value)
		{
			portMask:    0xfff0,
			port1:       96,
			port2:       100,
			shouldMatch: true,
		},
		{
			portMask:    0xfff0,
			port1:       96,
			port2:       112,
			shouldMatch: false,
		},
		// mask 0xff00
		{
			portMask:    0xff00,
			port1:       0x1234,
			port2:       0x1200,
			shouldMatch: true,
		},
	}
	for i, tc := range testCases {
		t.Run(fmt.Sprintf("tc%02d", i), func(t *testing.T) {
			got := matchPort(tc.portMask, tc.port1, tc.port2)
			if got != tc.shouldMatch {
				t.Errorf("matchPort(%d, %d, %d) = %t, want %t",
					tc.portMask, tc.port1, tc.port2, got, tc.shouldMatch)
			}
		})
	}
}

// makeIPv4Flow creates a flow with IPv4-mapped IPv6 addresses (16 bytes) so that
// matcher.MatchConntrackFlow works without conversion. MatcherBatch.MatchConntrackFlow
// converts IPv4 to IPv4-mapped internally; for direct matcher tests we must use 16-byte IPs.
func makeIPv4Flow(zone uint16, srcIP, dstIP string, srcPort, dstPort uint16, proto uint8) *netlink.ConntrackFlow {
	src := net.ParseIP("::ffff:" + srcIP)
	dst := net.ParseIP("::ffff:" + dstIP)
	if src == nil || dst == nil {
		panic("invalid ip")
	}
	return &netlink.ConntrackFlow{
		FamilyType: unix.AF_INET,
		Zone:       zone,
		HasLabels:  true,
		Forward: netlink.IPTuple{
			SrcIP:    src,
			DstIP:    dst,
			SrcPort:  srcPort,
			DstPort:  dstPort,
			Protocol: proto,
		},
		Reverse: netlink.IPTuple{
			SrcIP:    dst,
			DstIP:    src,
			SrcPort:  dstPort,
			DstPort:  srcPort,
			Protocol: proto,
		},
	}
}

// makeIPv6Flow creates a flow with native IPv6 addresses (16 bytes).
func makeIPv6Flow(zone uint16, srcIP, dstIP string, srcPort, dstPort uint16, proto uint8) *netlink.ConntrackFlow {
	src := net.ParseIP(srcIP)
	dst := net.ParseIP(dstIP)
	if src == nil || dst == nil || len(src) != 16 || len(dst) != 16 {
		panic("invalid IPv6 address")
	}
	return &netlink.ConntrackFlow{
		FamilyType: unix.AF_INET6,
		Zone:       zone,
		HasLabels:  true,
		Forward: netlink.IPTuple{
			SrcIP:    src,
			DstIP:    dst,
			SrcPort:  srcPort,
			DstPort:  dstPort,
			Protocol: proto,
		},
		Reverse: netlink.IPTuple{
			SrcIP:    dst,
			DstIP:    src,
			SrcPort:  dstPort,
			DstPort:  srcPort,
			Protocol: proto,
		},
	}
}

// makeFlowWithICMP creates a flow for ICMP or ICMPv6 with ICMPType and ICMPCode.
// For ICMP/ICMPv6, ports are 0; use icmpID for tuple identification.
func makeFlowWithICMP(zone uint16, family uint8, srcIP, dstIP string, icmpType, icmpCode uint8, icmpID uint16, proto uint8) *netlink.ConntrackFlow {
	var src, dst net.IP
	if family == unix.AF_INET {
		src = net.ParseIP("::ffff:" + srcIP)
		dst = net.ParseIP("::ffff:" + dstIP)
	} else {
		src = net.ParseIP(srcIP)
		dst = net.ParseIP(dstIP)
	}
	if src == nil || dst == nil {
		panic("invalid ip")
	}
	// Reverse: echo reply type 0, code 0
	revType, revCode := uint8(0), uint8(0)
	if icmpType == 8 {
		revType = 0 // echo reply
	}
	return &netlink.ConntrackFlow{
		FamilyType: family,
		Zone:       zone,
		HasLabels:  true,
		Forward: netlink.IPTuple{
			SrcIP:    src,
			DstIP:    dst,
			SrcPort:  0,
			DstPort:  0,
			Protocol: proto,
			ICMPID:   icmpID,
			ICMPType: icmpType,
			ICMPCode: icmpCode,
		},
		Reverse: netlink.IPTuple{
			SrcIP:    dst,
			DstIP:    src,
			SrcPort:  0,
			DstPort:  0,
			Protocol: proto,
			ICMPID:   icmpID,
			ICMPType: revType,
			ICMPCode: revCode,
		},
	}
}

// makeFlowGeneric creates a flow for protocols without ports (GRE, IPIP, etc).
func makeFlowGeneric(zone uint16, family uint8, srcIP, dstIP string, proto uint8) *netlink.ConntrackFlow {
	var src, dst net.IP
	if family == unix.AF_INET {
		src = net.ParseIP("::ffff:" + srcIP)
		dst = net.ParseIP("::ffff:" + dstIP)
	} else {
		src = net.ParseIP(srcIP)
		dst = net.ParseIP(dstIP)
	}
	if src == nil || dst == nil {
		panic("invalid ip")
	}
	return &netlink.ConntrackFlow{
		FamilyType: family,
		Zone:       zone,
		HasLabels:  true,
		Forward: netlink.IPTuple{
			SrcIP:    src,
			DstIP:    dst,
			SrcPort:  0,
			DstPort:  0,
			Protocol: proto,
		},
		Reverse: netlink.IPTuple{
			SrcIP:    dst,
			DstIP:    src,
			SrcPort:  0,
			DstPort:  0,
			Protocol: proto,
		},
	}
}

func TestMatcher_MatchConntrackFlow(t *testing.T) {
	matcher := Matcher{
		ID:             "r1",
		SrcIP:          ipTo16("192.168.1.1"),
		SrcIPPrefixLen: 128,
		DstIP:          ipTo16("192.168.1.2"),
		DstIPPrefixLen: 128,
		IPProtocol:     unix.IPPROTO_TCP,
		SrcPort:        12345,
		SrcPortMask:    0xffff,
		DstPort:        80,
		DstPortMask:    0xffff,
	}

	flowMatch := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.1", "192.168.1.2", 12345, 80, unix.IPPROTO_TCP)
	if !matcher.MatchConntrackFlow(flowMatch) {
		t.Error("expected matcher to match flow (forward direction)")
	}

	// reverse direction: src=dst, dst=src
	flowReverse := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.2", "192.168.1.1", 80, 12345, unix.IPPROTO_TCP)
	if !matcher.MatchConntrackFlow(flowReverse) {
		t.Error("expected matcher to match flow (reverse direction)")
	}

	// wrong ip
	flowWrongIP := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.3", "192.168.1.2", 12345, 80, unix.IPPROTO_TCP)
	if matcher.MatchConntrackFlow(flowWrongIP) {
		t.Error("expected matcher to NOT match flow with wrong src ip")
	}

	// wrong port
	flowWrongPort := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.1", "192.168.1.2", 12346, 80, unix.IPPROTO_TCP)
	if matcher.MatchConntrackFlow(flowWrongPort) {
		t.Error("expected matcher to NOT match flow with wrong src port")
	}

	// wrong protocol
	flowWrongProto := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.1", "192.168.1.2", 12345, 80, unix.IPPROTO_UDP)
	if matcher.MatchConntrackFlow(flowWrongProto) {
		t.Error("expected matcher to NOT match flow with wrong protocol")
	}
}

func TestMatcher_MatchConntrackFlow_Subnet(t *testing.T) {
	matcher := Matcher{
		ID:             "r1",
		SrcIP:          ipTo16("192.168.0.0"),
		SrcIPPrefixLen: toIpv6PrefixLen(24),
		DstIP:          ipTo16("10.0.0.0"),
		DstIPPrefixLen: toIpv6PrefixLen(16),
		IPProtocol:     unix.IPPROTO_TCP,
		DstPort:        443,
		DstPortMask:    0xffff,
	}

	// src in 192.168.0.0/24, dst in 10.0.0.0/16
	flowMatch := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.0.100", "10.0.5.5", 12345, 443, unix.IPPROTO_TCP)
	if !matcher.MatchConntrackFlow(flowMatch) {
		t.Error("expected matcher to match flow with subnet")
	}

	// src outside subnet
	flowWrongSrc := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.1", "10.0.5.5", 12345, 443, unix.IPPROTO_TCP)
	if matcher.MatchConntrackFlow(flowWrongSrc) {
		t.Error("expected matcher to NOT match flow with src outside subnet")
	}

	// dst outside subnet
	flowWrongDst := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.0.1", "11.0.0.1", 12345, 443, unix.IPPROTO_TCP)
	if matcher.MatchConntrackFlow(flowWrongDst) {
		t.Error("expected matcher to NOT match flow with dst outside subnet")
	}
}

func TestMatcher_MatchConntrackFlow_OnlySrcIP(t *testing.T) {
	matcher := Matcher{
		ID:             "r1",
		SrcIP:          ipTo16("192.168.1.1"),
		SrcIPPrefixLen: 128,
		DstIPPrefixLen: 0,
		IPProtocol:     unix.IPPROTO_TCP,
		DstPort:        80,
		DstPortMask:    0xffff,
	}

	flowMatch := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.1", "1.2.3.4", 12345, 80, unix.IPPROTO_TCP)
	if !matcher.MatchConntrackFlow(flowMatch) {
		t.Error("expected matcher with only src IP to match")
	}

	flowNoMatch := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.2", "1.2.3.4", 12345, 80, unix.IPPROTO_TCP)
	if matcher.MatchConntrackFlow(flowNoMatch) {
		t.Error("expected matcher to NOT match when src IP differs")
	}
}

func TestMatcher_MatchConntrackFlow_OnlyDstIP(t *testing.T) {
	matcher := Matcher{
		ID:             "r1",
		SrcIPPrefixLen: 0,
		DstIP:          ipTo16("10.0.0.1"),
		DstIPPrefixLen: 128,
		IPProtocol:     unix.IPPROTO_TCP,
		DstPort:        22,
		DstPortMask:    0xffff,
	}

	flowMatch := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.1", "10.0.0.1", 12345, 22, unix.IPPROTO_TCP)
	if !matcher.MatchConntrackFlow(flowMatch) {
		t.Error("expected matcher with only dst IP to match")
	}

	flowNoMatch := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.1", "10.0.0.2", 12345, 22, unix.IPPROTO_TCP)
	if matcher.MatchConntrackFlow(flowNoMatch) {
		t.Error("expected matcher to NOT match when dst IP differs")
	}
}

func TestMatcher_MatchConntrackFlow_PortMask(t *testing.T) {
	matcher := Matcher{
		ID:             "r1",
		SrcIP:          ipTo16("192.168.1.1"),
		SrcIPPrefixLen: 128,
		DstIP:          ipTo16("192.168.1.2"),
		DstIPPrefixLen: 128,
		IPProtocol:     unix.IPPROTO_TCP,
		SrcPort:        1024,
		SrcPortMask:    0xfff0, // match 1024-1039
		DstPort:        80,
		DstPortMask:    0xffff,
	}

	flowMatch := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.1", "192.168.1.2", 1025, 80, unix.IPPROTO_TCP)
	if !matcher.MatchConntrackFlow(flowMatch) {
		t.Error("expected matcher to match with port mask (1025 in 1024-1039)")
	}

	flowNoMatch := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.1", "192.168.1.2", 1040, 80, unix.IPPROTO_TCP)
	if matcher.MatchConntrackFlow(flowNoMatch) {
		t.Error("expected matcher to NOT match when src port outside mask range")
	}
}

func TestMatcher_MatchConntrackFlow_AnyProtocol(t *testing.T) {
	matcher := Matcher{
		ID:             "r1",
		SrcIP:          ipTo16("192.168.1.1"),
		SrcIPPrefixLen: 128,
		DstIP:          ipTo16("192.168.1.2"),
		DstIPPrefixLen: 128,
		IPProtocol:     0,
		SrcPort:        0,
		DstPort:        0,
	}

	// should match TCP
	flowTCP := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.1", "192.168.1.2", 12345, 80, unix.IPPROTO_TCP)
	if !matcher.MatchConntrackFlow(flowTCP) {
		t.Error("expected any-protocol matcher to match TCP")
	}

	// should match UDP
	flowUDP := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.1", "192.168.1.2", 12345, 53, unix.IPPROTO_UDP)
	if !matcher.MatchConntrackFlow(flowUDP) {
		t.Error("expected any-protocol matcher to match UDP")
	}

	// should match ICMP
	flowICMP := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.1", "192.168.1.2", 0, 0, unix.IPPROTO_ICMP)
	if !matcher.MatchConntrackFlow(flowICMP) {
		t.Error("expected any-protocol matcher to match ICMP")
	}
}

func TestCookMatcherBatch(t *testing.T) {
	matchers := []Matcher{
		{
			ID:             "r1",
			DstIP:          ipTo16("10.0.0.1"),
			DstIPPrefixLen: toIpv6PrefixLen(32),
			IPProtocol:     unix.IPPROTO_TCP,
			DstPort:        80,
			DstPortMask:    0xffff,
		},
		{
			ID:             "r2",
			SrcIP:          ipTo16("10.0.0.2"),
			SrcIPPrefixLen: toIpv6PrefixLen(32),
			IPProtocol:     unix.IPPROTO_UDP,
			SrcPort:        53,
			SrcPortMask:    0xffff,
		},
		{
			ID:             "r3",
			DstIP:          ipTo16("192.168.0.0"),
			DstIPPrefixLen: toIpv6PrefixLen(24),
			IPProtocol:     unix.IPPROTO_TCP,
		},
	}
	bm := CookMatcherBatch(matchers)
	if len(bm.IDs) != 3 {
		t.Errorf("IDs len = %d, want 3", len(bm.IDs))
	}
	if bm.ExactIPMatchers == nil {
		t.Error("ExactIPMatchers should not be nil")
	}
	if bm.PrefixIPMatchers == nil {
		t.Error("PrefixIPMatchers should not be nil")
	}
	if bm.AnyIPMatchers == nil {
		t.Error("AnyIPMatchers should not be nil")
	}
	// verify matcher IDs
	for i, id := range bm.IDs {
		exp := matchers[i].ID
		if id != exp {
			t.Errorf("IDs[%d] = %q, want %q", i, id, exp)
		}
	}
}

func TestCookMatcherBatch_Empty(t *testing.T) {
	bm := CookMatcherBatch(nil)
	if bm.IDs == nil {
		t.Error("IDs should not be nil (empty slice)")
	}
	if len(bm.IDs) != 0 {
		t.Errorf("IDs len = %d, want 0", len(bm.IDs))
	}
	if bm.ExactIPMatchers == nil {
		t.Error("ExactIPMatchers should not be nil")
	}
	if bm.PrefixIPMatchers == nil {
		t.Error("PrefixIPMatchers should not be nil")
	}
	if bm.AnyIPMatchers == nil {
		t.Error("AnyIPMatchers should not be nil")
	}
}

func TestCookMatcherBatch_MultiProtocol(t *testing.T) {
	matchers := []Matcher{
		{SrcIPPrefixLen: 0, DstIPPrefixLen: 0, IPProtocol: unix.IPPROTO_TCP, ID: "tcp"},
		{SrcIPPrefixLen: 0, DstIPPrefixLen: 0, IPProtocol: unix.IPPROTO_UDP, ID: "udp"},
		{SrcIPPrefixLen: 0, DstIPPrefixLen: 0, IPProtocol: unix.IPPROTO_ICMP, ID: "icmp"},
		{SrcIPPrefixLen: 0, DstIPPrefixLen: 0, IPProtocol: 50, ID: "esp"}, // OtherMatchers
	}
	bm := CookMatcherBatch(matchers)
	if len(bm.IDs) != 4 {
		t.Errorf("IDs len = %d, want 4", len(bm.IDs))
	}
	if !bm.AnyIPMatchers.HasMatchers {
		t.Error("AnyIPMatchers.HasMatchers should be true")
	}
	if len(bm.AnyIPMatchers.TCPMatchers) != 1 || len(bm.AnyIPMatchers.UDPMatchers) != 1 ||
		len(bm.AnyIPMatchers.ICMPMatchers) != 1 || len(bm.AnyIPMatchers.OtherMatchers) != 1 {
		t.Errorf("AnyIPMatchers should have 1 matcher each: Tcp=%d Udp=%d Icmp=%d Other=%d",
			len(bm.AnyIPMatchers.TCPMatchers), len(bm.AnyIPMatchers.UDPMatchers),
			len(bm.AnyIPMatchers.ICMPMatchers), len(bm.AnyIPMatchers.OtherMatchers))
	}
}

func TestMatcherBatch_MatchConntrackFlow(t *testing.T) {
	matcher := Matcher{
		ID:             "r1",
		SrcIP:          ipTo16("192.168.10.1"),
		SrcIPPrefixLen: 128,
		DstIP:          ipTo16("192.168.10.2"),
		DstIPPrefixLen: 128,
		IPProtocol:     unix.IPPROTO_TCP,
		SrcPort:        1000,
		SrcPortMask:    0xffff,
		DstPort:        80,
		DstPortMask:    0xffff,
	}
	bm := CookMatcherBatch([]Matcher{matcher})

	flow := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.10.1", "192.168.10.2", 1000, 80, unix.IPPROTO_TCP)
	if !bm.MatchConntrackFlow(flow) {
		t.Error("expected batch matcher to match flow")
	}

	flowWrongZone := makeIPv4Flow(constants.CTZoneForPolicyMin-1, "192.168.10.1", "192.168.10.2", 1000, 80, unix.IPPROTO_TCP)
	if bm.MatchConntrackFlow(flowWrongZone) {
		t.Error("expected batch matcher to NOT match flow with zone outside policy range")
	}

	flowWrongIP := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.10.3", "192.168.10.2", 1000, 80, unix.IPPROTO_TCP)
	if bm.MatchConntrackFlow(flowWrongIP) {
		t.Error("expected batch matcher to NOT match flow with wrong src ip")
	}
}

func TestMatcherBatch_MatchConntrackFlow_ZoneBoundary(t *testing.T) {
	matcher := Matcher{
		ID:             "r1",
		SrcIP:          ipTo16("192.168.1.1"),
		SrcIPPrefixLen: 128,
		DstIP:          ipTo16("192.168.1.2"),
		DstIPPrefixLen: 128,
		IPProtocol:     unix.IPPROTO_TCP,
		DstPort:        80,
		DstPortMask:    0xffff,
	}
	bm := CookMatcherBatch([]Matcher{matcher})

	// zone at min - should match
	flowMinZone := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.1", "192.168.1.2", 0, 80, unix.IPPROTO_TCP)
	if !bm.MatchConntrackFlow(flowMinZone) {
		t.Error("expected batch matcher to match flow at zone min")
	}

	// zone at max - should match
	flowMaxZone := makeIPv4Flow(constants.CTZoneForPolicyMax, "192.168.1.1", "192.168.1.2", 0, 80, unix.IPPROTO_TCP)
	if !bm.MatchConntrackFlow(flowMaxZone) {
		t.Error("expected batch matcher to match flow at zone max")
	}

	// zone below min - should not match
	flowBelow := makeIPv4Flow(constants.CTZoneForPolicyMin-1, "192.168.1.1", "192.168.1.2", 0, 80, unix.IPPROTO_TCP)
	if bm.MatchConntrackFlow(flowBelow) {
		t.Error("expected batch matcher to NOT match flow with zone below min")
	}

	// zone above max - should not match
	flowAbove := makeIPv4Flow(constants.CTZoneForPolicyMax+1, "192.168.1.1", "192.168.1.2", 0, 80, unix.IPPROTO_TCP)
	if bm.MatchConntrackFlow(flowAbove) {
		t.Error("expected batch matcher to NOT match flow with zone above max")
	}
}

func TestMatcherBatch_MatchConntrackFlow_Prefix(t *testing.T) {
	matcher := Matcher{
		ID:             "r1",
		SrcIP:          ipTo16("10.0.0.0"),
		SrcIPPrefixLen: toIpv6PrefixLen(24),
		DstIP:          ipTo16("192.168.0.0"),
		DstIPPrefixLen: toIpv6PrefixLen(24),
		IPProtocol:     unix.IPPROTO_TCP,
		DstPort:        80,
		DstPortMask:    0xffff,
	}
	bm := CookMatcherBatch([]Matcher{matcher})

	flowMatch := makeIPv4Flow(constants.CTZoneForPolicyMin, "10.0.0.50", "192.168.0.100", 12345, 80, unix.IPPROTO_TCP)
	if !bm.MatchConntrackFlow(flowMatch) {
		t.Error("expected batch matcher to match flow with prefix matchers")
	}

	flowNoMatch := makeIPv4Flow(constants.CTZoneForPolicyMin, "10.0.1.1", "192.168.0.1", 12345, 80, unix.IPPROTO_TCP)
	if bm.MatchConntrackFlow(flowNoMatch) {
		t.Error("expected batch matcher to NOT match flow with src outside prefix")
	}
}

func TestMatcherBatch_MatchConntrackFlow_IPv4Conversion(t *testing.T) {
	matcher := Matcher{
		ID:             "r1",
		SrcIP:          ipTo16("192.168.1.1"),
		SrcIPPrefixLen: 128,
		DstIP:          ipTo16("192.168.1.2"),
		DstIPPrefixLen: 128,
		IPProtocol:     unix.IPPROTO_TCP,
		DstPort:        80,
		DstPortMask:    0xffff,
	}
	bm := CookMatcherBatch([]Matcher{matcher})

	// flow with 4-byte IPv4 - MatchConntrackFlow converts to IPv4-mapped internally
	flow := &netlink.ConntrackFlow{
		FamilyType: unix.AF_INET,
		Zone:       constants.CTZoneForPolicyMin,
		HasLabels:  true,
		Forward: netlink.IPTuple{
			SrcIP:    net.ParseIP("192.168.1.1").To4(),
			DstIP:    net.ParseIP("192.168.1.2").To4(),
			SrcPort:  12345,
			DstPort:  80,
			Protocol: unix.IPPROTO_TCP,
		},
		Reverse: netlink.IPTuple{
			SrcIP:    net.ParseIP("192.168.1.2").To4(),
			DstIP:    net.ParseIP("192.168.1.1").To4(),
			SrcPort:  80,
			DstPort:  12345,
			Protocol: unix.IPPROTO_TCP,
		},
	}
	if !bm.MatchConntrackFlow(flow) {
		t.Error("expected batch matcher to match flow with 4-byte IPv4 (converted internally)")
	}
}

func TestMatcherBatch_MatchConntrackFlow_Multiple(t *testing.T) {
	matchers := []Matcher{
		{
			ID:             "r1",
			SrcIP:          ipTo16("192.168.1.1"),
			SrcIPPrefixLen: 128,
			DstIP:          ipTo16("192.168.1.2"),
			DstIPPrefixLen: 128,
			IPProtocol:     unix.IPPROTO_TCP,
			DstPort:        80,
			DstPortMask:    0xffff,
		},
		{
			ID:             "r2",
			SrcIP:          ipTo16("192.168.1.3"),
			SrcIPPrefixLen: 128,
			DstIP:          ipTo16("192.168.1.4"),
			DstIPPrefixLen: 128,
			IPProtocol:     unix.IPPROTO_TCP,
			DstPort:        443,
			DstPortMask:    0xffff,
		},
	}
	bm := CookMatcherBatch(matchers)

	// first matcher matches
	flow1 := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.1", "192.168.1.2", 0, 80, unix.IPPROTO_TCP)
	if !bm.MatchConntrackFlow(flow1) {
		t.Error("expected batch matcher to match first matcher")
	}

	// second matcher matches
	flow2 := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.3", "192.168.1.4", 0, 443, unix.IPPROTO_TCP)
	if !bm.MatchConntrackFlow(flow2) {
		t.Error("expected batch matcher to match second matcher")
	}

	// no matcher matches
	flowNone := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.5", "192.168.1.6", 0, 8080, unix.IPPROTO_TCP)
	if bm.MatchConntrackFlow(flowNone) {
		t.Error("expected batch matcher to NOT match when no matcher matches")
	}
}

func TestMatcherBatch_MatchConntrackFlow_AnyIP(t *testing.T) {
	matcher := Matcher{
		ID:             "r1",
		SrcIPPrefixLen: 0,
		DstIPPrefixLen: 0,
		IPProtocol:     unix.IPPROTO_TCP,
		DstPort:        443,
		DstPortMask:    0xffff,
	}
	bm := CookMatcherBatch([]Matcher{matcher})

	flow := makeIPv4Flow(constants.CTZoneForPolicyMin, "1.2.3.4", "5.6.7.8", 12345, 443, unix.IPPROTO_TCP)
	if !bm.MatchConntrackFlow(flow) {
		t.Error("expected any-IP matcher to match flow")
	}

	// wrong port - should not match
	flowWrongPort := makeIPv4Flow(constants.CTZoneForPolicyMin, "1.2.3.4", "5.6.7.8", 12345, 80, unix.IPPROTO_TCP)
	if bm.MatchConntrackFlow(flowWrongPort) {
		t.Error("expected any-IP matcher to NOT match when dst port differs")
	}

	// UDP any-IP matcher
	matcherUDP := Matcher{
		ID:             "r2",
		SrcIPPrefixLen: 0,
		DstIPPrefixLen: 0,
		IPProtocol:     unix.IPPROTO_UDP,
		DstPort:        53,
		DstPortMask:    0xffff,
	}
	bmUDP := CookMatcherBatch([]Matcher{matcherUDP})
	flowUDP := makeIPv4Flow(constants.CTZoneForPolicyMin, "8.8.8.8", "1.1.1.1", 54321, 53, unix.IPPROTO_UDP)
	if !bmUDP.MatchConntrackFlow(flowUDP) {
		t.Error("expected any-IP UDP matcher to match flow")
	}
}

func TestMatcher_MatchConntrackFlow_ICMP(t *testing.T) {
	matcher := Matcher{
		ID:             "r1",
		SrcIP:          ipTo16("192.168.1.1"),
		SrcIPPrefixLen: 128,
		DstIP:          ipTo16("192.168.1.2"),
		DstIPPrefixLen: 128,
		IPProtocol:     unix.IPPROTO_ICMP,
		IcmpTypeEnable: true,
		IcmpType:       8,
	}

	flow := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.1", "192.168.1.2", 0, 0, unix.IPPROTO_ICMP)
	flow.Forward.ICMPType = 8
	flow.Forward.ICMPCode = 0
	flow.Reverse.ICMPType = 0
	flow.Reverse.ICMPCode = 0

	if !matcher.MatchConntrackFlow(flow) {
		t.Error("expected ICMP matcher to match flow with type 8")
	}

	flow.Forward.ICMPType = 13
	if matcher.MatchConntrackFlow(flow) {
		t.Error("expected ICMP matcher to NOT match flow with wrong type")
	}
}

func TestMatcher_MatchConntrackFlow_ICMP_AnyType(t *testing.T) {
	matcher := Matcher{
		ID:             "r1",
		SrcIP:          ipTo16("192.168.1.1"),
		SrcIPPrefixLen: 128,
		DstIP:          ipTo16("192.168.1.2"),
		DstIPPrefixLen: 128,
		IPProtocol:     unix.IPPROTO_ICMP,
		IcmpTypeEnable: false,
	}

	flow := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.1", "192.168.1.2", 0, 0, unix.IPPROTO_ICMP)
	flow.Forward.ICMPType = 0
	flow.Forward.ICMPCode = 0

	if !matcher.MatchConntrackFlow(flow) {
		t.Error("expected ICMP matcher with IcmpTypeEnable=false to match any type")
	}

	flow.Forward.ICMPType = 8
	if !matcher.MatchConntrackFlow(flow) {
		t.Error("expected ICMP matcher with IcmpTypeEnable=false to match type 8")
	}
}

func TestMatcherBatch_MatchConntrackFlow_ICMP(t *testing.T) {
	matcher := Matcher{
		ID:             "r1",
		SrcIP:          ipTo16("192.168.1.1"),
		SrcIPPrefixLen: 128,
		DstIP:          ipTo16("192.168.1.2"),
		DstIPPrefixLen: 128,
		IPProtocol:     unix.IPPROTO_ICMP,
		IcmpTypeEnable: true,
		IcmpType:       8,
	}
	bm := CookMatcherBatch([]Matcher{matcher})

	flow := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.1", "192.168.1.2", 0, 0, unix.IPPROTO_ICMP)
	flow.Forward.ICMPType = 8
	if !bm.MatchConntrackFlow(flow) {
		t.Error("expected batch matcher to match ICMP flow")
	}
}

func TestMatcher_MatchConntrackFlow_UDP(t *testing.T) {
	matcher := Matcher{
		ID:             "r1",
		SrcIP:          ipTo16("192.168.1.1"),
		SrcIPPrefixLen: 128,
		DstIP:          ipTo16("192.168.1.2"),
		DstIPPrefixLen: 128,
		IPProtocol:     unix.IPPROTO_UDP,
		SrcPort:        54321,
		SrcPortMask:    0xffff,
		DstPort:        53,
		DstPortMask:    0xffff,
	}

	flowMatch := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.1", "192.168.1.2", 54321, 53, unix.IPPROTO_UDP)
	if !matcher.MatchConntrackFlow(flowMatch) {
		t.Error("expected matcher to match UDP flow (forward direction)")
	}

	flowReverse := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.2", "192.168.1.1", 53, 54321, unix.IPPROTO_UDP)
	if !matcher.MatchConntrackFlow(flowReverse) {
		t.Error("expected matcher to match UDP flow (reverse direction)")
	}

	flowWrongPort := makeIPv4Flow(constants.CTZoneForPolicyMin, "192.168.1.1", "192.168.1.2", 54322, 53, unix.IPPROTO_UDP)
	if matcher.MatchConntrackFlow(flowWrongPort) {
		t.Error("expected matcher to NOT match flow with wrong src port")
	}
}

func TestMatcher_MatchConntrackFlow_IPv6_TCP(t *testing.T) {
	matcher := Matcher{
		ID:             "r1",
		SrcIP:          ipTo16("2001:db8::1"),
		SrcIPPrefixLen: 128,
		DstIP:          ipTo16("2001:db8::2"),
		DstIPPrefixLen: 128,
		IPProtocol:     unix.IPPROTO_TCP,
		DstPort:        443,
		DstPortMask:    0xffff,
	}

	flowMatch := makeIPv6Flow(constants.CTZoneForPolicyMin, "2001:db8::1", "2001:db8::2", 12345, 443, unix.IPPROTO_TCP)
	if !matcher.MatchConntrackFlow(flowMatch) {
		t.Error("expected matcher to match IPv6 TCP flow")
	}

	flowWrongIP := makeIPv6Flow(constants.CTZoneForPolicyMin, "2001:db8::3", "2001:db8::2", 12345, 443, unix.IPPROTO_TCP)
	if matcher.MatchConntrackFlow(flowWrongIP) {
		t.Error("expected matcher to NOT match flow with wrong src ip")
	}
}

func TestMatcher_MatchConntrackFlow_IPv6_UDP(t *testing.T) {
	matcher := Matcher{
		ID:             "r1",
		SrcIP:          ipTo16("2001:db8::1"),
		SrcIPPrefixLen: 128,
		DstIP:          ipTo16("2001:db8::2"),
		DstIPPrefixLen: 128,
		IPProtocol:     unix.IPPROTO_UDP,
		DstPort:        53,
		DstPortMask:    0xffff,
	}

	flowMatch := makeIPv6Flow(constants.CTZoneForPolicyMin, "2001:db8::1", "2001:db8::2", 54321, 53, unix.IPPROTO_UDP)
	if !matcher.MatchConntrackFlow(flowMatch) {
		t.Error("expected matcher to match IPv6 UDP flow")
	}
}

func TestMatcher_MatchConntrackFlow_IPv6_ICMPv6(t *testing.T) {
	matcher := Matcher{
		ID:             "r1",
		SrcIP:          ipTo16("2001:db8::1"),
		SrcIPPrefixLen: 128,
		DstIP:          ipTo16("2001:db8::2"),
		DstIPPrefixLen: 128,
		IPProtocol:     unix.IPPROTO_ICMPV6,
		IcmpTypeEnable: true,
		IcmpType:       128, // ICMPv6 echo request
	}

	flow := makeFlowWithICMP(constants.CTZoneForPolicyMin, unix.AF_INET6, "2001:db8::1", "2001:db8::2", 128, 0, 1, unix.IPPROTO_ICMPV6)
	if !matcher.MatchConntrackFlow(flow) {
		t.Error("expected ICMPv6 matcher to match flow with type 128")
	}

	flow.Forward.ICMPType = 129 // echo reply
	if matcher.MatchConntrackFlow(flow) {
		t.Error("expected ICMPv6 matcher to NOT match flow with wrong type")
	}
}

func TestMatcher_MatchConntrackFlow_GRE(t *testing.T) {
	matcher := Matcher{
		ID:             "r1",
		SrcIP:          ipTo16("192.168.1.1"),
		SrcIPPrefixLen: 128,
		DstIP:          ipTo16("192.168.1.2"),
		DstIPPrefixLen: 128,
		IPProtocol:     unix.IPPROTO_GRE,
	}

	flowMatch := makeFlowGeneric(constants.CTZoneForPolicyMin, unix.AF_INET, "192.168.1.1", "192.168.1.2", unix.IPPROTO_GRE)
	if !matcher.MatchConntrackFlow(flowMatch) {
		t.Error("expected matcher to match GRE flow")
	}

	flowWrongIP := makeFlowGeneric(constants.CTZoneForPolicyMin, unix.AF_INET, "192.168.1.3", "192.168.1.2", unix.IPPROTO_GRE)
	if matcher.MatchConntrackFlow(flowWrongIP) {
		t.Error("expected matcher to NOT match GRE flow with wrong src ip")
	}
}

func TestMatcher_MatchConntrackFlow_IPIP(t *testing.T) {
	matcher := Matcher{
		ID:             "r1",
		SrcIP:          ipTo16("10.0.0.1"),
		SrcIPPrefixLen: 128,
		DstIP:          ipTo16("10.0.0.2"),
		DstIPPrefixLen: 128,
		IPProtocol:     unix.IPPROTO_IPIP,
	}

	flowMatch := makeFlowGeneric(constants.CTZoneForPolicyMin, unix.AF_INET, "10.0.0.1", "10.0.0.2", unix.IPPROTO_IPIP)
	if !matcher.MatchConntrackFlow(flowMatch) {
		t.Error("expected matcher to match IPIP flow")
	}

	flowWrongProto := makeFlowGeneric(constants.CTZoneForPolicyMin, unix.AF_INET, "10.0.0.1", "10.0.0.2", unix.IPPROTO_GRE)
	if matcher.MatchConntrackFlow(flowWrongProto) {
		t.Error("expected matcher to NOT match flow with wrong protocol")
	}
}

func TestMatcherBatch_MatchConntrackFlow_GRE(t *testing.T) {
	matcher := Matcher{
		ID:             "r1",
		SrcIP:          ipTo16("192.168.1.1"),
		SrcIPPrefixLen: 128,
		DstIP:          ipTo16("192.168.1.2"),
		DstIPPrefixLen: 128,
		IPProtocol:     unix.IPPROTO_GRE,
	}
	bm := CookMatcherBatch([]Matcher{matcher})

	flow := makeFlowGeneric(constants.CTZoneForPolicyMin, unix.AF_INET, "192.168.1.1", "192.168.1.2", unix.IPPROTO_GRE)
	if !bm.MatchConntrackFlow(flow) {
		t.Error("expected batch matcher to match GRE flow (OtherMatchers)")
	}
}

func TestMatcherBatch_MatchConntrackFlow_IPIP(t *testing.T) {
	matcher := Matcher{
		ID:             "r1",
		SrcIP:          ipTo16("10.0.0.1"),
		SrcIPPrefixLen: 128,
		DstIP:          ipTo16("10.0.0.2"),
		DstIPPrefixLen: 128,
		IPProtocol:     unix.IPPROTO_IPIP,
	}
	bm := CookMatcherBatch([]Matcher{matcher})

	flow := makeFlowGeneric(constants.CTZoneForPolicyMin, unix.AF_INET, "10.0.0.1", "10.0.0.2", unix.IPPROTO_IPIP)
	if !bm.MatchConntrackFlow(flow) {
		t.Error("expected batch matcher to match IPIP flow (OtherMatchers)")
	}
}

func TestMatcherBatch_MatchConntrackFlow_IPv6(t *testing.T) {
	matcher := Matcher{
		ID:             "r1",
		SrcIP:          ipTo16("2001:db8::1"),
		SrcIPPrefixLen: 128,
		DstIP:          ipTo16("2001:db8::2"),
		DstIPPrefixLen: 128,
		IPProtocol:     unix.IPPROTO_TCP,
		DstPort:        80,
		DstPortMask:    0xffff,
	}
	bm := CookMatcherBatch([]Matcher{matcher})

	flow := makeIPv6Flow(constants.CTZoneForPolicyMin, "2001:db8::1", "2001:db8::2", 12345, 80, unix.IPPROTO_TCP)
	if !bm.MatchConntrackFlow(flow) {
		t.Error("expected batch matcher to match IPv6 TCP flow")
	}

	flowICMPv6 := makeFlowWithICMP(constants.CTZoneForPolicyMin, unix.AF_INET6, "2001:db8::1", "2001:db8::2", 128, 0, 1, unix.IPPROTO_ICMPV6)
	matcherICMPv6 := Matcher{
		ID:             "r2",
		SrcIP:          ipTo16("2001:db8::1"),
		SrcIPPrefixLen: 128,
		DstIP:          ipTo16("2001:db8::2"),
		DstIPPrefixLen: 128,
		IPProtocol:     unix.IPPROTO_ICMPV6,
		IcmpTypeEnable: true,
		IcmpType:       128,
	}
	bmICMPv6 := CookMatcherBatch([]Matcher{matcherICMPv6})
	if !bmICMPv6.MatchConntrackFlow(flowICMPv6) {
		t.Error("expected batch matcher to match IPv6 ICMPv6 flow")
	}
}

func TestCookMatcherBatch_ICMPv6AndGRE(t *testing.T) {
	matchers := []Matcher{
		{SrcIPPrefixLen: 0, DstIPPrefixLen: 0, IPProtocol: unix.IPPROTO_ICMPV6, ID: "icmpv6"},
		{SrcIPPrefixLen: 0, DstIPPrefixLen: 0, IPProtocol: unix.IPPROTO_GRE, ID: "gre"},
		{SrcIPPrefixLen: 0, DstIPPrefixLen: 0, IPProtocol: unix.IPPROTO_IPIP, ID: "ipip"},
	}
	bm := CookMatcherBatch(matchers)
	if len(bm.IDs) != 3 {
		t.Errorf("IDs len = %d, want 3", len(bm.IDs))
	}
	if len(bm.AnyIPMatchers.ICMPMatchers) != 1 {
		t.Errorf("ICMPMatchers len = %d, want 1 (ICMPv6)", len(bm.AnyIPMatchers.ICMPMatchers))
	}
	if len(bm.AnyIPMatchers.OtherMatchers) != 2 {
		t.Errorf("OtherMatchers len = %d, want 2 (GRE, IPIP)", len(bm.AnyIPMatchers.OtherMatchers))
	}
}
